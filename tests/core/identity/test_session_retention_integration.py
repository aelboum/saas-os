"""RA-12-5 -- bounded session cleanup (`core.identity.session_retention`),
against a real PostgreSQL instance.

Proves the eligibility rules RA-12-4's audit and RA-12-5's remediation
both specify: an expired session is deleted regardless of revocation
state, a revoked session survives its grace period and is deleted only
once past it, an active (non-expired, non-revoked) session is never
touched, cleanup drains a backlog larger than one batch, cleanup is
idempotent, overlapping cleanup runs leave a correct final state, and
identity erasure (RA-12-3) is unaffected by any of this.

Marked `integration`, excluded from the default `pytest` run, mirroring
`tests/core/identity/test_erasure_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/identity/test_session_retention_integration.py
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from core.identity.config import SessionRetentionConfig
from core.identity.erasure import erase_user_identity
from core.identity.errors import SessionExpiredError, SessionRevokedError
from core.identity.models import Session, User
from core.identity.session_retention import cleanup_expired_sessions
from core.identity.sessions import issue_session, revoke_session, validate_session
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from infra.db import select, session_scope

pytestmark = pytest.mark.integration

_GRACE_PERIOD_SECONDS = 3600
_CONFIG = SessionRetentionConfig(
    revoked_grace_period_seconds=_GRACE_PERIOD_SECONDS,
    cleanup_batch_size=10,
    cleanup_interval_seconds=3600,
)


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")
    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.users LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at DATABASE_URL: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture
def user_id() -> Iterator[uuid.UUID]:
    new_id = uuid.uuid4()
    with session_scope() as session:
        session.add(User(id=new_id, is_active=True))
    yield new_id
    with session_scope() as session:
        session.execute(text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(new_id)})
        session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(new_id)})


def _seed_session(
    user_id: uuid.UUID,
    *,
    token_hash: str,
    expires_delta: timedelta,
    revoked_delta: timedelta | None = None,
) -> uuid.UUID:
    now = datetime.now(UTC)
    session_id = uuid.uuid4()
    revoked_at = now + revoked_delta if revoked_delta is not None else None
    with session_scope() as session:
        session.add(
            Session(
                id=session_id,
                user_id=user_id,
                token_hash=token_hash.ljust(64, "x")[:64],
                expires_at=now + expires_delta,
                revoked_at=revoked_at,
            )
        )
    return session_id


def _remaining_session_ids(user_id: uuid.UUID) -> set[uuid.UUID]:
    with session_scope() as session:
        rows = session.execute(select(Session.id).where(Session.user_id == user_id)).scalars().all()
        return set(rows)


def test_expired_session_is_deleted_active_and_future_expiring_remain(
    user_id: uuid.UUID,
) -> None:
    expired = _seed_session(user_id, token_hash="expired", expires_delta=-timedelta(hours=1))
    active = _seed_session(user_id, token_hash="active", expires_delta=timedelta(hours=1))
    future = _seed_session(user_id, token_hash="future", expires_delta=timedelta(days=1))

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == 1
    assert result.revoked_deleted == 0
    remaining = _remaining_session_ids(user_id)
    assert expired not in remaining
    assert {active, future} <= remaining


def test_recently_revoked_session_remains_during_grace_period(user_id: uuid.UUID) -> None:
    recent = _seed_session(
        user_id,
        token_hash="recent",
        expires_delta=timedelta(hours=1),
        revoked_delta=-timedelta(seconds=10),
    )

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.revoked_deleted == 0
    assert recent in _remaining_session_ids(user_id)


def test_revoked_session_older_than_grace_period_is_deleted(user_id: uuid.UUID) -> None:
    old = _seed_session(
        user_id,
        token_hash="old-revoked",
        expires_delta=timedelta(hours=1),
        revoked_delta=-timedelta(seconds=_GRACE_PERIOD_SECONDS + 60),
    )

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.revoked_deleted == 1
    assert old not in _remaining_session_ids(user_id)


def test_expired_and_revoked_session_is_deleted_as_expired(user_id: uuid.UUID) -> None:
    """An expired session is eligible regardless of revocation state --
    even revoked moments ago, well inside the grace period."""
    both = _seed_session(
        user_id,
        token_hash="expired-revoked",
        expires_delta=-timedelta(minutes=1),
        revoked_delta=-timedelta(seconds=1),
    )

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == 1
    assert result.revoked_deleted == 0
    assert both not in _remaining_session_ids(user_id)


def test_active_session_with_no_revocation_remains(user_id: uuid.UUID) -> None:
    active = _seed_session(user_id, token_hash="active-only", expires_delta=timedelta(hours=1))

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.total_deleted == 0
    assert active in _remaining_session_ids(user_id)


def test_batch_behavior_drains_a_backlog_larger_than_one_batch(user_id: uuid.UUID) -> None:
    seeded = [
        _seed_session(user_id, token_hash=f"batch-{i}", expires_delta=-timedelta(minutes=1))
        for i in range(25)
    ]
    assert _CONFIG.cleanup_batch_size < len(seeded)

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == 25
    assert result.batches >= 3  # 25 rows / batch size 10, rounded up
    assert _remaining_session_ids(user_id).isdisjoint(seeded)


def test_cleanup_is_idempotent(user_id: uuid.UUID) -> None:
    _seed_session(user_id, token_hash="once", expires_delta=-timedelta(minutes=1))

    first = cleanup_expired_sessions(config=_CONFIG)
    second = cleanup_expired_sessions(config=_CONFIG)

    assert first.expired_deleted == 1
    assert second.expired_deleted == 0
    assert second.revoked_deleted == 0
    assert second.batches == 0


def test_overlapping_cleanup_runs_leave_correct_final_state(user_id: uuid.UUID) -> None:
    expired_ids = [
        _seed_session(user_id, token_hash=f"race-{i}", expires_delta=-timedelta(minutes=1))
        for i in range(20)
    ]
    active = _seed_session(user_id, token_hash="race-active", expires_delta=timedelta(hours=1))

    results: list[int] = []
    errors: list[BaseException] = []

    def _run() -> None:
        try:
            r = cleanup_expired_sessions(config=_CONFIG)
            results.append(r.expired_deleted)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_run) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert sum(results) == 20
    remaining = _remaining_session_ids(user_id)
    assert remaining == {active}
    assert remaining.isdisjoint(expired_ids)


def test_expired_session_cannot_authenticate_even_before_cleanup(user_id: uuid.UUID) -> None:
    _, raw_token = issue_session(user_id, lifetime=timedelta(milliseconds=1))
    time.sleep(0.05)
    with pytest.raises(SessionExpiredError):
        validate_session(raw_token)
    # still physically present -- cleanup has not run
    assert len(_remaining_session_ids(user_id)) == 1


def test_revoked_session_cannot_authenticate_while_retained_during_grace_period(
    user_id: uuid.UUID,
) -> None:
    record, raw_token = issue_session(user_id)
    revoke_session(record.id)

    with pytest.raises(SessionRevokedError):
        validate_session(raw_token)

    # within grace period: cleanup must not remove it, and it still can't authenticate
    result = cleanup_expired_sessions(config=_CONFIG)
    assert result.revoked_deleted == 0
    with pytest.raises(SessionRevokedError):
        validate_session(raw_token)


def test_identity_erasure_still_deletes_sessions_immediately(user_id: uuid.UUID) -> None:
    """RA-12-5 security regression #5: RA-12-3 identity erasure is not
    regressed by this phase -- it still removes every session for the
    target user immediately, independent of expiry/revocation state and
    independent of this module's own scheduled cleanup."""
    _seed_session(user_id, token_hash="erase-active", expires_delta=timedelta(hours=1))
    _seed_session(user_id, token_hash="erase-future", expires_delta=timedelta(days=1))

    result = erase_user_identity(user_id, tenant_ids=(), actor_user_id=user_id)

    assert result.sessions_deleted == 2
    assert _remaining_session_ids(user_id) == set()


def test_cleanup_result_never_exposes_token_hash_or_session_id(user_id: uuid.UUID) -> None:
    """RA-12-5 security regression #6: no token value or identifier is
    persisted or exposed by the cleanup mechanism's own return value."""
    _seed_session(user_id, token_hash="opaque", expires_delta=-timedelta(minutes=1))

    result = cleanup_expired_sessions(config=_CONFIG)

    result_repr = repr(result)
    assert "opaque" not in result_repr
    assert str(user_id) not in result_repr
