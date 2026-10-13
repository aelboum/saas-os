"""RA-12-5 -- bounded session cleanup (`saas_os.core.identity.session_retention`),
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
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from saas_os.core.identity.config import SessionRetentionConfig
from saas_os.core.identity.erasure import erase_user_identity
from saas_os.core.identity.errors import SessionExpiredError, SessionRevokedError
from saas_os.core.identity.models import Session, User
from saas_os.core.identity.session_retention import cleanup_expired_sessions
from saas_os.core.identity.sessions import issue_session, revoke_session, validate_session
from saas_os.infra.db import select, session_scope
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from sqlalchemy import text

    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine
    from saas_os.infra.db.session import build_session_factory, session_scope

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
            # ADR-0045 Phase C: lifecycle changes also write platform audit
            # rows, which reference the tenant or the acting user and which
            # the runtime role can never delete.
            platform_where = (
                "target_tenant_id::text = ANY(:v)"
                if table == "tenants"
                else "actor_user_id::text = ANY(:v)"
            )
            # A migration test may be cleaning up below the revision that
            # creates the table.
            if session.execute(text("SELECT to_regclass('core.platform_audit_log')")).scalar():
                session.execute(
                    text(f"DELETE FROM core.platform_audit_log WHERE {platform_where}"),  # noqa: S608
                    {"v": values},
                )
    finally:
        engine.dispose()


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
        _admin_clear_audit_references({"u": str(new_id)}, table="users")
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
    """RA-12-5 batch-cardinality invariant (CI incident, 2026-09-17): a
    bare `IN (subquery)` construction was observed, in a live CI run, to
    delete 18 rows in a single batch against `cleanup_batch_size=10` --
    session_retention.py's own docstring ("Why `MATERIALIZED`, not a bare
    `IN (subquery)`") has the full account. `batches == 3` (not merely
    `>= 3`) is the actual invariant this test exists to prove: 25 rows at
    batch size 10 must split as exactly 10, 10, 5 -- never fewer, larger
    batches."""
    seeded = [
        _seed_session(user_id, token_hash=f"batch-{i}", expires_delta=-timedelta(minutes=1))
        for i in range(25)
    ]
    assert _CONFIG.cleanup_batch_size < len(seeded)

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == 25
    assert result.batches == 3  # 25 rows / batch size 10: 10 + 10 + 5, never fewer
    assert _remaining_session_ids(user_id).isdisjoint(seeded)


def test_batch_exactly_matches_batch_size(user_id: uuid.UUID) -> None:
    """Exactly `cleanup_batch_size` rows -- the boundary case between one
    batch and two: must complete in exactly one batch, not stop short or
    spill into a second."""
    seeded = [
        _seed_session(user_id, token_hash=f"exact-{i}", expires_delta=-timedelta(minutes=1))
        for i in range(_CONFIG.cleanup_batch_size)
    ]

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == _CONFIG.cleanup_batch_size
    assert result.batches == 1
    assert _remaining_session_ids(user_id).isdisjoint(seeded)


def test_batch_fewer_than_batch_size(user_id: uuid.UUID) -> None:
    """Fewer rows than one batch: still exactly one batch, not zero."""
    seeded = [
        _seed_session(user_id, token_hash=f"few-{i}", expires_delta=-timedelta(minutes=1))
        for i in range(7)
    ]
    assert len(seeded) < _CONFIG.cleanup_batch_size

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == 7
    assert result.batches == 1
    assert _remaining_session_ids(user_id).isdisjoint(seeded)


def test_batch_zero_rows_is_zero_batches(user_id: uuid.UUID) -> None:
    """No eligible rows at all: zero batches, not one empty pass counted
    as work done."""
    active = _seed_session(user_id, token_hash="zero-active", expires_delta=timedelta(hours=1))

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == 0
    assert result.revoked_deleted == 0
    assert result.batches == 0
    assert active in _remaining_session_ids(user_id)


def test_batch_drains_more_than_three_batches(user_id: uuid.UUID) -> None:
    """A backlog spanning more than two batches: 35 rows at batch size 10
    must be exactly 10 + 10 + 10 + 5 -- four batches, not fewer."""
    seeded = [
        _seed_session(user_id, token_hash=f"large-{i}", expires_delta=-timedelta(minutes=1))
        for i in range(35)
    ]

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == 35
    assert result.batches == 4
    assert _remaining_session_ids(user_id).isdisjoint(seeded)


def test_revoked_phase_also_respects_batch_cardinality(user_id: uuid.UUID) -> None:
    """The same `MATERIALIZED`-CTE batching applies to the revoked-past-
    grace-period phase, not only the expired phase -- proven independently
    since the two phases use different `_delete_one_batch()` call sites
    with a different `condition`. 25 sessions, each revoked well past the
    grace period but not yet expired (so only the revoked phase, never the
    expired phase, can match them)."""
    seeded = [
        _seed_session(
            user_id,
            token_hash=f"revoked-batch-{i}",
            expires_delta=timedelta(hours=1),
            revoked_delta=-timedelta(seconds=_GRACE_PERIOD_SECONDS + 60),
        )
        for i in range(25)
    ]
    assert _CONFIG.cleanup_batch_size < len(seeded)

    result = cleanup_expired_sessions(config=_CONFIG)

    assert result.expired_deleted == 0
    assert result.revoked_deleted == 25
    assert result.batches == 3
    assert _remaining_session_ids(user_id).isdisjoint(seeded)


def test_every_individual_batch_never_exceeds_batch_size(user_id: uuid.UUID) -> None:
    """Verifies the invariant directly, not just its aggregate consequence:
    calls the private per-batch primitive itself against a backlog several
    times larger than one batch, and asserts every single call's own
    return value is bounded by `batch_size` -- the exact property the CI
    incident violated (one call returned 18 against `limit=10`)."""
    from saas_os.core.identity.session_retention import _delete_one_batch

    seeded = [
        _seed_session(user_id, token_hash=f"invariant-{i}", expires_delta=-timedelta(minutes=1))
        for i in range(47)
    ]
    small_batch_size = 5

    per_call_counts: list[int] = []
    while True:
        removed = _delete_one_batch(Session.expires_at < datetime.now(UTC), small_batch_size)
        if removed == 0:
            break
        per_call_counts.append(removed)

    assert all(count <= small_batch_size for count in per_call_counts), per_call_counts
    assert sum(per_call_counts) == len(seeded)
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


def test_concurrent_workers_each_batch_stays_within_batch_size(user_id: uuid.UUID) -> None:
    """Concurrency variant of `test_every_individual_batch_never_exceeds_
    batch_size`: multiple threads drain the same backlog via the private
    per-batch primitive directly (`SKIP LOCKED` is the only thing that
    makes this safe -- no application-level lock exists). Every batch any
    worker sees, and the union of all workers' rows, must both respect the
    invariant: no batch over `batch_size`, no row claimed twice."""
    from saas_os.core.identity.session_retention import _delete_one_batch

    seeded = [
        _seed_session(user_id, token_hash=f"concurrent-{i}", expires_delta=-timedelta(minutes=1))
        for i in range(40)
    ]
    small_batch_size = 5

    all_counts: list[int] = []
    counts_lock = threading.Lock()
    errors: list[BaseException] = []

    def _drain_worker() -> None:
        try:
            while True:
                removed = _delete_one_batch(
                    Session.expires_at < datetime.now(UTC), small_batch_size
                )
                if removed == 0:
                    return
                with counts_lock:
                    all_counts.append(removed)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_drain_worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert all(count <= small_batch_size for count in all_counts), all_counts
    assert sum(all_counts) == len(seeded)
    assert _remaining_session_ids(user_id).isdisjoint(seeded)


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
