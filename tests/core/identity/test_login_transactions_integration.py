"""P2.2 -- `core/identity/login_transactions.py` against real PostgreSQL:
unpredictable per-login secrets, single-use consumption under a row
lock, expiry, state mismatch, replay, and a genuine two-thread race.

Marked `integration`. Run locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        pytest -m integration tests/core/identity/test_login_transactions_integration.py
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from core.identity.errors import LoginTransactionInvalidError
from core.identity.login_transactions import (
    begin_login_transaction,
    consume_login_transaction,
    derive_code_challenge,
    purge_expired_login_transactions,
)
from core.identity.models import LoginTransaction
from infra.db.config import get_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope
from sqlalchemy import text

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.login_transactions LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.login_transactions not reachable: {exc}")
    finally:
        probe.dispose()


def _row(transaction_id: uuid.UUID) -> LoginTransaction | None:
    with session_scope() as session:
        record = session.get(LoginTransaction, transaction_id)
        if record is not None:
            session.expunge(record)
        return record


def _delete(transaction_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.login_transactions WHERE id = :id"), {"id": str(transaction_id)}
        )


def test_begin_persists_a_row_with_unpredictable_secrets() -> None:
    first = begin_login_transaction()
    second = begin_login_transaction()
    try:
        row = _row(first.transaction_id)
        assert row is not None
        assert row.state == first.state
        assert row.nonce == first.nonce
        assert derive_code_challenge(row.code_verifier) == first.code_challenge
        # 256-bit token_urlsafe -> 43 chars; all three distinct per login and
        # across logins.
        assert len(first.state) == len(first.nonce) == len(row.code_verifier) == 43
        assert len({first.state, first.nonce, row.code_verifier}) == 3
        assert first.state != second.state
        assert first.nonce != second.nonce
        assert first.code_challenge != second.code_challenge
        assert first.expires_at > datetime.now(UTC) + timedelta(minutes=9)
    finally:
        _delete(first.transaction_id)
        _delete(second.transaction_id)


def test_consume_returns_nonce_and_verifier_and_deletes_the_row() -> None:
    started = begin_login_transaction()
    consumed = consume_login_transaction(started.transaction_id, started.state)
    assert consumed.nonce == started.nonce
    assert derive_code_challenge(consumed.code_verifier) == started.code_challenge
    assert _row(started.transaction_id) is None


def test_reused_transaction_is_rejected() -> None:
    started = begin_login_transaction()
    consume_login_transaction(started.transaction_id, started.state)
    with pytest.raises(LoginTransactionInvalidError):
        consume_login_transaction(started.transaction_id, started.state)


def test_mismatched_state_is_rejected_and_burns_the_transaction() -> None:
    started = begin_login_transaction()
    with pytest.raises(LoginTransactionInvalidError):
        consume_login_transaction(started.transaction_id, "not-the-state")
    # A second attempt with the *correct* state must also fail now.
    with pytest.raises(LoginTransactionInvalidError):
        consume_login_transaction(started.transaction_id, started.state)
    assert _row(started.transaction_id) is None


def test_unknown_transaction_is_rejected() -> None:
    with pytest.raises(LoginTransactionInvalidError):
        consume_login_transaction(uuid.uuid4(), "any-state")


def test_missing_state_is_rejected() -> None:
    started = begin_login_transaction()
    try:
        with pytest.raises(LoginTransactionInvalidError):
            consume_login_transaction(started.transaction_id, "")
    finally:
        _delete(started.transaction_id)


def test_expired_transaction_is_rejected() -> None:
    started = begin_login_transaction(lifetime=timedelta(seconds=30))
    later = datetime.now(UTC) + timedelta(minutes=1)
    with pytest.raises(LoginTransactionInvalidError):
        consume_login_transaction(started.transaction_id, started.state, now=later)
    assert _row(started.transaction_id) is None


def test_every_failure_is_the_same_error_with_no_secret_in_it() -> None:
    started = begin_login_transaction()
    with pytest.raises(LoginTransactionInvalidError) as excinfo:
        consume_login_transaction(started.transaction_id, "wrong")
    text_ = str(excinfo.value)
    assert started.state not in text_
    assert started.nonce not in text_
    assert str(started.transaction_id) not in text_


def test_two_concurrent_consumptions_yield_exactly_one_success() -> None:
    """The replay-safety property at the database level: two threads race
    to consume the same transaction; the row lock serializes them and the
    loser finds no row."""
    started = begin_login_transaction()

    def _attempt() -> str:
        try:
            consume_login_transaction(started.transaction_id, started.state)
            return "ok"
        except LoginTransactionInvalidError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _: _attempt(), range(2)))
    assert outcomes == ["ok", "rejected"]
    assert _row(started.transaction_id) is None


def test_purge_deletes_only_expired_transactions() -> None:
    live = begin_login_transaction()
    stale = begin_login_transaction(lifetime=timedelta(seconds=1))
    try:
        deleted = purge_expired_login_transactions(now=datetime.now(UTC) + timedelta(minutes=1))
        assert deleted >= 1
        assert _row(stale.transaction_id) is None
        # The live one expires 10 minutes from now -- not past `now`+1min.
        assert _row(live.transaction_id) is not None
    finally:
        _delete(live.transaction_id)
        _delete(stale.transaction_id)
