"""P1.11 -- `core.idempotency.run_idempotent()`/`begin_idempotent_operation()`
integration tests against a real PostgreSQL instance: the mandatory
concurrency gates (identical concurrent requests, same-key-different-
payload, cross-tenant isolation, retry-after-success, retry-after-failure),
using a generic dummy business operation. The two *real* Core consumers
(`core.billing.service.subscribe_idempotent()`,
`core.usage.service.consume_quota_idempotent()`) have their own,
consumer-specific integration tests.

Marked `integration`; excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/idempotency/test_idempotency_integration.py
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from core.idempotency.errors import IdempotencyKeyReusedError
from core.idempotency.service import IdempotencyStatus as Status
from core.idempotency.service import (
    begin_idempotent_operation,
    finalize_idempotent_operation,
    purge_expired_idempotency_records,
    run_idempotent,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.idempotency_records LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.idempotency_records does not exist yet -- run `alembic upgrade head`: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured: {exc}")


class _CounterFixture:
    """A generic 'business operation' with an observable, real database
    side effect (a row count in a scratch table) -- proves side-effect
    execution counts directly, independent of any one real consumer's
    own semantics."""

    def __init__(self) -> None:
        self.tenant = create_tenant(f"idem-tenant-{uuid.uuid4().hex[:8]}")
        self.table = f"idem_counter_{uuid.uuid4().hex[:8]}"
        engine = build_engine(get_migrations_database_config())
        try:
            factory = build_session_factory(engine)
            with session_scope(session_factory=factory) as session:
                session.execute(
                    text(f"CREATE TABLE {self.table} (id SERIAL PRIMARY KEY, tag TEXT)")
                )
                session.execute(text(f"GRANT ALL ON {self.table} TO saas_os_app"))
                session.execute(text(f"GRANT ALL ON {self.table}_id_seq TO saas_os_app"))
        finally:
            engine.dispose()

    def side_effect_count(self) -> int:
        with tenant_session_scope(self.tenant.id) as session:
            count = session.execute(text(f"SELECT COUNT(*) AS n FROM {self.table}")).one()
        return count.n

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.idempotency_records WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        engine = build_engine(get_migrations_database_config())
        try:
            factory = build_session_factory(engine)
            with session_scope(session_factory=factory) as session:
                session.execute(text(f"DROP TABLE IF EXISTS {self.table}"))
        finally:
            engine.dispose()
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def make_fixture():
    created: list[_CounterFixture] = []

    def _make() -> _CounterFixture:
        fx = _CounterFixture()
        created.append(fx)
        return fx

    yield _make
    for fx in created:
        fx.cleanup()


def _business_insert(fx: _CounterFixture, tag: str):
    def _fn(session):
        session.execute(text(f"INSERT INTO {fx.table} (tag) VALUES (:tag)"), {"tag": tag})
        return {"tag": tag}

    return _fn


# --- Test 1: identical concurrent requests -------------------------------


def test_concurrent_identical_requests_produce_exactly_one_side_effect(make_fixture) -> None:
    fx = make_fixture()
    key = "concurrent-key-1"

    def _attempt(_: int) -> tuple[bool, dict]:
        return run_idempotent(
            fx.tenant.id, "test.op", key, {"request": "X"}, _business_insert(fx, "X")
        )

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_attempt, range(10)))

    assert fx.side_effect_count() == 1
    assert all(result == {"tag": "X"} for _is_replay, result in results)
    assert sum(1 for is_replay, _ in results if not is_replay) == 1
    assert sum(1 for is_replay, _ in results if is_replay) == 9

    with tenant_session_scope(fx.tenant.id) as session:
        record_count = session.execute(
            text(
                "SELECT COUNT(*) AS n FROM core.idempotency_records "
                "WHERE tenant_id = :t AND operation = 'test.op' AND idempotency_key = :k"
            ),
            {"t": str(fx.tenant.id), "k": key},
        ).one()
    assert record_count.n == 1


# --- Test 2: same key, different payload ---------------------------------


def test_same_key_different_payload_one_succeeds_other_conflicts(make_fixture) -> None:
    fx = make_fixture()
    key = "same-key-different-payload"

    is_replay, result = run_idempotent(
        fx.tenant.id, "test.op", key, {"request": "X"}, _business_insert(fx, "X")
    )
    assert is_replay is False
    assert result == {"tag": "X"}

    with pytest.raises(IdempotencyKeyReusedError):
        run_idempotent(fx.tenant.id, "test.op", key, {"request": "Y"}, _business_insert(fx, "Y"))

    assert fx.side_effect_count() == 1  # the conflicting attempt never ran


# --- Test 3: cross-tenant same key ----------------------------------------


def test_cross_tenant_same_key_operates_independently(make_fixture) -> None:
    tenant_a = make_fixture()
    tenant_b = make_fixture()
    key = "shared-key-string"

    is_replay_a, result_a = run_idempotent(
        tenant_a.tenant.id, "test.op", key, {"request": "X"}, _business_insert(tenant_a, "X")
    )
    is_replay_b, result_b = run_idempotent(
        tenant_b.tenant.id, "test.op", key, {"request": "X"}, _business_insert(tenant_b, "X")
    )

    assert is_replay_a is False
    assert is_replay_b is False
    assert tenant_a.side_effect_count() == 1
    assert tenant_b.side_effect_count() == 1


def test_tenant_a_cannot_inspect_tenant_bs_idempotency_records(make_fixture) -> None:
    tenant_a = make_fixture()
    tenant_b = make_fixture()
    run_idempotent(
        tenant_b.tenant.id, "test.op", "key-1", {"request": "X"}, _business_insert(tenant_b, "X")
    )

    with tenant_session_scope(tenant_a.tenant.id) as session:
        visible = session.execute(
            text("SELECT COUNT(*) AS n FROM core.idempotency_records WHERE tenant_id = :t"),
            {"t": str(tenant_b.tenant.id)},
        ).one()
    assert visible.n == 0


# --- Test 4: retry after successful transaction ---------------------------


def test_retry_after_success_does_not_repeat_the_side_effect(make_fixture) -> None:
    fx = make_fixture()
    key = "retry-after-success"

    for _ in range(5):
        is_replay, result = run_idempotent(
            fx.tenant.id, "test.op", key, {"request": "X"}, _business_insert(fx, "X")
        )
        assert result == {"tag": "X"}

    assert fx.side_effect_count() == 1


# --- Test 5: failed transaction --------------------------------------------


def test_retry_after_a_failed_attempt_can_execute(make_fixture) -> None:
    fx = make_fixture()
    key = "retry-after-failure"

    def _failing_business(session):
        session.execute(text(f"INSERT INTO {fx.table} (tag) VALUES ('should-not-persist')"))
        raise RuntimeError("simulated business failure")

    with pytest.raises(RuntimeError):
        run_idempotent(fx.tenant.id, "test.op", key, {"request": "X"}, _failing_business)

    assert fx.side_effect_count() == 0  # rolled back entirely, including the insert

    is_replay, result = run_idempotent(
        fx.tenant.id, "test.op", key, {"request": "X"}, _business_insert(fx, "X")
    )
    assert is_replay is False
    assert fx.side_effect_count() == 1


# --- Concurrent distinct keys do not block each other ---------------------


def test_concurrent_distinct_keys_do_not_block_each_other(make_fixture) -> None:
    fx = make_fixture()

    def _attempt(i: int) -> bool:
        is_replay, _ = run_idempotent(
            fx.tenant.id,
            "test.op",
            f"distinct-key-{i}",
            {"request": i},
            _business_insert(fx, str(i)),
        )
        return is_replay

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_attempt, range(10)))

    assert all(is_replay is False for is_replay in results)
    assert fx.side_effect_count() == 10


# --- Two-step primitive (begin/finalize) -----------------------------------


def test_two_step_reservation_then_finalize_success(make_fixture) -> None:
    fx = make_fixture()
    reservation = begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-a", {"x": 1})
    assert reservation.is_replay is False

    finalize_idempotent_operation(
        fx.tenant.id, reservation.record_id, status=Status.SUCCEEDED, result={"done": True}
    )

    replay = begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-a", {"x": 1})
    assert replay.is_replay is True
    assert replay.result == {"done": True}


def test_two_step_pending_within_ttl_reports_in_progress(make_fixture) -> None:
    from core.idempotency.errors import IdempotencyInProgressError

    fx = make_fixture()
    reservation = begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-b", {"x": 1})
    assert reservation.is_replay is False
    # Never finalized -- simulates an operation still genuinely in flight.

    with pytest.raises(IdempotencyInProgressError):
        begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-b", {"x": 1})


def test_two_step_failed_reservation_allows_retry(make_fixture) -> None:
    fx = make_fixture()
    reservation = begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-c", {"x": 1})
    finalize_idempotent_operation(fx.tenant.id, reservation.record_id, status=Status.FAILED)

    retry = begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-c", {"x": 1})
    assert retry.is_replay is False

    finalize_idempotent_operation(
        fx.tenant.id, retry.record_id, status=Status.SUCCEEDED, result={"done": True}
    )
    replay = begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-c", {"x": 1})
    assert replay.is_replay is True


def test_two_step_abandoned_pending_past_ttl_allows_retry(make_fixture) -> None:
    fx = make_fixture()
    reservation = begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-d", {"x": 1})

    # Simulate a crashed/abandoned attempt: backdate updated_at past the
    # pending TTL directly (privileged role, mirrors other fixtures' own
    # admin-backdating helpers).
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text(
                    "UPDATE core.idempotency_records SET updated_at = :old "
                    "WHERE tenant_id = :t AND idempotency_key = 'key-d'"
                ),
                {"old": datetime.now(UTC) - timedelta(hours=1), "t": str(fx.tenant.id)},
            )
    finally:
        engine.dispose()

    retry = begin_idempotent_operation(fx.tenant.id, "test.two_step", "key-d", {"x": 1})
    assert retry.is_replay is False
    assert retry.record_id == reservation.record_id  # same row, reset rather than duplicated


# --- Retention --------------------------------------------------------


def test_purge_deletes_only_expired_records(make_fixture) -> None:
    fx = make_fixture()
    run_idempotent(
        fx.tenant.id, "test.op", "expires-soon", {"x": 1}, _business_insert(fx, "expires-soon")
    )

    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text(
                    "UPDATE core.idempotency_records SET expires_at = :old "
                    "WHERE tenant_id = :t AND idempotency_key = 'expires-soon'"
                ),
                {"old": datetime.now(UTC) - timedelta(seconds=1), "t": str(fx.tenant.id)},
            )
    finally:
        engine.dispose()

    deleted = purge_expired_idempotency_records(fx.tenant.id)
    assert deleted == 1
