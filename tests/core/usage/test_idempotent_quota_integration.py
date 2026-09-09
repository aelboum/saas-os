"""P1.11 -- `core.usage.service.consume_quota_idempotent()` integration
tests against a real PostgreSQL instance. This is the direct regression
this checkpoint's own "Interaction with P1.9 quota enforcement" section
requires: a retried request must not consume quota a second time.

Uses `core.idempotency.run_idempotent()`'s fully atomic, single-
transaction primitive (unlike `core.billing.service.subscribe_idempotent()`,
which needs the weaker two-step primitive for its external provider
call) -- `consume_quota_idempotent()` is entirely database-only, so the
concurrency test here proves the *stronger* guarantee: every concurrent
caller either executes or cleanly replays the committed result, never an
"in progress" outcome.

Marked `integration`; excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/usage/test_idempotent_quota_integration.py
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/usage/test_usage_integration.py's identical import for the
# full rationale (subscribe()'s audit write needs core.users mapped).
import core.identity.models  # noqa: F401
import pytest
from core.billing.provider import FakeBillingProvider
from core.billing.service import create_plan, subscribe
from core.idempotency.errors import IdempotencyKeyReusedError
from core.usage.errors import QuotaExceededError
from core.usage.service import aggregate_usage, consume_quota_idempotent
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
        pytest.skip(f"required tables do not exist yet -- run `alembic upgrade head`: {exc}")
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured: {exc}")


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _Fixture:
    def __init__(self, *, limit: int | None = None, metric: str = "api_calls") -> None:
        self.tenant = create_tenant(_unique("idem-quota-tenant"))
        self.plan_key = _unique("idem-quota-plan")
        self.metric = metric
        if limit is not None:
            create_plan(self.plan_key, "Idempotent Quota Plan", entitlements={metric: limit})
            subscribe(self.tenant.id, self.plan_key, provider=FakeBillingProvider())

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.idempotency_records WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.usage_events WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": self.plan_key}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def make_fixture():
    created: list[_Fixture] = []

    def _make(*, limit: int | None = None, metric: str = "api_calls") -> _Fixture:
        fx = _Fixture(limit=limit, metric=metric)
        created.append(fx)
        return fx

    yield _make
    for fx in created:
        fx.cleanup()


_WINDOW = (datetime.now(UTC) - timedelta(minutes=1), datetime.now(UTC) + timedelta(hours=1))


# --- The mandatory regression: retry must not double-consume quota --------


def test_first_request_consumes_quota_once_retry_consumes_zero_additional(make_fixture) -> None:
    fx = make_fixture(limit=10)
    key = "quota-idem-key-1"

    is_replay_1, result_1 = consume_quota_idempotent(
        fx.tenant.id, fx.metric, Decimal("3"), key, since=_WINDOW[0], until=_WINDOW[1]
    )
    assert is_replay_1 is False
    assert result_1.used == Decimal("3")

    for _ in range(5):
        is_replay, result = consume_quota_idempotent(
            fx.tenant.id, fx.metric, Decimal("3"), key, since=_WINDOW[0], until=_WINDOW[1]
        )
        assert is_replay is True
        assert result.used == Decimal("3")  # never grows past the one real consumption

    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("3")  # exactly one real usage-event row's worth


def test_different_keys_each_consume_quota_independently(make_fixture) -> None:
    fx = make_fixture(limit=10)
    consume_quota_idempotent(
        fx.tenant.id, fx.metric, Decimal("2"), "key-a", since=_WINDOW[0], until=_WINDOW[1]
    )
    consume_quota_idempotent(
        fx.tenant.id, fx.metric, Decimal("2"), "key-b", since=_WINDOW[0], until=_WINDOW[1]
    )
    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("4")  # two genuinely distinct requests, both counted


def test_same_key_different_quantity_is_rejected(make_fixture) -> None:
    fx = make_fixture(limit=10)
    key = "quota-idem-mismatch"
    consume_quota_idempotent(
        fx.tenant.id, fx.metric, Decimal("2"), key, since=_WINDOW[0], until=_WINDOW[1]
    )
    with pytest.raises(IdempotencyKeyReusedError):
        consume_quota_idempotent(
            fx.tenant.id, fx.metric, Decimal("5"), key, since=_WINDOW[0], until=_WINDOW[1]
        )
    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("2")  # the conflicting attempt never ran


def test_quota_exceeded_failure_is_not_cached_and_can_retry(make_fixture) -> None:
    fx = make_fixture(limit=2)
    key = "quota-idem-exceeded"

    with pytest.raises(QuotaExceededError):
        consume_quota_idempotent(
            fx.tenant.id, fx.metric, Decimal("5"), key, since=_WINDOW[0], until=_WINDOW[1]
        )

    # No idempotency record survives a QuotaExceededError (the whole
    # transaction, reservation included, rolled back) -- retrying the
    # exact same (over-limit) request fails again, cleanly, not as a
    # cached/replayed error.
    with pytest.raises(QuotaExceededError):
        consume_quota_idempotent(
            fx.tenant.id, fx.metric, Decimal("5"), key, since=_WINDOW[0], until=_WINDOW[1]
        )

    # A request that now fits consumes normally under the same key (no
    # stale reservation blocks it).
    is_replay, result = consume_quota_idempotent(
        fx.tenant.id, fx.metric, Decimal("1"), key, since=_WINDOW[0], until=_WINDOW[1]
    )
    assert is_replay is False
    assert result.used == Decimal("1")


# --- Concurrency: the mandatory gate (fully atomic primitive) ---------------


def test_concurrent_identical_requests_consume_quota_exactly_once(make_fixture) -> None:
    fx = make_fixture(limit=10)
    key = "quota-idem-concurrent"

    def _attempt(_: int) -> tuple[bool, Decimal]:
        is_replay, result = consume_quota_idempotent(
            fx.tenant.id, fx.metric, Decimal("3"), key, since=_WINDOW[0], until=_WINDOW[1]
        )
        return is_replay, result.used

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_attempt, range(10)))

    # Fully atomic primitive: every concurrent caller gets a definitive
    # answer -- exactly one executes, the rest cleanly replay (never
    # "in progress", unlike the two-step primitive
    # core.billing.service.subscribe_idempotent() needs).
    assert sum(1 for is_replay, _ in results if not is_replay) == 1
    assert sum(1 for is_replay, _ in results if is_replay) == 9
    assert all(used == Decimal("3") for _is_replay, used in results)

    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("3")  # quota consumed exactly once, not ten times


def test_concurrent_distinct_keys_all_consume_independently(make_fixture) -> None:
    fx = make_fixture(limit=100)

    def _attempt(i: int) -> None:
        consume_quota_idempotent(
            fx.tenant.id, fx.metric, Decimal("1"), f"key-{i}", since=_WINDOW[0], until=_WINDOW[1]
        )

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(_attempt, range(10)))

    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("10")


# --- Tenant isolation --------------------------------------------------


def test_cross_tenant_same_key_consumes_independently(make_fixture) -> None:
    tenant_a = make_fixture(limit=10)
    tenant_b = make_fixture(limit=10)
    key = "shared-quota-key"

    consume_quota_idempotent(
        tenant_a.tenant.id, "api_calls", Decimal("4"), key, since=_WINDOW[0], until=_WINDOW[1]
    )
    consume_quota_idempotent(
        tenant_b.tenant.id, "api_calls", Decimal("4"), key, since=_WINDOW[0], until=_WINDOW[1]
    )

    assert aggregate_usage(
        tenant_a.tenant.id, "api_calls", since=_WINDOW[0], until=_WINDOW[1]
    ) == Decimal("4")
    assert aggregate_usage(
        tenant_b.tenant.id, "api_calls", since=_WINDOW[0], until=_WINDOW[1]
    ) == Decimal("4")
