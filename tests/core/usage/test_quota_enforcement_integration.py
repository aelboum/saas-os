"""P1.9 -- `consume_quota()` integration tests against a real PostgreSQL
instance: sequential enforcement, real concurrent-consumption race safety
(the actual `pg_advisory_xact_lock` mechanism production code uses, not a
mock), cross-tenant isolation, and rollback/no-double-count behavior.

Mirrors `tests/core/usage/test_usage_integration.py`'s fixture structure
(real tenant + real `core.billing` plan/subscription, since
`consume_quota()` reads entitlements through `core.billing.get_entitlements()`
exactly like `check_quota()` does).

Marked `integration`; excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/usage/test_quota_enforcement_integration.py
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
from core.usage.errors import QuotaExceededError
from core.usage.service import aggregate_usage, consume_quota
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
            conn.execute(text("SELECT 1 FROM core.usage_events LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(f"core.usage_events does not exist yet -- run `alembic upgrade head`: {exc}")
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


def _unique_key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _TenantFixture:
    def __init__(self, *, limit: int | None = None, metric: str = "api_calls") -> None:
        self.tenant = create_tenant(f"quota-tenant-{uuid.uuid4().hex[:8]}")
        self.plan_key = _unique_key("quota-plan")
        self.metric = metric
        if limit is not None:
            create_plan(self.plan_key, "Quota Plan", entitlements={metric: limit})
            subscribe(self.tenant.id, self.plan_key, provider=FakeBillingProvider())

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
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
    created: list[_TenantFixture] = []

    def _make(*, limit: int | None = None, metric: str = "api_calls") -> _TenantFixture:
        fx = _TenantFixture(limit=limit, metric=metric)
        created.append(fx)
        return fx

    yield _make
    for fx in created:
        fx.cleanup()


_WINDOW = (datetime.now(UTC) - timedelta(minutes=1), datetime.now(UTC) + timedelta(hours=1))


# --- Sequential correctness -------------------------------------------------


def test_below_quota_succeeds(make_fixture) -> None:
    fx = make_fixture(limit=10)
    result = consume_quota(
        fx.tenant.id, fx.metric, Decimal("1"), since=_WINDOW[0], until=_WINDOW[1]
    )
    assert result.exceeded is False
    assert result.used == Decimal("1")


def test_exactly_at_quota_then_next_consumption_fails(make_fixture) -> None:
    fx = make_fixture(limit=3)
    for _ in range(3):
        consume_quota(fx.tenant.id, fx.metric, Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])

    with pytest.raises(QuotaExceededError) as excinfo:
        consume_quota(fx.tenant.id, fx.metric, Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])
    assert excinfo.value.used == Decimal("3")
    assert excinfo.value.limit == Decimal("3")

    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("3")  # the denied attempt recorded nothing


def test_no_configured_limit_never_denies(make_fixture) -> None:
    fx = make_fixture(limit=None)
    for _ in range(5):
        result = consume_quota(
            fx.tenant.id, "unconfigured_metric", Decimal("1000"), since=_WINDOW[0], until=_WINDOW[1]
        )
        assert result.exceeded is False


def test_failed_quota_check_does_not_record_usage(make_fixture) -> None:
    fx = make_fixture(limit=1)
    consume_quota(fx.tenant.id, fx.metric, Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])

    for _ in range(3):
        with pytest.raises(QuotaExceededError):
            consume_quota(fx.tenant.id, fx.metric, Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])

    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("1")


def test_repeated_checks_behave_deterministically(make_fixture) -> None:
    fx = make_fixture(limit=5)
    consume_quota(fx.tenant.id, fx.metric, Decimal("2"), since=_WINDOW[0], until=_WINDOW[1])

    from core.usage.service import check_quota

    first = check_quota(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    second = check_quota(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert first == second


def test_rollback_on_denial_does_not_double_count(make_fixture) -> None:
    """A denied consume_quota() call rolls back its entire transaction
    (module docstring) -- retrying immediately after a denial must never
    see inflated usage from the failed attempt."""
    fx = make_fixture(limit=2)
    consume_quota(fx.tenant.id, fx.metric, Decimal("2"), since=_WINDOW[0], until=_WINDOW[1])

    for _ in range(5):
        with pytest.raises(QuotaExceededError):
            consume_quota(fx.tenant.id, fx.metric, Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])

    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("2")


# --- Concurrency: the actual production transaction mechanism ---------------


def test_concurrent_consumption_at_the_boundary_allows_exactly_one_winner(make_fixture) -> None:
    """limit=N, current usage=N-1 (pre-seeded), two concurrent callers
    each try to consume the final unit -- at most one may succeed, and
    final usage must never exceed the limit. Uses real threads issuing
    real, separate DB sessions/transactions against the actual
    `consume_quota()` production code path (pg_advisory_xact_lock),
    never a mock."""
    fx = make_fixture(limit=5)
    consume_quota(fx.tenant.id, fx.metric, Decimal("4"), since=_WINDOW[0], until=_WINDOW[1])

    def _attempt() -> str:
        try:
            consume_quota(fx.tenant.id, fx.metric, Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])
            return "ok"
        except QuotaExceededError:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _attempt(), range(2)))

    assert results.count("ok") == 1
    assert results.count("denied") == 1

    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("5")
    assert total <= Decimal("5")


def test_concurrent_consumption_many_callers_never_exceeds_the_limit(make_fixture) -> None:
    """A stronger version of the boundary test: limit=5, ten concurrent
    callers each try to consume one unit from zero -- exactly five must
    succeed, final usage must be exactly the limit, never more."""
    fx = make_fixture(limit=5)

    def _attempt(_: int) -> str:
        try:
            consume_quota(fx.tenant.id, fx.metric, Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])
            return "ok"
        except QuotaExceededError:
            return "denied"

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_attempt, range(10)))

    assert results.count("ok") == 5
    assert results.count("denied") == 5

    total = aggregate_usage(fx.tenant.id, fx.metric, since=_WINDOW[0], until=_WINDOW[1])
    assert total == Decimal("5")


# --- Tenant isolation --------------------------------------------------


def test_tenant_a_cannot_consume_tenant_bs_quota(make_fixture) -> None:
    tenant_a = make_fixture(limit=10, metric="api_calls")
    tenant_b = make_fixture(limit=10, metric="api_calls")

    consume_quota(tenant_a.tenant.id, "api_calls", Decimal("7"), since=_WINDOW[0], until=_WINDOW[1])

    b_total = aggregate_usage(tenant_b.tenant.id, "api_calls", since=_WINDOW[0], until=_WINDOW[1])
    assert b_total == Decimal("0")

    a_total = aggregate_usage(tenant_a.tenant.id, "api_calls", since=_WINDOW[0], until=_WINDOW[1])
    assert a_total == Decimal("7")


def test_exhausting_tenant_as_quota_does_not_affect_tenant_b(make_fixture) -> None:
    tenant_a = make_fixture(limit=1, metric="api_calls")
    tenant_b = make_fixture(limit=1, metric="api_calls")

    consume_quota(tenant_a.tenant.id, "api_calls", Decimal("1"), since=_WINDOW[0], until=_WINDOW[1])
    with pytest.raises(QuotaExceededError):
        consume_quota(
            tenant_a.tenant.id, "api_calls", Decimal("1"), since=_WINDOW[0], until=_WINDOW[1]
        )

    # Tenant B, entirely independent, must still be able to consume its
    # own quota -- tenant A's exhaustion (and its advisory lock) must
    # never leak across tenants.
    result = consume_quota(
        tenant_b.tenant.id, "api_calls", Decimal("1"), since=_WINDOW[0], until=_WINDOW[1]
    )
    assert result.exceeded is False


def test_forged_tenant_id_cannot_alter_another_tenants_accounting(make_fixture) -> None:
    """Even if a caller somehow obtained tenant B's raw UUID (e.g. from a
    forged/guessed path parameter upstream), `consume_quota()` itself has
    no notion of "the caller's real tenant" -- it only ever accounts
    against whatever `tenant_id` argument it is given, which in the real
    HTTP path is always `RequestContext.tenant_id`
    (`api/dependencies.py`'s own verified-membership guarantee, never a
    caller-supplied value). This test proves the service-layer function
    itself cannot be tricked into crediting/debiting the wrong tenant's
    row -- RLS (`tenant_session_scope`) keeps each write scoped to
    exactly the `tenant_id` passed in."""
    tenant_a = make_fixture(limit=10, metric="api_calls")
    tenant_b = make_fixture(limit=10, metric="api_calls")

    consume_quota(tenant_a.tenant.id, "api_calls", Decimal("3"), since=_WINDOW[0], until=_WINDOW[1])
    consume_quota(tenant_b.tenant.id, "api_calls", Decimal("2"), since=_WINDOW[0], until=_WINDOW[1])

    assert aggregate_usage(
        tenant_a.tenant.id, "api_calls", since=_WINDOW[0], until=_WINDOW[1]
    ) == Decimal("3")
    assert aggregate_usage(
        tenant_b.tenant.id, "api_calls", since=_WINDOW[0], until=_WINDOW[1]
    ) == Decimal("2")
