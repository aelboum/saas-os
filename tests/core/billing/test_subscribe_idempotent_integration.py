"""P1.11 -- `saas_os.core.billing.service.subscribe_idempotent()` integration
tests against a real PostgreSQL instance. Proves the real-world reason
this consumer was selected: `subscribe()` calls a `BillingProvider`
(`FakeBillingProvider` here, `StripeBillingProvider` in production) --
without idempotency, a retried request creates a second real
subscription (and, with the real Stripe provider, double-bills the
tenant). `core.billing_subscriptions` itself has no uniqueness
constraint preventing this (`saas_os/core/billing/service.py::get_entitlements()`'s
own docstring).

Marked `integration`; excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/billing/test_subscribe_idempotent_integration.py
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/billing/test_billing_isolation_integration.py's identical
# import for the full rationale (subscribe()'s audit write needs
# core.users mapped).
import saas_os.core.identity.models  # noqa: F401
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import create_plan, subscribe_idempotent
from saas_os.core.idempotency.errors import IdempotencyInProgressError, IdempotencyKeyReusedError
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope


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
    finally:
        engine.dispose()


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


class _CountingProvider(FakeBillingProvider):
    """Wraps the real `FakeBillingProvider` to count real calls --
    proves *the external call itself* happens at most once per logical
    subscribe, not just that the local DB row is deduplicated."""

    def __init__(self) -> None:
        super().__init__()
        self.create_subscription_calls = 0
        self._lock = threading.Lock()

    def create_subscription(self, *, tenant_id, plan, idempotency_key=None, context=None):  # noqa: ANN001
        with self._lock:
            self.create_subscription_calls += 1
        return super().create_subscription(
            tenant_id=tenant_id, plan=plan, idempotency_key=idempotency_key, context=context
        )


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
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique("subscribe-idem-tenant"))
        self.plan_key = _unique("subscribe-idem-plan")
        create_plan(self.plan_key, "Idempotent Plan", entitlements={"seats": 10})
        self.provider = _CountingProvider()

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.idempotency_records WHERE tenant_id = :t"),
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
            _admin_clear_audit_references({"id": str(self.tenant.id)}, table="tenants")
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


def _subscription_count(tenant_id: uuid.UUID) -> int:
    with tenant_session_scope(tenant_id) as session:
        count = session.execute(
            text("SELECT COUNT(*) AS n FROM core.billing_subscriptions WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        ).one()
    return count.n


# --- Sequential correctness -------------------------------------------------


def test_first_request_creates_exactly_one_subscription(fx: _Fixture) -> None:
    is_replay, result = subscribe_idempotent(
        fx.tenant.id, fx.plan_key, "subscribe-key-1", provider=fx.provider
    )
    assert is_replay is False
    assert _subscription_count(fx.tenant.id) == 1
    assert fx.provider.create_subscription_calls == 1
    assert result.status == "active"


def test_exact_retry_reuses_the_result_without_a_second_provider_call(fx: _Fixture) -> None:
    _is_replay, first = subscribe_idempotent(
        fx.tenant.id, fx.plan_key, "subscribe-key-2", provider=fx.provider
    )
    is_replay, second = subscribe_idempotent(
        fx.tenant.id, fx.plan_key, "subscribe-key-2", provider=fx.provider
    )

    assert is_replay is True
    assert second.subscription_id == first.subscription_id
    assert second.provider_subscription_id == first.provider_subscription_id
    assert _subscription_count(fx.tenant.id) == 1
    assert fx.provider.create_subscription_calls == 1  # never called twice


def test_same_key_different_plan_is_rejected(fx: _Fixture) -> None:
    other_plan_key = _unique("subscribe-idem-other-plan")
    create_plan(other_plan_key, "Other Plan", entitlements={"seats": 5})
    try:
        subscribe_idempotent(fx.tenant.id, fx.plan_key, "shared-key", provider=fx.provider)
        with pytest.raises(IdempotencyKeyReusedError):
            subscribe_idempotent(fx.tenant.id, other_plan_key, "shared-key", provider=fx.provider)
        assert _subscription_count(fx.tenant.id) == 1
        assert fx.provider.create_subscription_calls == 1
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": other_plan_key}
            )


def test_retry_after_provider_failure_can_execute(fx: _Fixture) -> None:
    class _FailingOnceProvider(_CountingProvider):
        def __init__(self) -> None:
            super().__init__()
            self._fail_next = True

        def create_subscription(self, *, tenant_id, plan, idempotency_key=None, context=None):  # noqa: ANN001
            if self._fail_next:
                self._fail_next = False
                self.create_subscription_calls += 1
                raise RuntimeError("simulated transient provider failure")
            return super().create_subscription(tenant_id=tenant_id, plan=plan)

    provider = _FailingOnceProvider()
    with pytest.raises(RuntimeError):
        subscribe_idempotent(fx.tenant.id, fx.plan_key, "retry-key", provider=provider)
    assert _subscription_count(fx.tenant.id) == 0

    is_replay, result = subscribe_idempotent(
        fx.tenant.id, fx.plan_key, "retry-key", provider=provider
    )
    assert is_replay is False
    assert _subscription_count(fx.tenant.id) == 1
    assert result.status == "active"


def test_entitlement_or_validation_style_failure_leaves_no_subscription(fx: _Fixture) -> None:
    """A non-provider failure (here: a plan that doesn't exist) must
    behave the same way as a provider failure -- no subscription, and a
    retry of the *exact same request* (same key, same plan_key string --
    the fingerprint must match, module docstring: "fixing" the input by
    passing a different plan_key is a different logical request and
    deserves its own key) can proceed once the real problem
    (the plan not existing yet) is actually fixed."""
    from saas_os.core.billing.errors import PlanNotFoundError

    missing_plan_key = _unique("not-yet-created-plan")
    with pytest.raises(PlanNotFoundError):
        subscribe_idempotent(fx.tenant.id, missing_plan_key, "bad-plan-key", provider=fx.provider)
    assert _subscription_count(fx.tenant.id) == 0

    create_plan(missing_plan_key, "Now It Exists", entitlements={"seats": 1})
    try:
        is_replay, _result = subscribe_idempotent(
            fx.tenant.id, missing_plan_key, "bad-plan-key", provider=fx.provider
        )
        assert is_replay is False
        assert _subscription_count(fx.tenant.id) == 1
    finally:
        with tenant_session_scope(fx.tenant.id) as session:
            session.execute(
                text(
                    "DELETE FROM core.billing_subscriptions WHERE tenant_id = :t "
                    "AND plan_id = (SELECT id FROM core.billing_plans WHERE key = :k)"
                ),
                {"t": str(fx.tenant.id), "k": missing_plan_key},
            )
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": missing_plan_key}
            )


# --- Concurrency: the mandatory gate ----------------------------------


def test_concurrent_identical_subscribe_requests_call_the_provider_exactly_once(
    fx: _Fixture,
) -> None:
    """Unlike `saas_os.core.usage.service.consume_quota_idempotent()`'s fully
    atomic primitive (where a concurrent loser blocks on the winner's
    transaction and then replays its committed result), this two-step
    primitive's reservation transaction is deliberately short-lived (it
    must release before the external provider call runs -- module
    docstring's own documented limitation). A concurrent loser here can
    therefore observe the winner's reservation as still `pending` and
    receive `IdempotencyInProgressError` rather than a clean replay --
    this is the explicitly-defined in-progress semantics this
    checkpoint's own Concurrent Requests section allows ("the other must
    receive the same successful result or the repository's explicitly
    defined in-progress response semantics"). The invariant that actually
    matters -- the external side effect happens at most once -- is what
    this test asserts.
    """
    key = "concurrent-subscribe-key"

    def _attempt(_: int) -> str:
        try:
            is_replay, _result = subscribe_idempotent(
                fx.tenant.id, fx.plan_key, key, provider=fx.provider
            )
            return "replayed" if is_replay else "executed"
        except IdempotencyInProgressError:
            return "in_progress"

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_attempt, range(10)))

    assert results.count("executed") == 1  # exactly one real attempt
    assert results.count("replayed") + results.count("in_progress") == 9
    assert fx.provider.create_subscription_calls == 1  # the external call happened exactly once
    assert _subscription_count(fx.tenant.id) == 1


# --- Tenant isolation --------------------------------------------------


def test_cross_tenant_same_key_creates_independent_subscriptions(fx: _Fixture) -> None:
    other_tenant = create_tenant(_unique("subscribe-idem-tenant-b"))
    other_provider = _CountingProvider()
    try:
        subscribe_idempotent(
            fx.tenant.id, fx.plan_key, "shared-across-tenants", provider=fx.provider
        )
        is_replay, _result = subscribe_idempotent(
            other_tenant.id, fx.plan_key, "shared-across-tenants", provider=other_provider
        )
        assert is_replay is False
        assert _subscription_count(fx.tenant.id) == 1
        assert _subscription_count(other_tenant.id) == 1
    finally:
        with tenant_session_scope(other_tenant.id) as session:
            session.execute(
                text("DELETE FROM core.idempotency_records WHERE tenant_id = :t"),
                {"t": str(other_tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(other_tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(other_tenant.id)
        with session_scope() as session:
            _admin_clear_audit_references({"id": str(other_tenant.id)}, table="tenants")
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(other_tenant.id)}
            )
