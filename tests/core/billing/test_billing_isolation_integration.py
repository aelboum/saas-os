"""Cross-tenant isolation integration tests for `core.billing_subscriptions`
against a real PostgreSQL instance with the Phase 5.1 tables actually
migrated (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1's standing rule: "No
phase touching tenant data may merge without the cross-tenant isolation
suite ... passing against the new code").

Mirrors `tests/core/webhooks/test_webhooks_isolation_integration.py`'s
structure and discipline (real `saas_os_app` runtime role, not a
manufactured test-only role).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/billing/test_billing_isolation_integration.py
"""

from __future__ import annotations

import uuid

# Registers core.users on the shared declarative Base.metadata -- this
# file never otherwise imports core.identity, but
# AuditLogEntry.actor_user_id's ForeignKey("core.users.id") needs that
# table's mapping present for subscribe()'s audit write to resolve it
# (mirrors tests/core/webhooks/test_webhooks_isolation_integration.py's
# identical import).
import core.identity.models  # noqa: F401
import pytest
from core.billing.errors import SubscriptionNotFoundError
from core.billing.provider import FakeBillingProvider
from core.billing.service import create_plan, get_subscription, list_subscriptions, subscribe
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_billing_tables() -> None:
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
            conn.execute(text("SELECT 1 FROM core.billing_subscriptions LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.billing_subscriptions does not exist yet -- "
            f"run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


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


class _TenantRig:
    def __init__(self, label: str) -> None:
        self.tenant = create_tenant(f"billing-tenant-{label}-{uuid.uuid4().hex[:8]}")
        self.plan_key = _unique_key(f"plan-{label}")
        self.plan = create_plan(self.plan_key, f"Plan {label}")
        self.provider = FakeBillingProvider()
        self.subscription = subscribe(self.tenant.id, self.plan_key, provider=self.provider)


@pytest.fixture
def rig_a():
    return _TenantRig("a")


@pytest.fixture
def rig_b():
    return _TenantRig("b")


def _cleanup(rig: _TenantRig) -> None:
    with tenant_session_scope(rig.tenant.id) as session:
        session.execute(
            text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
            {"t": str(rig.tenant.id)},
        )
    _admin_delete_audit_log_for_tenant(rig.tenant.id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": rig.plan_key})
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(rig.tenant.id)})


@pytest.fixture(autouse=True)
def _cleanup_rigs(rig_a: _TenantRig, rig_b: _TenantRig):
    yield
    _cleanup(rig_a)
    _cleanup(rig_b)


# --- Setup correctness -----------------------------------------------------


def test_billing_subscriptions_has_force_row_level_security(rig_a: _TenantRig) -> None:
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'billing_subscriptions'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True


def test_billing_plans_catalog_deliberately_has_no_rls(rig_a: _TenantRig) -> None:
    """The global plan catalog is intentionally NOT RLS-protected (every
    tenant must be able to resolve every plan) -- regression guard
    mirroring `core/feature_flags`'/`core/api_keys`' equivalent for their
    own global tables."""
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'billing_plans'"
            )
        ).one()
    assert row[0] is False
    assert row[1] is False


# --- Cross-tenant: A cannot read/write/delete B's subscriptions -----------


def test_tenant_a_read_own_subscription_passes(rig_a: _TenantRig) -> None:
    fetched = get_subscription(rig_a.tenant.id, rig_a.subscription.id)
    assert fetched.id == rig_a.subscription.id


def test_tenant_a_cannot_read_tenant_bs_subscription(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    with pytest.raises(SubscriptionNotFoundError):
        get_subscription(rig_a.tenant.id, rig_b.subscription.id)


def test_tenant_a_list_does_not_include_tenant_bs_subscription(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    ids = {s.id for s in list_subscriptions(rig_a.tenant.id)}
    assert rig_b.subscription.id not in ids


def test_tenant_a_cannot_modify_tenant_bs_subscription_via_raw_sql(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        result = session.execute(
            text("UPDATE core.billing_subscriptions SET status = 'canceled' WHERE id = :id"),
            {"id": str(rig_b.subscription.id)},
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]

    still = get_subscription(rig_b.tenant.id, rig_b.subscription.id)
    assert still.status == "active"


def test_tenant_a_cannot_delete_tenant_bs_subscription_via_raw_sql(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        result = session.execute(
            text("DELETE FROM core.billing_subscriptions WHERE id = :id"),
            {"id": str(rig_b.subscription.id)},
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]

    still = get_subscription(rig_b.tenant.id, rig_b.subscription.id)
    assert still.id == rig_b.subscription.id


# --- Non-vacuous DB-boundary proof ------------------------------------------


def test_rls_alone_blocks_cross_tenant_read_with_no_application_filter(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        tenant_ids = {
            row[0]
            for row in session.execute(
                text("SELECT tenant_id FROM core.billing_subscriptions")
            ).all()
        }
    assert tenant_ids == {rig_a.tenant.id}


def test_missing_tenant_context_sees_zero_subscription_rows(rig_a: _TenantRig) -> None:
    with session_scope() as session:
        rows = session.execute(text("SELECT id FROM core.billing_subscriptions")).all()
    assert rows == []


def test_manually_forged_session_setting_cannot_grant_extra_access(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with session_scope() as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(uuid.uuid4())}
        )
        rows = session.execute(text("SELECT id FROM core.billing_subscriptions")).all()
    assert rows == []


def test_tenant_a_cannot_read_tenant_bs_provider_subscription_id(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        rows = session.execute(
            text("SELECT provider_subscription_id FROM core.billing_subscriptions WHERE id = :id"),
            {"id": str(rig_b.subscription.id)},
        ).all()
    assert rows == []
