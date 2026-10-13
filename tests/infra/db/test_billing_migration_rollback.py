"""Migration reversibility test for the Phase 5.1 billing migration
(docs/IMPLEMENTATION-ROADMAP.md Phase 5.1 Rollback Strategy note aside --
schema reversibility itself is validated against real disposable
PostgreSQL, not merely documented).

**Destructive**: this test downgrades past, then re-applies,
`2d0730e14a7f` (the billing-tables migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`core.billing_subscriptions`/`core.billing_plans`, then recreates them
empty. Run this only against a disposable database, never a shared
development or production database. Marked `integration` and excluded
from the default `pytest` run for exactly this reason, mirroring
`tests/infra/db/test_notifications_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_billing_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/billing/test_billing_isolation_integration.py's identical
# import for the full rationale.
import saas_os.core.identity.models  # noqa: F401
from lifecycle_callers import PROVISIONING
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import create_plan, get_subscription, subscribe
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_migrations_database_config
from saas_os.infra.db.engine import build_engine
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

_REPO_ROOT = Path(__file__).resolve().parents[3]
_BILLING_REVISION = "2d0730e14a7f"
_NOTIFICATIONS_REVISION = "230aeac01e1b"


@pytest.fixture(autouse=True)
def _require_reachable_privileged_database() -> None:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    finally:
        probe_engine.dispose()


def _alembic_config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _table_exists(table: str) -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'core' AND table_name = :t)"
                ),
                {"t": table},
            ).scalar_one()
        return bool(row)
    finally:
        engine.dispose()


def _rls_flags(table: str) -> tuple[bool, bool] | None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = :t"),
                {"t": table},
            ).one_or_none()
        return (row[0], row[1]) if row is not None else None
    finally:
        engine.dispose()


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


def test_billing_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("billing_plans")
    assert _table_exists("billing_subscriptions")
    assert _rls_flags("billing_plans") == (False, False)
    assert _rls_flags("billing_subscriptions") == (True, True)

    # --- seed real billing data through the actual service layer (not raw
    # SQL) before downgrading, proving the schema this migration created
    # is genuinely usable, not merely structurally present ---
    tenant = create_tenant(f"billing-rollback-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
    plan_key = f"rollback-plan-{uuid.uuid4().hex[:8]}"
    provider = FakeBillingProvider()
    try:
        create_plan(plan_key, "Rollback Plan")
        subscription = subscribe(tenant.id, plan_key, provider=provider)
        assert get_subscription(tenant.id, subscription.id).id == subscription.id

        try:
            # --- downgrade past the billing migration ---
            command.downgrade(cfg, _NOTIFICATIONS_REVISION)
            assert not _table_exists("billing_plans")
            assert not _table_exists("billing_subscriptions")
            # Phase 3.1-4.4's own tables must be untouched.
            assert _table_exists("tenants")
            assert _table_exists("users")
            assert _table_exists("tenant_memberships")
            assert _table_exists("roles")
            assert _table_exists("audit_log")
            assert _table_exists("api_keys")
            assert _table_exists("feature_flags")
            assert _table_exists("feature_flag_tenant_overrides")
            assert _table_exists("webhook_subscriptions")
            assert _table_exists("notifications")

            # --- re-apply the billing migration ---
            command.upgrade(cfg, _BILLING_REVISION)
            assert _table_exists("billing_plans")
            assert _table_exists("billing_subscriptions")
            assert _rls_flags("billing_plans") == (False, False)
            assert _rls_flags("billing_subscriptions") == (True, True)

            # --- advance the rest of the way to head before touching the
            # service layer ---
            # `subscribe()` runs head's own ORM: `require_open_tenant()` reads
            # `core.tenants.parent_id`/`inherits_billing` and the audit write
            # fills `saas_os.core.audit_log` columns that later migrations added
            # (`6b4f2d8a91c3`, `9aecff1d1135`, ...) -- none of which
            # exist at `_BILLING_REVISION`. This test's own job is only to prove
            # `2d0730e14a7f` itself is reversible, not to freeze those shared
            # tables' shape at that one revision forever: a real rollback is
            # always immediately followed by re-running every migration back
            # to head, never stopped partway (same rationale as
            # tests/infra/db/test_api_keys_migration_rollback.py). Upgrading
            # here first is what keeps the usability proof below meaningful
            # (RA-11-F4).
            command.upgrade(cfg, "head")

            # billing is usable again post-re-upgrade: a fresh plan +
            # subscription cycle works (the old rows were dropped with the
            # tables, which is expected -- this proves the *schema* is
            # usable again, not that data survived a destructive downgrade).
            new_plan_key = f"rollback-reseed-plan-{uuid.uuid4().hex[:8]}"
            create_plan(new_plan_key, "Rollback Reseed Plan")
            new_subscription = subscribe(tenant.id, new_plan_key, provider=provider)
            assert get_subscription(tenant.id, new_subscription.id).id == new_subscription.id
        finally:
            command.upgrade(cfg, "head")
    finally:
        # Delete subscriptions before the plans they reference (FK) --
        # this covers both the original and the reseeded subscription/plan
        # via the blanket tenant_id filter and the two-key IN clause below.
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.billing_plans WHERE key LIKE :prefix"),
                {"prefix": "rollback-%"},
            )
            _admin_clear_audit_references({"id": str(tenant.id)}, table="tenants")
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
