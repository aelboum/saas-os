"""Migration reversibility test for the Phase 4.3 webhook_subscriptions
migration (docs/IMPLEMENTATION-ROADMAP.md Phase 4.3 Rollback Strategy:
"revert code" -- validated against real disposable PostgreSQL, not
merely documented).

**Destructive**: this test downgrades past, then re-applies,
`01628d0d3eb6` (the webhook_subscriptions-table migration) on whatever
database `MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`core.webhook_subscriptions`, then recreates it empty. Run this only
against a disposable database, never a shared development or production
database. Marked `integration` and excluded from the default `pytest`
run for exactly this reason, mirroring
`tests/infra/db/test_feature_flags_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_webhooks_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/feature_flags/test_feature_flags_isolation_integration.py's
# identical import for the full rationale (subscribe()'s audit write
# needs core.users mapped).
import core.identity.models  # noqa: F401
import pytest
from alembic import command
from alembic.config import Config
from core.webhooks.service import get_subscription, subscribe
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WEBHOOKS_REVISION = "01628d0d3eb6"
_FEATURE_FLAGS_REVISION = "5d8c7a635e62"


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
    # core.audit_log DELETE is REVOKEd from the restricted runtime role
    # entirely (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4) -- test cleanup
    # must use the privileged migrations role here (subscribe() writes an
    # audit entry, which would otherwise block deleting the tenant via its
    # audit_log.tenant_id foreign key).
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def test_webhooks_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("webhook_subscriptions")
    assert _rls_flags("webhook_subscriptions") == (True, True)

    # --- seed a real subscription through the actual service layer (not
    # raw SQL) before downgrading, proving the schema this migration
    # created is genuinely usable, not merely structurally present ---
    tenant = create_tenant(f"webhooks-rollback-{uuid.uuid4().hex[:8]}")
    try:
        subscription, _raw_secret = subscribe(tenant.id, "https://example.com/rollback-hook")
        assert get_subscription(tenant.id, subscription.id).id == subscription.id

        try:
            # --- downgrade past the webhooks migration ---
            command.downgrade(cfg, _FEATURE_FLAGS_REVISION)
            assert not _table_exists("webhook_subscriptions")
            # Phase 3.1-4.2's own tables must be untouched.
            assert _table_exists("tenants")
            assert _table_exists("users")
            assert _table_exists("tenant_memberships")
            assert _table_exists("roles")
            assert _table_exists("audit_log")
            assert _table_exists("api_keys")
            assert _table_exists("feature_flags")
            assert _table_exists("feature_flag_tenant_overrides")

            # --- re-apply the webhooks migration ---
            command.upgrade(cfg, _WEBHOOKS_REVISION)
            assert _table_exists("webhook_subscriptions")
            assert _rls_flags("webhook_subscriptions") == (True, True)

            # webhooks is usable again post-re-upgrade: a fresh
            # subscription cycle works (the old row was dropped with the
            # table, which is expected -- this proves the *schema* is
            # usable again, not that data survived a destructive
            # downgrade).
            new_subscription, _ = subscribe(tenant.id, "https://example.com/rollback-reseed-hook")
            assert get_subscription(tenant.id, new_subscription.id).id == new_subscription.id
        finally:
            command.upgrade(cfg, "head")
    finally:
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.webhook_subscriptions WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(tenant.id)
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
