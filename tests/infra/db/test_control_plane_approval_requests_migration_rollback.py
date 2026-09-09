"""Migration reversibility test for the Phase 7.2 approval_requests
migration (docs/IMPLEMENTATION-ROADMAP.md Phase 7.2 Rollback Strategy:
"revert code; no live approvals pending at this phase" -- schema
reversibility itself is validated against real disposable PostgreSQL,
not merely documented).

**Destructive**: this test downgrades past, then re-applies,
`23310e44a21d` (the approval_requests-table migration) on whatever
database `MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`control_plane.approval_requests` and the `control_plane` schema itself,
then recreates both empty. Run this only against a disposable database,
never a shared development or production database. Marked `integration`
and excluded from the default `pytest` run for exactly this reason,
mirroring `tests/infra/db/test_usage_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/infra/db/test_control_plane_approval_requests_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from core.identity.service import add_tenant_membership, create_user
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from control_plane.approvals.service import get_approval, propose_action
from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_APPROVALS_REVISION = "23310e44a21d"
_USAGE_REVISION = "757d55add12a"


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


def _table_exists(schema: str, table: str) -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = :s AND table_name = :t)"
                ),
                {"s": schema, "t": table},
            ).scalar_one()
        return bool(row)
    finally:
        engine.dispose()


def _schema_exists(schema: str) -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = :s)"
                ),
                {"s": schema},
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


def test_approval_requests_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _schema_exists("control_plane")
    assert _table_exists("control_plane", "approval_requests")
    assert _rls_flags("approval_requests") == (True, True)

    # --- seed a real approval request through the actual service layer
    # (not raw SQL) before downgrading, proving the schema this migration
    # created is genuinely usable, not merely structurally present ---
    tenant = create_tenant(f"appr-rollback-{uuid.uuid4().hex[:8]}")
    proposer = create_user()
    try:
        add_tenant_membership(tenant.id, proposer.id)
        approval = propose_action(tenant.id, proposer.id, "rollback-stub-tool")
        assert get_approval(tenant.id, approval.id).id == approval.id

        try:
            # --- downgrade past the approval_requests migration ---
            command.downgrade(cfg, _USAGE_REVISION)
            assert not _table_exists("control_plane", "approval_requests")
            assert not _schema_exists("control_plane")
            # Phase 3.1-5.2's own tables must be untouched.
            assert _table_exists("core", "tenants")
            assert _table_exists("core", "users")
            assert _table_exists("core", "tenant_memberships")
            assert _table_exists("core", "roles")
            assert _table_exists("core", "audit_log")
            assert _table_exists("core", "api_keys")
            assert _table_exists("core", "feature_flags")
            assert _table_exists("core", "webhook_subscriptions")
            assert _table_exists("core", "notifications")
            assert _table_exists("core", "billing_plans")
            assert _table_exists("core", "billing_subscriptions")
            assert _table_exists("core", "usage_events")

            # --- re-apply the approval_requests migration ---
            command.upgrade(cfg, _APPROVALS_REVISION)
            assert _schema_exists("control_plane")
            assert _table_exists("control_plane", "approval_requests")
            assert _rls_flags("approval_requests") == (True, True)

            # approval_requests is usable again post-re-upgrade: a fresh
            # propose cycle works (the old row was dropped with the
            # table, which is expected -- this proves the *schema* is
            # usable again, not that data survived a destructive
            # downgrade).
            new_approval = propose_action(tenant.id, proposer.id, "rollback-reseed-stub-tool")
            assert get_approval(tenant.id, new_approval.id).id == new_approval.id
        finally:
            command.upgrade(cfg, "head")
    finally:
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM control_plane.approval_requests WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(tenant.id)
        with session_scope() as session:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(proposer.id)})
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
