"""Migration reversibility test for the Phase 3.4 audit_log migration
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 18: "Phase 3.1 migration
-> Phase 3.2 migration -> Phase 3.3 migration -> Phase 3.4 upgrade -> seed
real audit records -> Phase 3.4 downgrade -> verify audit structures
removed -> verify Phase 3.1/3.2/3.3 structures remain intact -> Phase 3.4
re-upgrade -> verify audit schema/RLS restored", run against real
disposable PostgreSQL, not just inspected).

**Destructive**: this test downgrades past, then re-applies, `2e7cb8c64903`
(the audit_log-table migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`core.audit_log`, then recreates it empty. Run this only against a
disposable database, never a shared development or production database.
Marked `integration` and excluded from the default `pytest` run for
exactly this reason, mirroring
`tests/infra/db/test_rbac_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_audit_log_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

# Registers core.users on the shared declarative Base.metadata (see
# tests/core/audit_log/test_audit_log_isolation_integration.py for the
# fuller explanation) -- required for record()'s ForeignKey("core.users.id")
# to resolve, even though this file never otherwise needs core.identity.
import core.identity.models  # noqa: F401
import pytest
from alembic import command
from alembic.config import Config
from core.audit_log.models import ActorType, AuditOutcome
from core.audit_log.service import record
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_AUDIT_LOG_REVISION = "2e7cb8c64903"
_RBAC_REVISION = "81ac56902107"


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


def _runtime_role_privileges(table: str) -> set[str]:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            rows = session.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE grantee = 'saas_os_app' AND table_schema = 'core' AND table_name = :t"
                ),
                {"t": table},
            ).all()
        return {r[0] for r in rows}
    finally:
        engine.dispose()


def test_audit_log_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("audit_log")
    assert _rls_flags("audit_log") == (True, True)
    assert _runtime_role_privileges("audit_log") == {"SELECT", "INSERT"}

    # --- seed a real audit record through the actual service layer (not
    # raw SQL) before downgrading, proving the schema this migration
    # created is genuinely usable, not merely structurally present ---
    tenant = create_tenant(f"audit-rollback-{uuid.uuid4().hex[:8]}")
    try:
        record(
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            action="rollback.seed",
            resource_type="probe",
            outcome=AuditOutcome.SUCCESS,
        )

        try:
            # --- downgrade past the audit_log migration ---
            command.downgrade(cfg, _RBAC_REVISION)
            assert not _table_exists("audit_log")
            # Phase 3.1/3.2/3.3's own tables must be untouched.
            assert _table_exists("tenants")
            assert _table_exists("users")
            assert _table_exists("tenant_memberships")
            assert _table_exists("roles")
            assert _table_exists("role_permissions")
            assert _table_exists("membership_roles")

            # --- re-apply the audit_log migration ---
            command.upgrade(cfg, _AUDIT_LOG_REVISION)
            assert _table_exists("audit_log")
            assert _rls_flags("audit_log") == (True, True)
            assert _runtime_role_privileges("audit_log") == {"SELECT", "INSERT"}

            # audit_log is usable again post-re-upgrade: a fresh record
            # succeeds (the old row was dropped with the table, which is
            # expected -- this proves the *schema* is usable again, not
            # that data survived a destructive downgrade).
            record(
                tenant_id=tenant.id,
                actor_type=ActorType.SYSTEM,
                action="rollback.reseed",
                resource_type="probe",
                outcome=AuditOutcome.SUCCESS,
            )
        finally:
            command.upgrade(cfg, "head")
    finally:
        admin_engine = build_engine(get_migrations_database_config())
        try:
            admin_factory = build_session_factory(admin_engine)
            with session_scope(session_factory=admin_factory) as session:
                session.execute(
                    text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant.id)}
                )
        finally:
            admin_engine.dispose()
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
