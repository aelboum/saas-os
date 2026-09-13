"""Migration reversibility test for the Phase J-RBAC-02 audit_log
service-account-actor migration (`a8ad8e61deb2`) -- upgrade -> verify
schema -> seed a real SERVICE_ACCOUNT audit record -> downgrade -> verify
the added column/constraints removed -> verify the original two-value
actor CHECK restored -> upgrade again -> verify the schema/behavior
restored, run against real disposable PostgreSQL, not just inspected.

**Destructive**: this test downgrades past, then re-applies, `a8ad8e61deb2`
on whatever database `MIGRATIONS_DATABASE_URL` points at -- it temporarily
drops `core.audit_log.actor_service_account_id` and the widened CHECK
constraints, restoring the pre-Phase-J-RBAC-02 two-value shape. Run this
only against a disposable database, never a shared development or
production database. Marked `integration` and excluded from the default
`pytest` run for exactly this reason, mirroring
`tests/infra/db/test_audit_log_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/infra/db/test_audit_log_service_account_actor_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

# Registers core.support_access_requests/core.delegation_grants on the
# shared declarative Base.metadata (architecture research Phase F --
# "Audit + Support Access") -- required for record()'s
# ForeignKey("core.support_access_requests.id")/ForeignKey("core.delegation_grants.id")
# to resolve, even though this file never otherwise needs core.rbac. Same
# precedent as `tests/infra/db/test_audit_log_migration_rollback.py`.
import core.rbac.models  # noqa: F401
import pytest
from alembic import command
from alembic.config import Config
from core.audit_log.models import ActorType, AuditOutcome
from core.audit_log.service import record
from core.identity.service import create_service_account
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SERVICE_ACCOUNT_ACTOR_REVISION = "a8ad8e61deb2"
_PREVIOUS_REVISION = "d9da5514672b"


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


def _column_exists(table: str, column: str) -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                    "WHERE table_schema = 'core' AND table_name = :t AND column_name = :c)"
                ),
                {"t": table, "c": column},
            ).scalar_one()
        return bool(row)
    finally:
        engine.dispose()


def _check_constraint_definition(name: str) -> str | None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :n"),
                {"n": name},
            ).one_or_none()
        return row[0] if row is not None else None
    finally:
        engine.dispose()


def test_service_account_actor_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _column_exists("audit_log", "actor_service_account_id")
    actor_type_check = _check_constraint_definition("ck_audit_log_actor_type")
    assert actor_type_check is not None
    assert "service_account" in actor_type_check

    # --- seed a real SERVICE_ACCOUNT audit record through the actual
    # service layer (not raw SQL) before downgrading, proving the schema
    # this migration created is genuinely usable, not merely structurally
    # present ---
    tenant = create_tenant(f"audit-sa-rollback-{uuid.uuid4().hex[:8]}")
    sa = create_service_account(tenant.id, f"svc-{uuid.uuid4().hex[:8]}")
    try:
        record(
            tenant_id=tenant.id,
            actor_type=ActorType.SERVICE_ACCOUNT,
            actor_service_account_id=sa.id,
            action="rollback.seed",
            resource_type="probe",
            outcome=AuditOutcome.SUCCESS,
        )

        try:
            # --- the seeded row must be gone before downgrading (its own
            # actor_service_account_id/column is about to be dropped) ---
            admin_engine = build_engine(get_migrations_database_config())
            try:
                admin_factory = build_session_factory(admin_engine)
                with session_scope(session_factory=admin_factory) as session:
                    session.execute(
                        text("DELETE FROM core.audit_log WHERE tenant_id = :t"),
                        {"t": str(tenant.id)},
                    )
            finally:
                admin_engine.dispose()

            # --- downgrade past this migration ---
            command.downgrade(cfg, _PREVIOUS_REVISION)
            assert not _column_exists("audit_log", "actor_service_account_id")
            restored_check = _check_constraint_definition("ck_audit_log_actor_type")
            assert restored_check is not None
            assert "service_account" not in restored_check
            # Every earlier phase's own table remains untouched.
            assert _column_exists("audit_log", "actor_user_id")
            assert _column_exists("audit_log", "acting_as_tenant_id")
            assert _column_exists("audit_log", "delegation_grant_id")
            assert _column_exists("audit_log", "support_access_id")

            # --- re-apply this migration ---
            command.upgrade(cfg, _SERVICE_ACCOUNT_ACTOR_REVISION)
            assert _column_exists("audit_log", "actor_service_account_id")
            reapplied_check = _check_constraint_definition("ck_audit_log_actor_type")
            assert reapplied_check is not None
            assert "service_account" in reapplied_check

            # audit_log is usable again post-re-upgrade: a fresh
            # SERVICE_ACCOUNT record succeeds -- proves the *schema* is
            # usable again, not that data survived a destructive downgrade
            # (it deliberately does not: the table itself was never
            # dropped, but this migration's own column/constraints were).
            record(
                tenant_id=tenant.id,
                actor_type=ActorType.SERVICE_ACCOUNT,
                actor_service_account_id=sa.id,
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
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.service_accounts WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


def test_downgrade_fails_closed_against_a_real_service_account_actor_row() -> None:
    """A downgrade that would leave a real `actor_type='service_account'`
    row violating the restored two-value CHECK must fail loudly at the
    database, never silently drop or reinterpret that row -- the correct,
    fail-closed behavior for a destructive downgrade that cannot represent
    the row's own actor type anymore."""
    cfg = _alembic_config()
    command.upgrade(cfg, "head")

    tenant = create_tenant(f"audit-sa-downgrade-{uuid.uuid4().hex[:8]}")
    sa = create_service_account(tenant.id, f"svc-{uuid.uuid4().hex[:8]}")
    try:
        record(
            tenant_id=tenant.id,
            actor_type=ActorType.SERVICE_ACCOUNT,
            actor_service_account_id=sa.id,
            action="rollback.blocking_row",
            resource_type="probe",
            outcome=AuditOutcome.SUCCESS,
        )

        # A CHECK-constraint violation surfaces as psycopg.errors.CheckViolation,
        # a subclass of IntegrityError -- not ProgrammingError.
        with pytest.raises(IntegrityError):
            command.downgrade(cfg, _PREVIOUS_REVISION)
    finally:
        # The failed downgrade may have left the migration state
        # mid-transition on some backends -- restore head explicitly
        # before cleanup, mirroring every other destructive-migration
        # test's own `finally: command.upgrade(cfg, "head")`.
        command.upgrade(cfg, "head")
        admin_engine = build_engine(get_migrations_database_config())
        try:
            admin_factory = build_session_factory(admin_engine)
            with session_scope(session_factory=admin_factory) as session:
                session.execute(
                    text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant.id)}
                )
        finally:
            admin_engine.dispose()
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.service_accounts WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
