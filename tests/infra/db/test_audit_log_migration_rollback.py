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
`saas_os.core.audit_log`, then recreates it empty. Run this only against a
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

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

# Registers core.users on the shared declarative Base.metadata (see
# tests/core/audit_log/test_audit_log_isolation_integration.py for the
# fuller explanation) -- required for record()'s ForeignKey("core.users.id")
# to resolve, even though this file never otherwise needs saas_os.core.identity.
import saas_os.core.identity.models  # noqa: F401

# Registers core.delegation_grants/core.support_access_requests on the
# shared declarative Base.metadata (architecture research Phase F --
# "Audit + Support Access") -- required for record()'s
# ForeignKey("core.delegation_grants.id")/ForeignKey("core.support_access_requests.id")
# to resolve, even though this file never otherwise needs saas_os.core.rbac. Same
# precedent as the saas_os.core.identity.models import immediately above.
import saas_os.core.rbac.models  # noqa: F401
from lifecycle_callers import PROVISIONING
from saas_os.core.audit_log.models import ActorType, AuditOutcome
from saas_os.core.audit_log.service import record
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_migrations_database_config
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.session import build_session_factory, session_scope


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
    tenant = create_tenant(f"audit-rollback-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
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

            # --- advance the rest of the way to head before touching the
            # service layer ---
            # `record()`'s ORM model is the CURRENT (head) shape of
            # `saas_os.core.audit_log` -- later phases are free to add columns to a
            # table an earlier migration created (architecture research
            # Phase F added `acting_as_tenant_id`/`delegation_grant_id`/
            # `support_access_id`, e.g. `9aecff1d1135`), and this test's own
            # job is only to prove `2e7cb8c64903` itself is reversible, not
            # to freeze the table's shape at that one revision forever.
            # Pinning the schema at `_AUDIT_LOG_REVISION` while calling
            # head's own service function would test an ORM/schema
            # combination that never actually exists in any real deployment
            # (a real rollback is always immediately followed by re-running
            # every migration back to head, never stopped partway) --
            # upgrading here first is what keeps the usability proof below
            # meaningful instead of accidentally asserting a stale,
            # no-longer-supported schema shape.
            command.upgrade(cfg, "head")

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
            _admin_clear_audit_references({"id": str(tenant.id)}, table="tenants")
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
