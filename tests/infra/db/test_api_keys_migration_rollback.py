"""Migration reversibility test for the Phase 4.1 api_keys migration
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.1 Rollback Strategy: "revert code;
no production keys issued yet at this phase" -- validated against real
disposable PostgreSQL, not merely documented).

**Destructive**: this test downgrades past, then re-applies, `3a2522ccb9ea`
(the api_keys-table migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`core.api_keys`, then recreates it empty. Run this only against a
disposable database, never a shared development or production database.
Marked `integration` and excluded from the default `pytest` run for
exactly this reason, mirroring
`tests/infra/db/test_rbac_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_api_keys_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from core.api_keys.service import create_api_key
from core.identity.service import add_tenant_membership, create_user
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_API_KEYS_REVISION = "3a2522ccb9ea"
_AUDIT_LOG_REVISION = "2e7cb8c64903"


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


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    # core.audit_log DELETE is REVOKEd from the restricted runtime role
    # entirely (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4) -- test cleanup
    # must use the privileged migrations role here.
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
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


def test_api_keys_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("api_keys")
    assert _runtime_role_privileges("api_keys") == {"SELECT", "INSERT", "UPDATE", "DELETE"}

    # --- seed a real API key through the actual service layer (not raw
    # SQL) before downgrading, proving the schema this migration created
    # is genuinely usable, not merely structurally present ---
    tenant = create_tenant(f"apikeys-rollback-{uuid.uuid4().hex[:8]}")
    user = create_user()
    try:
        add_tenant_membership(tenant.id, user.id)
        create_api_key(tenant.id, user.id, "rollback-seed-key")

        try:
            # --- downgrade past the api_keys migration ---
            command.downgrade(cfg, _AUDIT_LOG_REVISION)
            assert not _table_exists("api_keys")
            # Phase 3.1/3.2/3.3/3.4's own tables must be untouched.
            assert _table_exists("tenants")
            assert _table_exists("users")
            assert _table_exists("tenant_memberships")
            assert _table_exists("roles")
            assert _table_exists("audit_log")

            # --- re-apply the api_keys migration ---
            command.upgrade(cfg, _API_KEYS_REVISION)
            assert _table_exists("api_keys")
            assert _runtime_role_privileges("api_keys") == {
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
            }

            # --- advance the rest of the way to head before touching the
            # service layer ---
            # `create_api_key()`'s ORM model is the CURRENT (head) shape of
            # `core.api_keys` -- later phases are free to add columns to a
            # table an earlier migration created (architecture research
            # Phase E added `expires_at`/`service_account_id`, e.g.
            # `5964e254eeb6`), and this test's own job is only to prove
            # `3a2522ccb9ea` itself is reversible, not to freeze the table's
            # shape at that one revision forever. Pinning the schema at
            # `_API_KEYS_REVISION` while calling head's own service function
            # would test an ORM/schema combination that never actually
            # exists in any real deployment (a real rollback is always
            # immediately followed by re-running every migration back to
            # head, never stopped partway) -- upgrading here first is what
            # keeps the usability proof below meaningful instead of
            # accidentally asserting a stale, no-longer-supported schema
            # shape.
            command.upgrade(cfg, "head")

            # api_keys is usable again post-re-upgrade: a fresh key issues
            # successfully (the old row was dropped with the table, which
            # is expected -- this proves the *schema* is usable again, not
            # that data survived a destructive downgrade).
            create_api_key(tenant.id, user.id, "rollback-reseed-key")
        finally:
            command.upgrade(cfg, "head")
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(tenant.id)}
            )
        _admin_delete_audit_log_for_tenant(tenant.id)
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user.id)})
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
