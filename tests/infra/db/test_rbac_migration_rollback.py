"""Migration reversibility test for the Phase 3.3 RBAC migration
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 sections 25-26: "upgrade ->
verify schema -> verify RLS -> seed/test RBAC data -> downgrade -> verify
removal -> upgrade again -> verify", run against real disposable
PostgreSQL, not just inspected).

**Destructive**: this test downgrades past, then re-applies,
`81ac56902107` (the RBAC-tables migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`core.roles`/`core.permissions`/`core.role_permissions`/`core.membership_roles`
and the `core.tenant_memberships` composite-unique constraint the RBAC
migration adds, then recreates them empty. Run this only against a
disposable database, never a shared development or production database.
Marked `integration` and excluded from the default `pytest` run for
exactly this reason, mirroring
`tests/infra/db/test_identity_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_rbac_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from core.identity.service import add_tenant_membership, create_user
from core.rbac.service import assign_role, create_role, grant_permission, register_permission
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RBAC_REVISION = "81ac56902107"
_IDENTITY_REVISION = "770fe52b8468"


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


def _tenant_memberships_has_composite_unique() -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_constraint "
                    "WHERE conname = 'uq_tenant_memberships_tenant_id_id')"
                )
            ).scalar_one()
        return bool(row)
    finally:
        engine.dispose()


def test_rbac_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("roles")
    assert _table_exists("permissions")
    assert _table_exists("role_permissions")
    assert _table_exists("membership_roles")
    assert _rls_flags("roles") == (True, True)
    assert _rls_flags("role_permissions") == (True, True)
    assert _rls_flags("membership_roles") == (True, True)
    assert _tenant_memberships_has_composite_unique()

    # --- seed real RBAC data through the actual service layer (not raw
    # SQL) before downgrading, proving the schema this migration created
    # is genuinely usable, not merely structurally present ---
    tenant = create_tenant(f"rbac-rollback-{uuid.uuid4().hex[:8]}")
    user = create_user()
    resource, action = f"rollback-resource-{uuid.uuid4().hex[:8]}", "read"
    try:
        membership = add_tenant_membership(tenant.id, user.id)
        role = create_role(tenant.id, "editor")
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id)
        assign_role(tenant.id, membership.id, role.id)

        try:
            # --- downgrade past the RBAC migration ---
            command.downgrade(cfg, _IDENTITY_REVISION)
            assert not _table_exists("roles")
            assert not _table_exists("permissions")
            assert not _table_exists("role_permissions")
            assert not _table_exists("membership_roles")
            assert not _tenant_memberships_has_composite_unique()
            # Phase 3.2's own tables/constraints must be untouched.
            assert _table_exists("tenant_memberships")
            assert _table_exists("users")

            # --- re-apply the RBAC migration ---
            command.upgrade(cfg, _RBAC_REVISION)
            assert _table_exists("roles")
            assert _table_exists("permissions")
            assert _table_exists("role_permissions")
            assert _table_exists("membership_roles")
            assert _rls_flags("roles") == (True, True)
            assert _rls_flags("role_permissions") == (True, True)
            assert _rls_flags("membership_roles") == (True, True)
            assert _tenant_memberships_has_composite_unique()

            # RBAC is usable again post-re-upgrade: a fresh role/permission/
            # grant/assignment cycle works. `core.permissions` itself was
            # dropped and recreated by this same migration's downgrade/
            # upgrade (it is one of the four tables this migration owns),
            # so the pre-downgrade `permission.id` no longer exists --
            # re-registering it is expected, not a workaround: this proves
            # the *schema* is usable again, not that data survived a
            # destructive downgrade (it deliberately does not).
            new_role = create_role(tenant.id, "viewer")
            new_permission = register_permission(resource, action)
            grant_permission(tenant.id, new_role.id, new_permission.id)
            assign_role(tenant.id, membership.id, new_role.id)
        finally:
            command.upgrade(cfg, "head")
    finally:
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.membership_roles WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.role_permissions WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant.id)}
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user.id)})
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
            session.execute(
                text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
                {"r": resource, "a": action},
            )
