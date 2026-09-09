"""`core/rbac` role/permission/grant/assignment lifecycle integration tests
against a real PostgreSQL instance with the Phase 3.3 tables actually
migrated (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 27).

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/identity/test_identity_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_rbac_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import add_tenant_membership, create_user
from core.rbac.errors import (
    DuplicatePermissionGrantError,
    DuplicateRoleAssignmentError,
    DuplicateRoleNameError,
    MembershipNotFoundError,
    PermissionNotFoundError,
    RoleNotFoundError,
)
from core.rbac.service import (
    assign_role,
    create_role,
    delete_role,
    get_membership_role,
    get_permission,
    get_role,
    get_role_permission,
    grant_permission,
    list_membership_roles,
    list_permissions,
    list_roles,
    register_permission,
    remove_role,
    revoke_permission,
)
from infra.db.config import get_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_rbac_tables() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.roles LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(f"core.roles does not exist yet -- run `alembic upgrade head` first: {exc}")
    finally:
        probe_engine.dispose()


def _unique_name(prefix: str = "role") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.membership_roles WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.role_permissions WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant_id)})
    with session_scope() as session:
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_permission(resource: str, action: str) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
            {"r": resource, "a": action},
        )


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


# --- Roles -----------------------------------------------------------------


def test_create_role_then_get_it() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        role = create_role(tenant.id, "editor")
        assert role.tenant_id == tenant.id
        assert role.name == "editor"

        fetched = get_role(tenant.id, role.id)
        assert fetched.id == role.id
    finally:
        _cleanup_tenant(tenant.id)


def test_duplicate_role_name_within_tenant_is_rejected() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        create_role(tenant.id, "editor")
        with pytest.raises(DuplicateRoleNameError):
            create_role(tenant.id, "editor")
    finally:
        _cleanup_tenant(tenant.id)


def test_same_role_name_is_allowed_across_different_tenants() -> None:
    tenant_a = create_tenant(_unique_name("tenant-a"))
    tenant_b = create_tenant(_unique_name("tenant-b"))
    try:
        role_a = create_role(tenant_a.id, "editor")
        role_b = create_role(tenant_b.id, "editor")
        assert role_a.id != role_b.id
    finally:
        _cleanup_tenant(tenant_a.id)
        _cleanup_tenant(tenant_b.id)


def test_get_unknown_role_raises() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        with pytest.raises(RoleNotFoundError):
            get_role(tenant.id, uuid.uuid4())
    finally:
        _cleanup_tenant(tenant.id)


def test_list_roles_returns_only_this_tenants_roles() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        create_role(tenant.id, "editor")
        create_role(tenant.id, "viewer")
        roles = list_roles(tenant.id)
        assert {r.name for r in roles} == {"editor", "viewer"}
    finally:
        _cleanup_tenant(tenant.id)


def test_delete_role_removes_it() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        role = create_role(tenant.id, "editor")
        delete_role(tenant.id, role.id)
        with pytest.raises(RoleNotFoundError):
            get_role(tenant.id, role.id)
    finally:
        _cleanup_tenant(tenant.id)


def test_delete_role_still_granted_a_permission_is_rejected() -> None:
    """No CASCADE: a role in active use cannot be silently removed out
    from under a grant (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3
    section 25 delete semantics, `core/rbac/service.py::delete_role`)."""
    tenant = create_tenant(_unique_name("tenant"))
    resource, action = "widget", "read"
    try:
        role = create_role(tenant.id, "editor")
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id)

        with pytest.raises(Exception):  # noqa: PT011, B017 -- a raw FK IntegrityError, not a typed RBAC error
            delete_role(tenant.id, role.id)
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


# --- Permissions (global catalog) -----------------------------------------


def test_register_permission_then_get_it() -> None:
    resource, action = _unique_name("resource"), "read"
    try:
        permission = register_permission(resource, action)
        assert permission.resource == resource
        assert permission.action == action

        fetched = get_permission(resource, action)
        assert fetched is not None
        assert fetched.id == permission.id
    finally:
        _cleanup_permission(resource, action)


def test_register_permission_is_idempotent() -> None:
    resource, action = _unique_name("resource"), "read"
    try:
        first = register_permission(resource, action)
        second = register_permission(resource, action)
        assert first.id == second.id
        assert len(list_permissions()) >= 1
    finally:
        _cleanup_permission(resource, action)


def test_get_unknown_permission_returns_none() -> None:
    assert get_permission("never-registered-resource", "never-registered-action") is None


# --- Role <-> Permission grants ---------------------------------------------


def test_grant_permission_then_check_it() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor")
        permission = register_permission(resource, action)

        grant_permission(tenant.id, role.id, permission.id)

        assert get_role_permission(tenant.id, role.id, permission.id) is not None
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


def test_duplicate_grant_is_rejected() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor")
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id)

        with pytest.raises(DuplicatePermissionGrantError):
            grant_permission(tenant.id, role.id, permission.id)
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


def test_grant_unknown_permission_raises_permission_not_found() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        role = create_role(tenant.id, "editor")
        with pytest.raises(PermissionNotFoundError):
            grant_permission(tenant.id, role.id, uuid.uuid4())
    finally:
        _cleanup_tenant(tenant.id)


def test_revoke_permission_removes_grant() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor")
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id)

        revoke_permission(tenant.id, role.id, permission.id)

        assert get_role_permission(tenant.id, role.id, permission.id) is None
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


def test_revoke_permission_never_granted_is_a_no_op() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor")
        permission = register_permission(resource, action)
        revoke_permission(tenant.id, role.id, permission.id)  # must not raise
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


# --- Membership <-> Role assignments ---------------------------------------


def test_assign_role_then_check_it() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        membership = add_tenant_membership(tenant.id, user.id)
        role = create_role(tenant.id, "editor")

        assign_role(tenant.id, membership.id, role.id)

        assert get_membership_role(tenant.id, membership.id, role.id) is not None
        assert [r.role_id for r in list_membership_roles(tenant.id, membership.id)] == [role.id]
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_duplicate_assignment_is_rejected() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        membership = add_tenant_membership(tenant.id, user.id)
        role = create_role(tenant.id, "editor")
        assign_role(tenant.id, membership.id, role.id)

        with pytest.raises(DuplicateRoleAssignmentError):
            assign_role(tenant.id, membership.id, role.id)
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_assign_unknown_membership_raises_membership_not_found() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        role = create_role(tenant.id, "editor")
        with pytest.raises(MembershipNotFoundError):
            assign_role(tenant.id, uuid.uuid4(), role.id)
    finally:
        _cleanup_tenant(tenant.id)


def test_remove_role_removes_assignment() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        membership = add_tenant_membership(tenant.id, user.id)
        role = create_role(tenant.id, "editor")
        assign_role(tenant.id, membership.id, role.id)

        remove_role(tenant.id, membership.id, role.id)

        assert get_membership_role(tenant.id, membership.id, role.id) is None
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_remove_role_never_assigned_is_a_no_op() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    user = create_user()
    try:
        membership = add_tenant_membership(tenant.id, user.id)
        role = create_role(tenant.id, "editor")
        remove_role(tenant.id, membership.id, role.id)  # must not raise
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


# --- Concurrency (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 19) -----


def test_repeated_role_creation_with_the_same_name_never_produces_two_rows() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    try:
        create_role(tenant.id, "editor")
        for _ in range(5):
            with pytest.raises(DuplicateRoleNameError):
                create_role(tenant.id, "editor")

        roles = [r for r in list_roles(tenant.id) if r.name == "editor"]
        assert len(roles) == 1
    finally:
        _cleanup_tenant(tenant.id)


def test_repeated_permission_grant_never_produces_two_rows() -> None:
    tenant = create_tenant(_unique_name("tenant"))
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor")
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id)
        for _ in range(5):
            with pytest.raises(DuplicatePermissionGrantError):
                grant_permission(tenant.id, role.id, permission.id)

        with tenant_session_scope(tenant.id) as session:
            count = session.execute(
                text(
                    "SELECT COUNT(*) AS n FROM core.role_permissions "
                    "WHERE role_id = :r AND permission_id = :p"
                ),
                {"r": str(role.id), "p": str(permission.id)},
            ).scalar_one()
        assert count == 1
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)
