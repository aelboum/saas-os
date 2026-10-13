"""`saas_os/core/rbac` role/permission/grant/assignment lifecycle integration tests
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
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from lifecycle_callers import PROVISIONING
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.rbac.errors import (
    DuplicatePermissionGrantError,
    DuplicateRoleAssignmentError,
    DuplicateRoleNameError,
    MembershipNotFoundError,
    PermissionNotFoundError,
    RoleNotFoundError,
)
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
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
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import session_scope, tenant_session_scope


def _authority_admin(tenant_id: uuid.UUID, *capabilities: tuple[str, str]) -> UserCaller:
    """An active user holding exactly `capabilities` in `tenant_id` -- the
    explicit, authorized typed caller an authority-changing Core operation
    requires (ADR-0031). Provisioned with explicit provisioning authority."""
    from saas_os.core.authority import SystemAuthority, SystemCaller
    from saas_os.core.identity import add_tenant_membership, create_user
    from saas_os.core.rbac import (
        assign_first_role_for_new_tenant,
        create_role,
        grant_permission,
        register_permission,
    )

    provisioning = SystemCaller(SystemAuthority.PROVISIONING)
    user = create_user()
    membership = add_tenant_membership(tenant_id, user.id, caller=provisioning)
    role = create_role(tenant_id, f"authority-admin-{uuid.uuid4().hex[:8]}", caller=provisioning)
    for resource, action in capabilities:
        permission = register_permission(resource, action)
        grant_permission(tenant_id, role.id, permission.id, caller=provisioning)
    assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=provisioning)
    return UserCaller(user.id)


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


_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

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
        _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_permission(resource: str, action: str) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
            {"r": resource, "a": action},
        )


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        _admin_clear_audit_references({"id": str(user_id)}, table="users")
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


# --- Roles -----------------------------------------------------------------


def test_create_role_then_get_it() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        assert role.tenant_id == tenant.id
        assert role.name == "editor"

        fetched = get_role(tenant.id, role.id)
        assert fetched.id == role.id
    finally:
        _cleanup_tenant(tenant.id)


def test_duplicate_role_name_within_tenant_is_rejected() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    try:
        create_role(tenant.id, "editor", caller=_PROVISIONING)
        with pytest.raises(DuplicateRoleNameError):
            create_role(tenant.id, "editor", caller=_PROVISIONING)
    finally:
        _cleanup_tenant(tenant.id)


def test_same_role_name_is_allowed_across_different_tenants() -> None:
    tenant_a = create_tenant(_unique_name("tenant-a"), caller=PROVISIONING)
    tenant_b = create_tenant(_unique_name("tenant-b"), caller=PROVISIONING)
    try:
        role_a = create_role(tenant_a.id, "editor", caller=_PROVISIONING)
        role_b = create_role(tenant_b.id, "editor", caller=_PROVISIONING)
        assert role_a.id != role_b.id
    finally:
        _cleanup_tenant(tenant_a.id)
        _cleanup_tenant(tenant_b.id)


def test_get_unknown_role_raises() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    try:
        with pytest.raises(RoleNotFoundError):
            get_role(tenant.id, uuid.uuid4())
    finally:
        _cleanup_tenant(tenant.id)


def test_list_roles_returns_only_this_tenants_roles() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    try:
        create_role(tenant.id, "editor", caller=_PROVISIONING)
        create_role(tenant.id, "viewer", caller=_PROVISIONING)
        roles = list_roles(tenant.id)
        assert {r.name for r in roles} == {"editor", "viewer"}
    finally:
        _cleanup_tenant(tenant.id)


def test_delete_role_removes_it() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        delete_role(
            tenant.id,
            role.id,
            caller=_authority_admin(
                tenant.id,
                ("role", "delete"),
                ("role_permission", "revoke"),
                ("membership_role", "delete"),
            ),
        )
        with pytest.raises(RoleNotFoundError):
            get_role(tenant.id, role.id)
    finally:
        _cleanup_tenant(tenant.id)


def test_delete_role_still_granted_a_permission_is_rejected() -> None:
    """No CASCADE: a role in active use cannot be silently removed out
    from under a grant (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3
    section 25 delete semantics, `saas_os/core/rbac/service.py::delete_role`)."""
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    resource, action = "widget", "read"
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id, caller=_PROVISIONING)

        with pytest.raises(Exception):  # noqa: PT011, B017 -- a raw FK IntegrityError, not a typed RBAC error
            delete_role(
                tenant.id,
                role.id,
                caller=_authority_admin(
                    tenant.id,
                    ("role", "delete"),
                    ("role_permission", "revoke"),
                    ("membership_role", "delete"),
                ),
            )
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
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        permission = register_permission(resource, action)

        grant_permission(tenant.id, role.id, permission.id, caller=_PROVISIONING)

        assert get_role_permission(tenant.id, role.id, permission.id) is not None
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


def test_duplicate_grant_is_rejected() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id, caller=_PROVISIONING)

        with pytest.raises(DuplicatePermissionGrantError):
            grant_permission(tenant.id, role.id, permission.id, caller=_PROVISIONING)
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


def test_grant_unknown_permission_raises_permission_not_found() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        with pytest.raises(PermissionNotFoundError):
            grant_permission(tenant.id, role.id, uuid.uuid4(), caller=_PROVISIONING)
    finally:
        _cleanup_tenant(tenant.id)


def test_revoke_permission_removes_grant() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id, caller=_PROVISIONING)

        revoke_permission(
            tenant.id,
            role.id,
            permission.id,
            caller=_authority_admin(
                tenant.id,
                ("role", "delete"),
                ("role_permission", "revoke"),
                ("membership_role", "delete"),
            ),
        )

        assert get_role_permission(tenant.id, role.id, permission.id) is None
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


def test_revoke_permission_never_granted_is_a_no_op() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        permission = register_permission(resource, action)
        revoke_permission(
            tenant.id,
            role.id,
            permission.id,
            caller=_authority_admin(
                tenant.id,
                ("role", "delete"),
                ("role_permission", "revoke"),
                ("membership_role", "delete"),
            ),
        )  # must not raise
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_permission(resource, action)


# --- Membership <-> Role assignments ---------------------------------------


def test_assign_role_then_check_it() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    user = create_user()
    try:
        membership = add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)

        assign_first_role_for_new_tenant(tenant.id, membership.id, role.id, caller=_PROVISIONING)

        assert get_membership_role(tenant.id, membership.id, role.id) is not None
        assert [r.role_id for r in list_membership_roles(tenant.id, membership.id)] == [role.id]
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_duplicate_assignment_is_rejected() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    user = create_user()
    try:
        membership = add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        assign_first_role_for_new_tenant(tenant.id, membership.id, role.id, caller=_PROVISIONING)

        with pytest.raises(DuplicateRoleAssignmentError):
            assign_first_role_for_new_tenant(
                tenant.id, membership.id, role.id, caller=_PROVISIONING
            )
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_assign_unknown_membership_raises_membership_not_found() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        with pytest.raises(MembershipNotFoundError):
            assign_first_role_for_new_tenant(tenant.id, uuid.uuid4(), role.id, caller=_PROVISIONING)
    finally:
        _cleanup_tenant(tenant.id)


def test_remove_role_removes_assignment() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    user = create_user()
    try:
        membership = add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        assign_first_role_for_new_tenant(tenant.id, membership.id, role.id, caller=_PROVISIONING)

        remove_role(
            tenant.id,
            membership.id,
            role.id,
            caller=_authority_admin(
                tenant.id,
                ("role", "delete"),
                ("role_permission", "revoke"),
                ("membership_role", "delete"),
            ),
        )

        assert get_membership_role(tenant.id, membership.id, role.id) is None
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


def test_remove_role_never_assigned_is_a_no_op() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    user = create_user()
    try:
        membership = add_tenant_membership(tenant.id, user.id, caller=_PROVISIONING)
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        remove_role(
            tenant.id,
            membership.id,
            role.id,
            caller=_authority_admin(
                tenant.id,
                ("role", "delete"),
                ("role_permission", "revoke"),
                ("membership_role", "delete"),
            ),
        )  # must not raise
    finally:
        _cleanup_tenant(tenant.id)
        _cleanup_user(user.id)


# --- Concurrency (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 19) -----


def test_repeated_role_creation_with_the_same_name_never_produces_two_rows() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    try:
        create_role(tenant.id, "editor", caller=_PROVISIONING)
        for _ in range(5):
            with pytest.raises(DuplicateRoleNameError):
                create_role(tenant.id, "editor", caller=_PROVISIONING)

        roles = [r for r in list_roles(tenant.id) if r.name == "editor"]
        assert len(roles) == 1
    finally:
        _cleanup_tenant(tenant.id)


def test_repeated_permission_grant_never_produces_two_rows() -> None:
    tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
    resource, action = _unique_name("resource"), "read"
    try:
        role = create_role(tenant.id, "editor", caller=_PROVISIONING)
        permission = register_permission(resource, action)
        grant_permission(tenant.id, role.id, permission.id, caller=_PROVISIONING)
        for _ in range(5):
            with pytest.raises(DuplicatePermissionGrantError):
                grant_permission(tenant.id, role.id, permission.id, caller=_PROVISIONING)

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
