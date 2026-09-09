"""Role, permission, grant, and assignment operations
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.3).

Roles and their assignments/grants are tenant-owned data -- every function
that reads or writes `core.roles`, `core.role_permissions`, or
`core.membership_roles` takes an explicit `tenant_id` and uses
`tenant_session_scope()`, so the RLS policy on those tables (applied by
this phase's migration) is the same enforcement mechanism protecting every
other tenant-owned table (docs/MULTI-TENANCY.md).

`core.permissions` is the one global table here (this module's own
docstring in `core/rbac/models.py`) -- `register_permission`/`get_permission`/
`list_permissions` use plain `session_scope()`, mirroring how
`core/tenancy`'s tenant registry and `core/identity`'s user/external-identity
tables are read without a tenant context.

No role or permission is ever created, granted, or assigned as the
privileged migrations role -- every function here uses the restricted
`saas_os_app` runtime role via `infra.db.session_scope()`/
`tenant_session_scope()`, exactly like `core/tenancy` and `core/identity`.
"""

from __future__ import annotations

import uuid

from core.rbac.errors import (
    DuplicatePermissionError,
    DuplicatePermissionGrantError,
    DuplicateRoleAssignmentError,
    DuplicateRoleNameError,
    MembershipNotFoundError,
    PermissionNotFoundError,
    RoleNotFoundError,
)
from core.rbac.models import MembershipRole, Permission, Role, RolePermission
from infra.db import IntegrityError, select, session_scope, tenant_session_scope

# --- Roles -------------------------------------------------------------


def create_role(tenant_id: uuid.UUID, name: str) -> Role:
    """Create a role in `tenant_id`. The database-level unique constraint
    on (tenant_id, name) is the real enforcement mechanism; catching
    `IntegrityError` here is defense in depth for the race-condition path
    (two concurrent callers creating the same never-before-seen role name),
    mirroring `core/identity/service.py::link_external_identity`.
    """
    try:
        with tenant_session_scope(tenant_id) as session:
            role = Role(tenant_id=tenant_id, name=name)
            session.add(role)
            session.flush()
            session.refresh(role)
            session.expunge(role)
            return role
    except IntegrityError as exc:
        raise DuplicateRoleNameError(tenant_id, name) from exc


def get_role(tenant_id: uuid.UUID, role_id: uuid.UUID) -> Role:
    with tenant_session_scope(tenant_id) as session:
        role = session.get(Role, role_id)
        if role is None:
            raise RoleNotFoundError(tenant_id, role_id)
        session.expunge(role)
        return role


def list_roles(tenant_id: uuid.UUID) -> list[Role]:
    with tenant_session_scope(tenant_id) as session:
        roles = session.execute(select(Role).where(Role.tenant_id == tenant_id)).scalars().all()
        for role in roles:
            session.expunge(role)
        return list(roles)


def delete_role(tenant_id: uuid.UUID, role_id: uuid.UUID) -> None:
    """Delete a role. If the role still has permission grants or
    membership assignments, the foreign-key references from
    `role_permissions`/`membership_roles` reject the delete (Postgres's
    default `ON DELETE` behavior, no `CASCADE` declared) -- a role in use
    cannot be silently removed out from under an active assignment; the
    caller must revoke/remove those first.
    """
    with tenant_session_scope(tenant_id) as session:
        role = session.get(Role, role_id)
        if role is None:
            raise RoleNotFoundError(tenant_id, role_id)
        session.delete(role)


# --- Permissions (global catalog) ---------------------------------------


def register_permission(resource: str, action: str) -> Permission:
    """Idempotent: registering an already-registered (resource, action)
    pair returns the existing `Permission` rather than raising -- this is
    the "generic mechanism" Product code calls to declare its own
    permissions into the shared catalog (docs/IMPLEMENTATION-ROADMAP.md
    Phase 3.3 section 8) without needing to first check whether it already
    exists.
    """
    existing = get_permission(resource, action)
    if existing is not None:
        return existing
    try:
        with session_scope() as session:
            permission = Permission(resource=resource, action=action)
            session.add(permission)
            session.flush()
            session.refresh(permission)
            session.expunge(permission)
            return permission
    except IntegrityError:
        # Lost a race to a concurrent registration of the same
        # (resource, action) -- the other caller's row is canonical.
        existing = get_permission(resource, action)
        if existing is None:
            raise DuplicatePermissionError(resource, action) from None
        return existing


def get_permission(resource: str, action: str) -> Permission | None:
    with session_scope() as session:
        permission = session.execute(
            select(Permission).where(Permission.resource == resource, Permission.action == action)
        ).scalar_one_or_none()
        if permission is not None:
            session.expunge(permission)
        return permission


def get_permission_by_id(permission_id: uuid.UUID) -> Permission | None:
    with session_scope() as session:
        permission = session.get(Permission, permission_id)
        if permission is not None:
            session.expunge(permission)
        return permission


def list_permissions() -> list[Permission]:
    with session_scope() as session:
        permissions = session.execute(select(Permission)).scalars().all()
        for permission in permissions:
            session.expunge(permission)
        return list(permissions)


# --- Role <-> Permission grants -----------------------------------------


def grant_permission(
    tenant_id: uuid.UUID, role_id: uuid.UUID, permission_id: uuid.UUID
) -> RolePermission:
    """Grant `permission_id` to `role_id` within `tenant_id`.

    `role_id` must belong to `tenant_id` -- enforced structurally by the
    composite foreign key `(tenant_id, role_id) -> roles(tenant_id, id)`
    (`core/rbac/models.py`), not merely by this function remembering to
    check. A `role_id` from a different tenant fails at the database level
    with an `IntegrityError`, surfaced here as `RoleNotFoundError` (the
    same error a genuinely-nonexistent role_id would raise -- this lookup
    never distinguishes "wrong tenant" from "doesn't exist"). A
    `permission_id` that does not exist at all in the global catalog fails
    its own (plain, single-column) foreign key and is surfaced as
    `PermissionNotFoundError`.
    """
    try:
        with tenant_session_scope(tenant_id) as session:
            grant = RolePermission(
                tenant_id=tenant_id, role_id=role_id, permission_id=permission_id
            )
            session.add(grant)
            session.flush()
            session.refresh(grant)
            session.expunge(grant)
            return grant
    except IntegrityError as exc:
        # Disambiguate constraint violations by re-checking known state --
        # never leaks *which* constraint fired via the raw driver message.
        if get_role_permission(tenant_id, role_id, permission_id) is not None:
            raise DuplicatePermissionGrantError(role_id, permission_id) from exc
        if get_permission_by_id(permission_id) is None:
            raise PermissionNotFoundError(permission_id) from exc
        raise RoleNotFoundError(tenant_id, role_id) from exc


def get_role_permission(
    tenant_id: uuid.UUID, role_id: uuid.UUID, permission_id: uuid.UUID
) -> RolePermission | None:
    with tenant_session_scope(tenant_id) as session:
        grant = session.execute(
            select(RolePermission).where(
                RolePermission.tenant_id == tenant_id,
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id,
            )
        ).scalar_one_or_none()
        if grant is not None:
            session.expunge(grant)
        return grant


def revoke_permission(tenant_id: uuid.UUID, role_id: uuid.UUID, permission_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        grant = session.execute(
            select(RolePermission).where(
                RolePermission.tenant_id == tenant_id,
                RolePermission.role_id == role_id,
                RolePermission.permission_id == permission_id,
            )
        ).scalar_one_or_none()
        if grant is not None:
            session.delete(grant)


# --- Membership <-> Role assignments -------------------------------------


def assign_role(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, role_id: uuid.UUID
) -> MembershipRole:
    """Assign `role_id` to `membership_id` within `tenant_id`.

    Both `membership_id` and `role_id` must belong to `tenant_id` --
    enforced structurally by two composite foreign keys
    (`core/rbac/models.py`), not merely by this function remembering to
    check. Uses the existing `TenantMembership` identity from
    `core/identity` (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 10)
    -- there is no `user_id`-based shortcut here; a caller must already
    have resolved which membership it is assigning to. A `role_id` that
    does not belong to `tenant_id` raises `RoleNotFoundError`; a
    `membership_id` that does not belong to `tenant_id` raises
    `MembershipNotFoundError` -- these are two independent composite-FK
    violations, disambiguated explicitly below rather than assumed.
    """
    try:
        with tenant_session_scope(tenant_id) as session:
            assignment = MembershipRole(
                tenant_id=tenant_id, membership_id=membership_id, role_id=role_id
            )
            session.add(assignment)
            session.flush()
            session.refresh(assignment)
            session.expunge(assignment)
            return assignment
    except IntegrityError as exc:
        if get_membership_role(tenant_id, membership_id, role_id) is not None:
            raise DuplicateRoleAssignmentError(membership_id, role_id) from exc
        # get_role() itself raises RoleNotFoundError if role_id is invalid
        # for this tenant -- let that propagate as-is; only once the role
        # is confirmed valid do we attribute the failure to membership_id.
        get_role(tenant_id, role_id)
        raise MembershipNotFoundError(tenant_id, membership_id) from exc


def get_membership_role(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, role_id: uuid.UUID
) -> MembershipRole | None:
    with tenant_session_scope(tenant_id) as session:
        assignment = session.execute(
            select(MembershipRole).where(
                MembershipRole.tenant_id == tenant_id,
                MembershipRole.membership_id == membership_id,
                MembershipRole.role_id == role_id,
            )
        ).scalar_one_or_none()
        if assignment is not None:
            session.expunge(assignment)
        return assignment


def list_membership_roles(tenant_id: uuid.UUID, membership_id: uuid.UUID) -> list[MembershipRole]:
    with tenant_session_scope(tenant_id) as session:
        assignments = (
            session.execute(
                select(MembershipRole).where(
                    MembershipRole.tenant_id == tenant_id,
                    MembershipRole.membership_id == membership_id,
                )
            )
            .scalars()
            .all()
        )
        for assignment in assignments:
            session.expunge(assignment)
        return list(assignments)


def remove_role(tenant_id: uuid.UUID, membership_id: uuid.UUID, role_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        assignment = session.execute(
            select(MembershipRole).where(
                MembershipRole.tenant_id == tenant_id,
                MembershipRole.membership_id == membership_id,
                MembershipRole.role_id == role_id,
            )
        ).scalar_one_or_none()
        if assignment is not None:
            session.delete(assignment)
