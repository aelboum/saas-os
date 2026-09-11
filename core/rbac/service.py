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

`create_delegation()`/`revoke_delegation()` (architecture research:
universal multi-tenant tenancy, Phase C -- "Delegation") additionally
depend on `core.identity.get_user` (principal existence),
`core.tenancy.get_tenant` (scope-tenant existence), `core.rbac.can`/
`core.rbac.authorization._actor_reaches_tenant_at_scope` (delegation
creation itself must be authorized, and must never let a delegate exceed
the delegator's own authority), and `core.audit_log.record` (using the
existing audit mechanism, never a new one) -- see
`core/rbac/authorization.py`'s module docstring for the full evaluation
model these two functions plug into.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.identity import get_user
from core.rbac.authorization import _actor_reaches_tenant_at_scope, can
from core.rbac.errors import (
    DelegationNotAuthorizedError,
    DelegationNotFoundError,
    DuplicatePermissionError,
    DuplicatePermissionGrantError,
    DuplicateRoleAssignmentError,
    DuplicateRoleNameError,
    InvalidDelegationTimeRangeError,
    InvalidPrincipalError,
    MembershipNotFoundError,
    PermissionNotFoundError,
    RoleNotFoundError,
)
from core.rbac.models import DelegationGrant, MembershipRole, Permission, Role, RolePermission
from core.rbac.principal import PrincipalType
from core.rbac.scope import RoleScope
from core.tenancy import get_tenant
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
    tenant_id: uuid.UUID,
    membership_id: uuid.UUID,
    role_id: uuid.UUID,
    *,
    scope: RoleScope = RoleScope.SELF,
) -> MembershipRole:
    """Assign `role_id` to `membership_id` within `tenant_id`, at
    authorization `scope` (architecture research Phase B,
    `core/rbac/scope.py`) -- `RoleScope.SELF` (the default: this
    assignment authorizes only `tenant_id`, the exact, unchanged behavior
    every pre-Phase-B caller of `assign_role(tenant_id, membership_id,
    role_id)` already gets) or `RoleScope.SUBTREE` (also authorizes every
    *current* descendant of `tenant_id`, evaluated live by
    `core/rbac/authorization.py::can()` -- see that module and
    `core/rbac/scope.py` for the full semantics).

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
                tenant_id=tenant_id,
                membership_id=membership_id,
                role_id=role_id,
                scope=scope.value,
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


# --- Delegation grants (architecture research: universal multi-tenant
# tenancy, Phase C) ----------------------------------------------------


def create_delegation(
    *,
    delegator_user_id: uuid.UUID,
    delegate_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    scope_mode: RoleScope,
    permission_id: uuid.UUID,
    starts_at: datetime | None = None,
    expires_at: datetime | None = None,
    allow_redelegate: bool = False,
) -> DelegationGrant:
    """Create a `DelegationGrant`: `delegator_user_id` explicitly grants
    `delegate_user_id` the single permission `permission_id`, at
    `scope_mode` (`RoleScope.SELF` or `RoleScope.SUBTREE`), over
    `tenant_id`. Both parties are `PrincipalType.USER` -- this phase
    constructs no other principal type (`core/rbac/principal.py`).

    Fails closed, in this order, before any row is written:

    1. `tenant_id` must exist (`core.tenancy.TenantNotFoundError`
       propagates unchanged).
    2. Both `delegator_user_id` and `delegate_user_id` must resolve to a
       real `core.identity` user (`InvalidPrincipalError` otherwise) --
       neither party needs a *membership* in `tenant_id`; that is
       precisely the point of this primitive
       (docs -- delegation and membership are distinct concepts).
    3. `permission_id` must resolve in the global permission catalog
       (`PermissionNotFoundError` otherwise) -- this function never
       creates a permission on the delegator's behalf.
    4. `expires_at`, if given, must fall strictly after `starts_at`
       (`InvalidDelegationTimeRangeError` otherwise) -- the same
       invariant `ck_delegation_grants_valid_time_range` enforces at the
       database level.
    5. `delegator_user_id` must hold the dedicated "manage delegations in
       this tenant" capability (`(resource="delegation_grant",
       action="create")`, registered here idempotently, checked via the
       existing `can()` chokepoint -- no second authorization mechanism)
       (`DelegationNotAuthorizedError` otherwise).
    6. **No privilege amplification**: `delegator_user_id` must already
       hold, through ordinary membership-role authorization ALONE (never
       through another delegation -- `_actor_reaches_tenant_at_scope()`'s
       own docstring), at least `scope_mode`-level authority over
       `permission.resource`/`permission.action` at `tenant_id`
       (`DelegationNotAuthorizedError` otherwise). This is what makes
       "a delegator may delegate only permissions the delegator currently
       possesses within the delegation's target scope" concrete, and it
       is also what makes redelegation impossible by default: a delegate
       trying to call this function is evaluated by the *same* check,
       which never looks at `DelegationGrant` rows.
    """
    get_tenant(tenant_id)

    if get_user(delegator_user_id) is None:
        raise InvalidPrincipalError(PrincipalType.USER.value, delegator_user_id)
    if get_user(delegate_user_id) is None:
        raise InvalidPrincipalError(PrincipalType.USER.value, delegate_user_id)

    permission = get_permission_by_id(permission_id)
    if permission is None:
        raise PermissionNotFoundError(permission_id)

    resolved_starts_at = starts_at if starts_at is not None else datetime.now(UTC)
    if expires_at is not None and expires_at <= resolved_starts_at:
        raise InvalidDelegationTimeRangeError(resolved_starts_at, expires_at)

    register_permission("delegation_grant", "create")
    if not can(
        actor_id=delegator_user_id,
        tenant_id=tenant_id,
        action="create",
        resource="delegation_grant",
    ):
        raise DelegationNotAuthorizedError(delegator_user_id, tenant_id)

    if not _actor_reaches_tenant_at_scope(
        actor_id=delegator_user_id,
        tenant_id=tenant_id,
        action=permission.action,
        resource=permission.resource,
        required_scope=scope_mode,
    ):
        raise DelegationNotAuthorizedError(delegator_user_id, tenant_id)

    with tenant_session_scope(tenant_id) as session:
        grant = DelegationGrant(
            tenant_id=tenant_id,
            delegator_principal_type=PrincipalType.USER.value,
            delegator_principal_id=delegator_user_id,
            delegate_principal_type=PrincipalType.USER.value,
            delegate_principal_id=delegate_user_id,
            scope_mode=scope_mode.value,
            permission_id=permission_id,
            starts_at=resolved_starts_at,
            expires_at=expires_at,
            allow_redelegate=allow_redelegate,
        )
        session.add(grant)
        session.flush()
        session.refresh(grant)
        session.expunge(grant)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=delegator_user_id,
        action="delegation.create",
        resource_type="delegation_grant",
        resource_id=str(grant.id),
        outcome=AuditOutcome.SUCCESS,
    )
    return grant


def get_delegation(tenant_id: uuid.UUID, delegation_grant_id: uuid.UUID) -> DelegationGrant:
    with tenant_session_scope(tenant_id) as session:
        grant = session.get(DelegationGrant, delegation_grant_id)
        if grant is None or grant.tenant_id != tenant_id:
            raise DelegationNotFoundError(tenant_id, delegation_grant_id)
        session.expunge(grant)
        return grant


def list_delegations_for_delegate(
    tenant_id: uuid.UUID, delegate_user_id: uuid.UUID
) -> list[DelegationGrant]:
    """Every delegation grant (active, expired, or revoked) naming
    `delegate_user_id` as delegate within `tenant_id`, for
    audit/management visibility -- `can()` is the authority on which of
    these are actually *valid right now*; this is an unfiltered listing,
    mirroring `list_membership_roles()`'s own unfiltered shape."""
    with tenant_session_scope(tenant_id) as session:
        grants = (
            session.execute(
                select(DelegationGrant).where(
                    DelegationGrant.tenant_id == tenant_id,
                    DelegationGrant.delegate_principal_type == PrincipalType.USER.value,
                    DelegationGrant.delegate_principal_id == delegate_user_id,
                )
            )
            .scalars()
            .all()
        )
        for grant in grants:
            session.expunge(grant)
        return list(grants)


def revoke_delegation(
    *, revoker_user_id: uuid.UUID, tenant_id: uuid.UUID, delegation_grant_id: uuid.UUID
) -> DelegationGrant:
    """Revoke a `DelegationGrant`, immediately -- the very next `can()`
    call re-reads `revoked_at` live (`core/rbac/authorization.py`), so
    there is nothing further to invalidate (no cache, no session to
    revoke). Idempotent: revoking an already-revoked grant is a no-op
    that returns the grant unchanged, not an error.

    Authorized if `revoker_user_id` is either:
    - the grant's own delegator (self-revocation -- always allowed, no
      permission check needed: undoing your own grant can never exceed
      your own authority), or
    - independently authorized via the same dedicated
      "manage delegations in this tenant" capability
      (`(resource="delegation_grant", action="revoke")`) `create_delegation()`
      uses for creation, checked via the existing `can()` chokepoint.
    """
    with tenant_session_scope(tenant_id) as session:
        grant = session.get(DelegationGrant, delegation_grant_id)
        if grant is None or grant.tenant_id != tenant_id:
            raise DelegationNotFoundError(tenant_id, delegation_grant_id)
        session.expunge(grant)

    is_self_revocation = (
        grant.delegator_principal_type == PrincipalType.USER.value
        and grant.delegator_principal_id == revoker_user_id
    )
    if not is_self_revocation:
        register_permission("delegation_grant", "revoke")
        if not can(
            actor_id=revoker_user_id,
            tenant_id=tenant_id,
            action="revoke",
            resource="delegation_grant",
        ):
            raise DelegationNotAuthorizedError(revoker_user_id, tenant_id)

    if grant.revoked_at is not None:
        return grant

    with tenant_session_scope(tenant_id) as session:
        row = session.get(DelegationGrant, delegation_grant_id)
        if row is None:
            raise DelegationNotFoundError(tenant_id, delegation_grant_id)
        row.revoked_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        grant = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=revoker_user_id,
        action="delegation.revoke",
        resource_type="delegation_grant",
        resource_id=str(delegation_grant_id),
        outcome=AuditOutcome.SUCCESS,
    )
    return grant
