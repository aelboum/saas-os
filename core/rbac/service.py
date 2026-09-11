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

`create_deny()`/`revoke_deny()` (architecture research: universal
multi-tenant tenancy, Phase D -- "Explicit Deny") similarly depend on
`core.identity.get_user`, `core.tenancy.get_tenant`, `core.rbac.can`
(the "manage deny grants" capability check), and `core.audit_log.record`
-- but, unlike delegation, never `_actor_reaches_tenant_at_scope()`: a
deny cannot amplify privilege (it only removes it), so there is no
anti-amplification check to run (`core/rbac/models.py::DenyGrant`'s own
docstring).

`assign_service_account_role()`, `create_delegation_to_service_account()`,
and `create_deny_for_service_account()` (architecture research Phase E --
"Principal + Service Accounts + API Key Hardening") are the
`PrincipalType.SERVICE_ACCOUNT` analogues of `assign_role()`,
`create_delegation()`, and `create_deny()` respectively -- each reuses
the identical `Role`/`Permission`/`DelegationGrant`/`DenyGrant` entities
and the identical `can()` chokepoint, never a second permission model or
a second evaluation path. `assign_service_account_role()` additionally
depends on `core.identity.get_service_account` (principal existence) and
carries its own anti-amplification check, unlike `assign_role()` -- see
that function's own docstring for why a service-account role assignment
is treated more like delegation creation than like an ordinary
human-membership role assignment.

`create_support_access_request()`/`approve_support_access()`/
`deny_support_access()`/`revoke_support_access()` (architecture research
Phase F -- "Audit + Support Access") manage `SupportAccessRequest`'s own
lifecycle. Request creation is deliberately ungated (mirrors
`core/identity/service.py::add_tenant_membership()`); approval/denial/
revocation are each gated through the existing `can()` chokepoint, the
same discipline `create_deny()`/`create_delegation()` already use. No new
authorization engine, no new audit mechanism -- `core.audit_log.record()`'s
own `acting_as_tenant_id`/`support_access_id` linkage fields (also Phase
F) record every lifecycle event.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.identity import get_service_account, get_user
from core.rbac.authorization import _actor_reaches_tenant_at_scope, can
from core.rbac.errors import (
    DelegationNotAuthorizedError,
    DelegationNotFoundError,
    DenyNotAuthorizedError,
    DenyNotFoundError,
    DuplicatePermissionError,
    DuplicatePermissionGrantError,
    DuplicateRoleAssignmentError,
    DuplicateRoleNameError,
    DuplicateServiceAccountRoleAssignmentError,
    DuplicateSupportAccessRequestError,
    InvalidDelegationTimeRangeError,
    InvalidPrincipalError,
    InvalidSupportAccessTimeRangeError,
    MembershipNotFoundError,
    PermissionNotFoundError,
    RoleNotFoundError,
    ServiceAccountRoleNotAuthorizedError,
    SupportAccessAlreadyDecidedError,
    SupportAccessNotApprovedError,
    SupportAccessNotAuthorizedError,
    SupportAccessNotFoundError,
    SupportAccessSelfApprovalError,
)
from core.rbac.models import (
    DelegationGrant,
    DenyGrant,
    MembershipRole,
    Permission,
    Role,
    RolePermission,
    ServiceAccountRole,
    SupportAccessRequest,
)
from core.rbac.principal import PrincipalType
from core.rbac.scope import RoleScope
from core.tenancy import get_tenant
from infra.db import IntegrityError, select, session_scope, tenant_session_scope

# architecture research Phase F: a support-access request's own expiration
# window must be genuinely bounded, not merely "finite" -- an arbitrarily
# long window would not meaningfully be "time-bounded" (this phase's own
# approved security requirement: "have a bounded expiration").
_MAX_SUPPORT_ACCESS_DURATION = timedelta(hours=24)
_MAX_SUPPORT_ACCESS_REASON_LENGTH = 1000

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


def _list_role_permissions(tenant_id: uuid.UUID, role_id: uuid.UUID) -> list[Permission]:
    """Every `Permission` currently granted to `role_id` within
    `tenant_id` -- private, used only by
    `assign_service_account_role()`'s own anti-amplification check
    (architecture research Phase E) to walk a role's full permission set,
    since (unlike a `DelegationGrant`, which names exactly one
    `permission_id`) a `Role` may carry more than one."""
    with tenant_session_scope(tenant_id) as session:
        permissions = (
            session.execute(
                select(Permission)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .where(RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id)
            )
            .scalars()
            .all()
        )
        for permission in permissions:
            session.expunge(permission)
        return list(permissions)


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


# --- ServiceAccount <-> Role assignments (architecture research: universal
# multi-tenant tenancy, Phase E -- "Principal + Service Accounts + API Key
# Hardening") ---------------------------------------------------------


def assign_service_account_role(
    *,
    actor_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    service_account_id: uuid.UUID,
    role_id: uuid.UUID,
    scope: RoleScope = RoleScope.SELF,
) -> ServiceAccountRole:
    """Assign `role_id` to `service_account_id` within `tenant_id`, at
    authorization `scope` -- the machine-principal analogue of
    `assign_role()`, but, unlike `assign_role()` (which trusts its
    caller, Phase 8's ingress-layer responsibility), this function is
    itself gated: a service account is a machine credential reachable by
    anyone holding one of its API keys, so granting it a role carries
    real privilege-escalation risk `assign_role()`'s own human-membership
    case does not (`core/rbac/models.py::ServiceAccountRole`'s own
    docstring).

    Both `service_account_id` and `role_id` must belong to `tenant_id` --
    `service_account_id` structurally, via `ServiceAccountRole`'s own
    composite foreign key (`core/identity/models.py::ServiceAccount`'s
    docstring: a service account's `tenant_id` is fixed at creation), so
    this function cannot be used to grant a role "in" a tenant the
    service account does not belong to. `role_id` via the identical
    composite foreign key `assign_role()` already relies on.

    Fails closed, in this order, before any row is written:

    1. `tenant_id` must exist (`core.tenancy.TenantNotFoundError`
       propagates unchanged).
    2. `service_account_id` must resolve to a real service account within
       `tenant_id` (`InvalidPrincipalError` otherwise).
    3. `role_id` must resolve within `tenant_id` (`RoleNotFoundError`
       otherwise -- reuses `get_role()`).
    4. `actor_user_id` must hold the dedicated "manage service account
       roles in this tenant" capability (`(resource="service_account_role",
       action="create")`, registered here idempotently, checked via the
       existing `can()` chokepoint -- no second authorization mechanism)
       (`ServiceAccountRoleNotAuthorizedError` otherwise).
    5. **No privilege amplification**: for EVERY permission `role_id`
       currently grants (`_list_role_permissions()` -- a role may carry
       more than one, unlike a `DelegationGrant`'s single `permission_id`),
       `actor_user_id` must already hold, through ordinary
       membership-role authorization ALONE (never delegation --
       `_actor_reaches_tenant_at_scope()`'s own docstring), at least
       `scope`-level authority at `tenant_id`
       (`ServiceAccountRoleNotAuthorizedError` otherwise). This is the
       same discipline `create_delegation()`'s own step 6 applies to
       delegation creation, applied here per-permission -- so `actor_user_id`
       can never make a service account able to reach further, at a
       given permission, than `actor_user_id`'s own ordinary authority
       already reaches; a `SELF`-only actor cannot create a `SUBTREE`
       assignment, and authority obtained only via a `DelegationGrant`
       (never a further redelegation, and never usable to bootstrap a new
       service-account grant either) does not satisfy this check.
    """
    get_tenant(tenant_id)

    service_account = get_service_account(tenant_id, service_account_id)
    if service_account is None:
        raise InvalidPrincipalError(PrincipalType.SERVICE_ACCOUNT.value, service_account_id)

    # get_role() raises RoleNotFoundError if role_id is invalid for this
    # tenant -- let that propagate unchanged.
    get_role(tenant_id, role_id)

    register_permission("service_account_role", "create")
    if not can(
        actor_id=actor_user_id,
        tenant_id=tenant_id,
        action="create",
        resource="service_account_role",
    ):
        raise ServiceAccountRoleNotAuthorizedError(actor_user_id, tenant_id)

    for permission in _list_role_permissions(tenant_id, role_id):
        if not _actor_reaches_tenant_at_scope(
            actor_id=actor_user_id,
            tenant_id=tenant_id,
            action=permission.action,
            resource=permission.resource,
            required_scope=scope,
        ):
            raise ServiceAccountRoleNotAuthorizedError(actor_user_id, tenant_id)

    try:
        with tenant_session_scope(tenant_id) as session:
            assignment = ServiceAccountRole(
                tenant_id=tenant_id,
                service_account_id=service_account_id,
                role_id=role_id,
                scope=scope.value,
            )
            session.add(assignment)
            session.flush()
            session.refresh(assignment)
            session.expunge(assignment)
    except IntegrityError as exc:
        raise DuplicateServiceAccountRoleAssignmentError(service_account_id, role_id) from exc

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action="service_account_role.create",
        resource_type="service_account_role",
        resource_id=str(assignment.id),
        outcome=AuditOutcome.SUCCESS,
    )
    return assignment


def get_service_account_role(
    tenant_id: uuid.UUID, service_account_id: uuid.UUID, role_id: uuid.UUID
) -> ServiceAccountRole | None:
    with tenant_session_scope(tenant_id) as session:
        assignment = session.execute(
            select(ServiceAccountRole).where(
                ServiceAccountRole.tenant_id == tenant_id,
                ServiceAccountRole.service_account_id == service_account_id,
                ServiceAccountRole.role_id == role_id,
            )
        ).scalar_one_or_none()
        if assignment is not None:
            session.expunge(assignment)
        return assignment


def list_service_account_roles(
    tenant_id: uuid.UUID, service_account_id: uuid.UUID
) -> list[ServiceAccountRole]:
    with tenant_session_scope(tenant_id) as session:
        assignments = (
            session.execute(
                select(ServiceAccountRole).where(
                    ServiceAccountRole.tenant_id == tenant_id,
                    ServiceAccountRole.service_account_id == service_account_id,
                )
            )
            .scalars()
            .all()
        )
        for assignment in assignments:
            session.expunge(assignment)
        return list(assignments)


def remove_service_account_role(
    tenant_id: uuid.UUID, service_account_id: uuid.UUID, role_id: uuid.UUID
) -> None:
    with tenant_session_scope(tenant_id) as session:
        assignment = session.execute(
            select(ServiceAccountRole).where(
                ServiceAccountRole.tenant_id == tenant_id,
                ServiceAccountRole.service_account_id == service_account_id,
                ServiceAccountRole.role_id == role_id,
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


def create_delegation_to_service_account(
    *,
    delegator_user_id: uuid.UUID,
    service_account_id: uuid.UUID,
    service_account_tenant_id: uuid.UUID,
    tenant_id: uuid.UUID,
    scope_mode: RoleScope,
    permission_id: uuid.UUID,
    starts_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> DelegationGrant:
    """The `PrincipalType.SERVICE_ACCOUNT`-delegate analogue of
    `create_delegation()` (architecture research Phase E) -- a service
    account may be an explicit delegation *delegate*, never a delegator
    (that class's own docstring: no redelegation, regardless of principal
    type). `service_account_tenant_id` is the service account's own,
    single, fixed tenant (`core/identity/models.py::ServiceAccount`'s
    docstring) -- required to resolve it (a tenant-owned, RLS-protected
    row, unlike a globally-resolvable `User`) -- and is deliberately NOT
    required to equal `tenant_id`, the delegation's own scope tenant:
    delegation is intentionally hierarchy-independent
    (`DelegationGrant`'s own docstring), so a service account may be
    delegated authority anywhere its delegator's own authority reaches,
    exactly like a `User` delegate can.

    `allow_redelegate` is not exposed here (always `False`) -- this phase
    implements no consuming logic for it regardless of delegate principal
    type (`DelegationGrant`'s own docstring).

    Fails closed, in the same order and for the same reasons
    `create_delegation()` does, substituting the service-account
    existence check for the delegate-user existence check:

    1. `tenant_id` must exist.
    2. `delegator_user_id` must resolve to a real `core.identity` user.
    3. `service_account_id` must resolve within `service_account_tenant_id`
       (`InvalidPrincipalError` otherwise).
    4. `permission_id` must resolve in the global permission catalog.
    5. `expires_at`, if given, must fall strictly after `starts_at`.
    6. `delegator_user_id` must hold the "manage delegations in this
       tenant" capability.
    7. No privilege amplification: `delegator_user_id` must already hold,
       through ordinary membership-role authorization alone, at least
       `scope_mode`-level authority over `permission.resource`/`.action`
       at `tenant_id` -- identical check `create_delegation()` uses,
       independent of the delegate's principal type.
    """
    get_tenant(tenant_id)

    if get_user(delegator_user_id) is None:
        raise InvalidPrincipalError(PrincipalType.USER.value, delegator_user_id)

    service_account = get_service_account(service_account_tenant_id, service_account_id)
    if service_account is None:
        raise InvalidPrincipalError(PrincipalType.SERVICE_ACCOUNT.value, service_account_id)

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
            delegate_principal_type=PrincipalType.SERVICE_ACCOUNT.value,
            delegate_service_account_id=service_account_id,
            scope_mode=scope_mode.value,
            permission_id=permission_id,
            starts_at=resolved_starts_at,
            expires_at=expires_at,
            allow_redelegate=False,
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


# --- Deny grants (architecture research: universal multi-tenant tenancy,
# Phase D) ----------------------------------------------------------------


def create_deny(
    *,
    grantor_user_id: uuid.UUID,
    principal_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    scope_mode: RoleScope,
    permission_id: uuid.UUID,
) -> DenyGrant:
    """Create a `DenyGrant`: blocks `principal_user_id` from
    `permission_id`, at `scope_mode` (`RoleScope.SELF` or
    `RoleScope.SUBTREE`), over `tenant_id`. `principal_user_id` is
    `PrincipalType.USER` -- this phase constructs no other principal type
    (`core/rbac/principal.py`).

    Fails closed, in this order, before any row is written:

    1. `tenant_id` must exist (`core.tenancy.TenantNotFoundError`
       propagates unchanged).
    2. `principal_user_id` must resolve to a real `core.identity` user
       (`InvalidPrincipalError` otherwise) -- no membership in `tenant_id`
       is required, identical to `create_delegation()`'s own reasoning.
    3. `permission_id` must resolve in the global permission catalog
       (`PermissionNotFoundError` otherwise).
    4. `grantor_user_id` must hold the dedicated "manage deny grants in
       this tenant" capability (`(resource="deny_grant",
       action="create")`, registered here idempotently, checked via the
       existing `can()` chokepoint -- no second authorization mechanism)
       (`DenyNotAuthorizedError` otherwise).

    Deliberately **no** anti-amplification check (unlike
    `create_delegation()`'s step 6): a deny can only remove authority,
    never grant more than `grantor_user_id` already effectively controls
    -- `core/rbac/models.py::DenyGrant`'s own docstring.
    """
    get_tenant(tenant_id)

    if get_user(principal_user_id) is None:
        raise InvalidPrincipalError(PrincipalType.USER.value, principal_user_id)

    permission = get_permission_by_id(permission_id)
    if permission is None:
        raise PermissionNotFoundError(permission_id)

    register_permission("deny_grant", "create")
    if not can(
        actor_id=grantor_user_id,
        tenant_id=tenant_id,
        action="create",
        resource="deny_grant",
    ):
        raise DenyNotAuthorizedError(grantor_user_id, tenant_id)

    with tenant_session_scope(tenant_id) as session:
        grant = DenyGrant(
            tenant_id=tenant_id,
            principal_type=PrincipalType.USER.value,
            principal_id=principal_user_id,
            scope_mode=scope_mode.value,
            permission_id=permission_id,
        )
        session.add(grant)
        session.flush()
        session.refresh(grant)
        session.expunge(grant)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=grantor_user_id,
        action="deny.create",
        resource_type="deny_grant",
        resource_id=str(grant.id),
        outcome=AuditOutcome.SUCCESS,
    )
    return grant


def create_deny_for_service_account(
    *,
    grantor_user_id: uuid.UUID,
    service_account_id: uuid.UUID,
    service_account_tenant_id: uuid.UUID,
    tenant_id: uuid.UUID,
    scope_mode: RoleScope,
    permission_id: uuid.UUID,
) -> DenyGrant:
    """The `PrincipalType.SERVICE_ACCOUNT`-principal analogue of
    `create_deny()` (architecture research Phase E) -- blocks
    `service_account_id` from `permission_id`, at `scope_mode`, over
    `tenant_id`. `service_account_tenant_id` is the service account's
    own, single, fixed tenant, required to resolve it (a tenant-owned,
    RLS-protected row) -- deliberately NOT required to equal `tenant_id`
    for the identical hierarchy-independence reason
    `create_delegation_to_service_account()`'s own docstring gives: an
    ancestor's `SUBTREE` deny reaching a descendant service account is
    exactly the scenario this independence makes possible.

    Fails closed, in the same order and for the same reasons
    `create_deny()` does, substituting the service-account existence
    check for the principal-user existence check. Deliberately no
    anti-amplification check, identical to `create_deny()`'s own
    reasoning: a deny can only remove authority, never grant more than
    `grantor_user_id` already effectively controls.
    """
    get_tenant(tenant_id)

    service_account = get_service_account(service_account_tenant_id, service_account_id)
    if service_account is None:
        raise InvalidPrincipalError(PrincipalType.SERVICE_ACCOUNT.value, service_account_id)

    permission = get_permission_by_id(permission_id)
    if permission is None:
        raise PermissionNotFoundError(permission_id)

    register_permission("deny_grant", "create")
    if not can(
        actor_id=grantor_user_id,
        tenant_id=tenant_id,
        action="create",
        resource="deny_grant",
    ):
        raise DenyNotAuthorizedError(grantor_user_id, tenant_id)

    with tenant_session_scope(tenant_id) as session:
        grant = DenyGrant(
            tenant_id=tenant_id,
            principal_type=PrincipalType.SERVICE_ACCOUNT.value,
            principal_service_account_id=service_account_id,
            scope_mode=scope_mode.value,
            permission_id=permission_id,
        )
        session.add(grant)
        session.flush()
        session.refresh(grant)
        session.expunge(grant)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=grantor_user_id,
        action="deny.create",
        resource_type="deny_grant",
        resource_id=str(grant.id),
        outcome=AuditOutcome.SUCCESS,
    )
    return grant


def get_deny(tenant_id: uuid.UUID, deny_grant_id: uuid.UUID) -> DenyGrant:
    with tenant_session_scope(tenant_id) as session:
        grant = session.get(DenyGrant, deny_grant_id)
        if grant is None or grant.tenant_id != tenant_id:
            raise DenyNotFoundError(tenant_id, deny_grant_id)
        session.expunge(grant)
        return grant


def list_denies_for_principal(
    tenant_id: uuid.UUID, principal_user_id: uuid.UUID
) -> list[DenyGrant]:
    """Every deny grant (active or revoked) naming `principal_user_id`
    within `tenant_id`, for audit/management visibility -- `can()` is the
    authority on which of these are actually *active right now*; this is
    an unfiltered listing, mirroring `list_delegations_for_delegate()`'s
    own unfiltered shape."""
    with tenant_session_scope(tenant_id) as session:
        grants = (
            session.execute(
                select(DenyGrant).where(
                    DenyGrant.tenant_id == tenant_id,
                    DenyGrant.principal_type == PrincipalType.USER.value,
                    DenyGrant.principal_id == principal_user_id,
                )
            )
            .scalars()
            .all()
        )
        for grant in grants:
            session.expunge(grant)
        return list(grants)


def revoke_deny(
    *, revoker_user_id: uuid.UUID, tenant_id: uuid.UUID, deny_grant_id: uuid.UUID
) -> DenyGrant:
    """Revoke a `DenyGrant`, immediately -- the very next `can()` call
    re-reads `revoked_at` live (`core/rbac/authorization.py`), so there is
    nothing further to invalidate. Idempotent: revoking an already-revoked
    deny is a no-op that returns the grant unchanged, not an error.

    Unlike `revoke_delegation()`, there is deliberately **no**
    self-revocation shortcut: a `DenyGrant` does not record who created it
    (`core/rbac/models.py::DenyGrant`'s own docstring -- unilateral, not
    bilateral), so there is no cheap, correct way to compare
    `revoker_user_id` against "the original grantor" without adding a
    speculative column for exactly this one check. `revoker_user_id`
    always needs the dedicated "manage deny grants in this tenant"
    capability (`(resource="deny_grant", action="revoke")`, registered
    here idempotently, checked via the existing `can()` chokepoint) --
    the more conservative choice for a security-restricting control:
    whoever is unwinding a deny is re-verified against the *current*
    management capability, not merely "were you the one who created it".
    """
    with tenant_session_scope(tenant_id) as session:
        grant = session.get(DenyGrant, deny_grant_id)
        if grant is None or grant.tenant_id != tenant_id:
            raise DenyNotFoundError(tenant_id, deny_grant_id)
        session.expunge(grant)

    register_permission("deny_grant", "revoke")
    if not can(
        actor_id=revoker_user_id,
        tenant_id=tenant_id,
        action="revoke",
        resource="deny_grant",
    ):
        raise DenyNotAuthorizedError(revoker_user_id, tenant_id)

    if grant.revoked_at is not None:
        return grant

    with tenant_session_scope(tenant_id) as session:
        row = session.get(DenyGrant, deny_grant_id)
        if row is None:
            raise DenyNotFoundError(tenant_id, deny_grant_id)
        row.revoked_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        grant = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=revoker_user_id,
        action="deny.revoke",
        resource_type="deny_grant",
        resource_id=str(deny_grant_id),
        outcome=AuditOutcome.SUCCESS,
    )
    return grant


# --- Support access (architecture research: universal multi-tenant
# tenancy, Phase F -- "Audit + Support Access") --------------------------


def create_support_access_request(
    *,
    requester_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    reason: str,
    requested_expires_at: datetime,
    scope_mode: RoleScope = RoleScope.SELF,
    requested_starts_at: datetime | None = None,
) -> SupportAccessRequest:
    """Record a support engineer's own request for time-bounded support
    access to `tenant_id`. Grants nothing by itself -- deliberately
    ungated, mirroring `core/identity/service.py::add_tenant_membership()`'s
    own "trusts its caller" precedent (`SupportAccessRequest`'s own
    docstring: the real gate is `approve_support_access()`).

    Fails closed, in this order, before any row is written:

    1. `tenant_id` must exist (`core.tenancy.TenantNotFoundError`
       propagates unchanged).
    2. `requester_user_id` must resolve to a real `core.identity` user
       (`InvalidPrincipalError` otherwise).
    3. `reason` must be a non-empty, bounded string
       (`InvalidSupportAccessTimeRangeError`'s sibling check --
       `ValueError` via the same typed-error discipline; see below).
    4. `requested_expires_at` must fall strictly after `requested_starts_at`
       (defaulting to now) AND the resulting window must not exceed
       `_MAX_SUPPORT_ACCESS_DURATION` -- a support grant that could be
       requested with an arbitrarily long window would not meaningfully
       be "time-bounded" (`InvalidSupportAccessTimeRangeError` otherwise).

    A requester with an already-live (pending-review or
    approved-and-not-revoked) request for the same `(tenant_id, scope_mode)`
    cannot create a second one -- the database-level partial unique index
    is the real enforcement mechanism; `IntegrityError` is disambiguated
    here into `DuplicateSupportAccessRequestError`.
    """
    get_tenant(tenant_id)

    if get_user(requester_user_id) is None:
        raise InvalidPrincipalError(PrincipalType.USER.value, requester_user_id)

    if not reason or not reason.strip():
        raise InvalidSupportAccessTimeRangeError("reason must be a non-empty string.")
    if len(reason) > _MAX_SUPPORT_ACCESS_REASON_LENGTH:
        raise InvalidSupportAccessTimeRangeError(
            f"reason exceeds {_MAX_SUPPORT_ACCESS_REASON_LENGTH} characters."
        )

    resolved_starts_at = (
        requested_starts_at if requested_starts_at is not None else datetime.now(UTC)
    )
    if requested_expires_at <= resolved_starts_at:
        raise InvalidSupportAccessTimeRangeError(
            f"requested_expires_at ({requested_expires_at}) must be after "
            f"requested_starts_at ({resolved_starts_at})."
        )
    if requested_expires_at - resolved_starts_at > _MAX_SUPPORT_ACCESS_DURATION:
        raise InvalidSupportAccessTimeRangeError(
            f"requested support access window exceeds the maximum allowed duration "
            f"of {_MAX_SUPPORT_ACCESS_DURATION}."
        )

    try:
        with tenant_session_scope(tenant_id) as session:
            request = SupportAccessRequest(
                tenant_id=tenant_id,
                requester_user_id=requester_user_id,
                scope_mode=scope_mode.value,
                reason=reason,
                requested_starts_at=resolved_starts_at,
                requested_expires_at=requested_expires_at,
            )
            session.add(request)
            session.flush()
            session.refresh(request)
            session.expunge(request)
    except IntegrityError as exc:
        raise DuplicateSupportAccessRequestError(tenant_id, requester_user_id) from exc

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=requester_user_id,
        action="support_access.request",
        resource_type="support_access_request",
        resource_id=str(request.id),
        outcome=AuditOutcome.SUCCESS,
        acting_as_tenant_id=tenant_id,
        support_access_id=request.id,
    )
    return request


def get_support_access_request(tenant_id: uuid.UUID, request_id: uuid.UUID) -> SupportAccessRequest:
    with tenant_session_scope(tenant_id) as session:
        request = session.get(SupportAccessRequest, request_id)
        if request is None or request.tenant_id != tenant_id:
            raise SupportAccessNotFoundError(tenant_id, request_id)
        session.expunge(request)
        return request


def list_support_access_requests_for_tenant(tenant_id: uuid.UUID) -> list[SupportAccessRequest]:
    """Every support-access request (any lifecycle state) targeting
    `tenant_id`, for review/audit visibility -- mirrors
    `list_delegations_for_delegate()`'s own unfiltered shape;
    `core/rbac/support_status.py::compute_support_access_status()` is the
    authority on which of these are currently ACTIVE."""
    with tenant_session_scope(tenant_id) as session:
        requests = (
            session.execute(
                select(SupportAccessRequest).where(SupportAccessRequest.tenant_id == tenant_id)
            )
            .scalars()
            .all()
        )
        for request in requests:
            session.expunge(request)
        return list(requests)


def list_support_access_requests_for_requester(
    tenant_id: uuid.UUID, requester_user_id: uuid.UUID
) -> list[SupportAccessRequest]:
    with tenant_session_scope(tenant_id) as session:
        requests = (
            session.execute(
                select(SupportAccessRequest).where(
                    SupportAccessRequest.tenant_id == tenant_id,
                    SupportAccessRequest.requester_user_id == requester_user_id,
                )
            )
            .scalars()
            .all()
        )
        for request in requests:
            session.expunge(request)
        return list(requests)


def approve_support_access(
    *, approver_user_id: uuid.UUID, tenant_id: uuid.UUID, request_id: uuid.UUID
) -> SupportAccessRequest:
    """Approve a pending support-access request, immediately activating it
    (subject to its own `requested_starts_at`/`requested_expires_at`
    window) -- the very next `can()` call sees it, exactly like
    `create_delegation()`'s grant.

    Fails closed, in this order, before any row is written:

    1. `request_id` must resolve within `tenant_id`
       (`SupportAccessNotFoundError` otherwise).
    2. The request must not already be approved or denied
       (`SupportAccessAlreadyDecidedError` otherwise -- a decision, once
       made, is final).
    3. `approver_user_id` must not be the request's own
       `requester_user_id` (`SupportAccessSelfApprovalError` otherwise --
       also enforced at the database level,
       `ck_support_access_requests_no_self_approval`).
    4. `approver_user_id` must hold the dedicated "manage support access
       in this tenant" capability (`(resource="support_access_request",
       action="approve")`, registered here idempotently, checked via the
       existing `can()` chokepoint -- no second authorization mechanism,
       and never satisfiable by an active support grant itself --
       `core/rbac/authorization.py::_SUPPORT_ACCESS_EXCLUDED_RESOURCES`)
       (`SupportAccessNotAuthorizedError` otherwise).
    """
    request = get_support_access_request(tenant_id, request_id)

    if request.approved_at is not None or request.denied_at is not None:
        raise SupportAccessAlreadyDecidedError(request_id)

    if approver_user_id == request.requester_user_id:
        raise SupportAccessSelfApprovalError(approver_user_id, request_id)

    register_permission("support_access_request", "approve")
    if not can(
        actor_id=approver_user_id,
        tenant_id=tenant_id,
        action="approve",
        resource="support_access_request",
    ):
        raise SupportAccessNotAuthorizedError(approver_user_id, tenant_id)

    with tenant_session_scope(tenant_id) as session:
        row = session.get(SupportAccessRequest, request_id)
        if row is None:
            raise SupportAccessNotFoundError(tenant_id, request_id)
        row.approved_at = datetime.now(UTC)
        row.approved_by_user_id = approver_user_id
        session.flush()
        session.refresh(row)
        session.expunge(row)
        request = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=approver_user_id,
        action="support_access.approve",
        resource_type="support_access_request",
        resource_id=str(request_id),
        outcome=AuditOutcome.SUCCESS,
        acting_as_tenant_id=tenant_id,
        support_access_id=request_id,
    )
    return request


def deny_support_access(
    *, approver_user_id: uuid.UUID, tenant_id: uuid.UUID, request_id: uuid.UUID
) -> SupportAccessRequest:
    """Deny a pending support-access request -- terminal, like
    `approve_support_access()`'s own approval. Fails closed for the
    identical reasons and in the identical order `approve_support_access()`
    does, substituting "deny" for "approve" throughout (a request already
    approved cannot later be denied -- `SupportAccessAlreadyDecidedError`;
    self-denial is not restricted, unlike self-approval, since denying
    your own request only ever removes access, never grants it -- the
    same "a deny can only remove authority" reasoning
    `core/rbac/models.py::DenyGrant`'s own docstring already gives for
    skipping an anti-amplification check).
    """
    request = get_support_access_request(tenant_id, request_id)

    if request.approved_at is not None or request.denied_at is not None:
        raise SupportAccessAlreadyDecidedError(request_id)

    register_permission("support_access_request", "deny")
    if not can(
        actor_id=approver_user_id,
        tenant_id=tenant_id,
        action="deny",
        resource="support_access_request",
    ):
        raise SupportAccessNotAuthorizedError(approver_user_id, tenant_id)

    with tenant_session_scope(tenant_id) as session:
        row = session.get(SupportAccessRequest, request_id)
        if row is None:
            raise SupportAccessNotFoundError(tenant_id, request_id)
        row.denied_at = datetime.now(UTC)
        row.denied_by_user_id = approver_user_id
        session.flush()
        session.refresh(row)
        session.expunge(row)
        request = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=approver_user_id,
        action="support_access.deny",
        resource_type="support_access_request",
        resource_id=str(request_id),
        outcome=AuditOutcome.SUCCESS,
        acting_as_tenant_id=tenant_id,
        support_access_id=request_id,
    )
    return request


def revoke_support_access(
    *, revoker_user_id: uuid.UUID, tenant_id: uuid.UUID, request_id: uuid.UUID
) -> SupportAccessRequest:
    """Revoke a previously-approved support-access request, immediately --
    the very next `can()` call sees it, exactly like `revoke_deny()`.
    Idempotent: revoking an already-revoked request is a no-op that
    returns the request unchanged, not an error (mirrors
    `revoke_delegation()`/`revoke_deny()`).

    An unapproved request cannot be revoked (`SupportAccessNotApprovedError`
    -- it is DENIED, never "revoked";
    `ck_support_access_requests_revoke_requires_approval` enforces the
    identical invariant at the database level). `revoker_user_id` always
    needs the dedicated "manage support access in this tenant" capability
    (`(resource="support_access_request", action="revoke")`) -- no
    self-revocation shortcut, the same conservative choice
    `revoke_deny()`'s own docstring makes for a security-restricting
    control.
    """
    request = get_support_access_request(tenant_id, request_id)

    if request.approved_at is None:
        raise SupportAccessNotApprovedError(request_id)

    register_permission("support_access_request", "revoke")
    if not can(
        actor_id=revoker_user_id,
        tenant_id=tenant_id,
        action="revoke",
        resource="support_access_request",
    ):
        raise SupportAccessNotAuthorizedError(revoker_user_id, tenant_id)

    if request.revoked_at is not None:
        return request

    with tenant_session_scope(tenant_id) as session:
        row = session.get(SupportAccessRequest, request_id)
        if row is None:
            raise SupportAccessNotFoundError(tenant_id, request_id)
        row.revoked_at = datetime.now(UTC)
        row.revoked_by_user_id = revoker_user_id
        session.flush()
        session.refresh(row)
        session.expunge(row)
        request = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=revoker_user_id,
        action="support_access.revoke",
        resource_type="support_access_request",
        resource_id=str(request_id),
        outcome=AuditOutcome.SUCCESS,
        acting_as_tenant_id=tenant_id,
        support_access_id=request_id,
    )
    return request
