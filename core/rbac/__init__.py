"""`core/rbac` -- roles, permissions, and the single authorization
chokepoint (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3;
docs/SECURITY.md section 3: "Owned entirely by core/rbac, wholly
independent of ZITADEL -- the IdP authenticates identity, it never
determines permissions. Authorization is a single policy-evaluation call
(`can(actor, action, resource)`)").

Owns:
- the tenant-local `Role` entity (`core.roles`);
- the global `Permission` catalog (`core.permissions`) -- a capability
  definition, not tenant-owned data;
- `Role` <-> `Permission` grants (`core.role_permissions`, tenant-owned);
- `TenantMembership` <-> `Role` assignments (`core.membership_roles`,
  tenant-owned) -- anchored to `core/identity`'s existing membership
  identity, never to a global `User` directly, each at an explicit
  authorization `scope` (`RoleScope`: `SELF` or `SUBTREE` relative to the
  membership's tenant -- architecture research Phase B, `core/rbac/scope.py`);
- `DelegationGrant` (`core.delegation_grants`, tenant-owned) -- an
  explicit, scoped, time-bounded, revocable grant of exactly one
  `Permission` from one principal to another (architecture research Phase
  C -- "Delegation"; `core/rbac/principal.py::PrincipalType`);
- `DenyGrant` (`core.deny_grants`, tenant-owned) -- an explicit, scoped,
  revocable block of exactly one `Permission` for one principal that
  overrides every allow path `can()` would otherwise honor (architecture
  research Phase D -- "Explicit Deny": "DENY overrides ALLOW");
- `ServiceAccountRole` (`core.service_account_roles`, tenant-owned) --
  the machine-principal analogue of `MembershipRole`: which roles a
  tenant's `core/identity.ServiceAccount` has been assigned, and at what
  scope (architecture research Phase E -- "Principal + Service Accounts +
  API Key Hardening");
- the `can()` authorization chokepoint (`core/rbac/authorization.py`),
  which checks explicit deny first, then evaluates both ordinary
  allow paths (membership-role or service-account-role) and delegated
  authorization as paths of the same decision -- never a parallel
  `can_delegated()` or `is_denied()` system, and never a second
  authorization engine for machine principals.

Does NOT own: authentication (core/identity, Phase 3.2), the
`ServiceAccount`/`User` entities themselves (core/identity), tenant
isolation mechanics (infra/db, Phase 3.1), any HTTP/API surface (Phase
8), or AI Control Plane tool/data authorization (docs/ADR/0004-...,
docs/ADR/0013-...). Does use `core/audit_log`'s existing `record()`
(Phase 3.4) to log delegation/deny/service-account-role creation and
revocation -- never a new or redesigned audit mechanism (architecture
research Phase C).

`core/rbac` never imports sqlalchemy directly (pyproject.toml's "Only
infra/db may import SQLAlchemy or psycopg directly" contract) and never
reads another Core module's ORM models directly -- it reaches
`core/identity`'s membership data, `core/tenancy`'s tenant/ancestry data,
and `core/audit_log`'s write path only through those modules' published
interfaces (docs/DATA-ARCHITECTURE.md section 3).
"""

from core.rbac.authorization import can
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
    InvalidDelegationTimeRangeError,
    InvalidPrincipalError,
    MembershipNotFoundError,
    PermissionNotFoundError,
    RoleNotFoundError,
    ServiceAccountRoleNotAuthorizedError,
)
from core.rbac.models import (
    DelegationGrant,
    DenyGrant,
    MembershipRole,
    Permission,
    Role,
    RolePermission,
    ServiceAccountRole,
)
from core.rbac.principal import PrincipalType
from core.rbac.scope import RoleScope
from core.rbac.service import (
    assign_role,
    assign_service_account_role,
    create_delegation,
    create_delegation_to_service_account,
    create_deny,
    create_deny_for_service_account,
    create_role,
    delete_role,
    get_delegation,
    get_deny,
    get_membership_role,
    get_permission,
    get_permission_by_id,
    get_role,
    get_role_permission,
    get_service_account_role,
    grant_permission,
    list_delegations_for_delegate,
    list_denies_for_principal,
    list_membership_roles,
    list_permissions,
    list_roles,
    list_service_account_roles,
    register_permission,
    remove_role,
    remove_service_account_role,
    revoke_delegation,
    revoke_deny,
    revoke_permission,
)

__all__ = [
    "Role",
    "Permission",
    "RolePermission",
    "MembershipRole",
    "ServiceAccountRole",
    "RoleScope",
    "DelegationGrant",
    "DenyGrant",
    "PrincipalType",
    "can",
    "create_role",
    "get_role",
    "list_roles",
    "delete_role",
    "register_permission",
    "get_permission",
    "get_permission_by_id",
    "list_permissions",
    "grant_permission",
    "get_role_permission",
    "revoke_permission",
    "assign_role",
    "get_membership_role",
    "list_membership_roles",
    "remove_role",
    "assign_service_account_role",
    "get_service_account_role",
    "list_service_account_roles",
    "remove_service_account_role",
    "create_delegation",
    "create_delegation_to_service_account",
    "revoke_delegation",
    "get_delegation",
    "list_delegations_for_delegate",
    "create_deny",
    "create_deny_for_service_account",
    "revoke_deny",
    "get_deny",
    "list_denies_for_principal",
    "RoleNotFoundError",
    "DuplicateRoleNameError",
    "PermissionNotFoundError",
    "DuplicatePermissionError",
    "MembershipNotFoundError",
    "DuplicateRoleAssignmentError",
    "DuplicatePermissionGrantError",
    "DuplicateServiceAccountRoleAssignmentError",
    "ServiceAccountRoleNotAuthorizedError",
    "InvalidPrincipalError",
    "InvalidDelegationTimeRangeError",
    "DelegationNotAuthorizedError",
    "DelegationNotFoundError",
    "DenyNotAuthorizedError",
    "DenyNotFoundError",
]
