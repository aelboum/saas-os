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
- the `can()` authorization chokepoint (`core/rbac/authorization.py`),
  which evaluates both ordinary membership-role authorization and
  delegated authorization as two paths of the same decision, never a
  parallel `can_delegated()` system.

Does NOT own: authentication (core/identity, Phase 3.2), tenant isolation
mechanics (infra/db, Phase 3.1), any HTTP/API surface (Phase 8), or AI
Control Plane tool/data authorization (docs/ADR/0004-..., docs/ADR/0013-...).
Does use `core/audit_log`'s existing `record()` (Phase 3.4) to log
delegation creation/revocation -- never a new or redesigned audit
mechanism (architecture research Phase C).

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
from core.rbac.service import (
    assign_role,
    create_delegation,
    create_role,
    delete_role,
    get_delegation,
    get_membership_role,
    get_permission,
    get_permission_by_id,
    get_role,
    get_role_permission,
    grant_permission,
    list_delegations_for_delegate,
    list_membership_roles,
    list_permissions,
    list_roles,
    register_permission,
    remove_role,
    revoke_delegation,
    revoke_permission,
)

__all__ = [
    "Role",
    "Permission",
    "RolePermission",
    "MembershipRole",
    "RoleScope",
    "DelegationGrant",
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
    "create_delegation",
    "revoke_delegation",
    "get_delegation",
    "list_delegations_for_delegate",
    "RoleNotFoundError",
    "DuplicateRoleNameError",
    "PermissionNotFoundError",
    "DuplicatePermissionError",
    "MembershipNotFoundError",
    "DuplicateRoleAssignmentError",
    "DuplicatePermissionGrantError",
    "InvalidPrincipalError",
    "InvalidDelegationTimeRangeError",
    "DelegationNotAuthorizedError",
    "DelegationNotFoundError",
]
