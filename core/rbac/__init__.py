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
  identity, never to a global `User` directly;
- the `can()` authorization chokepoint (`core/rbac/authorization.py`).

Does NOT own: authentication (core/identity, Phase 3.2), tenant isolation
mechanics (infra/db, Phase 3.1), audit logging (core/audit-log, Phase 3.4),
any HTTP/API surface (Phase 8), or AI Control Plane tool/data authorization
(docs/ADR/0004-..., docs/ADR/0013-...).

`core/rbac` never imports sqlalchemy directly (pyproject.toml's "Only
infra/db may import SQLAlchemy or psycopg directly" contract) and never
reads another Core module's ORM models directly -- it reaches
`core/identity`'s membership data only through that module's published
interface (docs/DATA-ARCHITECTURE.md section 3).
"""

from core.rbac.authorization import can
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
from core.rbac.service import (
    assign_role,
    create_role,
    delete_role,
    get_membership_role,
    get_permission,
    get_permission_by_id,
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

__all__ = [
    "Role",
    "Permission",
    "RolePermission",
    "MembershipRole",
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
    "RoleNotFoundError",
    "DuplicateRoleNameError",
    "PermissionNotFoundError",
    "DuplicatePermissionError",
    "MembershipNotFoundError",
    "DuplicateRoleAssignmentError",
    "DuplicatePermissionGrantError",
]
