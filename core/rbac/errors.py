"""Typed errors for `core/rbac` (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3).

Every error here carries only identifying metadata (an id, a name, a
tenant id) -- never a raw credential (there is none in this module) and
never enough detail to distinguish "the row doesn't exist" from "the row
exists but belongs to a different tenant" in a way a caller could use to
probe another tenant's data (docs/SECURITY.md section 5).
"""

from __future__ import annotations

import uuid


class RoleNotFoundError(LookupError):
    """Raised when a role id does not resolve within the given tenant --
    deliberately the same error whether the role truly doesn't exist or
    exists under a different tenant, so this lookup itself never confirms
    or denies another tenant's data (docs/IMPLEMENTATION-ROADMAP.md Phase
    3.3 section 13)."""

    def __init__(self, tenant_id: uuid.UUID, role_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.role_id = role_id
        super().__init__(f"Role {role_id} not found in tenant {tenant_id}.")


class DuplicateRoleNameError(ValueError):
    def __init__(self, tenant_id: uuid.UUID, name: str) -> None:
        self.tenant_id = tenant_id
        self.name = name
        super().__init__(f"Role {name!r} already exists in tenant {tenant_id}.")


class PermissionNotFoundError(LookupError):
    """Raised when a `permission_id` does not resolve in the global
    permission catalog -- used by `grant_permission()` to disambiguate
    "no such permission" from a role-tenant mismatch (both surface as the
    same `IntegrityError` from Postgres)."""

    def __init__(self, permission_id: uuid.UUID) -> None:
        self.permission_id = permission_id
        super().__init__(f"Permission {permission_id} not found.")


class DuplicatePermissionError(ValueError):
    def __init__(self, resource: str, action: str) -> None:
        self.resource = resource
        self.action = action
        super().__init__(f"Permission {resource!r}:{action!r} already registered.")


class MembershipNotFoundError(LookupError):
    """Raised when a membership id does not resolve within the given
    tenant -- same non-distinguishing behavior as `RoleNotFoundError`."""

    def __init__(self, tenant_id: uuid.UUID, membership_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.membership_id = membership_id
        super().__init__(f"Membership {membership_id} not found in tenant {tenant_id}.")


class DuplicateRoleAssignmentError(ValueError):
    def __init__(self, membership_id: uuid.UUID, role_id: uuid.UUID) -> None:
        self.membership_id = membership_id
        self.role_id = role_id
        super().__init__(f"Membership {membership_id} already has role {role_id}.")


class DuplicatePermissionGrantError(ValueError):
    def __init__(self, role_id: uuid.UUID, permission_id: uuid.UUID) -> None:
        self.role_id = role_id
        self.permission_id = permission_id
        super().__init__(f"Role {role_id} already has permission {permission_id}.")
