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


class InvalidPrincipalError(ValueError):
    """Raised when a delegation principal (architecture research: Phase C
    -- Delegation) does not resolve to a real identity -- e.g. a
    `PrincipalType.USER` delegator/delegate whose `principal_id` is not a
    real `core.identity` user. Never raised for `PrincipalType.SYSTEM`
    (`core/rbac/principal.py`): no code path in this phase constructs a
    system-principal delegation for there to be an invalid one of."""

    def __init__(self, principal_type: str, principal_id: uuid.UUID) -> None:
        self.principal_type = principal_type
        self.principal_id = principal_id
        super().__init__(f"{principal_type} principal {principal_id} does not exist.")


class InvalidDelegationTimeRangeError(ValueError):
    """Raised when a delegation's `expires_at` does not fall strictly
    after its `starts_at` -- the same invariant
    `ck_delegation_grants_valid_time_range` enforces at the database
    level; this is the fail-closed, typed-error check before any write is
    attempted."""

    def __init__(self, starts_at: object, expires_at: object) -> None:
        self.starts_at = starts_at
        self.expires_at = expires_at
        super().__init__(f"expires_at ({expires_at}) must be after starts_at ({starts_at}).")


class DelegationNotAuthorizedError(PermissionError):
    """Raised when the requesting principal lacks sufficient authority to
    create or revoke a `DelegationGrant` (architecture research: Phase C
    -- "A delegator may delegate only permissions/roles that the
    delegator currently possesses within the delegation's target scope";
    "Delegation creation itself must be authorized"). Deliberately a
    single error covering both the delegation-management permission check
    and the anti-amplification check -- a caller must not be able to
    distinguish "you may not manage delegations here" from "you may
    manage delegations, but not this specific permission" (the same
    non-distinguishing discipline `RoleNotFoundError` already applies to
    cross-tenant probing, docs/SECURITY.md section 5)."""

    def __init__(self, actor_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        self.actor_id = actor_id
        self.tenant_id = tenant_id
        super().__init__(
            f"{actor_id} is not authorized to manage this delegation in tenant {tenant_id}."
        )


class DelegationNotFoundError(LookupError):
    """Raised when a `delegation_grant_id` does not resolve within the
    given tenant -- same non-distinguishing behavior as
    `RoleNotFoundError`."""

    def __init__(self, tenant_id: uuid.UUID, delegation_grant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.delegation_grant_id = delegation_grant_id
        super().__init__(f"Delegation grant {delegation_grant_id} not found in tenant {tenant_id}.")


class DenyNotAuthorizedError(PermissionError):
    """Raised when the requesting actor lacks the dedicated "manage deny
    grants in this tenant" capability (architecture research: Phase D --
    "Explicit Deny"). Unlike `DelegationNotAuthorizedError`, this never
    covers an anti-amplification check -- there is none for deny creation
    (`core/rbac/models.py::DenyGrant`'s own docstring: a deny can only
    remove authority, never grant more than its creator already
    effectively controls)."""

    def __init__(self, actor_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        self.actor_id = actor_id
        self.tenant_id = tenant_id
        super().__init__(
            f"{actor_id} is not authorized to manage deny grants in tenant {tenant_id}."
        )


class DenyNotFoundError(LookupError):
    """Raised when a `deny_grant_id` does not resolve within the given
    tenant -- same non-distinguishing behavior as `RoleNotFoundError`."""

    def __init__(self, tenant_id: uuid.UUID, deny_grant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.deny_grant_id = deny_grant_id
        super().__init__(f"Deny grant {deny_grant_id} not found in tenant {tenant_id}.")


class ServiceAccountRoleNotAuthorizedError(PermissionError):
    """Raised when the requesting actor lacks sufficient authority to
    assign a role to a service account (architecture research Phase E).
    Deliberately a single error covering both the "manage service account
    roles" management-capability check and the anti-amplification check
    -- a caller must not be able to distinguish the two, mirroring
    `DelegationNotAuthorizedError`'s own non-distinguishing discipline."""

    def __init__(self, actor_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        self.actor_id = actor_id
        self.tenant_id = tenant_id
        super().__init__(
            f"{actor_id} is not authorized to assign service account roles in tenant {tenant_id}."
        )


class DuplicateServiceAccountRoleAssignmentError(ValueError):
    def __init__(self, service_account_id: uuid.UUID, role_id: uuid.UUID) -> None:
        self.service_account_id = service_account_id
        self.role_id = role_id
        super().__init__(f"Service account {service_account_id} already has role {role_id}.")
