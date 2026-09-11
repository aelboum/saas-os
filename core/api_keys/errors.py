"""Typed errors for `core/api_keys` (docs/IMPLEMENTATION-ROADMAP.md Phase
4.1).

Every error here carries only identifying metadata (a key id, a tenant
id) -- never the raw key value, mirroring `core/identity/errors.py`'s own
discipline for session tokens (docs/SECURITY.md: "no credential or token
value ever logged").
"""

from __future__ import annotations

import uuid


class InvalidApiKeyNameError(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class ApiKeyNotFoundError(LookupError):
    """Raised when a key id does not resolve within the given tenant --
    deliberately the same error whether the key truly doesn't exist or
    belongs to a different tenant, so this lookup itself never confirms or
    denies another tenant's data (mirrors `core/rbac/errors.py::RoleNotFoundError`)."""

    def __init__(self, tenant_id: uuid.UUID, key_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.key_id = key_id
        super().__init__(f"API key {key_id} not found in tenant {tenant_id}.")


class InvalidApiKeyError(LookupError):
    """Raised by `validate_api_key()` when the presented raw key does not
    match any issued key. Never includes the raw key value."""

    def __init__(self) -> None:
        super().__init__("API key is invalid.")


class RevokedApiKeyError(ValueError):
    """Raised by `validate_api_key()` when the presented key matches a
    real, but revoked, key. Carries the key id only -- never the raw
    value -- for the caller's own audit/logging purposes; `validate_api_key()`
    itself already writes the audit-log entry this event requires
    (docs/IMPLEMENTATION-ROADMAP.md Phase 4.1 Acceptance Criteria: "revoked
    key access attempt is denied and audit-logged")."""

    def __init__(self, key_id: uuid.UUID) -> None:
        self.key_id = key_id
        super().__init__(f"API key {key_id} has been revoked.")


class TenantMembershipRequiredError(ValueError):
    """Raised when `create_api_key()` is called for a (tenant_id, user_id)
    pair that is not a real `TenantMembership` -- the same
    composite-foreign-key violation `core/rbac/service.py` already
    disambiguates for role assignments, applied here to key issuance."""

    def __init__(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.user_id = user_id
        super().__init__(f"User {user_id} is not a member of tenant {tenant_id}.")


class ServiceAccountRequiredError(ValueError):
    """Raised when `create_service_account_api_key()` is called for a
    (tenant_id, service_account_id) pair that is not a real
    `core.identity.ServiceAccount` belonging to that tenant -- the
    service-account-owned-key analogue of `TenantMembershipRequiredError`
    (architecture research Phase E)."""

    def __init__(self, tenant_id: uuid.UUID, service_account_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.service_account_id = service_account_id
        super().__init__(
            f"Service account {service_account_id} does not exist in tenant {tenant_id}."
        )


class ExpiredApiKeyError(ValueError):
    """Raised by `validate_api_key()` when the presented key matches a
    real, unrevoked, but expired key (architecture research Phase E:
    "expires_at <= now -> DENY"). Carries the key id only -- never the
    raw value -- mirroring `RevokedApiKeyError`'s own discipline;
    `validate_api_key()` audit-logs this denial for the identical reason
    it already audit-logs a revoked-key attempt."""

    def __init__(self, key_id: uuid.UUID) -> None:
        self.key_id = key_id
        super().__init__(f"API key {key_id} has expired.")


class InactiveServiceAccountError(ValueError):
    """Raised by `validate_api_key()` when a service-account-owned key's
    owning `ServiceAccount` no longer exists or is `DISABLED`
    (architecture research Phase E: "Disabled service accounts must
    cause their API keys to fail authentication"). Fails closed
    identically whether the account is merely disabled or has vanished
    entirely -- the caller cannot distinguish the two, mirroring
    `RoleNotFoundError`'s own non-distinguishing discipline. Never
    raised for a user-owned key."""

    def __init__(self, key_id: uuid.UUID, service_account_id: uuid.UUID) -> None:
        self.key_id = key_id
        self.service_account_id = service_account_id
        super().__init__(
            f"API key {key_id}'s service account {service_account_id} is missing or disabled."
        )


class ApiKeyNotAuthorizedError(PermissionError):
    """Raised when the requesting actor lacks the dedicated "manage API
    keys in this tenant" capability (architecture research Phase E:
    "Do not allow arbitrary users to create machine credentials" /
    "Revocation must also be explicitly authorized"). Covers both
    `create_service_account_api_key()` and `revoke_service_account_api_key()`
    -- a caller must not be able to distinguish "you may not manage keys
    here" from any other reason, mirroring
    `core/rbac/errors.py::DelegationNotAuthorizedError`'s own
    non-distinguishing discipline. Never raised for the original,
    ungated user-owned-key functions (`create_api_key()`/`revoke_api_key()`)
    -- those remain exactly as Phase 4.1 left them."""

    def __init__(self, actor_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        self.actor_id = actor_id
        self.tenant_id = tenant_id
        super().__init__(f"{actor_id} is not authorized to manage API keys in tenant {tenant_id}.")
