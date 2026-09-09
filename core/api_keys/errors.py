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
