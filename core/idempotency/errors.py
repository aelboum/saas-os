"""Typed errors for `core/idempotency` (P1.11). Every error here carries
only identifying metadata -- never the fingerprinted request payload,
never a stored result, never a secret.
"""

from __future__ import annotations

import uuid


class IdempotencyKeyInvalidError(ValueError):
    """Raised when a caller-supplied idempotency key fails basic input
    validation (missing, empty, oversized, or containing characters
    outside the safe set) -- before any database access. Never echoes
    the offending key value back (an oversized or malformed key could
    itself be attacker-controlled junk not worth repeating)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class IdempotencyKeyReusedError(RuntimeError):
    """Raised when `(tenant_id, operation, idempotency_key)` already has
    a recorded fingerprint that does not match the current request --
    the same key was reused for a genuinely different request body.
    Carries only identifying metadata (ids/operation name), never either
    request's actual content or fingerprint value."""

    def __init__(self, tenant_id: uuid.UUID, operation: str, idempotency_key: str) -> None:
        self.tenant_id = tenant_id
        self.operation = operation
        self.idempotency_key = idempotency_key
        super().__init__(
            f"Idempotency key {idempotency_key!r} for operation {operation!r} in tenant "
            f"{tenant_id} was already used with a different request."
        )


class IdempotencyInProgressError(RuntimeError):
    """Raised when a concurrent attempt for the same `(tenant_id,
    operation, idempotency_key)` is still in flight (its outcome not yet
    resolved) -- a deterministic, honest signal rather than silently
    blocking or silently re-executing a side-effecting operation whose
    prior attempt may or may not have already completed."""

    def __init__(self, tenant_id: uuid.UUID, operation: str, idempotency_key: str) -> None:
        self.tenant_id = tenant_id
        self.operation = operation
        self.idempotency_key = idempotency_key
        super().__init__(
            f"Idempotency key {idempotency_key!r} for operation {operation!r} in tenant "
            f"{tenant_id} is still being processed by a concurrent request."
        )


class IdempotencyConfigurationError(ValueError):
    """Raised when a `core/idempotency` environment variable holds an
    invalid value. Never carries a secret -- retention/TTL are plain
    non-secret tunables."""
