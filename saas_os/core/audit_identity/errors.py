"""Refusals of the audit identity retention operations (phases P2 and P3c:
legal holds on platform and tenant audit references and the expiry command;
docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections 4.9
and 4.10).

Each refusal carries the fixed `code` that its `denied` platform audit row
records and that the platform-admin router maps to one HTTP status. No
message names a user.
"""

from __future__ import annotations

import uuid


class AuditIdentityRetentionError(ValueError):
    """Base class: a request about audit identity holds or expiry was
    refused. `code` is what the refusal's `denied` platform audit row
    records."""

    code = "refused"


class InvalidAuditIdentityRequestError(AuditIdentityRetentionError):
    """An argument is malformed: a wrong type, a matter reference that is
    not identifier-shaped, a day range whose start is after its end, or a
    confirmation that does not go with the request."""

    code = "invalid_request"


class AuditIdentityHoldNotFoundError(AuditIdentityRetentionError):
    """No hold has this id."""

    code = "hold_not_found"

    def __init__(self, hold_id: uuid.UUID) -> None:
        super().__init__(f"No audit identity hold {hold_id}.")
        self.hold_id = hold_id


class AuditIdentityHoldTenantNotFoundError(AuditIdentityRetentionError):
    """A tenant-scope hold names a tenant that does not exist. A hold may be
    placed on a tenant in any status, purged ones included (phase P3c)."""

    code = "tenant_not_found"

    def __init__(self, tenant_id: uuid.UUID) -> None:
        super().__init__(f"No tenant {tenant_id}.")
        self.tenant_id = tenant_id


class AuditIdentityHoldAlreadyActiveError(AuditIdentityRetentionError):
    """An active hold with the same matter reference and the same subject
    (or the same scope-wide subject) exists."""

    code = "hold_already_active"

    def __init__(self) -> None:
        super().__init__("An active audit identity hold with this reference and subject exists.")


class AuditIdentityHoldAlreadyReleasedError(AuditIdentityRetentionError):
    """The hold was released already; a released hold is never changed."""

    code = "hold_already_released"

    def __init__(self, hold_id: uuid.UUID) -> None:
        super().__init__(f"Audit identity hold {hold_id} is already released.")
        self.hold_id = hold_id


class AuditIdentitySessionEvidenceError(AuditIdentityRetentionError):
    """The platform-admin session evidence does not name a live session of
    the caller (a release needs it; owner decision O8)."""

    code = "session_evidence_invalid"

    def __init__(self) -> None:
        super().__init__("The session evidence does not name a live session of the caller.")


class AuditIdentityExpiryDisabledError(AuditIdentityRetentionError):
    """`apply` was asked for while the expiry gate is off (owner decision O9
    of 2026-11-03). Refused before any database connection."""

    code = "apply_disabled"

    def __init__(self) -> None:
        super().__init__(
            "Audit identity expiry --apply is disabled until an authenticated, "
            "register-eligible approval mechanism is implemented, reviewed and tested "
            "(owner decision O9)."
        )


class AuditIdentityIndexUnavailableError(AuditIdentityRetentionError):
    """A tenant scope's expiry plan needs the `core.audit_log` subject
    reference indexes of migration `d4f8b2e6a9c1` (phase P3b), and one of
    them is missing or not valid. Without them the record bound would scan
    the table, so the plan is refused (docs/architecture/
    AUDIT-IDENTITY-P3-PLAN.md section 3, M2, deployment order)."""

    code = "index_unavailable"

    def __init__(self, index: str) -> None:
        super().__init__(
            f"Index core.{index} is missing or not valid; run the migrations "
            "(saas-os-migrate upgrade) before a tenant expiry plan."
        )
        self.index = index


class AuditIdentityExpiryConfirmationMismatchError(AuditIdentityRetentionError):
    """With `apply`: a confirmed count or digest differs from what the run
    recomputed under its locks. Nothing was deleted or unlinked."""

    code = "confirmation_mismatch"

    def __init__(self) -> None:
        super().__init__(
            "The confirmation does not match the eligible set; nothing was changed. "
            "Run a new dry run."
        )


__all__ = [
    "AuditIdentityExpiryConfirmationMismatchError",
    "AuditIdentityExpiryDisabledError",
    "AuditIdentityHoldAlreadyActiveError",
    "AuditIdentityHoldAlreadyReleasedError",
    "AuditIdentityHoldNotFoundError",
    "AuditIdentityHoldTenantNotFoundError",
    "AuditIdentityIndexUnavailableError",
    "AuditIdentityRetentionError",
    "AuditIdentitySessionEvidenceError",
    "InvalidAuditIdentityRequestError",
]
