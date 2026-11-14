"""Refusals of the audit identity retention operations (phase P2: legal holds
on platform audit references and the expiry command;
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
    "AuditIdentityRetentionError",
    "AuditIdentitySessionEvidenceError",
    "InvalidAuditIdentityRequestError",
]
