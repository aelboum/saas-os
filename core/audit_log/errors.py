"""Typed errors for `core/audit_log` (docs/IMPLEMENTATION-ROADMAP.md Phase
3.4).

Every error here carries only identifying metadata (a field name, a bound,
a rejected key) -- never the rejected value itself, since a value that
failed metadata validation is exactly the kind of thing (a would-be
credential, an oversized payload) that must never end up echoed back into
a log line or exception message (docs/SECURITY.md).
"""

from __future__ import annotations

import uuid


class InvalidAuditRecordError(ValueError):
    """Base class for every reason `record()` refuses to write an entry.
    The audit API fails closed on invalid input (docs/IMPLEMENTATION-
    ROADMAP.md Phase 3.4 section 8: "The audit API should fail closed when
    supplied metadata violates its contract") -- never silently drops a
    field or truncates a value to make an invalid call succeed.
    """


class InvalidActorError(InvalidAuditRecordError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class InvalidOutcomeError(InvalidAuditRecordError):
    def __init__(self, outcome: str) -> None:
        self.outcome = outcome
        super().__init__(f"Invalid audit outcome: {outcome!r}.")


class InvalidActionOrResourceError(InvalidAuditRecordError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class MetadataNotJSONSerializableError(InvalidAuditRecordError):
    def __init__(self) -> None:
        super().__init__(
            "Audit metadata must be JSON-serializable (str/int/float/bool/None/list/dict)."
        )


class MetadataTooLargeError(InvalidAuditRecordError):
    def __init__(self, size_bytes: int, limit_bytes: int) -> None:
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes
        super().__init__(
            f"Audit metadata is {size_bytes} bytes serialized, "
            f"exceeding the {limit_bytes}-byte limit."
        )


class ForbiddenMetadataKeyError(InvalidAuditRecordError):
    """Raised when a metadata key matches the explicit sensitive-key
    denylist (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 8) -- never
    includes the rejected *value*, only the offending *key name*, which is
    not itself sensitive (e.g. "password"), only what it might have pointed to.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Audit metadata key {key!r} is not permitted (looks like a credential).")


class AuditLogEntryNotFoundError(LookupError):
    def __init__(self, tenant_id: uuid.UUID, entry_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.entry_id = entry_id
        super().__init__(f"Audit log entry {entry_id} not found in tenant {tenant_id}.")
