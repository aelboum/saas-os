"""Typed errors for `saas_os/core/outbox` (Foundation Reliability & Events, RE-1).
Errors carry only the offending field's name and a reason -- never the
event payload, which may hold tenant data."""

from __future__ import annotations


class InvalidOutboxEventError(ValueError):
    """`append_event()` was given a malformed event. Raised before anything
    is written, so the caller's transaction is untouched."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid outbox event {field}: {reason}.")


class PermanentEventError(Exception):
    """Raised by an outbox event's consumer when retrying cannot succeed: a
    malformed event, a destination that permanently refuses it, or a
    security-policy rejection (RE-4). The dispatcher dead-letters the event
    at once instead of spending its remaining attempts. Any other exception
    is treated as transient and retried with backoff. The message must
    carry identifiers and a category only, never payload content -- it is
    stored as the event's `last_error`."""
