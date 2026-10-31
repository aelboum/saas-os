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


class RetryAfterEventError(Exception):
    """Raised by an outbox event's consumer when the destination asked to be
    retried later: a provider's `Retry-After`, or a quota that resets at a
    known boundary (outbox decision brief Q1, option 1A). The dispatcher
    schedules the next attempt no earlier than `retry_after_seconds` from
    now, bounded by `OUTBOX_RETRY_HINT_MAX_SECONDS` (default 86400), and
    never earlier than the ordinary backoff. The attempt is still counted,
    so an event that keeps being deferred is still dead-lettered once its
    attempts run out.

    `retry_after_seconds` may be `math.inf` ("as long as the bound
    allows"). A negative, `NaN` or non-numeric value is read as no hint.
    The message must carry identifiers and a category only, never payload
    content -- it is stored as the event's `last_error`."""

    retry_after_seconds: float

    def __init__(self, retry_after_seconds: float, reason: str) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(reason)
