"""Typed errors for `core/outbox` (Foundation Reliability & Events, RE-1).
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
