"""Correlation context (docs/OBSERVABILITY.md section 2): `tenant_id`,
`user_id`, `request_id`, `agent_id`, `action_id`.

This is the *application/request* correlation scheme -- a distinct concept
from an OpenTelemetry trace ID or span ID (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.2 task 7: "do not pretend these are interchangeable"). A trace ID
identifies one distributed trace as OpenTelemetry constructs it; a
correlation ID here identifies one inbound request/job execution as the
*application* defines it. `infra.observability.logging` attaches both,
separately, to every log record -- see that module for how they combine.

Backed by `contextvars.ContextVar` (not a thread-local): correct under
asyncio, where multiple concurrent requests interleave on the same thread.
`bind_correlation_context()` is the only sanctioned way to set values --
always scoped to a `with` block, so context never leaks past where it was
bound (proven in tests/infra/observability/test_context.py).
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class CorrelationContext:
    tenant_id: str | None = None
    user_id: str | None = None
    request_id: str | None = None
    agent_id: str | None = None
    action_id: str | None = None


_EMPTY = CorrelationContext()

_current: contextvars.ContextVar[CorrelationContext] = contextvars.ContextVar(
    "saas_os_correlation_context", default=_EMPTY
)


def get_correlation_context() -> CorrelationContext:
    """The currently bound context, or an all-`None` context if nothing
    has been bound (never raises -- absence is a valid, common state, e.g.
    genuinely tenant-agnostic platform-internal activity per
    docs/OBSERVABILITY.md section 2).
    """
    return _current.get()


@contextmanager
def bind_correlation_context(
    *,
    tenant_id: str | None = None,
    user_id: str | None = None,
    request_id: str | None = None,
    agent_id: str | None = None,
    action_id: str | None = None,
) -> Iterator[CorrelationContext]:
    """Bind correlation fields for the duration of a `with` block. Fields
    left as `None` here are inherited from any already-bound context
    (supports nesting -- e.g. an outer request-level bind, an inner
    per-tool-call bind that only adds `agent_id`/`action_id`), *not*
    overwritten to `None`.
    """
    parent = get_correlation_context()
    updates = {
        key: value
        for key, value in {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "action_id": action_id,
        }.items()
        if value is not None
    }
    new_context = replace(parent, **updates)
    token = _current.set(new_context)
    try:
        yield new_context
    finally:
        _current.reset(token)
