"""Transactional outbox (Foundation Reliability & Events, RE-1).

`append_event(session, ...)` records an event in the caller's own
transaction, so it commits or rolls back with the mutation that caused it
(`core/outbox/service.py`). Rows live in `core.outbox_events`
(tenant-owned, RLS-protected; `core/outbox/models.py`) as `pending` until
the durable dispatcher's state machine (`core/outbox/dispatch.py`, RE-2)
claims them, records each attempt, retries with backoff and dead-letters on
exhaustion -- in PostgreSQL. Handing claimed events to the job queue is the
worker layer's job (`api/outbox_dispatcher.py`); this package never touches
Redis.
"""

from core.outbox.config import (
    OutboxConfigurationError,
    OutboxDispatchConfig,
    get_outbox_dispatch_config,
)
from core.outbox.consumption import (
    claim_event_consumption,
    event_consumption_recorded,
    record_event_consumption,
)
from core.outbox.dispatch import (
    ClaimedEvent,
    EventExecution,
    begin_event_execution,
    claim_due_events,
    complete_event,
    fail_event,
    release_claim,
    retry_delay,
)
from core.outbox.errors import InvalidOutboxEventError, PermanentEventError
from core.outbox.models import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxConsumption,
    OutboxEvent,
)
from core.outbox.service import (
    append_event,
    delete_aggregate_events,
    purge_tenant_outbox_events,
)

__all__ = [
    "OutboxConsumption",
    "claim_event_consumption",
    "event_consumption_recorded",
    "record_event_consumption",
    "ClaimedEvent",
    "EventExecution",
    "OutboxConfigurationError",
    "OutboxDispatchConfig",
    "begin_event_execution",
    "claim_due_events",
    "complete_event",
    "fail_event",
    "get_outbox_dispatch_config",
    "release_claim",
    "retry_delay",
    "OUTBOX_STATUS_DEAD_LETTERED",
    "OUTBOX_STATUS_PENDING",
    "OUTBOX_STATUS_PUBLISHED",
    "InvalidOutboxEventError",
    "PermanentEventError",
    "OutboxEvent",
    "append_event",
    "delete_aggregate_events",
    "purge_tenant_outbox_events",
]
