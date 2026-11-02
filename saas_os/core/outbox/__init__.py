"""Transactional outbox (Foundation Reliability & Events, RE-1).

`append_event(session, ...)` records an event in the caller's own
transaction, so it commits or rolls back with the mutation that caused it
(`saas_os/core/outbox/service.py`). Rows live in `core.outbox_events`
(tenant-owned, RLS-protected; `saas_os/core/outbox/models.py`) as `pending` until
the durable dispatcher's state machine (`saas_os/core/outbox/dispatch.py`, RE-2)
claims them, records each attempt, retries with backoff and dead-letters on
exhaustion -- in PostgreSQL. Handing claimed events to the job queue is the
worker layer's job (`saas_os/api/outbox_dispatcher.py`); this package never touches
Redis.
"""

from saas_os.core.outbox.config import (
    OutboxConfigurationError,
    OutboxDispatchConfig,
    get_outbox_dispatch_config,
)
from saas_os.core.outbox.consumption import (
    claim_event_consumption,
    event_consumption_recorded,
    record_event_consumption,
)
from saas_os.core.outbox.dispatch import (
    ClaimedEvent,
    EventExecution,
    begin_event_execution,
    claim_due_events,
    complete_event,
    fail_event,
    release_claim,
    retry_delay,
    retry_hint_delay,
    rewrite_stored_errors,
)
from saas_os.core.outbox.errors import (
    InvalidOutboxEventError,
    PermanentEventError,
    RetryAfterEventError,
)
from saas_os.core.outbox.models import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxConsumption,
    OutboxEvent,
)
from saas_os.core.outbox.replay import (
    MAX_REPLAY_EVENTS,
    OutboxReplayResult,
    replay_dead_lettered_events,
)
from saas_os.core.outbox.service import (
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
    "rewrite_stored_errors",
    "OUTBOX_STATUS_DEAD_LETTERED",
    "OUTBOX_STATUS_PENDING",
    "OUTBOX_STATUS_PUBLISHED",
    "InvalidOutboxEventError",
    "PermanentEventError",
    "MAX_REPLAY_EVENTS",
    "OutboxReplayResult",
    "replay_dead_lettered_events",
    "RetryAfterEventError",
    "retry_hint_delay",
    "OutboxEvent",
    "append_event",
    "delete_aggregate_events",
    "purge_tenant_outbox_events",
]
