"""Durable outbox dispatch -- the worker-layer orchestration (Foundation
Reliability & Events, RE-2).

PostgreSQL (`core.outbox_events`, state machine in `core/outbox/dispatch.py`)
is the source of truth; Redis/ARQ only carries work. Two jobs:

`_dispatch_outbox_cycle` -- a *system* job the worker runs every
`OUTBOX_POLL_SECONDS` (`infra.jobs.queue.system_cron`). Each cycle claims a
bounded batch of due events (`claim_due_events()`: SKIP LOCKED, per-tenant
cap, attempt counted, lease set, committed) and hands each claim to the
queue as one `_run_outbox_event` job. A failed hand-off gives the claim
back (`release_claim()`, attempt refunded). Nothing is marked published
here: a successful hand-off is not an acknowledgement.

`_run_outbox_event` -- a *tenant* job (its `TenantJobPayload.tenant_id` is
the event's own tenant; `data` carries only the event id and claim token).
It confirms the claim under that tenant's RLS scope and renews the lease
(`begin_event_execution()`), runs the event type's existing consumer
in-process with the event's stored payload -- the same handler, the same
`TenantJobContext`/`TenantJobPayload` contract, the same lifecycle fences
and security checks the handler applies as a registered job -- and then
records the outcome: `complete_event()` (published) or `fail_event()`
(backoff, or dead-lettered once attempts run out; at once when the consumer
raises `PermanentEventError`, RE-4). A consumer failure is
recorded in PostgreSQL and the job itself returns normally, so ARQ's own
retries and the Redis dead-letter list are never the record of an outbox
event; if recording the outcome fails, the job raises and the lease expiry
recovers the event.

Crash boundaries (the event is never lost; it may run more than once):
- claim committed, crash before hand-off -> lease expires, reclaimed;
- handed off, crash before the job runs or while it runs (including ARQ's
  job timeout) -> lease expires, reclaimed; a stale job finds its claim
  superseded and does nothing;
- consumer succeeded, crash before `complete_event()` -> lease expires,
  the event runs again (at-least-once; consumer dedupe is RE-5).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from arq.worker import Function
from infra.jobs.queue import get_redis_pool

from core.outbox import (
    OutboxDispatchConfig,
    PermanentEventError,
    begin_event_execution,
    claim_due_events,
    complete_event,
    fail_event,
    get_outbox_dispatch_config,
    release_claim,
)
from infra.jobs import (
    SystemJobContext,
    TenantJobContext,
    TenantJobPayload,
    enqueue_job,
    register_system_job,
    register_tenant_job,
)

logger = logging.getLogger(__name__)

OutboxHandler = Callable[[TenantJobContext, TenantJobPayload], Awaitable[None]]


def outbox_event_handlers() -> Mapping[str, OutboxHandler]:
    """Each outbox event type's consumer, as published by the Core module
    that produces it. Imported at call time: every module imports
    `core.tenancy`, and the worker assembles its registry lazily the same
    way (`api/worker.py`)."""
    from core.notifications.service import OUTBOX_EVENT_HANDLERS as notifications
    from core.usage.service import OUTBOX_EVENT_HANDLERS as usage
    from core.webhooks.service import OUTBOX_EVENT_HANDLERS as webhooks

    return {**webhooks, **usage, **notifications}


async def _run_outbox_event(context: TenantJobContext, payload: TenantJobPayload) -> None:
    event_id = uuid.UUID(str(payload.data["outbox_event_id"]))
    claim_token = uuid.UUID(str(payload.data["claim_token"]))
    log_fields = {"outbox_event_id": str(event_id)}

    execution = begin_event_execution(context.tenant_id, event_id, claim_token)
    if execution is None:
        logger.info("outbox_event_not_current", extra=log_fields)
        return
    log_fields["outbox_event_type"] = execution.event_type

    handler = outbox_event_handlers().get(execution.event_type)
    if handler is None:
        fail_event(
            context.tenant_id,
            event_id,
            claim_token,
            f"UnknownEventType: no consumer for {execution.event_type!r}",
            terminal=True,
        )
        logger.error("outbox_event_unknown_type", extra=log_fields)
        return

    try:
        await handler(
            TenantJobContext(
                tenant_id=execution.tenant_id,
                correlation_id=execution.correlation_id,
                # RE-5: the event's stable identity, the same on every attempt,
                # so the consumer can suppress a repeated execution.
                event_id=execution.id,
            ),
            TenantJobPayload(
                tenant_id=str(execution.tenant_id),
                data=dict(execution.payload),
                correlation_id=execution.correlation_id,
            ),
        )
    except PermanentEventError as exc:
        # RE-4: the consumer says retrying cannot succeed (malformed event,
        # permanent destination refusal, security-policy rejection).
        status = fail_event(context.tenant_id, event_id, claim_token, exc, terminal=True)
        logger.warning(
            "outbox_event_rejected",
            extra={**log_fields, "outbox_status": status, "error_type": type(exc).__name__},
        )
        return
    except Exception as exc:  # noqa: BLE001 -- every consumer failure is recorded durably
        status = fail_event(context.tenant_id, event_id, claim_token, exc)
        logger.warning(
            "outbox_event_failed",
            extra={**log_fields, "outbox_status": status, "error_type": type(exc).__name__},
        )
        return

    if complete_event(context.tenant_id, event_id, claim_token):
        logger.info("outbox_event_published", extra=log_fields)
    else:
        logger.info("outbox_event_completion_superseded", extra=log_fields)


@dataclass(frozen=True)
class DispatchReport:
    claimed: int
    enqueued: int
    released: int


async def dispatch_outbox_once(
    *,
    pool: Any = None,
    config: OutboxDispatchConfig | None = None,
    now: datetime | None = None,
    queue_name: str | None = None,
) -> DispatchReport:
    """One dispatch cycle: claim due events, hand each to the queue, give
    back the claim of any hand-off that fails. The queue connection is
    opened before anything is claimed, so an unreachable queue claims
    nothing. `queue_name` is for test isolation; production uses the
    default queue."""
    cfg = config or get_outbox_dispatch_config()
    owns_pool = pool is None
    active_pool = pool or await get_redis_pool()
    enqueued = released = 0
    try:
        claims = claim_due_events(config=cfg, now=now)
        for claim in claims:
            try:
                await enqueue_job(
                    _run_outbox_event.__name__,
                    TenantJobPayload(
                        tenant_id=str(claim.tenant_id),
                        data={
                            "outbox_event_id": str(claim.id),
                            "claim_token": str(claim.claim_token),
                        },
                        correlation_id=claim.correlation_id,
                    ),
                    pool=active_pool,
                    queue_name=queue_name,
                )
                enqueued += 1
            except Exception as exc:  # noqa: BLE001 -- the claim is given back, never lost
                release_claim(
                    claim.tenant_id, claim.id, claim.claim_token, exc, config=cfg, now=now
                )
                released += 1
                logger.warning(
                    "outbox_event_enqueue_failed",
                    extra={"outbox_event_id": str(claim.id), "error_type": type(exc).__name__},
                )
    finally:
        if owns_pool:
            await active_pool.aclose()
    return DispatchReport(claimed=len(claims), enqueued=enqueued, released=released)


async def _dispatch_outbox_cycle(context: SystemJobContext) -> None:
    """The scheduled dispatch cycle. A failing cycle (database or queue
    unreachable) is logged and ends; the next tick tries again -- the
    outbox rows are the state, so nothing is lost or retried here."""
    try:
        report = await dispatch_outbox_once()
    except Exception as exc:  # noqa: BLE001 -- the next cycle retries
        logger.warning("outbox_dispatch_cycle_failed", extra={"error_type": type(exc).__name__})
        return
    if report.claimed:
        logger.info(
            "outbox_dispatch_cycle",
            extra={
                "outbox_claimed": report.claimed,
                "outbox_enqueued": report.enqueued,
                "outbox_released": report.released,
            },
        )


OUTBOX_JOB_FUNCTIONS: list[Function] = [register_tenant_job(_run_outbox_event)]
OUTBOX_DISPATCH_CYCLE: Function = register_system_job(_dispatch_outbox_cycle)
