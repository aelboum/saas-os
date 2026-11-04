"""Durable outbox dispatch -- the worker-layer orchestration (Foundation
Reliability & Events, RE-2).

PostgreSQL (`core.outbox_events`, state machine in `saas_os/core/outbox/dispatch.py`)
is the source of truth; Redis/ARQ only carries work. Two jobs:

`_dispatch_outbox_cycle` -- a *system* job the worker runs every
`OUTBOX_POLL_SECONDS` (`saas_os.infra.jobs.queue.system_cron`). Each cycle claims a
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
raises `PermanentEventError`, RE-4; later than the backoff when it raises
`RetryAfterEventError`, within `OUTBOX_RETRY_HINT_MAX_SECONDS`). A consumer failure is
recorded in PostgreSQL and the job itself returns normally, so ARQ's own
retries and the Redis dead-letter list are never the record of an outbox
event. If recording a failure's outcome fails (the database is briefly
unavailable), the write is tried again in-process a few times; if it still
fails, the job logs `outbox_event_outcome_unrecorded` and returns normally.
It never raises there: ARQ would retry the job with the same, still valid
claim token and run the consumer again at once -- while a timed-out
consumer's thread may still be sending (review of #189, ledger row F5).
The event then stays claimed until its lease expires and is reclaimed like
a crashed run (below); recording a success that fails still raises (the
consumers de-duplicate a repeated success, RE-5).

Crash boundaries (the event is never lost; it may run more than once):
- claim committed, crash before hand-off -> lease expires, reclaimed;
- handed off, crash before the job runs or while it runs -> lease expires,
  reclaimed; a stale job finds its claim superseded and does nothing;
- consumer runs out of time (`OUTBOX_CONSUMER_TIMEOUT_SECONDS`, ledger row
  F5, owner decision of 2026-11-01) -> dead-lettered at once with the claim
  it holds, never reclaimed: its external effect may already have happened,
  so it runs again only when an operator replays it;
- consumer reports an ambiguous outcome (`AmbiguousOutcomeError`: its
  request may have been sent, the outcome is unknown) -> dead-lettered at
  once, unless it declared a safe retry policy (an idempotency window, or
  at-least-once delivery on a stable id); never published;
- consumer lets a bare timeout escape unclassified (`TimeoutError`, which
  includes `asyncio.TimeoutError` and `socket.timeout`, or an `httpx`
  timeout; owner decision D of 2026-11-01) -> treated as ambiguous with no
  retry policy: dead-lettered at once (`OutcomeUnknown: <type>
  (unclassified)`), because a timeout after the consumer started never
  proves that nothing was sent. A consumer with evidence that nothing was
  sent raises `ConfirmedNotSentError` and keeps the ordinary retry;
- consumer succeeded, crash before `complete_event()` -> lease expires,
  the event runs again (at-least-once; consumer dedupe is RE-5);
- consumer failed (any classification, a timeout included), and recording
  that failure kept failing -> nothing durable says the attempt ended, so
  the lease expiry reclaims the event (`LeaseExpired`) and runs it again,
  exactly as after a worker crash mid-send. Telling such a run apart
  without a durable record needs the crash-recovery design (#195); until
  then `outbox_event_outcome_unrecorded` is the signal to check the
  destination. The lease is at least `MIN_LEASE_SECONDS` (360 s), so that
  run never starts while the first consumer is inside its deadline.

Started marker (crash recovery D4, `docs/architecture/OUTBOX-STARTED-MARKER.md`):
the consumer's `TenantJobContext` carries `start_external_effect`, bound to
this event and claim (`mark_external_effect_started()`), which a consumer's
`context.external_effect()` calls before its external request. Once that
marker is committed, a crash is no longer retried: the reclaim dead-letters
the event `CrashAfterStart:` and a failure is dead-lettered by
`fail_event()` (its exception rule). With `OUTBOX_EXTERNAL_EFFECT_MARKERS`
off (the default) no marker is written and every boundary above is
unchanged. `ExternalEffectNotStartedError` (the claim was no longer current
when the marker was due) records no outcome: nothing was sent, and the
owner of the claim, or the reclaim, decides the event.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from typing import Any

import httpx
from arq.worker import Function

from saas_os.core.outbox import (
    AmbiguousOutcomeError,
    ConfirmedNotSentError,
    ExternalEffectAlreadyStartedError,
    ExternalEffectNotStartedError,
    OutboxDispatchConfig,
    PermanentEventError,
    RetryAfterEventError,
    begin_event_execution,
    claim_due_events,
    complete_event,
    fail_event,
    get_outbox_dispatch_config,
    mark_external_effect_started,
    release_claim,
)
from saas_os.core.outbox.dispatch import record_ambiguous_outcome
from saas_os.infra.jobs import (
    SystemJobContext,
    TenantJobContext,
    TenantJobPayload,
    enqueue_job,
    register_system_job,
    register_tenant_job,
)
from saas_os.infra.jobs.queue import HANDLER_TIMEOUT_SECONDS, get_redis_pool

logger = logging.getLogger(__name__)

# Ledger row F5 (owner decision of 2026-11-01: no automatic retry after a
# timeout whose external effect is uncertain). A consumer gets this long,
# inside the job wrapper's own deadline (`HANDLER_TIMEOUT_SECONDS`), so the
# timeout is caught here with time left to record it on the event.
OUTBOX_CONSUMER_TIMEOUT_SECONDS = HANDLER_TIMEOUT_SECONDS - 30.0
# The durable `last_error` of a timed-out event: what happened and what to do,
# never the payload.
_CONSUMER_TIMED_OUT_REASON = (
    "ConsumerTimedOut: outcome unknown; not retried automatically. "
    "Check the destination, then replay (saas-os-operator replay-outbox-events)."
)

# Owner decision D of 2026-11-01: the phase recorded for a bare timeout that
# escaped a consumer without a classification.
_UNCLASSIFIED_PHASE = "unclassified"

OutboxHandler = Callable[[TenantJobContext, TenantJobPayload], Awaitable[None]]


class _ExternalEffectStarter:
    """`TenantJobContext.start_external_effect` for one execution (D4):
    writes this claim's started marker and remembers a refusal, so the
    execution records no outcome even if the consumer caught
    `ExternalEffectNotStartedError` and returned or raised something else
    -- nothing was sent, and publishing or failing the event would decide
    an attempt this execution does not own.

    A second `external_effect()` entry after this execution's marker was
    committed raises `ExternalEffectAlreadyStartedError` before anything is
    written or sent, and does not count as a refusal: the first request may
    have gone out, so the execution's outcome is still recorded (a failure
    after the marker is dead-lettered `OutcomeUnknown:`). With markers off
    nothing is written, nothing is remembered, and repeated entries behave
    as before."""

    def __init__(self, tenant_id: uuid.UUID, event_id: uuid.UUID, claim_token: uuid.UUID) -> None:
        self._tenant_id = tenant_id
        self._event_id = event_id
        self._claim_token = claim_token
        self.refused = False
        self.started = False

    def __call__(self) -> bool:
        if self.started:
            raise ExternalEffectAlreadyStartedError(self._event_id)
        try:
            written = mark_external_effect_started(
                self._tenant_id, self._event_id, self._claim_token
            )
        except ExternalEffectNotStartedError:
            self.refused = True
            raise
        self.started = written
        return written


def outbox_event_handlers() -> Mapping[str, OutboxHandler]:
    """Each outbox event type's consumer, as published by the Core module
    that produces it. Imported at call time: every module imports
    `saas_os.core.tenancy`, and the worker assembles its registry lazily the same
    way (`saas_os/api/worker.py`)."""
    from saas_os.core.billing.projections import OUTBOX_EVENT_HANDLERS as billing
    from saas_os.core.notifications.service import OUTBOX_EVENT_HANDLERS as notifications
    from saas_os.core.usage.service import OUTBOX_EVENT_HANDLERS as usage
    from saas_os.core.webhooks.service import OUTBOX_EVENT_HANDLERS as webhooks

    return {**webhooks, **usage, **notifications, **billing}


def _is_unclassified_timeout(exc: BaseException) -> bool:
    """Whether `exc` is a timeout the consumer did not classify (owner
    decision D of 2026-11-01): a `TimeoutError` (`asyncio.TimeoutError`,
    `socket.timeout` and `concurrent.futures.TimeoutError` are the same
    class), an `httpx.TimeoutException` (not a `TimeoutError` subclass), or an
    exception group holding one -- unless it is a `ConfirmedNotSentError`.
    An explicit `AmbiguousOutcomeError`, `PermanentEventError` or
    `RetryAfterEventError` is handled before this is asked."""
    if isinstance(exc, ConfirmedNotSentError):
        return False
    if isinstance(exc, TimeoutError | httpx.TimeoutException):
        return True
    if isinstance(exc, BaseExceptionGroup):
        group: BaseExceptionGroup[BaseException] = exc
        return any(_is_unclassified_timeout(inner) for inner in group.exceptions)
    return False


def _ambiguous_members(exc: BaseException) -> list[AmbiguousOutcomeError]:
    """Every `AmbiguousOutcomeError` in `exc`, nested exception groups
    included."""
    if isinstance(exc, AmbiguousOutcomeError):
        return [exc]
    if isinstance(exc, BaseExceptionGroup):
        group: BaseExceptionGroup[BaseException] = exc
        return [found for inner in group.exceptions for found in _ambiguous_members(inner)]
    return []


def _ambiguous_outcome(exc: Exception) -> AmbiguousOutcomeError | None:
    """The ambiguous outcome `exc` reports, or None.

    - `exc` itself an `AmbiguousOutcomeError`: as raised.
    - A bare timeout, alone or anywhere in an exception group (owner
      decision D of 2026-11-01): ambiguous with no retry policy, phase
      `unclassified`, its type name as the reason.
    - An exception group holding `AmbiguousOutcomeError`s (review of #197):
      ambiguous; the most conservative policy wins -- `at_least_once` only
      if every member declares it, `retry_within` (the shortest) only if
      every member declares one, otherwise none (dead-lettered). A bare
      timeout in the same group means no policy. `ConfirmedNotSentError`
      members change nothing: they report only their own part.

    An explicit `AmbiguousOutcomeError` comes first. Otherwise an `exc` that
    is itself a `PermanentEventError` or `RetryAfterEventError` keeps that
    meaning (also when it is a timeout): None."""
    if isinstance(exc, AmbiguousOutcomeError):
        return exc
    if isinstance(exc, PermanentEventError | RetryAfterEventError):
        return None
    if _is_unclassified_timeout(exc):
        return AmbiguousOutcomeError(type(exc).__name__, phase=_UNCLASSIFIED_PHASE)
    members = _ambiguous_members(exc)
    if not members:
        return None
    first = members[0]
    windows = [m.retry_within for m in members]
    if all(m.at_least_once for m in members):
        return AmbiguousOutcomeError(first.reason, phase=first.phase, at_least_once=True)
    if all(w is not None for w in windows):
        shortest = min(w for w in windows if w is not None)
        return AmbiguousOutcomeError(first.reason, phase=first.phase, retry_within=shortest)
    return AmbiguousOutcomeError(first.reason, phase=first.phase)


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

    starter = _ExternalEffectStarter(context.tenant_id, event_id, claim_token)
    deadline = asyncio.timeout(OUTBOX_CONSUMER_TIMEOUT_SECONDS)
    try:
        async with deadline:
            await handler(
                TenantJobContext(
                    tenant_id=execution.tenant_id,
                    correlation_id=execution.correlation_id,
                    # RE-5: the event's stable identity, the same on every
                    # attempt, so the consumer can suppress a repeated execution.
                    event_id=execution.id,
                    # D4: the started marker of this claim, written by the
                    # consumer's `context.external_effect()` (off by default).
                    start_external_effect=starter,
                ),
                TenantJobPayload(
                    tenant_id=str(execution.tenant_id),
                    data=dict(execution.payload),
                    correlation_id=execution.correlation_id,
                ),
            )
    except ExternalEffectNotStartedError:
        # D4: the claim was superseded, its lease expired, or this claim
        # already marked the event (a duplicated execution). Nothing was
        # sent; no outcome is recorded by this execution.
        logger.info("outbox_event_external_effect_not_started", extra=log_fields)
        return
    except Exception as exc:  # noqa: BLE001 -- every consumer failure is recorded durably
        if starter.refused:
            # D4: the marker was refused (the consumer caught
            # `ExternalEffectNotStartedError` and raised something else, or
            # ran out of time afterwards): nothing was sent and this
            # execution does not own the attempt, so no outcome is recorded
            # -- the timeout's dead letter included.
            logger.info("outbox_event_external_effect_not_started", extra=log_fields)
            return
        if deadline.expired():
            # Ledger row F5 (owner decision of 2026-11-01): the consumer ran
            # out of time, so whether its external effect happened is unknown
            # (an e-mail sent from a thread the cancellation does not stop, a
            # webhook already received). Decided by the deadline, not by the
            # exception's type: a consumer that catches the cancellation and
            # raises something else has timed out all the same (review of
            # #189). It is dead-lettered now, with the claim it holds, instead
            # of being left for the lease to expire and run it again. An
            # operator brings it back, after checking the destination, with
            # the audited replay (`saas-os-operator replay-outbox-events`,
            # `platform.outbox:replay`).
            await _write_outcome(
                partial(_record_consumer_timeout, context, event_id, claim_token, exc, log_fields),
                log_fields,
            )
            return
        # A failure inside the deadline -- the consumer's own client timeout
        # included: owner decision D of 2026-11-01 reversed #189's "ordinary
        # failure" for it -- is classified like every other consumer error.
        await _write_outcome(
            partial(_record_consumer_failure, context, event_id, claim_token, exc, log_fields),
            log_fields,
        )
        return

    if starter.refused:
        logger.info("outbox_event_external_effect_not_started", extra=log_fields)
        return
    if complete_event(context.tenant_id, event_id, claim_token):
        logger.info("outbox_event_published", extra=log_fields)
    else:
        logger.info("outbox_event_completion_superseded", extra=log_fields)


# Pauses between in-process attempts to record a failure's outcome
# (module docstring): about 2.5 s in all, well inside the 30 s the job keeps
# after the consumer's deadline.
_OUTCOME_WRITE_RETRY_DELAYS = (0.5, 2.0)


async def _write_outcome(write: Callable[[], None], log_fields: Mapping[str, str]) -> bool:
    """Run `write` (a failure's outcome) until it succeeds, a bounded number
    of times. Never raises: a raise would make ARQ retry the job and run the
    consumer again with the same claim (module docstring). Each write is
    conditional on the claim token, so one that committed before its error
    surfaced makes the next a no-op. Returns whether it was recorded."""
    for delay in (*_OUTCOME_WRITE_RETRY_DELAYS, None):
        try:
            write()
        except Exception as exc:  # noqa: BLE001 -- see the docstring
            if delay is None:
                logger.error(
                    "outbox_event_outcome_unrecorded",
                    extra={**log_fields, "error_type": type(exc).__name__},
                )
                return False
            await asyncio.sleep(delay)
        else:
            return True
    return False  # pragma: no cover -- the loop always returns


def _record_consumer_timeout(
    context: TenantJobContext,
    event_id: uuid.UUID,
    claim_token: uuid.UUID,
    exc: Exception,
    log_fields: Mapping[str, str],
) -> None:
    status = fail_event(
        context.tenant_id, event_id, claim_token, _CONSUMER_TIMED_OUT_REASON, terminal=True
    )
    logger.error(
        "outbox_event_timed_out",
        extra={
            **log_fields,
            "outbox_status": status,
            "error_type": type(exc).__name__,
            "outbox_consumer_timeout_seconds": OUTBOX_CONSUMER_TIMEOUT_SECONDS,
        },
    )


def _record_consumer_failure(
    context: TenantJobContext,
    event_id: uuid.UUID,
    claim_token: uuid.UUID,
    exc: Exception,
    log_fields: Mapping[str, str],
) -> None:
    """Record a consumer failure (not the dispatcher's own deadline) by its
    classification, the consumer's explicit statement first."""
    ambiguous = _ambiguous_outcome(exc)
    if ambiguous is not None:
        # Owner decision of 2026-11-01 (ledger row F5): the consumer's
        # transport saw its request possibly sent with no confirmed outcome
        # -- or, owner decision D, a bare timeout escaped unclassified (only
        # its type name is stored, never its text). Never published;
        # dead-lettered unless the consumer declared a retry policy that
        # still allows a retry (`saas_os/core/outbox/dispatch.py`,
        # "Ambiguous outcomes").
        status = record_ambiguous_outcome(context.tenant_id, event_id, claim_token, ambiguous)
        logger.warning(
            "outbox_event_outcome_unknown",
            extra={
                **log_fields,
                "outbox_status": status,
                "error_type": type(exc).__name__,
                "outcome_phase": ambiguous.phase,
            },
        )
        return
    if isinstance(exc, PermanentEventError):
        # RE-4: the consumer says retrying cannot succeed (malformed event,
        # permanent destination refusal, security-policy rejection).
        status = fail_event(context.tenant_id, event_id, claim_token, exc, terminal=True)
        logger.warning(
            "outbox_event_rejected",
            extra={**log_fields, "outbox_status": status, "error_type": type(exc).__name__},
        )
        return
    if isinstance(exc, RetryAfterEventError):
        # Outbox decision brief Q1, 1A: the destination asked to be retried
        # later (a rate limit or a quota). Bounded, and the attempt counts.
        status = fail_event(
            context.tenant_id, event_id, claim_token, exc, retry_after=exc.retry_after_seconds
        )
        logger.warning(
            "outbox_event_deferred",
            extra={**log_fields, "outbox_status": status, "error_type": type(exc).__name__},
        )
        return
    # Any other exception, including a `ConfirmedNotSentError`: the ordinary
    # retry policy (backoff, dead-lettered when the attempts run out). Owner
    # decision of 2026-11-02: an unclassified exception that is not a timeout
    # (a database error, a `ConnectionError`, a `RuntimeError`) is NOT
    # treated as ambiguous; only the timeouts above are.
    status = fail_event(context.tenant_id, event_id, claim_token, exc)
    logger.warning(
        "outbox_event_failed",
        extra={**log_fields, "outbox_status": status, "error_type": type(exc).__name__},
    )


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
