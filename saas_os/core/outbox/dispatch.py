"""The durable outbox state machine (Foundation Reliability & Events, RE-2).

PostgreSQL is the source of truth for every event's delivery. This module
owns the transitions; it never touches Redis or a job queue (the
orchestration that hands claimed events to the queue lives in the worker
layer, `saas_os/api/outbox_dispatcher.py`).

States of a `core.outbox_events` row::

    pending, unclaimed      claim_token NULL; due once next_attempt_at <= now
    pending, claimed        claim_token set;  next_attempt_at = lease expiry
    published   (terminal)  the consumer completed; published_at set
    dead_lettered (terminal) attempts exhausted or no consumer; last_error set

Transitions -- each conditional on the row's current state, under a row lock
(`FOR UPDATE`), in the event's own tenant scope:

    claim_due_events()       pending & due -> claimed: attempts += 1, a fresh
                             claim_token, next_attempt_at = now + lease.
                             A due row whose claim_token is still set is a
                             stale lease (the owner vanished): it is
                             reclaimed the same way, recording the lost
                             attempt in last_error. A due row with no
                             attempts left is dead-lettered instead.
    begin_event_execution()  claimed (matching token) -> lease renewed;
                             returns the event to run. A closed tenant
                             releases the claim instead (nothing runs).
    complete_event()         claimed (matching token) -> published
    fail_event()             claimed (matching token) -> unclaimed with a
                             backoff (attempts left) or dead_lettered; a
                             consumer's retry hint (`retry_after`) delays
                             the retry further, within its bound
    release_claim()          claimed (matching token) -> unclaimed, the
                             attempt refunded: the hand-off to the queue
                             failed, so the event never ran

**Ownership.** A claim is proven by its `claim_token`. Every transition
after the claim names the token; if the row no longer carries it (the lease
expired and another dispatcher reclaimed it, or the event was purged) the
transition changes nothing and returns False/None. So a worker that lost
its claim can never publish, fail or dead-letter an event it no longer
owns.

**Leases.** Claims are found with `SELECT ... FOR UPDATE SKIP LOCKED`, so
concurrent dispatchers never claim the same row, and a dispatcher never
waits on another's in-flight claim transaction. A committed claim lasts
until `next_attempt_at`; after that the same "due" predicate makes it
claimable again -- no separate stale-claim sweep exists or is needed.

**At-least-once, never exactly-once.** An attempt is counted when it is
claimed, before the event is handed to the queue, so a crash anywhere
afterwards still consumes an attempt and a crash loop is bounded. A worker
that ran the consumer but died before `complete_event()` leaves the event
claimed; the lease expires and the event runs again. Consumers that must
not act twice dedupe on the stable event id (RE-5). Nothing here marks an
event published unless its consumer returned.

**Tenancy.** Every read and write runs under the event's own tenant RLS
scope -- one tenant at a time (`saas_os.infra.db.bind_tenant_scope()` /
`tenant_session_scope()`), never a cross-tenant query and never an RLS
bypass. Tenants are enumerated through `saas_os.core.tenancy.list_open_tenant_ids()`;
a closed tenant's events are never claimed.
"""

from __future__ import annotations

import math
import random
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from saas_os.core.outbox.config import OutboxDispatchConfig, get_outbox_dispatch_config
from saas_os.core.outbox.models import (
    OUTBOX_STATUS_DEAD_LETTERED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxEvent,
)
from saas_os.core.tenancy import (
    TenantClosedError,
    TenantNotFoundError,
    list_open_tenant_ids,
    list_tenant_ids,
    lock_open_tenant,
)
from saas_os.infra.db import Session, bind_tenant_scope, select, session_scope, tenant_session_scope

_MAX_ERROR_LENGTH = 500

Random = Callable[[], float]


@dataclass(frozen=True)
class ClaimedEvent:
    """A claim the dispatcher holds: what it hands to the queue."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    event_type: str
    claim_token: uuid.UUID
    attempts: int
    correlation_id: str | None


@dataclass(frozen=True)
class EventExecution:
    """A claimed event about to run, with what its consumer needs."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    event_type: str
    payload: dict[str, object]
    correlation_id: str | None
    attempts: int


def _now(now: datetime | None) -> datetime:
    return now if now is not None else datetime.now(UTC)


def describe_error(error: BaseException | str) -> str:
    """The durable `last_error` text: the exception type and its message,
    bounded. Consumers' errors carry identifiers and categories, never
    payload content (their own documented convention).

    Each NUL becomes U+FFFD: PostgreSQL text cannot hold one, and a message
    can -- redis-py quotes a refused pipeline command, the pickled job
    included, in its error (`OutOfMemoryError` when Redis is full). Storing
    it raw would fail the very write that gives the claim back."""
    text = error if isinstance(error, str) else f"{type(error).__name__}: {error}"
    return text.replace("\x00", "\ufffd")[:_MAX_ERROR_LENGTH]


def retry_delay(
    attempts: int, config: OutboxDispatchConfig, rng: Random = random.random
) -> timedelta:
    """Delay before the next attempt after `attempts` failed ones: the base
    doubled per attempt, capped, plus up to `retry_jitter_ratio` of it."""
    exponent = max(attempts - 1, 0)
    delay = min(config.retry_base_seconds * (2**exponent), config.retry_max_seconds)
    jitter = delay * config.retry_jitter_ratio * rng()
    return timedelta(seconds=delay + jitter)


def retry_hint_delay(retry_after: object, config: OutboxDispatchConfig) -> timedelta:
    """A consumer's retry hint as a delay: capped at
    `retry_hint_max_seconds`; `math.inf` is the cap; a negative, `NaN`,
    boolean or non-numeric value is no hint (zero). Outbox decision brief
    Q1, option 1A."""
    if isinstance(retry_after, bool) or not isinstance(retry_after, int | float):
        return timedelta(0)
    if math.isnan(retry_after) or retry_after <= 0:
        return timedelta(0)
    return timedelta(seconds=min(float(retry_after), config.retry_hint_max_seconds))


def _dead_letter(row: OutboxEvent, reason: str | None) -> None:
    row.status = OUTBOX_STATUS_DEAD_LETTERED
    row.claim_token = None
    if reason is not None:
        row.last_error = describe_error(reason)


def _claim_hook(session: Session) -> None:
    """Called inside the claim transaction after rows are locked and
    claimed, before COMMIT. A seam for deterministic concurrency tests;
    does nothing."""


def claim_due_events(
    *,
    config: OutboxDispatchConfig | None = None,
    now: datetime | None = None,
    rng: Random = random.random,
) -> list[ClaimedEvent]:
    """Claim up to `batch_size` due events (at most `per_tenant_limit` per
    tenant), across every open tenant, in one transaction; return the
    claims. Tenants are visited from a random starting point so no tenant
    is always last. Rows another dispatcher holds are skipped, never waited
    for. See the module docstring for the transition."""
    cfg = config or get_outbox_dispatch_config()
    at = _now(now)
    tenant_ids = list_open_tenant_ids()
    if not tenant_ids:
        return []
    start = int(rng() * len(tenant_ids)) % len(tenant_ids)
    ordered = tenant_ids[start:] + tenant_ids[:start]

    claimed: list[ClaimedEvent] = []
    with session_scope() as session:
        for tenant_id in ordered:
            remaining = cfg.batch_size - len(claimed)
            if remaining <= 0:
                break
            with bind_tenant_scope(session, tenant_id):
                rows = (
                    session.execute(
                        select(OutboxEvent)
                        .where(
                            OutboxEvent.tenant_id == tenant_id,
                            OutboxEvent.status == OUTBOX_STATUS_PENDING,
                            OutboxEvent.next_attempt_at <= at,
                        )
                        .order_by(OutboxEvent.next_attempt_at, OutboxEvent.id)
                        .limit(min(cfg.per_tenant_limit, remaining))
                        .with_for_update(skip_locked=True)
                    )
                    .scalars()
                    .all()
                )
                for row in rows:
                    lease_lost = row.claim_token is not None
                    if row.attempts >= cfg.max_attempts:
                        _dead_letter(
                            row,
                            f"LeaseExpired: no outcome recorded for final attempt {row.attempts}"
                            if lease_lost
                            else None,
                        )
                        continue
                    if lease_lost:
                        row.last_error = describe_error(
                            f"LeaseExpired: no outcome recorded for attempt {row.attempts}"
                        )
                    claim_token = uuid.uuid4()
                    row.attempts += 1
                    row.claim_token = claim_token
                    row.next_attempt_at = at + cfg.lease
                    claimed.append(
                        ClaimedEvent(
                            id=row.id,
                            tenant_id=row.tenant_id,
                            event_type=row.event_type,
                            claim_token=claim_token,
                            attempts=row.attempts,
                            correlation_id=row.correlation_id,
                        )
                    )
                session.flush()
        _claim_hook(session)
    return claimed


def _locked_claimed_row(
    session: Session, event_id: uuid.UUID, claim_token: uuid.UUID
) -> OutboxEvent | None:
    """The event, row-locked, if it is still pending and owned by
    `claim_token` -- else None."""
    row = session.execute(
        select(OutboxEvent).where(OutboxEvent.id == event_id).with_for_update()
    ).scalar_one_or_none()
    if row is None or row.status != OUTBOX_STATUS_PENDING or row.claim_token != claim_token:
        return None
    return row


def begin_event_execution(
    tenant_id: uuid.UUID,
    event_id: uuid.UUID,
    claim_token: uuid.UUID,
    *,
    config: OutboxDispatchConfig | None = None,
    now: datetime | None = None,
) -> EventExecution | None:
    """Start running a claimed event: under `tenant_id`'s scope, confirm the
    claim is still current and renew its lease, then return the event.
    Returns None -- nothing to run -- if the claim is no longer current, the
    event is not this tenant's, or the tenant has closed. A closed tenant's
    claim is released (the event stays pending; it is never claimed again
    and the purge removes it). The tenant row is locked before the event
    row, the same order as the purge, so the two never deadlock."""
    cfg = config or get_outbox_dispatch_config()
    at = _now(now)
    with tenant_session_scope(tenant_id) as session:
        try:
            lock_open_tenant(session, tenant_id)
        except (TenantClosedError, TenantNotFoundError):
            row = _locked_claimed_row(session, event_id, claim_token)
            if row is not None:
                row.claim_token = None
            return None
        row = _locked_claimed_row(session, event_id, claim_token)
        if row is None:
            return None
        row.next_attempt_at = at + cfg.lease
        return EventExecution(
            id=row.id,
            tenant_id=row.tenant_id,
            event_type=row.event_type,
            payload=dict(row.payload),
            correlation_id=row.correlation_id,
            attempts=row.attempts,
        )


def complete_event(
    tenant_id: uuid.UUID,
    event_id: uuid.UUID,
    claim_token: uuid.UUID,
    *,
    now: datetime | None = None,
) -> bool:
    """Mark a claimed event published -- only if `claim_token` still owns
    it. Returns whether it did."""
    with tenant_session_scope(tenant_id) as session:
        row = _locked_claimed_row(session, event_id, claim_token)
        if row is None:
            return False
        row.status = OUTBOX_STATUS_PUBLISHED
        row.published_at = _now(now)
        row.claim_token = None
        return True


def fail_event(
    tenant_id: uuid.UUID,
    event_id: uuid.UUID,
    claim_token: uuid.UUID,
    error: BaseException | str,
    *,
    terminal: bool = False,
    retry_after: float | None = None,
    config: OutboxDispatchConfig | None = None,
    now: datetime | None = None,
    rng: Random = random.random,
) -> str | None:
    """Record a failed attempt of a claimed event -- only if `claim_token`
    still owns it. With attempts left (and not `terminal`), the event is
    released for a retry after `retry_delay()`, or after the consumer's
    `retry_after` hint when that is longer (`retry_hint_delay()`: bounded by
    `retry_hint_max_seconds`); otherwise it is dead-lettered. The hint never
    refunds the attempt. Returns the new status, or None if the claim was
    no longer current."""
    cfg = config or get_outbox_dispatch_config()
    at = _now(now)
    with tenant_session_scope(tenant_id) as session:
        row = _locked_claimed_row(session, event_id, claim_token)
        if row is None:
            return None
        row.last_error = describe_error(error)
        if terminal or row.attempts >= cfg.max_attempts:
            _dead_letter(row, None)
        else:
            row.claim_token = None
            delay = retry_delay(row.attempts, cfg, rng)
            if retry_after is not None:
                delay = max(delay, retry_hint_delay(retry_after, cfg))
            row.next_attempt_at = at + delay
        return row.status


def release_claim(
    tenant_id: uuid.UUID,
    event_id: uuid.UUID,
    claim_token: uuid.UUID,
    error: BaseException | str,
    *,
    config: OutboxDispatchConfig | None = None,
    now: datetime | None = None,
) -> bool:
    """Give a claim back because the event could not be handed to the queue
    (it never ran): the attempt is refunded and the event becomes due again
    after `enqueue_retry_seconds`, so a queue outage delays events but never
    exhausts them. Only if `claim_token` still owns it."""
    cfg = config or get_outbox_dispatch_config()
    at = _now(now)
    with tenant_session_scope(tenant_id) as session:
        row = _locked_claimed_row(session, event_id, claim_token)
        if row is None:
            return False
        row.attempts = max(row.attempts - 1, 0)
        row.claim_token = None
        row.next_attempt_at = at + cfg.enqueue_retry_delay
        row.last_error = describe_error(error)
        return True


def rewrite_stored_errors(replacements: Mapping[str, str], *, apply: bool) -> int:
    """Replace every stored `last_error` that starts with one of
    `replacements`' prefixes by that prefix's replacement text, in every
    tenant's events (closed tenants included), each tenant in its own
    transaction under its own row security. Returns how many events match;
    with `apply=False` nothing is written. For removing text that should
    never have been stored (`saas_os.core.webhooks.stored_errors`): the
    status, attempts and schedule of an event are never changed."""
    matched = 0
    for tenant_id in list_tenant_ids():
        with tenant_session_scope(tenant_id) as session:
            for prefix, replacement in replacements.items():
                query = select(OutboxEvent).where(
                    OutboxEvent.tenant_id == tenant_id,
                    OutboxEvent.last_error.startswith(prefix, autoescape=True),
                )
                # Only a run that writes locks the rows: a count must not
                # hold up the dispatcher.
                if apply:
                    query = query.with_for_update()
                rows = session.execute(query).scalars().all()
                matched += len(rows)
                if apply:
                    for row in rows:
                        row.last_error = describe_error(replacement)
            if not apply:
                session.rollback()
    return matched
