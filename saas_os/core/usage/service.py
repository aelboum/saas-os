"""Usage ingestion, on-demand aggregation, and quota checking
(docs/IMPLEMENTATION-ROADMAP.md Phase 5.2).

`ingest_event()` records a `saas_os.core.outbox` event in the caller's own
transaction (RE-1, transactional outbox); persistence then happens through
`saas_os.infra.jobs` once the dispatcher (RE-2) publishes it, mirroring
`saas_os/core/notifications/service.py::dispatch_notification()` and
`saas_os/core/webhooks/service.py::trigger_event()` exactly -- the same
"genuinely single-step-retryable" job shape
(`docs/ADR/0007-background-job-and-workflow-engine.md`), reused here
rather than reinvented; ingestion must never block a caller on a
database write. `saas_os/core/usage` owns the job *handler*
(`_ingest_usage_event_job`, registered via `saas_os.infra.jobs.register_tenant_job` and
exported as `USAGE_JOB_FUNCTIONS` for a worker process to register);
`saas_os/infra/jobs` owns the generic retry-count/dead-letter execution metadata
(docs/DATA-ARCHITECTURE.md section 5).

`aggregate_usage()` computes a `SUM` over raw `core.usage_events` rows
on-demand, every call -- no cached/materialized aggregate table exists.
This directly satisfies the roadmap's own Rollback Strategy ("aggregation
can be recomputed from raw events; raw events are the source of truth"):
there is no derived state to invalidate or repair after a rollback,
because none is ever persisted.

`check_quota()` is the one place `saas_os/core/usage` reads `saas_os/core/billing` --
combining `saas_os.core.billing.service.get_entitlements()` (the existing,
already-tested plan -> entitlement lookup) with `aggregate_usage()`.
`saas_os/core/usage` has no independent notion of a "limit"; it only asks
`saas_os/core/billing` what the tenant's plan currently allows for a given
metric key. No Stripe-specific coupling exists here or anywhere else in
this module -- `saas_os/core/billing` already isolates that behind its own
provider abstraction.

`metric` is a plain string that deliberately reuses `Plan.entitlements`'
own key vocabulary (`saas_os/core/usage/models.py`'s own docstring) -- no
separate metric catalog/enum is introduced.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from arq.worker import Function

from saas_os.core.idempotency import run_idempotent
from saas_os.core.outbox import append_event, claim_event_consumption
from saas_os.core.tenancy import (
    TenantClosedError,
    TenantNotFoundError,
    get_descendant_ids,
    lock_open_tenant,
    require_open_tenant,
)
from saas_os.core.usage.errors import (
    InvalidUsageEventError,
    MalformedUsageEventError,
    QuotaExceededError,
    UsageIngestionError,
)
from saas_os.core.usage.models import UsageEvent
from saas_os.infra.db import (
    Session,
    acquire_tenant_advisory_lock,
    select,
    sum_,
    tenant_session_scope,
)
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload, register_tenant_job

_MAX_METRIC_LENGTH = 100

logger = logging.getLogger(__name__)


def _validate_metric(metric: str) -> None:
    if not metric or not metric.strip():
        raise InvalidUsageEventError("metric must be a non-empty string.")
    if len(metric) > _MAX_METRIC_LENGTH:
        raise InvalidUsageEventError(f"metric exceeds {_MAX_METRIC_LENGTH} characters.")


# Phase 5.2 metering semantics: a quantity is an exact decimal (`Decimal`, or
# an `int`, which converts exactly) -- never a binary `float` -- finite (not
# NaN or Infinity: PostgreSQL's unconstrained `numeric` would store either,
# and one infinite row poisons every later SUM), non-negative (zero is a
# valid, recorded quantity), below 10**18, with at most 18 decimal places.
# Out-of-range values are refused, never rounded or clamped.
_MAX_QUANTITY = Decimal(10) ** 18
_MAX_QUANTITY_DECIMAL_PLACES = 18


def _validate_quantity(quantity: object) -> Decimal:
    """The quantity as an exact `Decimal`, or `InvalidUsageEventError`."""
    if isinstance(quantity, bool) or not isinstance(quantity, (Decimal, int)):
        raise InvalidUsageEventError("quantity must be a Decimal or an int, never a float.")
    value = Decimal(quantity)
    if not value.is_finite():
        raise InvalidUsageEventError("quantity must be a finite number.")
    if value < 0:
        raise InvalidUsageEventError("quantity must not be negative.")
    if value >= _MAX_QUANTITY:
        raise InvalidUsageEventError("quantity must be less than 10**18.")
    exponent = value.normalize().as_tuple().exponent
    if value != 0 and isinstance(exponent, int) and -exponent > _MAX_QUANTITY_DECIMAL_PLACES:
        raise InvalidUsageEventError(
            f"quantity must have at most {_MAX_QUANTITY_DECIMAL_PLACES} decimal places."
        )
    return value


def _utc(name: str, value: object) -> datetime:
    """`value` normalized to UTC; a naive datetime is refused -- a usage time
    or window is never interpreted in a server's local timezone."""
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise InvalidUsageEventError(f"{name} must be a timezone-aware datetime.")
    return value.astimezone(UTC)


def _window(since: datetime | None, until: datetime | None) -> tuple[datetime, datetime]:
    """The aggregation window `[since, until)` in UTC: both bounds, or neither
    (the current UTC calendar month). A single bound is refused rather than
    silently ignored."""
    if since is None and until is None:
        return _current_utc_month_window()
    if since is None or until is None:
        raise InvalidUsageEventError("since and until must be given together.")
    start, end = _utc("since", since), _utc("until", until)
    if start > end:
        raise InvalidUsageEventError("since must not be after until.")
    return start, end


# --- Ingestion (async, job-queued) ---------------------------------------


# RE-1 (transactional outbox): the outbox event type a usage event is
# recorded under; its payload is exactly the data `_ingest_usage_event_job()`
# consumes.
USAGE_INGESTION_EVENT_TYPE = "usage.ingestion"


def ingest_event(
    session: Session,
    tenant_id: uuid.UUID,
    metric: str,
    quantity: Decimal,
    *,
    occurred_at: datetime | None = None,
) -> uuid.UUID:
    """Record one usage event for `tenant_id` in the caller's own
    transaction (RE-1, transactional outbox): a `saas_os.core.outbox` event appended
    on `session` -- the caller's `tenant_session_scope(tenant_id)` session --
    so it commits or rolls back with the caller's mutation. Nothing is
    committed here and no queue is contacted. Returns the outbox event id.
    Persisting the `core.usage_events` row is still asynchronous: the
    dispatcher (RE-2) publishes the event to `_ingest_usage_event_job`.

    `occurred_at` defaults to "now" (UTC) when not supplied; a supplied one
    must be timezone-aware and is recorded in UTC. Validation (`metric`,
    `quantity` -- exact, finite, non-negative, bounded: `_validate_quantity()`
    -- and `occurred_at`) happens here, before anything is recorded, so an
    invalid call fails immediately rather than surfacing later as a
    dead-lettered job. The tenant lifecycle is checked in the same
    transaction (`lock_open_tenant()`): a closed tenant raises
    `TenantClosedError`, as before.
    """
    _validate_metric(metric)
    quantity = _validate_quantity(quantity)
    event_occurred_at = (
        _utc("occurred_at", occurred_at) if occurred_at is not None else datetime.now(UTC)
    )
    lock_open_tenant(session, tenant_id)

    return append_event(
        session,
        tenant_id=tenant_id,
        event_type=USAGE_INGESTION_EVENT_TYPE,
        aggregate_type="usage_metric",
        aggregate_id=metric,
        payload={
            "metric": metric,
            "quantity": str(quantity),
            "occurred_at": event_occurred_at.isoformat(),
        },
    )


async def _ingest_usage_event_job(context: TenantJobContext, payload: TenantJobPayload) -> None:
    """The registered job handler: insert one `UsageEvent` row -- at most
    once per outbox event (RE-5, `saas_os.core.outbox.claim_event_consumption()`).
    Raises `UsageIngestionError` on failure (including a failure to check
    the consumption record -- never read as "already done") so the event is
    retried; this function never implements retry/backoff itself. A
    tenant job (`register_tenant_job`, Foundation Enforcement FE-5): the
    worker has already validated the payload and parsed
    `context.tenant_id`."""
    tenant_id = context.tenant_id
    metric, quantity, occurred_at = _parse_ingestion(payload.data)

    # PRIV-03 P7 (privacy re-audit RA-03): the execution-time lifecycle
    # fence. `ingest_event()`'s `lock_open_tenant()` only proves the
    # tenant was open when the event was *recorded*; a tenant that has since
    # committed DELETED/PURGING/PURGED gets no new usage row -- not even
    # after PURGED, where the retained table's FK to the tombstone would
    # otherwise let the insert through. Dropping is a normal return, never
    # an exception, so `saas_os.infra.jobs`' wrapper does not retry or dead-letter
    # a job that must simply not run (the shape `control_plane...
    # continuous_loop`'s `TENANT_CLOSED` outcome established). The insert
    # then repeats the check *inside* its own transaction with
    # `lock_open_tenant()` (`core.tenants` FOR SHARE, serialized against
    # the FOR UPDATE lifecycle transitions), so a closure cannot commit
    # between the check and the write.
    try:
        require_open_tenant(tenant_id)
    except TenantClosedError:
        logger.info("usage_event_dropped_tenant_closed")
        return
    except TenantNotFoundError:
        # Not "closed" -- a tenant that does not exist is a genuine
        # failure, not a lifecycle outcome: fall through so the insert
        # below fails exactly as it always has (and is retried/
        # dead-lettered as `UsageIngestionError`).
        pass

    try:
        with tenant_session_scope(tenant_id) as session:
            lock_open_tenant(session, tenant_id)
            # RE-5: the consumption claim and the usage row commit together,
            # so a repeated execution of the same outbox event -- concurrent
            # or after a worker died before the dispatcher recorded the
            # outcome -- never counts the usage twice. A job with no event
            # identity (queued directly, before the outbox existed) has
            # nothing to deduplicate on and inserts as before.
            if context.event_id is not None and not claim_event_consumption(
                session,
                tenant_id=tenant_id,
                consumer=USAGE_INGESTION_EVENT_TYPE,
                event_id=context.event_id,
            ):
                logger.info("usage_event_duplicate_suppressed")
                return
            event = UsageEvent(
                tenant_id=tenant_id,
                metric=metric,
                quantity=quantity,
                occurred_at=occurred_at,
            )
            session.add(event)
            session.flush()
    except TenantClosedError:
        logger.info("usage_event_dropped_tenant_closed")
        return
    except Exception as exc:
        raise UsageIngestionError(tenant_id, metric, type(exc).__name__) from exc


def _parse_ingestion(data: Mapping[str, object]) -> tuple[str, Decimal, datetime]:
    """The event's fields, validated exactly as `ingest_event()` validated
    them (Phase 5.2). An event that fails is permanent
    (`MalformedUsageEventError`): it is dead-lettered, never retried and
    never recorded with a coerced value. A naive `occurred_at` can only come
    from an event recorded before times were required to be aware, and is
    read as UTC."""
    try:
        metric = str(data["metric"])
        _validate_metric(metric)
        quantity = _validate_quantity(Decimal(str(data["quantity"])))
        occurred_at = datetime.fromisoformat(str(data["occurred_at"]))
    except (KeyError, ValueError, ArithmeticError) as exc:
        raise MalformedUsageEventError(
            f"invalid usage event payload ({type(exc).__name__})"
        ) from exc
    if occurred_at.utcoffset() is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)
    return metric, quantity, occurred_at.astimezone(UTC)


USAGE_JOB_FUNCTIONS: list[Function] = [register_tenant_job(_ingest_usage_event_job)]

# RE-2 (durable outbox dispatcher): the consumer of each outbox event type
# this module produces. The dispatcher runs it in-process, inside its own
# outbox job, with the event's payload -- the same handler, payload and
# fences as the registered job above.
OUTBOX_EVENT_HANDLERS: dict[
    str, Callable[[TenantJobContext, TenantJobPayload], Awaitable[None]]
] = {USAGE_INGESTION_EVENT_TYPE: _ingest_usage_event_job}


# --- Aggregation (on-demand, never cached) --------------------------------


def aggregate_usage(
    tenant_id: uuid.UUID, metric: str, *, since: datetime, until: datetime
) -> Decimal:
    """Sum `quantity` for `metric` within `[since, until)`, computed by a
    SQL `SUM` over raw `core.usage_events` rows every call -- see module
    docstring for why no cached aggregate table exists. Returns
    `Decimal("0")` when no matching events exist (a documented safe
    default, never an error)."""
    since, until = _window(since, until)
    with tenant_session_scope(tenant_id) as session:
        total = session.execute(
            select(sum_(UsageEvent.quantity)).where(
                UsageEvent.tenant_id == tenant_id,
                UsageEvent.metric == metric,
                UsageEvent.occurred_at >= since,
                UsageEvent.occurred_at < until,
            )
        ).scalar_one()
    return total if total is not None else Decimal("0")


def aggregate_usage_including_descendants(
    tenant_id: uuid.UUID, metric: str, *, since: datetime, until: datetime
) -> Decimal:
    """Hierarchy-aware rollup (architecture research Phase H --
    "Hierarchy-Aware Billing & Usage" section 10): sum `metric` for
    `tenant_id` AND every one of its current structural descendants
    (`saas_os.core.tenancy.get_descendant_ids()` -- one indexed read over the
    precomputed `core.tenant_ancestry` closure table, never a recursive
    query), each usage row remaining attributed to whichever tenant
    actually generated it.

    **Usage location and billing ownership are kept separate** (this
    phase's own explicit requirement): this function does NOT consult
    `saas_os.core.billing`, `resolve_billing_owner()`, or any tenant's
    `inherits_billing` flag -- it is a pure structural-subtree rollup. A
    caller that wants "this billing owner's effective pool" passes
    `saas_os.core.billing.service.resolve_billing_owner(tenant_id)`'s result as
    `tenant_id` here; a caller that wants "this tenant's own reporting
    rollup regardless of billing" passes the tenant's own id directly.
    Neither usage is moved, retagged, or duplicated: every summed row
    keeps its own original `UsageEvent.tenant_id` forever
    (`saas_os/core/usage/models.py`'s own immutability docstring) -- this
    function only changes what is *read*, in memory, for one aggregate
    number; it writes nothing.

    **Not RLS-bypassing**: `core.usage_events` remains single-`app.tenant_id`
    RLS-protected (architecture research Phase H section 14: "never
    weaken RLS... never use SECURITY DEFINER"). Reading N tenants' rows
    therefore costs N separate `tenant_session_scope()` queries -- one
    per descendant -- summed here in Python, never one query spanning
    tenants and never a second GUC. `saas_os.core.tenancy`'s own
    `TENANT_MAX_HIERARCHY_DEPTH` guardrail (default 6) bounds hierarchy
    *depth*, not subtree *width*; a tenant with a very large number of
    descendants makes this call proportionally expensive by construction
    -- deliberately not used by `check_quota()`/`consume_quota()`'s own
    request-time enforcement path for exactly this reason (see those
    functions' own docstrings), reserved for reporting/rollup callers
    that can tolerate that cost.

    **Grants no reporting-visibility authorization by itself** (module
    docstring's own hierarchy-authorization boundary, restated for this
    function specifically): a caller that exposes this number to an end
    user remains responsible for its own authorization check first -- "a
    user must not see descendant usage merely because the tenants are
    hierarchically related" (this phase's own approved design).
    """
    total = Decimal("0")
    for descendant_id in get_descendant_ids(tenant_id):
        total += aggregate_usage(descendant_id, metric, since=since, until=until)
    return total


# --- Quota checking (combines saas_os/core/billing entitlements + aggregation) ---


@dataclass(frozen=True)
class QuotaCheckResult:
    metric: str
    used: Decimal
    limit: Decimal | None
    exceeded: bool


def _current_utc_month_window() -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )
    return start, end


def _numeric_limit(entitlements: dict[str, object], metric: str) -> Decimal | None:
    """A missing, non-numeric, or boolean entitlement value for `metric`
    is treated as "no configured limit" (`None`) -- a documented safe
    default mirroring `get_entitlements()`'s own "no active subscription
    -> {}" convention, never an error: quota checks are expected to run
    on every gated action, so an unconfigured metric must be a normal,
    cheap case to handle. Shared by `check_quota()` (read-only
    measurement) and `consume_quota()` (P1.9 atomic enforcement) so the
    two never disagree on what "no limit" means for the same metric.
    """
    raw_limit = entitlements.get(metric)
    if (
        raw_limit is None
        or isinstance(raw_limit, bool)
        or not isinstance(raw_limit, (int, float, Decimal))
    ):
        return None
    return Decimal(str(raw_limit))


def check_quota(
    tenant_id: uuid.UUID,
    metric: str,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
) -> QuotaCheckResult:
    """Compare `metric`'s aggregated usage (default window: the current
    UTC calendar month) against the entitlement limit
    `saas_os.core.billing.service.get_entitlements()` reports for this tenant's
    active plan.

    Read-only measurement -- never records usage, never raises on
    "exceeded" (the caller decides what to do with the result). This is
    deliberately distinct from `consume_quota()` (P1.9): this function
    answers "what is the current state," `consume_quota()` answers "may
    this one more unit happen, and if so, account for it atomically."
    Suitable for a dashboard/status read; NOT suitable, by itself, as a
    request-time enforcement gate (two concurrent callers can each
    observe "not yet exceeded" and both proceed -- see `consume_quota()`'s
    own docstring).

    **Hierarchy-aware on the LIMIT side only (architecture research Phase
    H)**: `get_entitlements(tenant_id)` transparently resolves
    `tenant_id`'s billing owner, so a tenant with `inherits_billing=True`
    is compared against its resolved owner's plan limit. The USED side
    remains `aggregate_usage(tenant_id, ...)` -- exactly `tenant_id`'s own
    usage, never pooled with siblings or descendants (module docstring
    section 9/11: usage location, billing ownership, and authorization
    tenant are kept as three separate concepts, never collapsed into
    one). A caller that wants the pooled/rollup number for reporting
    calls `aggregate_usage_including_descendants()` explicitly instead --
    this function does not do so implicitly. See that function's own
    docstring for why request-time enforcement deliberately does not use
    it (unbounded subtree width).
    """
    from saas_os.core.billing.service import get_entitlements

    window_start, window_end = _window(since, until)
    used = aggregate_usage(tenant_id, metric, since=window_start, until=window_end)
    limit = _numeric_limit(get_entitlements(tenant_id), metric)

    exceeded = limit is not None and used > limit
    return QuotaCheckResult(metric=metric, used=used, limit=limit, exceeded=exceeded)


# --- Quota enforcement (P1.9: atomic check-and-consume) -------------------


def consume_quota(
    tenant_id: uuid.UUID,
    metric: str,
    quantity: Decimal = Decimal("1"),
    *,
    since: datetime | None = None,
    until: datetime | None = None,
) -> QuotaCheckResult:
    """Atomically check `metric`'s quota and, if `quantity` more would not
    exceed it, record that usage -- the enforcement counterpart to
    `check_quota()` (see that function's own docstring for the
    measurement/enforcement distinction). Raises `QuotaExceededError`
    (never records usage) when the limit would be exceeded; returns the
    post-consumption `QuotaCheckResult` otherwise.

    **Hierarchy-aware on the LIMIT side only, unchanged atomicity**
    (architecture research Phase H): the limit comes from
    `get_entitlements(tenant_id)`, which resolves `tenant_id`'s billing
    owner -- a tenant with `inherits_billing=True` is enforced against
    its resolved owner's plan limit. The advisory lock and the usage
    read/write both remain keyed and scoped to `tenant_id` itself, exactly
    as before Phase H -- `core.usage_events` stays single-`app.tenant_id`
    RLS-protected per transaction (architecture research Phase H section
    14: never weaken RLS), so a true cross-tenant pooled-and-atomic
    check-and-consume across a shared billing subtree is not implemented
    in this phase (it would require either relaxing RLS to span tenants
    within one transaction, or a distributed lock spanning several
    per-tenant transactions -- both explicitly out of scope, sections 14
    and 17). Known, documented consequence: if several children all
    inherit the same parent's plan, each is independently capped at that
    plan's limit rather than sharing one pooled allowance -- this phase's
    own "minimum required pieces" scoping (section 11) deliberately does
    not attempt shared-pool enforcement rather than ship a half-correct,
    RLS-weakening, or non-atomic version of it.

    **Race safety**: `saas_os/core/usage`'s existing usage-recording path
    (`ingest_event()`) is asynchronous -- job-queued through `saas_os.infra.jobs`
    (module docstring) -- which makes it structurally unsuitable for
    atomic enforcement: the write can land arbitrarily long after the
    call returns, so nothing could ever be checked against it atomically.
    This function therefore does not go through that queue for the unit
    being enforced. Instead, the read that decides "does this exceed
    quota" and the write that accounts for the newly-consumed quantity
    happen inside one `tenant_session_scope()` transaction, serialized
    against any other concurrent call for the *same* `(tenant_id, metric)`
    pair by a PostgreSQL transaction-scoped advisory lock
    (`pg_advisory_xact_lock`, keyed by a hash of both) -- a primitive
    PostgreSQL already provides, requiring no schema change, no second
    usage-recording mechanism, and no Redis/distributed quota state. The
    lock is scoped to this one transaction and is released automatically
    at commit or rollback; it never blocks unrelated `(tenant_id, metric)`
    pairs, and never blocks `check_quota()`'s own plain (non-locking)
    read.

    This is not a second usage source: the row inserted here lands in the
    exact same `core.usage_events` table `ingest_event()` eventually
    writes to (`saas_os/core/usage/models.py`) -- this path simply writes
    synchronously, inline, for the one call that needs the write and the
    check to be atomic with each other. A caller that also wants the
    async/job-queued path for other, non-enforcement-critical usage
    recording is unaffected; the two coexist as two entry points into one
    canonical table, never two tables.

    A denied call raises before any row is inserted (the whole
    transaction rolls back), so a failed quota check never records usage
    -- and, symmetrically, a business operation that raises *after* a
    successful `consume_quota()` call already has its usage recorded
    (by design: the quota was consumed the moment this function returned
    without raising, mirroring how a real resource was reserved).
    """
    _validate_metric(metric)
    quantity = _validate_quantity(quantity)
    window_start, window_end = _window(since, until)
    require_open_tenant(tenant_id)

    from saas_os.core.billing.service import get_entitlements

    limit = _numeric_limit(get_entitlements(tenant_id), metric)

    with tenant_session_scope(tenant_id) as session:
        return _consume_quota_in_session(
            session, tenant_id, metric, quantity, limit, window_start, window_end
        )


def _consume_quota_in_session(
    session: Session,
    tenant_id: uuid.UUID,
    metric: str,
    quantity: Decimal,
    limit: Decimal | None,
    window_start: datetime,
    window_end: datetime,
) -> QuotaCheckResult:
    """The actual atomic check-and-record logic, extracted from
    `consume_quota()` (P1.11) so `consume_quota_idempotent()` can run it
    inside the *same* transaction its idempotency reservation uses
    (`saas_os.core.idempotency.run_idempotent()`) rather than nesting a second,
    separate `tenant_session_scope()` -- `consume_quota()` itself is
    unchanged in behavior, just delegates to this helper with a session
    it opened itself.
    """
    # Transaction-scoped advisory lock: serializes concurrent attempts
    # for this exact (tenant_id, metric) pair only. Auto-released at
    # commit/rollback -- no explicit unlock, no risk of a leaked lock on
    # a pooled connection.
    acquire_tenant_advisory_lock(session, tenant_id, metric)

    used = session.execute(
        select(sum_(UsageEvent.quantity)).where(
            UsageEvent.tenant_id == tenant_id,
            UsageEvent.metric == metric,
            UsageEvent.occurred_at >= window_start,
            UsageEvent.occurred_at < window_end,
        )
    ).scalar_one()
    used = used if used is not None else Decimal("0")

    if limit is not None and used + quantity > limit:
        raise QuotaExceededError(tenant_id, metric, used=used, limit=limit)

    session.add(
        UsageEvent(
            tenant_id=tenant_id, metric=metric, quantity=quantity, occurred_at=datetime.now(UTC)
        )
    )
    session.flush()
    return QuotaCheckResult(metric=metric, used=used + quantity, limit=limit, exceeded=False)


def consume_quota_idempotent(
    tenant_id: uuid.UUID,
    metric: str,
    quantity: Decimal,
    idempotency_key: str,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
) -> tuple[bool, QuotaCheckResult]:
    """P1.11: the idempotent counterpart to `consume_quota()`. Uses
    `saas_os.core.idempotency.run_idempotent()` -- the fully atomic, single-
    transaction primitive, not the two-step one `saas_os.core.billing.service.
    subscribe_idempotent()` needs -- because this entire operation is a
    database mutation with no external call in the middle. The
    reservation insert, the quota check, the `UsageEvent` insert, and the
    result finalize all commit (or all roll back) together: a retry can
    never observe a state where the reservation exists but the usage
    event does not, or vice versa.

    Regression this function exists to prove (this checkpoint's own P1.9
    interaction requirement): a retry with the same key and the same
    `(metric, quantity)` consumes quota exactly once, never twice --
    `tests/core/usage/test_idempotent_quota_integration.py` proves this
    against real PostgreSQL, both sequentially and concurrently.

    Fingerprint payload is `{"metric": metric, "quantity": str(quantity)}`
    -- the two inputs that determine what would actually be consumed.

    If the limit would be exceeded, `_consume_quota_in_session()` raises
    `QuotaExceededError` *inside* `run_idempotent()`'s transaction, which
    unwinds the reservation along with it (`saas_os/core/idempotency/service.py`'s
    own docstring: a business-logic failure leaves no row behind) -- so a
    quota-exceeded response is never cached; a later retry (e.g. after
    the tenant's window rolls over, or their plan changes) re-checks
    quota fresh, exactly like `consume_quota()` itself already does.

    Returns `(is_replay, result)`.
    """
    from saas_os.core.billing.service import get_entitlements

    # Phase 5.2: the same validation as `consume_quota()`. Previously none --
    # a negative quantity was recorded as negative usage, lowering the
    # measured total and so the quota decision itself.
    _validate_metric(metric)
    quantity = _validate_quantity(quantity)
    window_start, window_end = _window(since, until)
    limit = _numeric_limit(get_entitlements(tenant_id), metric)

    def _business(session: Session) -> dict[str, object]:
        result = _consume_quota_in_session(
            session, tenant_id, metric, quantity, limit, window_start, window_end
        )
        return {
            "metric": result.metric,
            "used": str(result.used),
            "limit": str(result.limit) if result.limit is not None else None,
            "exceeded": result.exceeded,
        }

    is_replay, stored = run_idempotent(
        tenant_id,
        "usage.consume_quota",
        idempotency_key,
        {"metric": metric, "quantity": str(quantity)},
        _business,
    )
    result = QuotaCheckResult(
        metric=str(stored["metric"]),
        used=Decimal(str(stored["used"])),
        limit=Decimal(str(stored["limit"])) if stored["limit"] is not None else None,
        exceeded=bool(stored["exceeded"]),
    )
    return is_replay, result
