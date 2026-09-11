"""Usage ingestion, on-demand aggregation, and quota checking
(docs/IMPLEMENTATION-ROADMAP.md Phase 5.2).

`ingest_event()` enqueues persistence through `infra.jobs`, mirroring
`core/notifications/service.py::dispatch_notification()` and
`core/webhooks/service.py::trigger_event()` exactly -- the same
"genuinely single-step-retryable" job shape
(`docs/ADR/0007-background-job-and-workflow-engine.md`), reused here
rather than reinvented; ingestion must never block a caller on a
database write. `core/usage` owns the job *handler*
(`_ingest_usage_event_job`, registered via `infra.jobs.register_job` and
exported as `USAGE_JOB_FUNCTIONS` for a worker process to register);
`infra/jobs` owns the generic retry-count/dead-letter execution metadata
(docs/DATA-ARCHITECTURE.md section 5).

`aggregate_usage()` computes a `SUM` over raw `core.usage_events` rows
on-demand, every call -- no cached/materialized aggregate table exists.
This directly satisfies the roadmap's own Rollback Strategy ("aggregation
can be recomputed from raw events; raw events are the source of truth"):
there is no derived state to invalidate or repair after a rollback,
because none is ever persisted.

`check_quota()` is the one place `core/usage` reads `core/billing` --
combining `core.billing.service.get_entitlements()` (the existing,
already-tested plan -> entitlement lookup) with `aggregate_usage()`.
`core/usage` has no independent notion of a "limit"; it only asks
`core/billing` what the tenant's plan currently allows for a given
metric key. No Stripe-specific coupling exists here or anywhere else in
this module -- `core/billing` already isolates that behind its own
provider abstraction.

`metric` is a plain string that deliberately reuses `Plan.entitlements`'
own key vocabulary (`core/usage/models.py`'s own docstring) -- no
separate metric catalog/enum is introduced.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from arq.worker import Function

from core.idempotency import run_idempotent
from core.tenancy import get_descendant_ids
from core.usage.errors import InvalidUsageEventError, QuotaExceededError, UsageIngestionError
from core.usage.models import UsageEvent
from infra.db import Session, acquire_tenant_advisory_lock, func, select, tenant_session_scope
from infra.jobs import TenantJobPayload, enqueue_job, register_job

_MAX_METRIC_LENGTH = 100


def _validate_metric(metric: str) -> None:
    if not metric or not metric.strip():
        raise InvalidUsageEventError("metric must be a non-empty string.")
    if len(metric) > _MAX_METRIC_LENGTH:
        raise InvalidUsageEventError(f"metric exceeds {_MAX_METRIC_LENGTH} characters.")


def _validate_quantity(quantity: Decimal) -> None:
    if quantity < 0:
        raise InvalidUsageEventError("quantity must not be negative.")


# --- Ingestion (async, job-queued) ---------------------------------------


async def ingest_event(
    tenant_id: uuid.UUID,
    metric: str,
    quantity: Decimal,
    *,
    occurred_at: datetime | None = None,
    queue_name: str | None = None,
) -> str:
    """Enqueue persistence of one usage event for `tenant_id`. Returns the
    arq job ID -- persistence itself happens asynchronously via
    `infra.jobs`; this function does not block on a database write.

    `occurred_at` defaults to "now" (UTC) when not supplied. Validation
    (`metric`/`quantity`) happens here, before enqueueing, so an invalid
    call fails immediately rather than surfacing later as a dead-lettered
    job.

    `queue_name` is a thin passthrough to `infra.jobs.enqueue_job()`'s own
    parameter of the same name, for test isolation (mirrors
    `core/notifications/service.py::dispatch_notification`'s identical
    parameter).
    """
    _validate_metric(metric)
    _validate_quantity(quantity)
    event_occurred_at = occurred_at or datetime.now(UTC)

    return await enqueue_job(
        _ingest_usage_event_job.__name__,
        TenantJobPayload(
            tenant_id=str(tenant_id),
            data={
                "metric": metric,
                "quantity": str(quantity),
                "occurred_at": event_occurred_at.isoformat(),
            },
        ),
        queue_name=queue_name,
    )


async def _ingest_usage_event_job(payload: TenantJobPayload | None) -> None:
    """The registered job handler: insert one `UsageEvent` row. Raises
    `UsageIngestionError` on failure so `infra.jobs`' own wrapper
    (`register_job`) retries with backoff, then dead-letters on
    exhaustion -- this function never implements retry/backoff itself.
    """
    if payload is None:
        raise ValueError("_ingest_usage_event_job requires a TenantJobPayload, got None.")

    tenant_id = uuid.UUID(payload.tenant_id)
    metric = payload.data["metric"]
    quantity = Decimal(payload.data["quantity"])
    occurred_at = datetime.fromisoformat(payload.data["occurred_at"])

    try:
        with tenant_session_scope(tenant_id) as session:
            event = UsageEvent(
                tenant_id=tenant_id,
                metric=metric,
                quantity=quantity,
                occurred_at=occurred_at,
            )
            session.add(event)
            session.flush()
    except Exception as exc:
        raise UsageIngestionError(tenant_id, metric, type(exc).__name__) from exc


USAGE_JOB_FUNCTIONS: list[Function] = [register_job(_ingest_usage_event_job)]


# --- Aggregation (on-demand, never cached) --------------------------------


def aggregate_usage(
    tenant_id: uuid.UUID, metric: str, *, since: datetime, until: datetime
) -> Decimal:
    """Sum `quantity` for `metric` within `[since, until)`, computed by a
    SQL `SUM` over raw `core.usage_events` rows every call -- see module
    docstring for why no cached aggregate table exists. Returns
    `Decimal("0")` when no matching events exist (a documented safe
    default, never an error)."""
    with tenant_session_scope(tenant_id) as session:
        total = session.execute(
            select(func.sum(UsageEvent.quantity)).where(
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
    (`core.tenancy.get_descendant_ids()` -- one indexed read over the
    precomputed `core.tenant_ancestry` closure table, never a recursive
    query), each usage row remaining attributed to whichever tenant
    actually generated it.

    **Usage location and billing ownership are kept separate** (this
    phase's own explicit requirement): this function does NOT consult
    `core.billing`, `resolve_billing_owner()`, or any tenant's
    `inherits_billing` flag -- it is a pure structural-subtree rollup. A
    caller that wants "this billing owner's effective pool" passes
    `core.billing.service.resolve_billing_owner(tenant_id)`'s result as
    `tenant_id` here; a caller that wants "this tenant's own reporting
    rollup regardless of billing" passes the tenant's own id directly.
    Neither usage is moved, retagged, or duplicated: every summed row
    keeps its own original `UsageEvent.tenant_id` forever
    (`core/usage/models.py`'s own immutability docstring) -- this
    function only changes what is *read*, in memory, for one aggregate
    number; it writes nothing.

    **Not RLS-bypassing**: `core.usage_events` remains single-`app.tenant_id`
    RLS-protected (architecture research Phase H section 14: "never
    weaken RLS... never use SECURITY DEFINER"). Reading N tenants' rows
    therefore costs N separate `tenant_session_scope()` queries -- one
    per descendant -- summed here in Python, never one query spanning
    tenants and never a second GUC. `core.tenancy`'s own
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


# --- Quota checking (combines core/billing entitlements + aggregation) ---


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
    `core.billing.service.get_entitlements()` reports for this tenant's
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
    from core.billing.service import get_entitlements

    if since is not None and until is not None:
        window_start, window_end = since, until
    else:
        window_start, window_end = _current_utc_month_window()

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

    **Race safety**: `core/usage`'s existing usage-recording path
    (`ingest_event()`) is asynchronous -- job-queued through `infra.jobs`
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
    writes to (`core/usage/models.py`) -- this path simply writes
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
    if quantity < 0:
        raise InvalidUsageEventError("quantity must not be negative.")

    from core.billing.service import get_entitlements

    if since is not None and until is not None:
        window_start, window_end = since, until
    else:
        window_start, window_end = _current_utc_month_window()

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
    (`core.idempotency.run_idempotent()`) rather than nesting a second,
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
        select(func.sum(UsageEvent.quantity)).where(
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
    `core.idempotency.run_idempotent()` -- the fully atomic, single-
    transaction primitive, not the two-step one `core.billing.service.
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
    unwinds the reservation along with it (`core/idempotency/service.py`'s
    own docstring: a business-logic failure leaves no row behind) -- so a
    quota-exceeded response is never cached; a later retry (e.g. after
    the tenant's window rolls over, or their plan changes) re-checks
    quota fresh, exactly like `consume_quota()` itself already does.

    Returns `(is_replay, result)`.
    """
    from core.billing.service import get_entitlements

    if since is not None and until is not None:
        window_start, window_end = since, until
    else:
        window_start, window_end = _current_utc_month_window()

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
