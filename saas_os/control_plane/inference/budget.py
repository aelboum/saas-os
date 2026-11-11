"""The monthly monetary AI budget: reserve, then settle (ADR-0054 amendment of
2026-11-10; Gap 21b, stage 5; owner decisions of 2026-11-09).

**What it limits.** Estimated platform spend: tokens (and the other billable
units a price defines) times the operator's listed rates, in one currency.
It is not a provider invoice and is never presented as one; the provider's
invoice can differ (Gap 21 section 12). The control is on the platform's own
estimate.

**The effective monthly limit** of a tenant, in one currency, is built from
three parts, each optional:

- the **plan budget**: for every entitlement-granting subscription
  (`saas_os.core.billing.entitlement_plan_ids`), the plan's budget version in
  effect (`control_plane.ai_plan_budgets`); with several plans, the largest
  amount, all in one currency (plans in two currencies refuse with
  `budget_currency_conflict`, owner decision 4: no conversion). The plan part
  is frozen in the month's period row at first use and afterwards only ever
  lowered: a later, lower plan budget applies at once, a higher one from the
  next month (owner decision 10: plan limits are hard upper bounds);
- a platform operator's **override** (`ai_budget_overrides`), while active and
  before it expires: it replaces the plan part, so it can raise the budget
  above the plan (owner decision 3);
- the tenant's own **cap** (`ai_tenant_budgets`): the limit is never above it,
  so a tenant can lower its budget and never raise it.

A tenant with none of the three has no budget: it is admitted on the token
quota alone, exactly as before this stage, unless
`AI_INFERENCE_BUDGET_REQUIRED=true`, which refuses it (`budget_not_configured`).

**Admission (reserve).** In the transaction that starts an attempt
(`service._begin_attempt`), after the attempt row is inserted and before
anything is sent: read the budget's parts (a tenant with none stops here, with
no lock taken), take the tenant's budget lock (a transaction-level advisory
lock), lock or create the month's period row, resolve the price of the
attempt's model in effect *now* (the database clock), refuse unless it is
fresh (`accounting.price_status`, 24 hours from `reviewed_at`) and in the
budget's currency (`budget_pricing_unavailable`), compute the attempt's worst
case (`worst_case_cost`) and refuse if `settled + retained + reserved + worst
case` would exceed the limit (`monthly_budget_exhausted`). Otherwise the
worst case is added to `reserved` and a `held` reservation row records it,
with the price version. A refusal rolls the transaction back, so the attempt
row is not written and nothing is sent. Every refusal is
`InferenceQuotaExceededError` with one of the reasons above (or
`budget_unavailable` for data that cannot be read); it writes no audit row,
like the token quota.

Because every admission of a tenant runs under the same lock and reads the
committed amounts, two attempts can never both be admitted when only one
fits.

**Settlement.** In the attempt's settlement transaction (after its row lock,
so a reservation is resolved exactly once):

- success with provider-reported usage: the cost is estimated with the
  reservation's price version (not the one in effect at settlement), moved
  from `reserved` to `settled`. It can be above the worst case only if the
  provider reported more tokens than the worst case allows; that excess is
  recorded and can take the month past its limit (the next admission then
  refuses);
- success with estimated usage (the provider reported none): the worst case
  is settled, or the estimate if it is higher;
- a cost that cannot be estimated (a used unit the price has no rate for):
  the worst case stays charged as `retained` (`expired_unknown`);
- the provider certainly did not accept the request: the reservation is
  released;
- possibly accepted, interrupted, failed in an unknown way, or abandoned by a
  process that died (the stale-attempt sweep): the worst case stays charged
  as `retained` (`expired_unknown`, owner decision 6). Only a platform
  operator can release it (`budget_admin.release_budget_reservation`,
  audited); nothing releases it by time.

A reservation belongs to the month it was made in, whenever it settles.

**Warnings** (Gap 21c, stage 6). A budget can carry warning thresholds:
whole percentages of the limit, 1 to 100, strictly ascending, at most ten.
The tenant's own list (`ai_tenant_budgets.warn_thresholds`, set with its cap)
replaces the plan's (`ai_plan_budgets.warn_thresholds`, of the plan version
that sets the plan part); an empty list means no warnings; none at all means
no warnings (SaaS OS sets no default, owner decision 2). A threshold is
reached when `settled + retained + reserved` (the figure admission compares
with the limit) is above zero and at least that percentage of the limit.

Each threshold is notified at most once per tenant and month: the period
row's `last_threshold_notified` holds the highest threshold notified, and
only a threshold above it can be notified. Notifying a threshold writes, in
the same transaction as the change that reached it, one webhook event
`ai.budget.threshold_crossed` to each of the tenant's webhook subscriptions
(`saas_os.core.webhooks.trigger_event`; owner decision of 2026-11-11) and one
`ai.budget.threshold_crossed` audit row attributed to the caller whose request
reached it. Neither carries an amount: the event and the row give the
threshold, the month and the currency only, because managing webhooks or
reading the audit log does not imply `ai.usage:read`. Delivering the warning
to a person (an email, an inbox item) is the product's job.

Thresholds are checked at admission (after the worst case is reserved, so a
warning can precede the spend it warns about) and at a settlement that adds
more than the attempt reserved. Nothing else raises the figure. The
notification runs in a savepoint: if it fails, the request goes on, nothing of
the notification is kept, `last_threshold_notified` is not advanced, and the
next admission or settlement tries again. A threshold below one already
notified this month is never notified (a list changed mid-month starts from
where the month is). A new month starts with nothing notified.

**Not implemented here** (later stages): automatic holds (owner decision 11:
refusal only) and any HTTP surface.
"""

from __future__ import annotations

import enum
import logging
import os
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_CEILING, Decimal

from saas_os.control_plane.inference.accounting import (
    CostEstimate,
    PriceStatus,
    estimate_cost,
    month_window,
    price_in_effect,
    price_status,
)
from saas_os.control_plane.inference.budget_models import (
    AIBudgetOverride,
    AIBudgetPeriod,
    AIBudgetReservation,
    AIPlanBudget,
    AITenantBudget,
    ReservationState,
)
from saas_os.control_plane.inference.config.models import AIModelPrice
from saas_os.control_plane.inference.errors import (
    InferenceInternalError,
    InferenceQuotaExceededError,
)
from saas_os.core.audit_log import record_in_transaction
from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.webhooks import trigger_event
from saas_os.infra.db import Session, acquire_tenant_advisory_lock, now, select

logger = logging.getLogger(__name__)

_MILLION = Decimal(1_000_000)
_QUANTUM = Decimal("0.00000001")
_LOCK_KEY = "ai_budget"
_REQUIRED_SETTING = "AI_INFERENCE_BUDGET_REQUIRED"
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"", "0", "false", "no", "off"})

# Refusal reasons (closed set; `InferenceQuotaExceededError.reason`).
EXHAUSTED = "monthly_budget_exhausted"
PRICING_UNAVAILABLE = "budget_pricing_unavailable"
CURRENCY_CONFLICT = "budget_currency_conflict"
UNAVAILABLE = "budget_unavailable"
NOT_CONFIGURED = "budget_not_configured"
BUDGET_REASONS = frozenset(
    {EXHAUSTED, PRICING_UNAVAILABLE, CURRENCY_CONFLICT, UNAVAILABLE, NOT_CONFIGURED}
)

# Warnings (Gap 21c; module docstring, "Warnings").
THRESHOLD_EVENT = "ai.budget.threshold_crossed"
THRESHOLD_ACTION = "ai.budget.threshold_crossed"
MAX_THRESHOLDS = 10
_RESOURCE_BUDGET = "ai_budget"
_BASIS = "estimated_platform_spend"


class InvalidThresholdsError(ValueError):
    """A warning threshold list that is not 1 to 10 whole percentages from 1
    to 100 in strictly ascending order."""


def parse_thresholds(value: object) -> tuple[int, ...] | None:
    """A stored or supplied threshold list as a tuple, None for none.
    Raises `InvalidThresholdsError` for anything but a list (or tuple) of at
    most `MAX_THRESHOLDS` integers (never booleans), each 1 to 100, strictly
    ascending. An empty list is valid: no warnings."""
    if value is None:
        return None
    if not isinstance(value, list | tuple) or len(value) > MAX_THRESHOLDS:
        raise InvalidThresholdsError("thresholds")
    previous = 0
    for item in value:
        if type(item) is not int or not previous < item <= 100:
            raise InvalidThresholdsError("thresholds")
        previous = item
    return tuple(value)


def budget_required(env: Mapping[str, str] | None = None) -> bool:
    """`AI_INFERENCE_BUDGET_REQUIRED`: whether a tenant without a budget is
    refused. Default false (compatibility); the owner's production rule is ON
    whenever AI is enabled (decision 8). A value that is neither true nor
    false refuses (`InferenceInternalError`): a typo must not silently turn
    the requirement off."""
    raw = (os.environ if env is None else env).get(_REQUIRED_SETTING, "")
    normalized = raw.strip().lower()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise InferenceInternalError("invalid_ai_inference_budget_required")


def database_time(session: Session) -> datetime:
    """The database's clock, in UTC: the one clock admission uses for the
    month, price staleness and override expiry (the outbox precedent,
    `core/outbox/dispatch.py`), so hosts whose clocks differ agree."""
    return session.execute(select(now())).scalar_one().astimezone(UTC)


def _refuse(reason: str) -> InferenceQuotaExceededError:
    logger.info("ai_inference_budget_refused", extra={"ai_reason": reason})
    return InferenceQuotaExceededError(reason)


# --- the effective limit --------------------------------------------------------------


@dataclass(frozen=True)
class BudgetParts:
    """The three optional parts of a tenant's limit, as read at one moment.
    Amounts are `Decimal` in `currency`; `currency` is None when no part
    exists."""

    currency: str | None
    plan: Decimal | None
    plan_version: str | None
    override: Decimal | None
    override_expires_at: datetime | None
    cap: Decimal | None
    # The warning thresholds in force (module docstring, "Warnings"); None or
    # empty: no warnings.
    thresholds: tuple[int, ...] | None = None

    @property
    def configured(self) -> bool:
        return self.plan is not None or self.override is not None or self.cap is not None


class BudgetSource(enum.StrEnum):
    PLAN = "plan"
    OVERRIDE = "override"
    TENANT_CAP = "tenant_cap"


def plan_budget_in_effect(
    session: Session, plan_id: uuid.UUID, at: datetime
) -> AIPlanBudget | None:
    return session.execute(
        select(AIPlanBudget)
        .where(AIPlanBudget.plan_id == plan_id, AIPlanBudget.effective_from <= at)
        .order_by(AIPlanBudget.effective_from.desc(), AIPlanBudget.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def read_parts(
    session: Session, tenant_id: uuid.UUID, plan_ids: Sequence[uuid.UUID], at: datetime
) -> BudgetParts:
    """Read the three parts in the caller's tenant transaction. Raises
    `InferenceQuotaExceededError(budget_currency_conflict)` when the parts
    that exist are not all in one currency."""
    currencies: set[str] = set()
    plan: Decimal | None = None
    plan_version: str | None = None
    plan_thresholds: object = None
    for plan_id in dict.fromkeys(plan_ids):
        row = plan_budget_in_effect(session, plan_id, at)
        if row is None or row.monthly_amount is None or row.currency is None:
            continue
        currencies.add(row.currency)
        if plan is None or row.monthly_amount > plan:
            plan, plan_version = row.monthly_amount, row.budget_version
            plan_thresholds = row.warn_thresholds
    override_row = session.execute(
        select(AIBudgetOverride).where(AIBudgetOverride.target_tenant_id == tenant_id)
    ).scalar_one_or_none()
    override: Decimal | None = None
    expires: datetime | None = None
    if override_row is not None and override_row.active and override_row.expires_at > at:
        override, expires = override_row.amount, override_row.expires_at
        currencies.add(override_row.currency)
    cap_row = session.execute(
        select(AITenantBudget).where(AITenantBudget.tenant_id == tenant_id)
    ).scalar_one_or_none()
    cap: Decimal | None = None
    if cap_row is not None and cap_row.cap_amount is not None:
        cap = cap_row.cap_amount
        currencies.add(cap_row.currency)
    if len(currencies) > 1:
        raise _refuse(CURRENCY_CONFLICT)
    # The tenant's own list, when it has set one, replaces the plan's.
    stored = (
        cap_row.warn_thresholds
        if cap_row is not None and cap_row.warn_thresholds is not None
        else plan_thresholds
    )
    try:
        thresholds = parse_thresholds(stored)
    except InvalidThresholdsError:
        # Written only through validation; anything else is unreadable data.
        raise _refuse(UNAVAILABLE) from None
    return BudgetParts(
        currency=next(iter(currencies), None),
        plan=plan,
        plan_version=plan_version,
        override=override,
        override_expires_at=expires,
        cap=cap,
        thresholds=thresholds,
    )


def _lowest(*values: Decimal | None) -> Decimal | None:
    present = [v for v in values if v is not None]
    return min(present) if present else None


def effective_limit(
    parts: BudgetParts, frozen_plan: Decimal | None
) -> tuple[Decimal | None, BudgetSource | None]:
    """The limit and the part that sets it. The plan part is the lower of the
    frozen and the current plan budget; an active override replaces it; the
    tenant's cap is never exceeded."""
    plan_part = _lowest(frozen_plan, parts.plan)
    base, source = (
        (parts.override, BudgetSource.OVERRIDE)
        if parts.override is not None
        else (plan_part, BudgetSource.PLAN if plan_part is not None else None)
    )
    if parts.cap is not None and (base is None or parts.cap < base):
        return parts.cap, BudgetSource.TENANT_CAP
    return base, source


# --- worst case -----------------------------------------------------------------------


def worst_case_cost(price: AIModelPrice, *, input_bytes: int, max_output_tokens: int) -> Decimal:
    """The most one attempt can cost under `price`, rounded **up** at 1e-8.

    Input: at most one token per input byte (every token of text covers at
    least one byte), priced at the highest input-side rate the price defines
    (input, cached input, cache write), since the provider decides which of
    them applies. Output: `max_output_tokens` at the output rate. Plus the
    amount per request. Tokens a provider adds on its own (a chat template)
    are not covered: a provider that reports more than this is settled at
    what it reported, and the excess is recorded (module docstring)."""
    input_rate = max(
        price.input_per_million,
        price.cached_input_per_million or Decimal(0),
        price.cache_write_per_million or Decimal(0),
    )
    amount = (
        Decimal(max(1, input_bytes)) * input_rate
        + Decimal(max_output_tokens) * price.output_per_million
    ) / _MILLION
    if price.per_request is not None:
        amount += price.per_request
    return amount.quantize(_QUANTUM, rounding=ROUND_CEILING)


# --- admission ------------------------------------------------------------------------


def _locked_period(
    session: Session,
    tenant_id: uuid.UUID,
    period_start: datetime,
    currency: str,
    plan: Decimal | None,
) -> AIBudgetPeriod:
    """The month's period row, locked, created with the plan part frozen at
    first use. Called under the tenant's budget lock, so creation does not
    race."""
    period = session.execute(
        select(AIBudgetPeriod)
        .where(AIBudgetPeriod.tenant_id == tenant_id, AIBudgetPeriod.period_start == period_start)
        .with_for_update()
    ).scalar_one_or_none()
    if period is None:
        period = AIBudgetPeriod(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            period_start=period_start,
            currency=currency,
            plan_limit=plan,
            reserved=Decimal(0),
            retained=Decimal(0),
            settled=Decimal(0),
        )
        session.add(period)
        session.flush()
        return period
    if period.currency != currency:
        raise _refuse(CURRENCY_CONFLICT)
    lowered = _lowest(period.plan_limit, plan)
    if lowered != period.plan_limit:
        period.plan_limit = lowered
    return period


# --- warnings -------------------------------------------------------------------------


def _used(period: AIBudgetPeriod) -> Decimal:
    return period.settled + period.retained + period.reserved


def thresholds_reached(
    thresholds: Sequence[int] | None, *, used: Decimal, limit: Decimal
) -> tuple[int, ...]:
    """The thresholds `used` has reached against `limit`, ascending. Nothing
    is reached while nothing is used."""
    if not thresholds or used <= 0:
        return ()
    return tuple(t for t in thresholds if used * 100 >= limit * t)


def notify_thresholds(
    session: Session,
    tenant_id: uuid.UUID,
    period: AIBudgetPeriod,
    *,
    limit: Decimal,
    thresholds: Sequence[int] | None,
    caller: UserCaller | ServiceAccountCaller,
    trigger: str,
) -> tuple[int, ...]:
    """Notify every threshold reached and not yet notified this month (module
    docstring, "Warnings"), in the caller's transaction, which holds the
    period row's lock. Returns the thresholds notified. A failure is logged
    and leaves nothing behind (savepoint); it never fails the caller."""
    last = period.last_threshold_notified or 0
    due = tuple(
        t for t in thresholds_reached(thresholds, used=_used(period), limit=limit) if t > last
    )
    if not due:
        return ()
    month = period.period_start.astimezone(UTC).isoformat()
    try:
        with session.begin_nested():
            for threshold in due:
                facts: dict[str, object] = {
                    "threshold_percent": threshold,
                    "period_start": month,
                    "currency": period.currency,
                    "basis": _BASIS,
                }
                trigger_event(session, tenant_id, THRESHOLD_EVENT, dict(facts))
                record_in_transaction(
                    session,
                    caller=caller,
                    tenant_id=tenant_id,
                    action=THRESHOLD_ACTION,
                    resource_type=_RESOURCE_BUDGET,
                    resource_id=str(tenant_id),
                    metadata={**facts, "trigger": trigger},
                )
            period.last_threshold_notified = due[-1]
            session.flush()
    except Exception as exc:  # noqa: BLE001 -- a warning never fails the request
        logger.warning(
            "ai_budget_threshold_notification_failed",
            extra={"error_type": type(exc).__name__},
        )
        return ()
    return due


@dataclass(frozen=True)
class Reservation:
    id: uuid.UUID
    amount: Decimal
    currency: str
    pricing_version: str


def reserve(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    plan_ids: Sequence[uuid.UUID],
    model_ref: uuid.UUID,
    input_bytes: int,
    max_output_tokens: int,
    attempt_id: uuid.UUID,
    request_id: uuid.UUID,
    attempt_number: int,
    required: bool,
    caller: UserCaller | ServiceAccountCaller,
) -> Reservation | None:
    """Admit one attempt against the tenant's budget in the caller's
    transaction (module docstring, "Admission"), after the attempt row is
    flushed, and notify the warning thresholds the reservation reaches
    ("Warnings", attributed to `caller`). None: the tenant has no budget and
    none is required. A refusal raises `InferenceQuotaExceededError`; the
    caller's transaction must then roll back."""
    at = database_time(session)
    parts = read_parts(session, tenant_id, plan_ids, at)
    if not parts.configured:
        if required:
            raise _refuse(NOT_CONFIGURED)
        return None
    # Only a tenant with a budget serializes its attempt starts. The parts are
    # not written under this lock, so reading them first changes nothing.
    acquire_tenant_advisory_lock(session, tenant_id, _LOCK_KEY)
    currency = parts.currency
    assert currency is not None  # configured implies a currency
    period_start, _ = month_window(at)
    period = _locked_period(session, tenant_id, period_start, currency, parts.plan)
    limit, _source = effective_limit(parts, period.plan_limit)
    if limit is None:  # pragma: no cover -- configured implies a limit
        raise _refuse(UNAVAILABLE)
    price = price_in_effect(session, model_ref, at)
    if price is None or price_status(price, at=at) is not PriceStatus.FRESH:
        raise _refuse(PRICING_UNAVAILABLE)
    if price.currency != currency:
        raise _refuse(PRICING_UNAVAILABLE)
    worst = worst_case_cost(price, input_bytes=input_bytes, max_output_tokens=max_output_tokens)
    if period.settled + period.retained + period.reserved + worst > limit:
        raise _refuse(EXHAUSTED)
    period.reserved += worst
    reservation = AIBudgetReservation(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        period_id=period.id,
        attempt_id=attempt_id,
        request_id=request_id,
        attempt_number=attempt_number,
        price_id=price.id,
        currency=currency,
        amount=worst,
        state=ReservationState.HELD.value,
    )
    session.add(reservation)
    session.flush()
    notify_thresholds(
        session,
        tenant_id,
        period,
        limit=limit,
        thresholds=parts.thresholds,
        caller=caller,
        trigger="admission",
    )
    return Reservation(reservation.id, worst, currency, price.pricing_version)


# --- settlement -----------------------------------------------------------------------


class Resolution(enum.StrEnum):
    """How settlement resolves a held reservation."""

    SETTLE = "settle"  # a known estimated cost
    RELEASE = "release"  # certainly not accepted
    UNKNOWN = "unknown"  # worst case stays charged


def held_reservation(session: Session, attempt_id: uuid.UUID) -> AIBudgetReservation | None:
    """The attempt's reservation, locked, if it is still held."""
    row = session.execute(
        select(AIBudgetReservation)
        .where(AIBudgetReservation.attempt_id == attempt_id)
        .with_for_update()
    ).scalar_one_or_none()
    if row is None or row.state != ReservationState.HELD.value:
        return None
    return row


def reservation_price(session: Session, reservation: AIBudgetReservation) -> AIModelPrice | None:
    return session.get(AIModelPrice, reservation.price_id)


def resolve(
    session: Session,
    reservation: AIBudgetReservation,
    resolution: Resolution,
    *,
    at: datetime,
    cost: Decimal | None = None,
) -> None:
    """Move a held reservation out of `reserved` (caller holds its lock and
    has checked it is held). SETTLE needs `cost`."""
    period = session.execute(
        select(AIBudgetPeriod).where(AIBudgetPeriod.id == reservation.period_id).with_for_update()
    ).scalar_one()
    period.reserved = max(Decimal(0), period.reserved - reservation.amount)
    if resolution is Resolution.SETTLE:
        assert cost is not None
        period.settled += cost
        reservation.state = ReservationState.SETTLED.value
        reservation.settled_amount = cost
    elif resolution is Resolution.RELEASE:
        reservation.state = ReservationState.RELEASED.value
    else:
        period.retained += reservation.amount
        reservation.state = ReservationState.EXPIRED_UNKNOWN.value
    reservation.resolved_at = at
    session.flush()


def settle_success(
    session: Session,
    reservation: AIBudgetReservation,
    *,
    at: datetime,
    provenance: str,
    input_tokens: int | None,
    output_tokens: int | None,
    cached_input_tokens: int | None,
    cache_write_tokens: int | None,
) -> CostEstimate | None:
    """Settle a successful attempt with the reservation's price version and
    return the cost estimate to record on the attempt (None: unknown)."""
    price = reservation_price(session, reservation)
    cost = estimate_cost(
        price,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_input_tokens=cached_input_tokens,
        cache_write_tokens=cache_write_tokens,
    )
    if cost is None:
        resolve(session, reservation, Resolution.UNKNOWN, at=at)
    elif provenance == "provider_reported":
        resolve(session, reservation, Resolution.SETTLE, at=at, cost=cost.amount)
    else:
        resolve(
            session,
            reservation,
            Resolution.SETTLE,
            at=at,
            cost=max(cost.amount, reservation.amount),
        )
    return cost


def notify_after_settlement(
    session: Session,
    reservation: AIBudgetReservation,
    *,
    plan_ids: Sequence[uuid.UUID],
    caller: UserCaller | ServiceAccountCaller,
) -> tuple[int, ...]:
    """After `settle_success`: when the settled cost is above what the
    attempt reserved (the only way settlement raises the month's figure),
    notify the thresholds now reached ("Warnings"). The limit is the one in
    force now, built with the period's frozen plan part. Any failure is
    logged and leaves nothing behind; settlement is never failed by it."""
    if (
        reservation.state != ReservationState.SETTLED.value
        or reservation.settled_amount is None
        or reservation.settled_amount <= reservation.amount
    ):
        return ()
    try:
        with session.begin_nested():
            period = session.execute(
                select(AIBudgetPeriod)
                .where(AIBudgetPeriod.id == reservation.period_id)
                .with_for_update()
            ).scalar_one()
            parts = read_parts(session, reservation.tenant_id, plan_ids, database_time(session))
            limit, _ = effective_limit(parts, period.plan_limit)
            if limit is None or parts.currency != period.currency:
                return ()
    except Exception as exc:  # noqa: BLE001 -- a warning never fails settlement
        logger.warning(
            "ai_budget_threshold_notification_failed",
            extra={"error_type": type(exc).__name__},
        )
        return ()
    return notify_thresholds(
        session,
        reservation.tenant_id,
        period,
        limit=limit,
        thresholds=parts.thresholds,
        caller=caller,
        trigger="settlement",
    )


def expire_unknown(session: Session, attempt_ids: Sequence[uuid.UUID], *, at: datetime) -> int:
    """Mark the held reservations of `attempt_ids` (attempts the stale sweep
    just abandoned) `expired_unknown`: the worst case stays charged."""
    if not attempt_ids:
        return 0
    rows = (
        session.execute(
            select(AIBudgetReservation)
            .where(
                AIBudgetReservation.attempt_id.in_(list(attempt_ids)),
                AIBudgetReservation.state == ReservationState.HELD.value,
            )
            .order_by(AIBudgetReservation.id)
            .with_for_update()
        )
        .scalars()
        .all()
    )
    for row in rows:
        resolve(session, row, Resolution.UNKNOWN, at=at)
    return len(rows)


# --- status (read) --------------------------------------------------------------------


class BudgetState(enum.StrEnum):
    UNCONFIGURED = "unconfigured"
    OK = "ok"
    WARNING = "warning"
    EXHAUSTED = "exhausted"
    CURRENCY_CONFLICT = "currency_conflict"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class BudgetStatus:
    """The tenant's budget in the current UTC month. Amounts are **estimated
    platform spend** in `currency`, never invoice amounts. `retained` is the
    worst case kept for attempts whose outcome is unknown. `remaining` is the
    limit less settled, retained and reserved, never below zero. `state` is
    `unconfigured` (no budget; amounts None), `ok`, `warning` (a warning
    threshold is reached and something remains), `exhausted` (nothing
    remains), `currency_conflict` or `unavailable` (data could not be read).
    `warn_thresholds` are the thresholds in force (empty: none);
    `threshold_reached` is the highest of them reached now, None if none (it
    can be below a threshold already notified this month, after a release)."""

    state: str
    currency: str | None = None
    limit: Decimal | None = None
    source: str | None = None
    settled: Decimal | None = None
    reserved: Decimal | None = None
    retained: Decimal | None = None
    remaining: Decimal | None = None
    period_start: datetime | None = None
    override_expires_at: datetime | None = None
    basis: str = _BASIS
    warn_thresholds: tuple[int, ...] = ()
    threshold_reached: int | None = None


def budget_status(
    session: Session, tenant_id: uuid.UUID, plan_ids: Sequence[uuid.UUID]
) -> BudgetStatus:
    """Read-only status in the caller's tenant transaction. Never creates a
    period row."""
    at = database_time(session)
    try:
        parts = read_parts(session, tenant_id, plan_ids, at)
    except InferenceQuotaExceededError as refused:
        state = (
            BudgetState.CURRENCY_CONFLICT
            if refused.reason == CURRENCY_CONFLICT
            else BudgetState.UNAVAILABLE
        )
        return BudgetStatus(state.value)
    if not parts.configured:
        return BudgetStatus(BudgetState.UNCONFIGURED.value)
    period_start, _ = month_window(at)
    period = session.execute(
        select(AIBudgetPeriod).where(
            AIBudgetPeriod.tenant_id == tenant_id, AIBudgetPeriod.period_start == period_start
        )
    ).scalar_one_or_none()
    if period is not None and period.currency != parts.currency:
        return BudgetStatus(BudgetState.CURRENCY_CONFLICT.value)
    frozen = period.plan_limit if period is not None else None
    limit, source = effective_limit(parts, frozen)
    zero = Decimal(0).quantize(_QUANTUM)
    settled = period.settled if period is not None else zero
    reserved = period.reserved if period is not None else zero
    retained = period.retained if period is not None else zero
    assert limit is not None
    remaining = max(zero, limit - settled - reserved - retained)
    reached = thresholds_reached(parts.thresholds, used=settled + reserved + retained, limit=limit)
    if remaining <= 0:
        state = BudgetState.EXHAUSTED
    elif reached:
        state = BudgetState.WARNING
    else:
        state = BudgetState.OK
    return BudgetStatus(
        state=state.value,
        warn_thresholds=parts.thresholds or (),
        threshold_reached=reached[-1] if reached else None,
        currency=parts.currency,
        limit=limit,
        source=source.value if source is not None else None,
        settled=settled,
        reserved=reserved,
        retained=retained,
        remaining=remaining,
        period_start=period_start,
        override_expires_at=parts.override_expires_at,
    )
