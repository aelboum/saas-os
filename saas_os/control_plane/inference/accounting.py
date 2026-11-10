"""Usage accounting: cost estimates and the soft token quota (ADR-0054
section 7; Phase AI-F; AI-INFERENCE-CONTRACTS section 7).

**Cost estimates.** At settlement an attempt whose token counts are known
(`provider_reported` or `estimated`) is priced with the model's price version
in effect at that moment (`control_plane.ai_model_prices`). The estimate, its
currency and its `pricing_version` are stored on the attempt and returned in
the usage report. It is an estimate, never a billed amount; with no price
configured, or unknown usage, nothing is estimated (never zero).

**Billable units (Gap 21a).** Besides input, output and cached input, a price
may carry a cache-write rate, a flat amount per provider request and rates of
other billable units (`unit_rates`). A unit the attempt used that the price
has no rate for makes the cost unknown: nothing is estimated, and the cost is
never recorded as zero or as a part of the amount.

**Price staleness (Gap 21a).** A price is current for at most 24 hours after
a platform operator last confirmed it (`reviewed_at`); a deployment may
shorten that with `AI_PRICE_MAX_AGE_SECONDS`, never lengthen it.
`price_status` classifies a price as fresh, stale, unverifiable (never
confirmed, or confirmed in the future) or missing. It decides nothing by
itself: no request is refused on it until the spend-limit stage (Gap 21b)
calls it at admission, and a settled attempt is priced whatever the status.

**Soft token quota.** A tenant's plan may carry the numeric entitlement
`ai.tokens` -- a monthly (UTC calendar month) limit on input plus output
tokens. Admission refuses a request whose recorded usage this month, plus an
estimate of its input and its full `max_output_tokens`, would exceed the
limit (`InferenceQuotaExceededError`). It is **soft**: concurrent requests are
checked against the same recorded usage and can together overshoot, and
usage of attempts still in flight, or unknown, is not counted. It is not a
hard ceiling and is never documented as one (decision: soft quotas; Q8
records the hard-cap requirements).

With `AI_INFERENCE_TOKEN_QUOTA_REQUIRED=true` a tenant whose plan has no
`ai.tokens` limit is refused, so a deployment that requires a limit never
runs unlimited by omission. A present but malformed `ai.tokens` (not a
non-negative integer) always refuses (`quota_invalid`, owner ruling
2026-10-31), so a typo in a plan never reads as unlimited. Unreadable
entitlement or ledger data always refuses.
"""

from __future__ import annotations

import enum
import logging
import math
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

from saas_os.control_plane.inference.attempts import AIInferenceAttempt
from saas_os.control_plane.inference.config.models import AIModelPrice, decode_unit_rates
from saas_os.control_plane.inference.errors import (
    InferenceInternalError,
    InferenceQuotaExceededError,
)
from saas_os.core.billing import get_entitlements
from saas_os.infra.db import Session, select, sum_, tenant_session_scope

TOKEN_QUOTA_ENTITLEMENT = "ai.tokens"

logger = logging.getLogger(__name__)
_MILLION = Decimal(1_000_000)
_COST_QUANTUM = Decimal("0.00000001")


@dataclass(frozen=True)
class CostEstimate:
    amount: Decimal
    currency: str
    pricing_version: str


def price_in_effect(session: Session, model_ref: uuid.UUID, at: datetime) -> AIModelPrice | None:
    return session.execute(
        select(AIModelPrice)
        .where(AIModelPrice.model_ref == model_ref, AIModelPrice.effective_from <= at)
        .order_by(AIModelPrice.effective_from.desc(), AIModelPrice.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def estimate_cost(
    price: AIModelPrice | None,
    *,
    input_tokens: int | None,
    output_tokens: int | None,
    cached_input_tokens: int | None = None,
    cache_write_tokens: int | None = None,
    other_units: Mapping[str, int] | None = None,
) -> CostEstimate | None:
    """Estimated platform spend of one provider request, never an amount a
    provider invoices.

    Token rates are per million tokens. Cached input is priced at its own rate
    when the price has one (otherwise as ordinary input). Cache-write tokens
    are a count of their own, priced at the cache-write rate. `per_request`,
    when the price has one, is added once. `other_units` maps a billable unit
    name to the quantity used, priced at the unit's rate in `unit_rates`.

    None (cost unknown, never zero) when no price is configured, when the
    input or output count is unknown, or when the attempt used a unit the
    price has no rate for: cache-write tokens without a cache-write rate, or
    another unit without a usable rate. A quantity that is not a non-negative
    integer is unknown as well."""
    if price is None or input_tokens is None or output_tokens is None:
        return None
    cached = cached_input_tokens or 0
    if price.cached_input_per_million is None:
        cached_cost = Decimal(0)
        plain_input = input_tokens
    else:
        cached = min(cached, input_tokens)
        cached_cost = Decimal(cached) * price.cached_input_per_million
        plain_input = input_tokens - cached
    per_million = (
        Decimal(plain_input) * price.input_per_million
        + Decimal(output_tokens) * price.output_per_million
        + cached_cost
    )
    cache_write = cache_write_tokens or 0
    if cache_write > 0:
        if price.cache_write_per_million is None:
            return None
        per_million += Decimal(cache_write) * price.cache_write_per_million
    amount = per_million / _MILLION
    if price.per_request is not None:
        amount += price.per_request
    if other_units:
        rates = decode_unit_rates(price.unit_rates)
        for name, quantity in other_units.items():
            if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 0:
                return None
            if quantity == 0:
                continue
            rate = rates.get(name)
            if rate is None:
                return None
            amount += Decimal(quantity) * rate
    return CostEstimate(
        amount=amount.quantize(_COST_QUANTUM, rounding=ROUND_HALF_UP),
        currency=price.currency,
        pricing_version=price.pricing_version,
    )


class PriceStatus(enum.StrEnum):
    """Whether a price may be relied on at a moment. Only `FRESH` may."""

    FRESH = "fresh"
    # Last confirmed longer ago than the maximum price age.
    STALE = "stale"
    # Never confirmed, or confirmed at a time that has not happened yet.
    UNVERIFIABLE = "unverifiable"
    # The model has no price in effect.
    MISSING = "missing"


# The owner's limit (ADR-0054 section 12e, 2026-11-09). A deployment setting
# can shorten it and nothing can lengthen it.
PRICE_MAX_AGE = timedelta(hours=24)
_PRICE_MAX_AGE_SETTING = "AI_PRICE_MAX_AGE_SECONDS"
# A review time this far ahead of the reader's clock is ordinary clock
# difference between two hosts; further ahead, the time cannot be trusted.
_REVIEW_CLOCK_TOLERANCE = timedelta(minutes=5)


def price_max_age(env: Mapping[str, str] | None = None) -> timedelta:
    """The maximum age of a price: 24 hours, or the whole number of seconds in
    `AI_PRICE_MAX_AGE_SECONDS` (1 to 86400). An empty value means the
    default. Any other value refuses (`InferenceInternalError`), like the
    other AI settings: a typo must not silently lengthen the limit."""
    raw = (os.environ if env is None else env).get(_PRICE_MAX_AGE_SETTING)
    if raw is None or raw.strip() == "":
        return PRICE_MAX_AGE
    try:
        seconds = int(raw)
    except ValueError as exc:
        raise InferenceInternalError("invalid_ai_price_max_age_seconds") from exc
    if not 0 < seconds <= PRICE_MAX_AGE.total_seconds():
        raise InferenceInternalError("invalid_ai_price_max_age_seconds")
    return timedelta(seconds=seconds)


def price_status(
    price: AIModelPrice | None, *, at: datetime, max_age: timedelta | None = None
) -> PriceStatus:
    """Classify the price in effect for a model at `at` (an aware datetime).

    The age of a price is counted from `reviewed_at`, the last time a
    platform operator confirmed it. A price exactly as old as the limit is
    still fresh; one older is stale. `max_age` defaults to `price_max_age()`
    and is never taken as longer than 24 hours.

    This is a classification only. Nothing in the request path calls it yet
    (Gap 21a): the refusal on a price that is not fresh belongs to the
    spend-limit stage (Gap 21b)."""
    if price is None:
        return PriceStatus.MISSING
    reviewed_at = price.reviewed_at
    if reviewed_at is None or reviewed_at.tzinfo is None:
        return PriceStatus.UNVERIFIABLE
    limit = min(price_max_age() if max_age is None else max_age, PRICE_MAX_AGE)
    age = at - reviewed_at
    if age < -_REVIEW_CLOCK_TOLERANCE:
        return PriceStatus.UNVERIFIABLE
    if age > limit:
        return PriceStatus.STALE
    return PriceStatus.FRESH


_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"", "0", "false", "no", "off"})


def quota_required(env: Mapping[str, str] | None = None) -> bool:
    """A value that is neither true nor false refuses
    (`InferenceInternalError`), like the other AI settings: a typo must not
    silently turn the requirement off."""
    raw = (os.environ if env is None else env).get("AI_INFERENCE_TOKEN_QUOTA_REQUIRED", "")
    normalized = raw.strip().lower()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise InferenceInternalError("invalid_ai_inference_token_quota_required")


def month_window(now: datetime | None = None) -> tuple[datetime, datetime]:
    current = now or datetime.now(UTC)
    start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )
    return start, end


def _limit(entitlements: Mapping[str, object]) -> int | None:
    """A non-negative integer, or `None` when the plan has no `ai.tokens`.

    A present value that is not a non-negative integer (a string, a float, a
    negative number, a boolean) refuses (`quota_invalid`), whatever
    `AI_INFERENCE_TOKEN_QUOTA_REQUIRED` says (owner ruling 2026-10-31, ledger
    row 1006). Core's numeric entitlements read such a value as no limit
    (`saas_os.core.usage.service._numeric_limit`); the AI quota does not,
    because a typo in a plan must not grant unlimited AI spend. It is logged
    with the value's type only."""
    raw = entitlements.get(TOKEN_QUOTA_ENTITLEMENT)
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        logger.warning("ai_token_quota_invalid", extra={"value_type": type(raw).__name__})
        raise InferenceQuotaExceededError("quota_invalid")
    return raw


def recorded_tokens(tenant_id: uuid.UUID, since: datetime, until: datetime) -> int:
    a = AIInferenceAttempt
    with tenant_session_scope(tenant_id) as session:
        inputs, outputs = session.execute(
            select(sum_(a.input_tokens), sum_(a.output_tokens)).where(
                a.tenant_id == tenant_id, a.started_at >= since, a.started_at < until
            )
        ).one()
    return int(inputs or 0) + int(outputs or 0)


def check_soft_token_quota(
    tenant_id: uuid.UUID,
    *,
    input_bytes: int,
    max_output_tokens: int,
    required: bool | None = None,
    entitlements: Callable[[uuid.UUID], Mapping[str, object]] = get_entitlements,
    recorded: Callable[[uuid.UUID, datetime, datetime], int] = recorded_tokens,
) -> None:
    must_have_limit = quota_required() if required is None else required
    try:
        granted = entitlements(tenant_id)
    except Exception as exc:  # noqa: BLE001 -- unreadable configuration refuses
        raise InferenceQuotaExceededError("quota_unavailable") from exc
    limit = _limit(granted)
    if limit is None:
        if must_have_limit:
            raise InferenceQuotaExceededError("quota_not_configured")
        return
    since, until = month_window()
    try:
        used = recorded(tenant_id, since, until)
    except Exception as exc:  # noqa: BLE001
        raise InferenceQuotaExceededError("quota_unavailable") from exc
    projected = used + max(1, math.ceil(input_bytes / 4)) + max_output_tokens
    if projected > limit:
        raise InferenceQuotaExceededError("monthly_token_quota")
