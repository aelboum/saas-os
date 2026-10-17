"""Usage accounting: cost estimates and the soft token quota (ADR-0054
section 7; Phase AI-F; AI-INFERENCE-CONTRACTS section 7).

**Cost estimates.** At settlement an attempt whose token counts are known
(`provider_reported` or `estimated`) is priced with the model's price version
in effect at that moment (`control_plane.ai_model_prices`). The estimate, its
currency and its `pricing_version` are stored on the attempt and returned in
the usage report. It is an estimate, never a billed amount; with no price
configured, or unknown usage, nothing is estimated (never zero).

**Soft token quota.** A tenant's plan may carry the numeric entitlement
`ai.tokens` -- a monthly (UTC calendar month) limit on input plus output
tokens. Admission refuses a request whose recorded usage this month, plus an
estimate of its input and its full `max_output_tokens`, would exceed the
limit (`InferenceQuotaExceededError`). It is **soft**: concurrent requests are
checked against the same recorded usage and can together overshoot, and
usage of attempts still in flight, or unknown, is not counted. It is not a
hard ceiling and is never documented as one (decision: soft quotas; Q8
records the hard-cap requirements).

With `AI_INFERENCE_TOKEN_QUOTA_REQUIRED=true` a tenant whose plan has no valid
`ai.tokens` limit is refused, so a deployment that requires a limit never
runs unlimited by omission. Unreadable entitlement or ledger data always
refuses.
"""

from __future__ import annotations

import math
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal

from saas_os.control_plane.inference.attempts import AIInferenceAttempt
from saas_os.control_plane.inference.config.models import AIModelPrice
from saas_os.control_plane.inference.errors import InferenceQuotaExceededError
from saas_os.core.billing import get_entitlements
from saas_os.infra.db import Session, select, sum_, tenant_session_scope

TOKEN_QUOTA_ENTITLEMENT = "ai.tokens"
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
) -> CostEstimate | None:
    """Rates per million tokens; cached input at its own rate when the
    price has one (otherwise as ordinary input). None when no price is
    configured or a count is unknown."""
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
    amount = (
        Decimal(plain_input) * price.input_per_million
        + Decimal(output_tokens) * price.output_per_million
        + cached_cost
    ) / _MILLION
    return CostEstimate(
        amount=amount.quantize(_COST_QUANTUM, rounding=ROUND_HALF_UP),
        currency=price.currency,
        pricing_version=price.pricing_version,
    )


def quota_required(env: Mapping[str, str] | None = None) -> bool:
    raw = (os.environ if env is None else env).get("AI_INFERENCE_TOKEN_QUOTA_REQUIRED", "")
    return raw.strip().lower() in {"1", "true", "yes"}


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
    raw = entitlements.get(TOKEN_QUOTA_ENTITLEMENT)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        return None
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
        limit = _limit(entitlements(tenant_id))
    except Exception as exc:  # noqa: BLE001 -- unreadable configuration refuses
        raise InferenceQuotaExceededError("quota_unavailable") from exc
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
