"""Opt-in capability router: a tenant's own AI usage and limits (ADR-0054
amendment of 2026-11-11, Gap 22b; owner decisions of 2026-11-09 and
2026-11-11).

    from saas_os.api.v1.ai_usage import router as ai_usage_router
    app.include_router(ai_usage_router)

Not mounted by `build_platform_app()` and not re-exported by
`saas_os.api.v1`: importing this module loads the AI Control Plane, which
nothing else in the HTTP layer does. It is the one module of `saas_os.api`
allowed to import it, and only `saas_os.control_plane.inference.tenant_usage`
(import-linter, "API does not depend on Products or the AI Control Plane",
`ignore_imports`).

Three reads, all gated on `ai.usage:read` (registered by
`saas_os.inference.register_ai_permissions`; granted to no role by SaaS OS):

- `GET /v1/tenants/{tenant_id}/ai/usage?since=&until=&group_by=` -- the
  tenant's attempts over at most 93 days (`read_tenant_ai_usage`);
- `GET /v1/tenants/{tenant_id}/ai/usage/monthly?since=&until=&group_by=` --
  whole UTC months from the monthly rollup, at most 24 months
  (`read_tenant_ai_monthly_usage`; owner decision of 2026-11-13). It keeps
  the counts of attempts whose rows the retention job has deleted;
- `GET /v1/tenants/{tenant_id}/ai/limits` -- the soft token quota and the
  monthly budget of the current UTC month (`read_tenant_ai_limits`).

A user only: an API key is refused by the route dependency, and Core refuses
a service account and support access again. Core writes the `ai.usage.read`
audit row in the read's own transaction. Money is a decimal string, never a
float, per currency. No prompt, completion, credential, request id, error
detail or stored decision is in any response.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from saas_os.api.context import RequestContext
from saas_os.api.dependencies import require_permission
from saas_os.api.errors import invalid_request, not_found
from saas_os.api.v1._common import TENANT_UNAVAILABLE, denied, user_caller
from saas_os.control_plane.inference.tenant_usage import (
    AIBudgetStatus,
    AIQuotaStatus,
    AIUsageAmounts,
    AIUsageReadError,
    read_tenant_ai_limits,
    read_tenant_ai_monthly_usage,
    read_tenant_ai_usage,
)
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError

router = APIRouter(prefix="/v1/tenants/{tenant_id}/ai", tags=["ai"])

# `ai.usage:read`, spelled out: the constant lives in the AI Control Plane's
# permissions module, which this router does not import.
_read = require_permission("ai.usage", "read")
_INVALID = "Invalid AI usage window or grouping."
_INVALID_MONTHLY = "Invalid AI monthly usage window or grouping."


class CostResponse(BaseModel):
    currency: str
    estimated: Decimal


class StateCountResponse(BaseModel):
    state: str
    attempts: int


class ProvenanceTokensResponse(BaseModel):
    provenance: str
    attempts: int
    input_tokens: int
    output_tokens: int


class AmountsResponse(BaseModel):
    attempts: int
    attempts_by_state: list[StateCountResponse]
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    tokens_by_provenance: list[ProvenanceTokensResponse]
    estimated_cost: list[CostResponse]
    usage_unknown_attempts: int
    cost_unknown_attempts: int


class GroupResponse(BaseModel):
    key: str
    amounts: AmountsResponse


class QuotaResponse(BaseModel):
    state: str
    limit: int | None
    used: int | None
    remaining: int | None
    basis: str


class BudgetResponse(BaseModel):
    state: str
    basis: str
    currency: str | None
    limit: Decimal | None
    source: str | None
    settled: Decimal | None
    reserved: Decimal | None
    retained: Decimal | None
    remaining: Decimal | None
    period_start: datetime | None
    warn_thresholds: list[int]
    threshold_reached: int | None


class LimitsResponse(BaseModel):
    tenant_id: uuid.UUID
    token_quota: QuotaResponse
    budget: BudgetResponse


class UsageResponse(BaseModel):
    tenant_id: uuid.UUID
    since: datetime
    until: datetime
    timezone: str
    group_by: str
    basis: str
    totals: AmountsResponse
    groups: list[GroupResponse]
    token_quota: QuotaResponse
    budget: BudgetResponse


class MonthlyUsageResponse(BaseModel):
    tenant_id: uuid.UUID
    since: datetime
    until: datetime
    timezone: str
    group_by: str
    basis: str
    totals: AmountsResponse
    groups: list[GroupResponse]


def _amounts(a: AIUsageAmounts) -> AmountsResponse:
    return AmountsResponse(
        attempts=a.attempts,
        attempts_by_state=[StateCountResponse(state=s, attempts=n) for s, n in a.attempts_by_state],
        input_tokens=a.input_tokens,
        output_tokens=a.output_tokens,
        cached_input_tokens=a.cached_input_tokens,
        tokens_by_provenance=[
            ProvenanceTokensResponse(
                provenance=p.provenance,
                attempts=p.attempts,
                input_tokens=p.input_tokens,
                output_tokens=p.output_tokens,
            )
            for p in a.tokens_by_provenance
        ],
        estimated_cost=[CostResponse(currency=c.currency, estimated=c.estimated) for c in a.cost],
        usage_unknown_attempts=a.usage_unknown_attempts,
        cost_unknown_attempts=a.cost_unknown_attempts,
    )


def _quota(q: AIQuotaStatus) -> QuotaResponse:
    return QuotaResponse(
        state=q.state, limit=q.limit, used=q.used, remaining=q.remaining, basis=q.basis
    )


def _budget(b: AIBudgetStatus) -> BudgetResponse:
    return BudgetResponse(
        state=b.state,
        basis="estimated_platform_spend",
        currency=b.currency,
        limit=b.limit,
        source=b.source,
        settled=b.settled,
        reserved=b.reserved,
        retained=b.retained,
        remaining=b.remaining,
        period_start=b.period_start,
        warn_thresholds=list(b.warn_thresholds),
        threshold_reached=b.threshold_reached,
    )


@router.get("/usage", response_model=UsageResponse)
def ai_usage(
    since: datetime | None = None,
    until: datetime | None = None,
    group_by: str = "provider",
    context: RequestContext = Depends(_read),
) -> UsageResponse:
    """`since`/`until`: both timezone-aware or both omitted (the current UTC
    month), at most 93 days apart. `group_by`: provider, model, use_case, day,
    provenance or state."""
    try:
        report = read_tenant_ai_usage(
            context.tenant_id,
            caller=user_caller(context),
            since=since,
            until=until,
            group_by=group_by,
        )
    except AuthorityNotAuthorizedError:
        raise denied() from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    except AIUsageReadError:
        raise invalid_request(_INVALID) from None
    return UsageResponse(
        tenant_id=report.tenant_id,
        since=report.since,
        until=report.until,
        timezone="UTC",
        group_by=report.group_by.value,
        basis=report.basis,
        totals=_amounts(report.totals),
        groups=[GroupResponse(key=g.key, amounts=_amounts(g.amounts)) for g in report.groups],
        token_quota=_quota(report.quota),
        budget=_budget(report.budget),
    )


@router.get("/usage/monthly", response_model=MonthlyUsageResponse)
def ai_monthly_usage(
    since: datetime | None = None,
    until: datetime | None = None,
    group_by: str = "month",
    context: RequestContext = Depends(_read),
) -> MonthlyUsageResponse:
    """Whole UTC months. `since`/`until`: both or neither (the current month
    and the eleven before it), each the first instant of a UTC month, at most
    24 months apart. `group_by`: month (every month of the window, empty ones
    included), provider, model, use_case, provenance or state. Counts finished
    attempts only, including attempts whose rows no longer exist."""
    try:
        report = read_tenant_ai_monthly_usage(
            context.tenant_id,
            caller=user_caller(context),
            since=since,
            until=until,
            group_by=group_by,
        )
    except AuthorityNotAuthorizedError:
        raise denied() from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    except AIUsageReadError:
        raise invalid_request(_INVALID_MONTHLY) from None
    return MonthlyUsageResponse(
        tenant_id=report.tenant_id,
        since=report.since,
        until=report.until,
        timezone="UTC",
        group_by=report.group_by.value,
        basis=report.basis,
        totals=_amounts(report.totals),
        groups=[GroupResponse(key=g.key, amounts=_amounts(g.amounts)) for g in report.groups],
    )


@router.get("/limits", response_model=LimitsResponse)
def ai_limits(context: RequestContext = Depends(_read)) -> LimitsResponse:
    """The soft monthly token quota and the monthly budget, current UTC month."""
    try:
        report = read_tenant_ai_limits(context.tenant_id, caller=user_caller(context))
    except AuthorityNotAuthorizedError:
        raise denied() from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    return LimitsResponse(
        tenant_id=report.tenant_id,
        token_quota=_quota(report.quota),
        budget=_budget(report.budget),
    )
