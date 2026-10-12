"""Opt-in capability router: usage visibility (docs/ADR/0040-...).

    app.include_router(saas_os.api.v1.usage_router)

Not mounted by `build_platform_app()`. One read: this tenant's own usage
against its entitlement limits, as
`saas_os.core.usage.service_tenant_usage_report` computes it
(ADR-0037). It requires `billing.subscription:read` -- the permission
Core itself enforces on that report.

Read-only. Recording usage is not exposed: a route that let a client
assert its own consumption would be a metering bypass. A product records
usage server-side (`saas_os.core.usage.ingest_event`) from its own
business operations. Descendant roll-ups, and the payer and merchant
reports, are not exposed.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from saas_os.api.context import RequestContext
from saas_os.api.dependencies import require_permission
from saas_os.api.errors import invalid_request, not_found
from saas_os.api.v1._common import PRINTABLE, TENANT_UNAVAILABLE, denied, user_caller
from saas_os.api.v1.permissions import BILLING_SUBSCRIPTION, READ
from saas_os.core.billing.errors import BillingNotAuthorizedError
from saas_os.core.usage import service_tenant_usage_report
from saas_os.core.usage.errors import InvalidUsageEventError

router = APIRouter(prefix="/v1/tenants/{tenant_id}/usage", tags=["usage"])

_read = require_permission(BILLING_SUBSCRIPTION, READ)

_MAX_METRICS = 50
_METRIC = re.compile(PRINTABLE)


class MetricUsageResponse(BaseModel):
    metric: str
    used: Decimal
    limit: Decimal | None
    remaining: Decimal | None
    over_limit: bool


class UsageReportResponse(BaseModel):
    tenant_id: uuid.UUID
    since: datetime
    until: datetime
    metrics: list[MetricUsageResponse]
    effective_entitlements: dict[str, object]


@router.get("", response_model=UsageReportResponse)
def usage_report(
    since: datetime | None = None,
    until: datetime | None = None,
    metric: Annotated[list[str] | None, Query(max_length=_MAX_METRICS)] = None,
    context: RequestContext = Depends(_read),
) -> UsageReportResponse:
    """`since`/`until` are both timezone-aware or both omitted (the current
    UTC month); `metric` may repeat to restrict the report."""
    if metric and not all(_METRIC.fullmatch(m) for m in metric):
        raise invalid_request("Invalid usage report window or metric.")
    try:
        report = service_tenant_usage_report(
            user_caller(context),
            context.tenant_id,
            since=since,
            until=until,
            metrics=set(metric) if metric else None,
        )
    except BillingNotAuthorizedError:
        raise denied() from None
    except TENANT_UNAVAILABLE:
        raise not_found("tenant") from None
    except InvalidUsageEventError:
        raise invalid_request("Invalid usage report window or metric.") from None
    return UsageReportResponse(
        tenant_id=report.tenant_id,
        since=report.since,
        until=report.until,
        metrics=[
            MetricUsageResponse(
                metric=m.metric,
                used=m.used,
                limit=m.limit,
                remaining=m.remaining,
                over_limit=m.over_limit,
            )
            for m in report.metrics
        ],
        effective_entitlements=dict(report.effective_entitlements),
    )
