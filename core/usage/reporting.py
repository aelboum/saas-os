"""Usage reporting (Phase 5.3 step 6): read-only views that explain B2B2C
usage without changing who owns it.

**Ownership is unchanged.** A usage event belongs to the tenant where it
occurred (`core.usage_events.tenant_id`, Phase 5.2 / ADR-0037). Nothing
here moves, copies, re-attributes or pools usage: every number is a `SUM`
over that one ledger, under the owning tenant's RLS scope, with the Phase
5.2 window semantics (`[since, until)`, timezone-aware, UTC) and exact
`Decimal` arithmetic. Reports never write usage, quota, entitlements,
subscriptions or audit entries, and never call a provider.

Three views, each authorized with `can(session=...)` in the reading
transaction:

- `service_tenant_usage_report(caller, tenant_id, ...)` --
  `billing.subscription:read` on the tenant. Its own usage per metric, its
  live subscriptions (all of them, at every merchant -- none is "the"
  subscription), and, per metric, the limit enforcement actually applies:
  `core.billing.get_entitlements()`, which combines every active
  subscription key by key (boolean OR, numeric MAX; ADR-0029 amendment).
  `remaining = limit - used` (negative when over); no numeric limit means
  `limit is None` (unlimited under the current 0.x quota semantics,
  ADR-0029 decision 0.4).

  `include_descendants=True` adds the tenant's current descendants as a
  **reporting** aggregate: the caller needs the same authority on every
  tenant included (no silent omission), each tenant's usage is read under
  its own scope and reported separately as well as summed, and **no limit
  or remaining is computed** for the sum -- there are no shared pools, so a
  descendant-inclusive total is never a quota.

- `payer_subscription_usage(caller, payer_tenant_id, service_tenant_id,
  subscription_id, ...)` -- `billing.account:read` on the payer, and the
  canonical subscription must record that payer.
- `merchant_subscription_usage(caller, merchant_tenant_id,
  service_tenant_id, subscription_id, ...)` -- `billing.merchant:manage` on
  the merchant's owner (the seller-projection permission, ADR-0029), and
  the canonical subscription's merchant must belong to that tenant.

The payer and merchant views show the **service tenant's** usage (it stays
the owner) for the metrics the subscription's own plan defines, and nothing
else of that tenant; a missing subscription, one with another payer or
merchant, and a denial are the same `BillingNotAuthorizedError`, so neither
view can probe for subscriptions. The subscription is looked up in
`core.billing_subscriptions`, never in the seller/payer projections.

Reads are not audited (not billing mutations, ADR-0031).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from core.billing.authorization import (
    BILLING_ACCOUNT,
    BILLING_MERCHANT,
    BILLING_SUBSCRIPTION,
    authorize_billing,
    require_billing_caller,
)
from core.billing.errors import BillingNotAuthorizedError
from core.billing.lifecycle import ENTITLEMENT_GRANTING_STATUSES, LIVE_STATUSES
from core.billing.models import BillingAccount, Plan, Subscription
from core.billing.service import get_entitlements
from core.tenancy import get_descendant_ids, get_tenant
from core.usage.models import UsageEvent
from core.usage.service import _numeric_limit, _validate_metric, _window
from infra.db import Session, bind_tenant_scope, select, sum_, tenant_session_scope

_SERVICE_OPERATION = "usage.report.service_tenant"
_PAYER_OPERATION = "usage.report.payer"
_MERCHANT_OPERATION = "usage.report.merchant"


@dataclass(frozen=True)
class MetricUsage:
    """One metric's usage in the window, and -- for a single tenant's own
    usage only -- the limit enforcement applies to it."""

    metric: str
    used: Decimal
    limit: Decimal | None
    remaining: Decimal | None
    over_limit: bool


@dataclass(frozen=True)
class SubscriptionContext:
    """One live canonical subscription of the service tenant, as context.
    No provider reference."""

    subscription_id: uuid.UUID
    plan_id: uuid.UUID
    plan_key: str
    merchant_account_id: uuid.UUID | None
    payer_tenant_id: uuid.UUID | None
    status: str
    grants_entitlements: bool
    plan_entitlements: dict[str, object]


@dataclass(frozen=True)
class TenantUsageReport:
    tenant_id: uuid.UUID
    since: datetime
    until: datetime
    scope: str  # "direct" or "descendants"
    metrics: tuple[MetricUsage, ...]
    subscriptions: tuple[SubscriptionContext, ...]
    effective_entitlements: dict[str, object]
    inherits_billing: bool
    per_tenant: dict[uuid.UUID, dict[str, Decimal]]


@dataclass(frozen=True)
class SubscriptionUsageReport:
    """A payer's or merchant's view of one subscription's service-tenant
    usage, for the metrics that subscription's plan defines."""

    subscription_id: uuid.UUID
    service_tenant_id: uuid.UUID
    plan_id: uuid.UUID
    status: str
    since: datetime
    until: datetime
    usage: dict[str, Decimal]


def _usage_totals(
    session: Session,
    tenant_id: uuid.UUID,
    since: datetime,
    until: datetime,
    metrics: frozenset[str] | None,
) -> dict[str, Decimal]:
    """`SUM(quantity)` per metric over `[since, until)` for one tenant, under
    that tenant's RLS scope (bound in `session`'s transaction)."""
    with bind_tenant_scope(session, tenant_id):
        query = (
            select(UsageEvent.metric, sum_(UsageEvent.quantity))
            .where(
                UsageEvent.tenant_id == tenant_id,
                UsageEvent.occurred_at >= since,
                UsageEvent.occurred_at < until,
            )
            .group_by(UsageEvent.metric)
        )
        if metrics is not None:
            query = query.where(UsageEvent.metric.in_(sorted(metrics)))
        return {metric: Decimal(total) for metric, total in session.execute(query).all()}


def _metric_filter(metrics: object) -> frozenset[str] | None:
    if metrics is None:
        return None
    selected = frozenset(metrics)  # type: ignore[arg-type]
    for metric in selected:
        _validate_metric(metric)
    return selected


def _subscription_contexts(
    session: Session, tenant_id: uuid.UUID
) -> tuple[SubscriptionContext, ...]:
    rows = session.execute(
        select(Subscription, Plan)
        .join(Plan, Plan.id == Subscription.plan_id)
        .where(
            Subscription.tenant_id == tenant_id,
            Subscription.status.in_([s.value for s in LIVE_STATUSES]),
        )
        .order_by(Subscription.created_at.desc(), Subscription.id)
    ).all()
    granting = {s.value for s in ENTITLEMENT_GRANTING_STATUSES}
    return tuple(
        SubscriptionContext(
            subscription_id=subscription.id,
            plan_id=plan.id,
            plan_key=plan.key,
            merchant_account_id=subscription.merchant_account_id,
            payer_tenant_id=subscription.payer_tenant_id,
            status=subscription.status,
            grants_entitlements=subscription.status in granting,
            plan_entitlements=dict(plan.entitlements),
        )
        for subscription, plan in rows
    )


def service_tenant_usage_report(
    caller: object,
    tenant_id: uuid.UUID,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    metrics: frozenset[str] | set[str] | list[str] | None = None,
    include_descendants: bool = False,
) -> TenantUsageReport:
    """`tenant_id`'s usage report (module docstring). The window is
    `[since, until)` in UTC -- both bounds, timezone-aware, or neither (the
    current UTC calendar month). `metrics` restricts the report; otherwise
    every metric with usage in the window, plus every numeric entitlement
    key, is reported."""
    require_billing_caller(caller)
    start, end = _window(since, until)
    selected = _metric_filter(metrics)

    with tenant_session_scope(tenant_id) as session:
        tenants = [tenant_id]
        if include_descendants:
            tenants += sorted(get_descendant_ids(tenant_id) - {tenant_id})
        authorize_billing(
            caller,
            [(tenant, BILLING_SUBSCRIPTION, "read") for tenant in tenants],
            operation=_SERVICE_OPERATION,
            session=session,
        )
        per_tenant = {
            tenant: _usage_totals(session, tenant, start, end, selected) for tenant in tenants
        }
        subscriptions = _subscription_contexts(session, tenant_id)

    effective = get_entitlements(tenant_id)
    own = per_tenant[tenant_id]
    numeric_keys = {key for key in effective if _numeric_limit(effective, key) is not None}
    reported = set(own) | (numeric_keys if selected is None else numeric_keys & selected)
    if include_descendants:
        totals: dict[str, Decimal] = {}
        for usage in per_tenant.values():
            for metric, quantity in usage.items():
                totals[metric] = totals.get(metric, Decimal(0)) + quantity
        reported |= set(totals)
        lines = tuple(
            # A descendant-inclusive total is a report, never a pool: no limit.
            MetricUsage(metric, totals.get(metric, Decimal(0)), None, None, False)
            for metric in sorted(reported)
        )
    else:
        lines = tuple(
            _metric_line(metric, own.get(metric, Decimal(0)), effective)
            for metric in sorted(reported)
        )
    return TenantUsageReport(
        tenant_id=tenant_id,
        since=start,
        until=end,
        scope="descendants" if include_descendants else "direct",
        metrics=lines,
        subscriptions=subscriptions,
        effective_entitlements=effective,
        inherits_billing=get_tenant(tenant_id).inherits_billing,
        per_tenant=per_tenant,
    )


def _metric_line(metric: str, used: Decimal, effective: dict[str, object]) -> MetricUsage:
    limit = _numeric_limit(effective, metric)
    if limit is None:
        return MetricUsage(metric, used, None, None, False)
    return MetricUsage(metric, used, limit, limit - used, used > limit)


def _subscription_usage(
    caller: object,
    *,
    authority: tuple[uuid.UUID, str, str],
    operation: str,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    party_matches,  # type: ignore[no-untyped-def]
    since: datetime | None,
    until: datetime | None,
) -> SubscriptionUsageReport:
    require_billing_caller(caller)
    start, end = _window(since, until)
    with tenant_session_scope(service_tenant_id) as session:
        authorize_billing(caller, [authority], operation=operation, session=session)
        found = session.execute(
            select(Subscription, Plan)
            .join(Plan, Plan.id == Subscription.plan_id)
            .where(
                Subscription.id == subscription_id,
                Subscription.tenant_id == service_tenant_id,
            )
        ).one_or_none()
        if found is None or not party_matches(session, found[0]):
            raise BillingNotAuthorizedError(operation)
        subscription, plan = found
        metrics = frozenset(key for key in plan.entitlements if isinstance(key, str))
        usage = _usage_totals(session, service_tenant_id, start, end, metrics) if metrics else {}
        return SubscriptionUsageReport(
            subscription_id=subscription.id,
            service_tenant_id=service_tenant_id,
            plan_id=plan.id,
            status=subscription.status,
            since=start,
            until=end,
            usage={metric: usage.get(metric, Decimal(0)) for metric in sorted(metrics)},
        )


def payer_subscription_usage(
    caller: object,
    payer_tenant_id: uuid.UUID,
    *,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    since: datetime | None = None,
    until: datetime | None = None,
) -> SubscriptionUsageReport:
    """The service tenant's usage under one subscription `payer_tenant_id`
    pays for (`billing.account:read` on the payer; the canonical row must
    record this payer). Module docstring."""

    def pays(_: Session, subscription: Subscription) -> bool:
        return subscription.payer_tenant_id == payer_tenant_id

    return _subscription_usage(
        caller,
        authority=(payer_tenant_id, BILLING_ACCOUNT, "read"),
        operation=_PAYER_OPERATION,
        service_tenant_id=service_tenant_id,
        subscription_id=subscription_id,
        party_matches=pays,
        since=since,
        until=until,
    )


def merchant_subscription_usage(
    caller: object,
    merchant_tenant_id: uuid.UUID,
    *,
    service_tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    since: datetime | None = None,
    until: datetime | None = None,
) -> SubscriptionUsageReport:
    """The service tenant's usage under one subscription sold by
    `merchant_tenant_id`'s merchant (`billing.merchant:manage` on that
    tenant; the canonical row's merchant -- read from its payer's billing
    account under the payer's scope -- must belong to it)."""

    def sold(session: Session, subscription: Subscription) -> bool:
        if subscription.payer_tenant_id is None or subscription.billing_account_id is None:
            return False
        with bind_tenant_scope(session, subscription.payer_tenant_id):
            account = session.execute(
                select(BillingAccount).where(
                    BillingAccount.id == subscription.billing_account_id,
                    BillingAccount.tenant_id == subscription.payer_tenant_id,
                )
            ).scalar_one_or_none()
        return (
            account is not None
            and account.merchant_tenant_id == merchant_tenant_id
            and account.merchant_account_id == subscription.merchant_account_id
        )

    return _subscription_usage(
        caller,
        authority=(merchant_tenant_id, BILLING_MERCHANT, "manage"),
        operation=_MERCHANT_OPERATION,
        service_tenant_id=service_tenant_id,
        subscription_id=subscription_id,
        party_matches=sold,
        since=since,
        until=until,
    )
