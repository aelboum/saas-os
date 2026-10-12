"""Opt-in capability router: billing and subscription lifecycle
(docs/ADR/0040-...).

    app.include_router(saas_os.api.v1.build_billing_router())
    app.include_router(saas_os.api.v1.build_billing_router(provider=my_provider))

Not mounted by `build_platform_app()`. A factory, not a module-level
router, because a subscription is created and cancelled through a
`BillingProvider`: a product passes its own adapter explicitly, or passes
nothing and gets Core's default (the Stripe adapter, which needs the
`saas-os[stripe]` extra, ADR-0041). The provider is fixed when the router
is built; nothing in a request can select one.

The tenant in the path is the **service tenant** for entitlements, plans,
subscribe and cancel, and the **payer** for the payer subscription reads.
Every billing invariant stays where it already is, inside
`saas_os.core.billing`:

- a subscription needs authority on *both* sides -- `billing.account:charge`
  at the payer and `billing.subscription:create` at the service tenant
  (ADR-0029). The route checks the service-tenant half as its route
  policy; Core checks both, in the final transaction. A caller who names
  a payer they cannot charge gets the generic 403;
- a subscribe request must carry an `Idempotency-Key`; a replay returns
  the original result and makes no second provider call;
- entitlement ownership, plan eligibility and payer/merchant consistency
  are decided by Core, never re-derived here.

Catalog management, merchant and billing-account setup, seller views,
invoices and plan changes are not exposed. Neither is the inbound
provider webhook: it needs the provider-event ledger ADR-0029 defers
(ADR-0040, gap G4).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from saas_os.api.context import RequestContext
from saas_os.api.dependencies import get_idempotency_key, require_permission
from saas_os.api.errors import (
    conflict,
    idempotency_in_progress,
    idempotency_key_invalid,
    idempotency_key_reused,
    not_found,
    service_unavailable,
)
from saas_os.api.v1._common import (
    DEFAULT_PAGE_SIZE,
    TENANT_UNAVAILABLE,
    Limit,
    Offset,
    denied,
    page,
    user_caller,
)
from saas_os.api.v1.permissions import (
    BILLING_ACCOUNT,
    BILLING_SUBSCRIPTION,
    CANCEL,
    CREATE,
    READ,
)
from saas_os.core.billing import (
    BillingProvider,
    SubscribeResult,
    cancel_commercial_subscription,
    create_subscription,
    get_entitlements,
    list_plans,
)
from saas_os.core.billing.errors import (
    BillingAccountNotFoundError,
    BillingNotAuthorizedError,
    BillingProviderContractError,
    BillingProviderError,
    BillingProviderMismatchError,
    CommercialPartyNotActiveError,
    InheritedBillingSubscriptionError,
    LegacyReconciliationError,
    LiveSubscriptionExistsError,
    MerchantNotEligibleForPlanError,
    PlanNotEligibleError,
    ProviderReferenceMismatchError,
    SubscriptionNotFoundError,
    SubscriptionProjectionNotFoundError,
)
from saas_os.core.billing.projections import (
    PayerSubscriptionView,
    get_payer_subscription,
    list_payer_subscriptions,
)
from saas_os.core.idempotency.errors import IdempotencyInProgressError, IdempotencyKeyReusedError

_PROVIDER_RETRY_AFTER_SECONDS = 5


class EntitlementsResponse(BaseModel):
    entitlements: dict[str, object]


class PlanResponse(BaseModel):
    id: uuid.UUID
    key: str
    name: str
    entitlements: dict[str, object]


class SubscribeRequest(BaseModel):
    plan_id: uuid.UUID
    payer_tenant_id: uuid.UUID
    billing_account_id: uuid.UUID


class SubscriptionResponse(BaseModel):
    subscription_id: uuid.UUID
    plan_id: uuid.UUID
    status: str
    payer_tenant_id: uuid.UUID | None
    billing_account_id: uuid.UUID | None


class CreatedSubscriptionResponse(SubscriptionResponse):
    # True when this Idempotency-Key had already produced this subscription.
    replayed: bool


class PayerSubscriptionResponse(BaseModel):
    subscription_id: uuid.UUID
    billing_account_id: uuid.UUID
    service_tenant_id: uuid.UUID
    plan_id: uuid.UUID
    status: str
    verification: str
    subscription_created_at: datetime
    subscription_updated_at: datetime


def _subscription(result: SubscribeResult) -> dict[str, Any]:
    # `provider_subscription_id` is deliberately not returned: it is the
    # provider's own reference, of no use to a tenant's client.
    return {
        "subscription_id": result.subscription_id,
        "plan_id": result.plan_id,
        "status": result.status,
        "payer_tenant_id": result.payer_tenant_id,
        "billing_account_id": result.billing_account_id,
    }


def _payer_view(view: PayerSubscriptionView) -> PayerSubscriptionResponse:
    return PayerSubscriptionResponse(
        subscription_id=view.subscription_id,
        billing_account_id=view.billing_account_id,
        service_tenant_id=view.service_tenant_id,
        plan_id=view.plan_id,
        status=view.status,
        verification=view.verification,
        subscription_created_at=view.subscription_created_at,
        subscription_updated_at=view.subscription_updated_at,
    )


def build_billing_router(*, provider: BillingProvider | None = None) -> APIRouter:
    """The billing capability router, bound to `provider` (module
    docstring). `None` means Core's default provider."""
    router = APIRouter(prefix="/v1/tenants/{tenant_id}/billing", tags=["billing"])

    read_subscription = require_permission(BILLING_SUBSCRIPTION, READ)
    create_permission = require_permission(BILLING_SUBSCRIPTION, CREATE)
    cancel_permission = require_permission(BILLING_SUBSCRIPTION, CANCEL)
    read_account = require_permission(BILLING_ACCOUNT, READ)

    @router.get("/entitlements", response_model=EntitlementsResponse)
    def entitlements(context: RequestContext = Depends(read_subscription)) -> EntitlementsResponse:
        return EntitlementsResponse(entitlements=get_entitlements(context.tenant_id))

    @router.get("/plans", response_model=list[PlanResponse])
    def plans(
        limit: Limit = DEFAULT_PAGE_SIZE,
        offset: Offset = 0,
        context: RequestContext = Depends(create_permission),
    ) -> list[PlanResponse]:
        """The plans this tenant is eligible to subscribe to -- eligibility
        is Core's (`saas_os.core.billing.list_plans`)."""
        try:
            eligible = list_plans(user_caller(context), service_tenant_id=context.tenant_id)
        except TENANT_UNAVAILABLE:
            raise not_found("tenant") from None
        return [
            PlanResponse(id=p.id, key=p.key, name=p.name, entitlements=dict(p.entitlements or {}))
            for p in page(eligible, limit=limit, offset=offset)
        ]

    @router.post(
        "/subscriptions",
        response_model=CreatedSubscriptionResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def subscribe(
        body: SubscribeRequest,
        context: RequestContext = Depends(create_permission),
        idempotency_key: str | None = Depends(get_idempotency_key),
    ) -> CreatedSubscriptionResponse:
        if idempotency_key is None:
            raise idempotency_key_invalid()
        try:
            replayed, result = create_subscription(
                user_caller(context),
                service_tenant_id=context.tenant_id,
                payer_tenant_id=body.payer_tenant_id,
                billing_account_id=body.billing_account_id,
                plan_id=body.plan_id,
                idempotency_key=idempotency_key,
                provider=provider,
            )
        except BillingNotAuthorizedError:
            raise denied() from None
        except (PlanNotEligibleError, BillingAccountNotFoundError):
            # One answer for an unknown plan, a plan not offered to this
            # tenant and an unknown billing account: distinct answers
            # would tell a caller which private plan ids exist.
            raise not_found("plan or billing account") from None
        except LiveSubscriptionExistsError:
            raise conflict("A live subscription already exists.") from None
        except (
            BillingProviderMismatchError,
            CommercialPartyNotActiveError,
            InheritedBillingSubscriptionError,
            MerchantNotEligibleForPlanError,
        ):
            raise conflict("A subscription cannot be created for this request.") from None
        except IdempotencyKeyReusedError:
            raise idempotency_key_reused() from None
        except IdempotencyInProgressError:
            raise idempotency_in_progress() from None
        except TENANT_UNAVAILABLE:
            raise not_found("tenant") from None
        except (BillingProviderError, BillingProviderContractError):
            raise service_unavailable(_PROVIDER_RETRY_AFTER_SECONDS) from None
        return CreatedSubscriptionResponse(**_subscription(result), replayed=replayed)

    @router.post("/subscriptions/{subscription_id}/cancel", response_model=SubscriptionResponse)
    def cancel(
        subscription_id: uuid.UUID, context: RequestContext = Depends(cancel_permission)
    ) -> SubscriptionResponse:
        try:
            result = cancel_commercial_subscription(
                user_caller(context),
                service_tenant_id=context.tenant_id,
                subscription_id=subscription_id,
                provider=provider,
            )
        except SubscriptionNotFoundError:
            raise not_found("subscription") from None
        except BillingNotAuthorizedError:
            raise denied() from None
        except (
            BillingProviderMismatchError,
            LegacyReconciliationError,
            ProviderReferenceMismatchError,
        ):
            raise conflict("This subscription cannot be cancelled through this route.") from None
        except TENANT_UNAVAILABLE:
            raise not_found("tenant") from None
        except (BillingProviderError, BillingProviderContractError):
            raise service_unavailable(_PROVIDER_RETRY_AFTER_SECONDS) from None
        return SubscriptionResponse(**_subscription(result))

    @router.get("/payer-subscriptions", response_model=list[PayerSubscriptionResponse])
    def payer_subscriptions(
        limit: Limit = DEFAULT_PAGE_SIZE,
        offset: Offset = 0,
        context: RequestContext = Depends(read_account),
    ) -> list[PayerSubscriptionResponse]:
        """Subscriptions this tenant pays for, whichever tenant they serve."""
        try:
            views = list_payer_subscriptions(user_caller(context), context.tenant_id)
        except BillingNotAuthorizedError:
            raise denied() from None
        return [_payer_view(v) for v in page(views, limit=limit, offset=offset)]

    @router.get("/payer-subscriptions/{subscription_id}", response_model=PayerSubscriptionResponse)
    def payer_subscription(
        subscription_id: uuid.UUID, context: RequestContext = Depends(read_account)
    ) -> PayerSubscriptionResponse:
        try:
            view = get_payer_subscription(user_caller(context), context.tenant_id, subscription_id)
        except SubscriptionProjectionNotFoundError:
            raise not_found("subscription") from None
        except BillingNotAuthorizedError:
            raise denied() from None
        return _payer_view(view)

    return router
