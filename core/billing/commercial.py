"""The authorized commercial subscription entry point (Billing Foundation
v2 Phase 2; docs/ADR/0029-commercial-parties-and-billing-relationships.md).

`create_subscription()` creates a subscription with three explicitly
named parties:

    service tenant  -- `Subscription.tenant_id`: receives the service and
                       its entitlements; the subscription's RLS owner.
    payer           -- `(payer_tenant_id, billing_account_id)`: the
                       `BillingAccount` that is charged.
    payee           -- the billing account's merchant
                       (`BillingAccount.merchant_*`): derived, never
                       supplied separately, never stored twice.

**Dual authorization** (ADR-0029, invariant 6), both through
`core.rbac.can()` (`core/billing/authorization.py`):

    billing.account:charge        on the payer tenant
    billing.subscription:create   on the service tenant

The payer is never trusted because it was supplied: the caller must hold
`charge` on the payer tenant, and the billing account must actually belong
to that payer (it is read under the payer's own RLS scope). The service
tenant is authorized independently. `SUBTREE` roles, delegations and
denies apply exactly as `can()` defines them. A denial is the same
`BillingNotAuthorizedError` whichever check failed.

**Entitlements follow the service tenant.** `get_entitlements()` is
unchanged and reads `Subscription.tenant_id`; paying for a subscription
grants the payer nothing (ADR-0029, invariant 7).

**Scope boundaries this phase deliberately keeps** (later phases change
them, not this one):

- Until Catalog v2 gives plans an owner and a merchant, every plan is sold
  only by a merchant owned by the platform tenant
  (`core.tenancy.get_platform_tenant_id()`); a billing account at any
  other merchant is rejected (`MerchantNotEligibleForPlanError`).
- The provider adapter must be the merchant's provider
  (`BillingProviderMismatchError`); the deployment's Stripe default is only
  constructed for a `"stripe"` merchant.
- The created row's `status` is `"active"` as soon as the provider returns
  an id -- the same unconfirmed-activation semantics as the legacy path.
  Provider-confirmed activation is Phase 3 (ADR-0008 amendment); this row
  is legacy-unverified until then, like every other `active` row
  (ADR-0029, Decision 0.5).
- No provider customer is created or recorded here; the billing account's
  `provider_customer_ref` stays NULL (provider integration redesign is a
  later phase).

**`inherits_billing` is never used to decide a payer.** The payer is
always the explicitly named billing account. A service tenant that
inherits billing is refused (`require_service_tenant_owns_billing()`),
exactly as the legacy path refuses it, because its own subscription would
never be consulted for entitlements.

**Idempotency** reuses `core.idempotency`'s two-step primitive, scoped to
the service tenant, fingerprinted by `{plan_key, payer_tenant_id,
billing_account_id}` -- the same discipline (and the same documented
crash window) as `core/billing/service.py::subscribe_idempotent()`.

**Ordering.** The provider reference is registered in the global
`core.billing_provider_refs` index *before* the subscription row is
written, with the row's id pre-allocated, so a provider subscription id
can never end up mapped to two local rows; if the row insert then fails,
the dangling reference resolves to a row that does not exist and every
lookup through it fails closed (`get_subscription_by_provider_ref()`).
"""

from __future__ import annotations

import uuid

from core.audit_log import AuditOutcome
from core.audit_log import record as record_audit_event
from core.billing.authorization import (
    BILLING_ACCOUNT,
    BILLING_SUBSCRIPTION,
    audit_actor,
    authorize_billing,
)
from core.billing.errors import (
    BillingProviderMismatchError,
    MerchantNotEligibleForPlanError,
    SubscriptionNotFoundError,
)
from core.billing.models import Subscription
from core.billing.parties import (
    get_billing_account,
    get_merchant_account,
    require_active_billing_account,
    require_active_merchant_account,
)
from core.billing.provider import BillingProvider
from core.billing.provider_refs import (
    LocalObjectType,
    ProviderObjectType,
    register_provider_ref,
    resolve_provider_ref,
)
from core.billing.service import (
    SubscribeResult,
    _default_provider,
    get_plan,
    provider_name,
    require_service_tenant_owns_billing,
)
from core.idempotency import (
    IdempotencyStatus,
    begin_idempotent_operation,
    finalize_idempotent_operation,
)
from core.tenancy import get_platform_tenant_id, require_open_tenant
from infra.db import tenant_session_scope

_OPERATION = "billing.subscription.create"
_STRIPE = "stripe"


def create_subscription(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_key: str,
    idempotency_key: str,
    provider: BillingProvider | None = None,
) -> tuple[bool, SubscribeResult]:
    """Create a subscription for `service_tenant_id`, paid through
    `payer_tenant_id`'s billing account `billing_account_id`, against
    `plan_key`. `caller` is a `BillingActor` or an explicit
    `trusted_system(reason)` -- never `None`. Returns `(is_replay, result)`.
    See the module docstring for the full contract."""
    validated = authorize_billing(
        caller,
        [
            (payer_tenant_id, BILLING_ACCOUNT, "charge"),
            (service_tenant_id, BILLING_SUBSCRIPTION, "create"),
        ],
        operation=_OPERATION,
    )
    service_tenant = require_open_tenant(service_tenant_id)
    require_open_tenant(payer_tenant_id)
    require_service_tenant_owns_billing(service_tenant)

    account = require_active_billing_account(
        get_billing_account(payer_tenant_id, billing_account_id)
    )
    merchant = require_active_merchant_account(
        get_merchant_account(account.merchant_tenant_id, account.merchant_account_id)
    )
    if merchant.tenant_id != get_platform_tenant_id():
        raise MerchantNotEligibleForPlanError(merchant.id, plan_key)

    if provider is not None:
        active_provider = provider
    elif merchant.provider == _STRIPE:
        active_provider = _default_provider()
    else:
        raise BillingProviderMismatchError(merchant.provider, None)
    adapter_name = provider_name(active_provider)
    if adapter_name != merchant.provider:
        raise BillingProviderMismatchError(merchant.provider, adapter_name)

    plan = get_plan(plan_key)

    reservation = begin_idempotent_operation(
        service_tenant_id,
        _OPERATION,
        idempotency_key,
        {
            "plan_key": plan_key,
            "payer_tenant_id": str(payer_tenant_id),
            "billing_account_id": str(billing_account_id),
        },
    )
    if reservation.is_replay:
        assert reservation.result is not None
        return True, SubscribeResult.from_dict(reservation.result)

    try:
        provider_subscription_id = active_provider.create_subscription(
            tenant_id=payer_tenant_id, plan=plan
        )
        subscription_id = uuid.uuid4()
        register_provider_ref(
            provider=merchant.provider,
            provider_account_ref=merchant.provider_account_ref,
            object_type=ProviderObjectType.SUBSCRIPTION,
            provider_object_ref=provider_subscription_id,
            tenant_id=service_tenant_id,
            local_object_type=LocalObjectType.BILLING_SUBSCRIPTION,
            local_object_id=subscription_id,
        )
        with tenant_session_scope(service_tenant_id) as session:
            subscription = Subscription(
                id=subscription_id,
                tenant_id=service_tenant_id,
                plan_id=plan.id,
                status="active",
                provider_subscription_id=provider_subscription_id,
                payer_tenant_id=payer_tenant_id,
                billing_account_id=account.id,
                provider=merchant.provider,
            )
            session.add(subscription)
            session.flush()
            session.refresh(subscription)
            session.expunge(subscription)
    except Exception:
        finalize_idempotent_operation(
            service_tenant_id, reservation.record_id, status=IdempotencyStatus.FAILED
        )
        raise

    actor_type, actor_user_id, extra = audit_actor(validated)
    record_audit_event(
        tenant_id=service_tenant_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action="billing.subscription_created",
        resource_type="billing_subscription",
        resource_id=str(subscription.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "plan_key": plan_key,
            "payer_tenant_id": str(payer_tenant_id),
            "billing_account_id": str(account.id),
            "merchant_account_id": str(merchant.id),
            **extra,
        },
    )
    if payer_tenant_id != service_tenant_id:
        # The payer is charged for a subscription it does not hold -- it
        # gets its own audit record, under its own tenant.
        record_audit_event(
            tenant_id=payer_tenant_id,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            action="billing.subscription_charged_to_account",
            resource_type="billing_account",
            resource_id=str(account.id),
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "plan_key": plan_key,
                "service_tenant_id": str(service_tenant_id),
                "subscription_id": str(subscription.id),
                **extra,
            },
        )

    result = SubscribeResult.from_subscription(subscription)
    finalize_idempotent_operation(
        service_tenant_id,
        reservation.record_id,
        status=IdempotencyStatus.SUCCEEDED,
        result=result.to_dict(),
    )
    return False, result


def get_subscription_by_provider_ref(
    *, provider: str, provider_account_ref: str, provider_subscription_ref: str
) -> Subscription:
    """The bounded cross-tenant lookup: resolve a provider subscription
    reference through the global `core.billing_provider_refs` index, then
    read the subscription under `tenant_session_scope()` for the resolved
    tenant only. The row must itself carry the same provider and provider
    subscription id (defense in depth against a stale or dangling
    reference); otherwise `SubscriptionNotFoundError`."""
    resolution = resolve_provider_ref(
        provider=provider,
        provider_account_ref=provider_account_ref,
        object_type=ProviderObjectType.SUBSCRIPTION,
        provider_object_ref=provider_subscription_ref,
    )
    if resolution.local_object_type is not LocalObjectType.BILLING_SUBSCRIPTION:
        raise SubscriptionNotFoundError(resolution.tenant_id, resolution.local_object_id)
    with tenant_session_scope(resolution.tenant_id) as session:
        subscription = session.get(Subscription, resolution.local_object_id)
        if (
            subscription is None
            or subscription.tenant_id != resolution.tenant_id
            or subscription.provider != provider
            or subscription.provider_subscription_id != provider_subscription_ref
        ):
            raise SubscriptionNotFoundError(resolution.tenant_id, resolution.local_object_id)
        session.expunge(subscription)
        return subscription
