"""`saas_os/core/billing` -- provider-abstraction interface, plans, subscriptions,
entitlements (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1;
docs/ADR/0008-billing-provider.md).

Owns:
- the global `Plan` catalog (`core.billing_plans`) -- a pricing-tier
  definition and its entitlement mapping;
- the tenant-owned `Subscription` (`core.billing_subscriptions`,
  RLS-protected) -- a tenant's subscription state/lifecycle against a plan;
- the `BillingProvider` interface (`saas_os/core/billing/provider.py`) and its
  two implementations: `FakeBillingProvider` (in-memory) and
  `StripeBillingProvider` (`saas_os/core/billing/stripe_provider.py`, the only
  file that imports `stripe`);
- `get_entitlements()`, the product-agnostic "plan -> feature/limit"
  lookup (`docs/ARCHITECTURE-DISCOVERY.md` section 14);
- `resolve_billing_owner()` (architecture research Phase H --
  "Hierarchy-Aware Billing & Usage"), the one deterministic,
  hierarchy-aware function deciding whose `Subscription`
  `get_entitlements()` reads -- never an authorization decision.

Does NOT own (Non-Goals, deliberately deferred -- not built by this
phase since no Tests/Acceptance Criterion exercises them):
- **Invoices/Payments**: `docs/ADR/0008-...`'s own table names them as
  distinct concepts, but persisting or syncing local mirrors of Stripe's
  invoice/payment records is deferred to a future phase with an actual
  tested need -- Stripe itself remains the system of record until then.
- **Usage metering**: owned by the future `saas_os/core/usage` (Phase 5.2),
  which feeds entitlement/quota checks through this module's own
  interface, never by `saas_os/core/billing` reading usage data directly.
- **Webhook ingress**: `saas_os/core/billing/stripe_provider.py::verify_stripe_webhook_signature()`
  is a pure, reusable verification primitive; no HTTP route receives a
  Stripe webhook yet (Phase 8's ingress layer).
- **Plan tier ordering**: `upgrade_subscription()` is a direction-agnostic
  plan change; nothing validates "the new plan is actually higher-tier."
- Any HTTP/API surface, frontend, or product-specific billing logic.

**Commercial parties (Billing Foundation v2 Phase 2,
docs/ADR/0029-commercial-parties-and-billing-relationships.md):**
`MerchantAccount` (payee) and `BillingAccount` (payer) in
`saas_os/core/billing/parties.py`; the global-by-design provider-reference index
in `saas_os/core/billing/provider_refs.py`; the billing permission vocabulary and
caller model in `saas_os/core/billing/authorization.py` (converged on
`saas_os.core.authority` callers by Phase 5.3 step 1); and the
dual-authorized `create_subscription()` in `saas_os/core/billing/commercial.py`.
`Subscription.tenant_id` remains the service tenant.
"""

from saas_os.core.billing.authorization import (
    BILLING_PERMISSIONS,
    BILLING_SYSTEM_AUTHORITY,
    BillingActor,
    BillingCaller,
    TrustedSystemCaller,
    register_billing_permissions,
    trusted_system,
)
from saas_os.core.billing.catalog import (
    EligibilityReason,
    PlanEligibility,
    PlanOfferStatus,
    PlanStatus,
    PlanVisibility,
    adopt_legacy_plan,
    create_owned_plan,
    create_plan_offer,
    evaluate_plan_eligibility,
    list_plans,
    revoke_plan_offer,
    set_plan_visibility,
    withdraw_plan,
)
from saas_os.core.billing.commercial import (
    CancellationCapacity,
    SubscriptionReconciliation,
    cancel_commercial_subscription,
    create_subscription,
    get_subscription_by_provider_ref,
    reconcile_legacy_subscription,
    reconcile_subscription_status,
)
from saas_os.core.billing.errors import (
    BillingAccountNotFoundError,
    BillingActorRequiredError,
    BillingInheritanceMigrationError,
    BillingNotAuthorizedError,
    BillingProviderContractError,
    BillingProviderError,
    BillingProviderMismatchError,
    CommercialPartyNotActiveError,
    DuplicateMerchantAccountError,
    DuplicatePlanKeyError,
    EntitlementDeniedError,
    InheritedBillingSubscriptionError,
    InvalidBillingHierarchyError,
    InvalidBillingPartyError,
    InvalidPlanKeyError,
    InvalidSubscriptionTransitionError,
    InvalidWebhookSignatureError,
    LegacyBillingPathError,
    LegacyReconciliationError,
    LiveSubscriptionExistsError,
    MerchantAccountNotFoundError,
    MerchantNotEligibleForPlanError,
    PlanNotFoundError,
    ProviderEventProcessingError,
    ProviderRefConflictError,
    ProviderReferenceMismatchError,
    ProviderRefNotFoundError,
    SubscriptionNotFoundError,
)
from saas_os.core.billing.inheritance import (
    migrate_inherited_tenant_to_sponsorship,
    opt_out_of_billing_inheritance,
)
from saas_os.core.billing.lifecycle import (
    ALLOWED_TRANSITIONS,
    LIVE_STATUSES,
    SubscriptionStatus,
    VerificationState,
)
from saas_os.core.billing.models import (
    BillingAccount,
    MerchantAccount,
    Plan,
    ProviderEvent,
    ProviderRef,
    Subscription,
)
from saas_os.core.billing.oversight import (
    CommercialOverviewPage,
    SubscriptionOverview,
    TenantCommercialOverview,
    commercial_overview,
)
from saas_os.core.billing.parties import (
    BillingAccountStatus,
    MerchantAccountStatus,
    create_merchant_account,
    get_billing_account,
    get_merchant_account,
    get_or_create_billing_account,
    list_billing_accounts,
    list_merchant_accounts,
    set_merchant_account_status,
)
from saas_os.core.billing.provider import (
    BillingProvider,
    FakeBillingProvider,
    ProviderEventNotice,
    ProviderSubscriptionState,
)
from saas_os.core.billing.provider_events import (
    PROVIDER_EVENT_RETENTION,
    UNKNOWN_SUBSCRIPTION_GRACE,
    ProviderEventOutcome,
    ProviderEventResult,
    ProviderEventStatus,
    process_provider_event,
    prune_provider_events,
)
from saas_os.core.billing.provider_refs import (
    LocalObjectType,
    ProviderObjectType,
    ProviderRefResolution,
    find_provider_object_ref,
    register_provider_ref,
    resolve_provider_ref,
)
from saas_os.core.billing.service import (
    SubscribeResult,
    cancel_subscription,
    combine_entitlements,
    create_plan,
    get_entitlements,
    get_plan,
    get_subscription,
    has_entitlement,
    list_subscriptions,
    require_entitlement,
    resolve_billing_owner,
    subscribe,
    subscribe_idempotent,
    upgrade_subscription,
)

__all__ = [
    # ADR-0045 section 9d: the commercial overview (platform oversight).
    "commercial_overview",
    "CommercialOverviewPage",
    "TenantCommercialOverview",
    "SubscriptionOverview",
    "Plan",
    "Subscription",
    "BillingProvider",
    "FakeBillingProvider",
    "create_plan",
    "get_plan",
    "list_plans",
    "EligibilityReason",
    "PlanEligibility",
    "PlanOfferStatus",
    "PlanStatus",
    "PlanVisibility",
    "adopt_legacy_plan",
    "create_owned_plan",
    "create_plan_offer",
    "evaluate_plan_eligibility",
    "revoke_plan_offer",
    "set_plan_visibility",
    "withdraw_plan",
    "subscribe",
    "subscribe_idempotent",
    "SubscribeResult",
    "upgrade_subscription",
    "cancel_subscription",
    "get_subscription",
    "list_subscriptions",
    "combine_entitlements",
    "get_entitlements",
    "has_entitlement",
    "require_entitlement",
    "resolve_billing_owner",
    "InvalidPlanKeyError",
    "DuplicatePlanKeyError",
    "PlanNotFoundError",
    "SubscriptionNotFoundError",
    "BillingProviderError",
    "InvalidWebhookSignatureError",
    # ADR-0048: inbound provider events.
    "PROVIDER_EVENT_RETENTION",
    "UNKNOWN_SUBSCRIPTION_GRACE",
    "ProviderEvent",
    "ProviderEventNotice",
    "ProviderEventOutcome",
    "ProviderEventProcessingError",
    "ProviderEventResult",
    "ProviderEventStatus",
    "process_provider_event",
    "prune_provider_events",
    "EntitlementDeniedError",
    "InvalidBillingHierarchyError",
    "InheritedBillingSubscriptionError",
    # Billing Foundation v2 Phase 2 -- commercial parties
    "MerchantAccount",
    "BillingAccount",
    "ProviderRef",
    "MerchantAccountStatus",
    "BillingAccountStatus",
    "create_merchant_account",
    "set_merchant_account_status",
    "get_merchant_account",
    "list_merchant_accounts",
    "get_or_create_billing_account",
    "get_billing_account",
    "list_billing_accounts",
    "ProviderObjectType",
    "LocalObjectType",
    "ProviderRefResolution",
    "register_provider_ref",
    "resolve_provider_ref",
    "BILLING_PERMISSIONS",
    "BILLING_SYSTEM_AUTHORITY",
    "BillingActor",
    "BillingCaller",
    "TrustedSystemCaller",
    "trusted_system",
    "register_billing_permissions",
    "create_subscription",
    "CancellationCapacity",
    "migrate_inherited_tenant_to_sponsorship",
    "opt_out_of_billing_inheritance",
    "BillingInheritanceMigrationError",
    "get_subscription_by_provider_ref",
    "BillingActorRequiredError",
    "LegacyBillingPathError",
    "BillingNotAuthorizedError",
    "InvalidBillingPartyError",
    "MerchantAccountNotFoundError",
    "DuplicateMerchantAccountError",
    "BillingAccountNotFoundError",
    "CommercialPartyNotActiveError",
    "MerchantNotEligibleForPlanError",
    "BillingProviderMismatchError",
    "ProviderRefConflictError",
    "ProviderRefNotFoundError",
    # Billing Foundation v2 Phase 3 -- lifecycle safety
    "SubscriptionStatus",
    "VerificationState",
    "ALLOWED_TRANSITIONS",
    "LIVE_STATUSES",
    "ProviderSubscriptionState",
    "SubscriptionReconciliation",
    "reconcile_subscription_status",
    "cancel_commercial_subscription",
    "reconcile_legacy_subscription",
    "InvalidSubscriptionTransitionError",
    "LiveSubscriptionExistsError",
    "LegacyReconciliationError",
    "ProviderReferenceMismatchError",
    "BillingProviderContractError",
    "find_provider_object_ref",
]
