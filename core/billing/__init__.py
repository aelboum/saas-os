"""`core/billing` -- provider-abstraction interface, plans, subscriptions,
entitlements (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1;
docs/ADR/0008-billing-provider.md).

Owns:
- the global `Plan` catalog (`core.billing_plans`) -- a pricing-tier
  definition and its entitlement mapping;
- the tenant-owned `Subscription` (`core.billing_subscriptions`,
  RLS-protected) -- a tenant's subscription state/lifecycle against a plan;
- the `BillingProvider` interface (`core/billing/provider.py`) and its
  two implementations: `FakeBillingProvider` (in-memory) and
  `StripeBillingProvider` (`core/billing/stripe_provider.py`, the only
  file that imports `stripe`);
- `get_entitlements()`, the product-agnostic "plan -> feature/limit"
  lookup (`docs/ARCHITECTURE-DISCOVERY.md` section 14).

Does NOT own (Non-Goals, deliberately deferred -- not built by this
phase since no Tests/Acceptance Criterion exercises them):
- **Invoices/Payments**: `docs/ADR/0008-...`'s own table names them as
  distinct concepts, but persisting or syncing local mirrors of Stripe's
  invoice/payment records is deferred to a future phase with an actual
  tested need -- Stripe itself remains the system of record until then.
- **Usage metering**: owned by the future `core/usage` (Phase 5.2),
  which feeds entitlement/quota checks through this module's own
  interface, never by `core/billing` reading usage data directly.
- **Webhook ingress**: `core/billing/stripe_provider.py::verify_stripe_webhook_signature()`
  is a pure, reusable verification primitive; no HTTP route receives a
  Stripe webhook yet (Phase 8's ingress layer).
- **Plan tier ordering**: `upgrade_subscription()` is a direction-agnostic
  plan change; nothing validates "the new plan is actually higher-tier."
- Any HTTP/API surface, frontend, or product-specific billing logic.
"""

from core.billing.errors import (
    BillingProviderError,
    DuplicatePlanKeyError,
    EntitlementDeniedError,
    InvalidPlanKeyError,
    InvalidWebhookSignatureError,
    PlanNotFoundError,
    SubscriptionNotFoundError,
)
from core.billing.models import Plan, Subscription
from core.billing.provider import BillingProvider, FakeBillingProvider
from core.billing.service import (
    SubscribeResult,
    cancel_subscription,
    create_plan,
    get_entitlements,
    get_plan,
    get_subscription,
    has_entitlement,
    list_plans,
    list_subscriptions,
    require_entitlement,
    subscribe,
    subscribe_idempotent,
    upgrade_subscription,
)

__all__ = [
    "Plan",
    "Subscription",
    "BillingProvider",
    "FakeBillingProvider",
    "create_plan",
    "get_plan",
    "list_plans",
    "subscribe",
    "subscribe_idempotent",
    "SubscribeResult",
    "upgrade_subscription",
    "cancel_subscription",
    "get_subscription",
    "list_subscriptions",
    "get_entitlements",
    "has_entitlement",
    "require_entitlement",
    "InvalidPlanKeyError",
    "DuplicatePlanKeyError",
    "PlanNotFoundError",
    "SubscriptionNotFoundError",
    "BillingProviderError",
    "InvalidWebhookSignatureError",
    "EntitlementDeniedError",
]
