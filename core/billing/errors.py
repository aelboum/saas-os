"""Typed errors for `core/billing` (docs/IMPLEMENTATION-ROADMAP.md Phase
5.1). Every error here carries only identifying metadata -- never a
payment credential, a raw provider API key, or a webhook payload's
contents.
"""

from __future__ import annotations

import uuid


class InvalidPlanKeyError(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class DuplicatePlanKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Billing plan {key!r} already exists.")


class PlanNotFoundError(LookupError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Billing plan {key!r} not found.")


class SubscriptionNotFoundError(LookupError):
    """Raised when a subscription id does not resolve within the given
    tenant -- deliberately the same error whether the subscription truly
    doesn't exist or belongs to a different tenant, so this lookup itself
    never confirms or denies another tenant's data (docs/SECURITY.md
    section 5), mirroring `core/webhooks`'s `WebhookSubscriptionNotFoundError`."""

    def __init__(self, tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        super().__init__(f"Subscription {subscription_id} not found in tenant {tenant_id}.")


class BillingProviderError(RuntimeError):
    """Raised when the underlying billing provider (Stripe, or the fake
    test adapter) rejects an operation. Carries only the provider's error
    *type name* and a short reason -- never the raw provider exception,
    which could echo request parameters or account-identifying detail."""

    def __init__(self, operation: str, reason: str) -> None:
        self.operation = operation
        super().__init__(f"Billing provider operation {operation!r} failed: {reason}")


class InvalidWebhookSignatureError(ValueError):
    """Raised when a provider webhook payload's signature does not verify
    -- never includes the payload or the webhook secret in its message."""

    def __init__(self) -> None:
        super().__init__("Webhook signature verification failed.")


class InvalidBillingHierarchyError(RuntimeError):
    """Raised by `resolve_billing_owner()` (architecture research Phase H
    -- "Hierarchy-Aware Billing & Usage") when a tenant's
    `inherits_billing=True` configuration cannot be resolved to a real
    billing owner -- e.g. a root tenant (no parent) with no ancestor to
    inherit from, or every ancestor up to the root also has
    `inherits_billing=True` (nobody in the chain actually owns billing).
    Fail-closed by design (this phase's own approved requirement: "if
    configuration is invalid, fail closed rather than guessing") -- never
    silently falls back to treating the tenant as its own owner, which
    would silently reactivate billing for a tenant that explicitly opted
    out of owning it itself."""

    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        super().__init__(
            f"Tenant {tenant_id} has inherits_billing=True but no ancestor resolves to a "
            "valid billing owner."
        )


class InheritedBillingSubscriptionError(RuntimeError):
    """Raised by `subscribe()`/`subscribe_idempotent()` when called
    directly on a tenant with `Tenant.inherits_billing=True` (architecture
    research Phase H billing-owner consistency repair). Such a tenant does
    not own its own billing -- `get_entitlements()` would keep reading
    the resolved owner's plan regardless of any `Subscription` row
    created here, and creating one anyway would be exactly the
    "multiple billing owners" ambiguity the whole hierarchy design
    forbids. Fails closed rather than silently redirecting the mutation
    to the resolved owner (a mutation on a tenant other than the one
    literally supplied, with no explicit authorization for it in this
    phase) or silently creating the child's own orphaned subscription. A
    caller that wants to subscribe the resolved owner calls
    `resolve_billing_owner(tenant_id)` itself first, then
    `subscribe(owner_id, ...)`."""

    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        super().__init__(
            f"Tenant {tenant_id} inherits billing and does not own its own subscription; "
            "call subscribe() on its resolved billing owner instead."
        )


class EntitlementDeniedError(RuntimeError):
    """Raised by `require_entitlement()` (P1.9) when the tenant's active
    plan does not grant a given boolean capability key. Carries only the
    entitlement key -- never the tenant's full entitlements dict, plan
    name, or any other subscription detail (mirrors
    `SubscriptionNotFoundError`'s own minimal-disclosure convention)."""

    def __init__(self, tenant_id: uuid.UUID, key: str) -> None:
        self.tenant_id = tenant_id
        self.key = key
        super().__init__(f"Tenant {tenant_id} is not entitled to {key!r}.")
