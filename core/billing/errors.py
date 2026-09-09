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
