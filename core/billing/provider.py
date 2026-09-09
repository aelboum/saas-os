"""The `BillingProvider` interface (docs/IMPLEMENTATION-ROADMAP.md Phase
5.1; docs/ADR/0008-billing-provider.md: "core/billing defines an internal
provider-abstraction interface; Stripe is the first (and initially only)
concrete implementation behind it").

This module and `core/billing/models.py` are the only vocabulary
Core/Product code needs -- neither imports `stripe` (confirmed by
`tests/core/billing/test_billing_models.py`'s and this module's own
no-direct-stripe-import tests). Only `core/billing/stripe_provider.py`
knows Stripe's specific object model, exactly as ADR-0008 requires.

`FakeBillingProvider` is the second, in-memory implementation of this
same interface -- not a test mock bolted onto internals, but a real,
independent adapter satisfying the identical `BillingProvider` contract
(docs/IMPLEMENTATION-ROADMAP.md Phase 5.1's own Tests requirement: "a
substitution test confirming a mock/fake provider adapter satisfies the
same interface, proves the abstraction isn't leaky"). It is what
`core/billing/service.py`'s own tests run against by default, since it
needs no external network access or provider credentials.
"""

from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable

from core.billing.models import Plan


@runtime_checkable
class BillingProvider(Protocol):
    """Exactly the three provider-side lifecycle operations
    docs/IMPLEMENTATION-ROADMAP.md Phase 5.1's Acceptance Criteria names:
    create, change plan ("upgrade"), and cancel. Nothing about invoices,
    payments, or webhook delivery belongs to this interface -- see
    `core/billing/__init__.py`'s own Non-Goals for why those are deferred.
    """

    def create_subscription(self, *, tenant_id: uuid.UUID, plan: Plan) -> str:
        """Create a subscription at the provider for `tenant_id` against
        `plan`. Returns the provider's own subscription identifier."""
        ...

    def change_plan(self, *, provider_subscription_id: str, plan: Plan) -> None:
        """Change an existing provider-side subscription to `plan`."""
        ...

    def cancel_subscription(self, *, provider_subscription_id: str) -> None:
        """Cancel an existing provider-side subscription."""
        ...


class FakeBillingProvider:
    """An in-memory `BillingProvider` -- no network access, no
    credentials. Each instance tracks its own fabricated subscription
    state so tests can assert against it directly if needed.
    """

    def __init__(self) -> None:
        self._subscriptions: dict[str, str] = {}  # provider_subscription_id -> plan_key

    def create_subscription(self, *, tenant_id: uuid.UUID, plan: Plan) -> str:
        provider_subscription_id = f"fake_sub_{uuid.uuid4().hex}"
        self._subscriptions[provider_subscription_id] = plan.key
        return provider_subscription_id

    def change_plan(self, *, provider_subscription_id: str, plan: Plan) -> None:
        self._subscriptions[provider_subscription_id] = plan.key

    def cancel_subscription(self, *, provider_subscription_id: str) -> None:
        self._subscriptions.pop(provider_subscription_id, None)
