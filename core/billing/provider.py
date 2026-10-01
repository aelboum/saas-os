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

import enum
import uuid
from typing import Protocol, runtime_checkable

from core.billing.errors import BillingProviderError
from core.billing.models import Plan


class ProviderSubscriptionState(enum.StrEnum):
    """The provider-neutral answer to "what is the authoritative state of
    this provider subscription right now?" (Billing Foundation v2 Phase 3;
    `core/billing/lifecycle.py`). Adapters translate their native states
    into exactly one of these; nothing provider-specific crosses the
    adapter boundary.

        active     -- the provider positively confirms an active, paid-up
                      subscription.
        pending    -- exists, not yet active (e.g. awaiting first payment).
        past_due   -- exists, live, with a payment problem.
        canceled   -- terminal at the provider (canceled or expired).
        not_found  -- the provider has no such subscription.
        unknown    -- a state the adapter does not (yet) map, e.g. a trial
                      or pause state whose semantics belong to a later
                      phase. Never treated as active.

    A provider *error* (unreachable, authentication failure, rate limit) is
    not a state: `get_subscription_status()` raises `BillingProviderError`
    instead, so an outage can never be mistaken for any answer."""

    ACTIVE = "active"
    PENDING = "pending"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"


@runtime_checkable
class BillingProvider(Protocol):
    """The provider-side lifecycle operations: create, change plan
    ("upgrade"), cancel (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1), and --
    Billing Foundation v2 Phase 3 -- the synchronous status query that
    provider-confirmed activation and reconciliation rest on. Nothing about invoices,
    payments, or webhook delivery belongs to this interface -- see
    `core/billing/__init__.py`'s own Non-Goals for why those are deferred.
    """

    name: str
    """A short, stable, provider-neutral adapter name (e.g. `"stripe"`,
    `"fake"`) persisted as `Subscription.provider`/`MerchantAccount.provider`
    (Billing Foundation v2 Phase 2; docs/ADR/0008-... amendment, point 3:
    "provider is persisted per subscription"). An opaque label, never a
    provider SDK type."""

    honors_idempotency_keys: bool
    """An explicit declaration that `create_subscription()` forwards a given
    `idempotency_key` to the provider so that a repeated key returns the
    subscription the first call created (Billing Foundation v2 Phase 3).
    The commercial path (`core/billing/commercial.py::create_subscription()`)
    refuses an adapter that does not declare `True`
    (`BillingProviderContractError`): an adapter that cannot or does not
    honor keys must not be used for commercial subscriptions, rather than
    being trusted to. Python cannot verify the behavior itself; the
    declaration makes the obligation explicit and is pinned for the
    shipped adapters by tests."""

    def create_subscription(
        self, *, tenant_id: uuid.UUID, plan: Plan, idempotency_key: str | None = None
    ) -> str:
        """Create a subscription at the provider for `tenant_id` against
        `plan`. Returns the provider's own subscription identifier --
        *creation only*: an id is never proof of an active subscription
        (`get_subscription_status()` is). `idempotency_key`, when given, is
        a stable, provider-neutral key for one logical commercial
        operation: an adapter must pass it to the provider so a retry with
        the same key returns the same provider subscription rather than
        creating a second one (Billing Foundation v2 Phase 3; the legacy
        `subscribe()` path passes none)."""
        ...

    def get_subscription_status(
        self, *, provider_subscription_id: str
    ) -> ProviderSubscriptionState:
        """The provider's current authoritative state for this
        subscription, translated to `ProviderSubscriptionState`. Raises
        `BillingProviderError` when the provider cannot be asked (never
        returns a guess)."""
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

    Phase 3 test controls, all provider-neutral: `initial_state` is the
    state a newly created subscription reports (default `active`: the fake
    "provider" confirms payment); `set_state()` changes one subscription's
    reported state; `status_unavailable = True` makes
    `get_subscription_status()` raise `BillingProviderError`, simulating
    an outage. A repeated `idempotency_key` returns the subscription the
    first call created, exactly as a real provider's idempotency does.
    """

    name = "fake"
    honors_idempotency_keys = True

    def __init__(
        self, *, initial_state: ProviderSubscriptionState = ProviderSubscriptionState.ACTIVE
    ) -> None:
        self._subscriptions: dict[str, str] = {}  # provider_subscription_id -> plan_key
        self._states: dict[str, ProviderSubscriptionState] = {}
        self._by_idempotency_key: dict[str, str] = {}
        self.initial_state = initial_state
        self.status_unavailable = False

    def create_subscription(
        self, *, tenant_id: uuid.UUID, plan: Plan, idempotency_key: str | None = None
    ) -> str:
        if idempotency_key is not None and idempotency_key in self._by_idempotency_key:
            return self._by_idempotency_key[idempotency_key]
        provider_subscription_id = f"fake_sub_{uuid.uuid4().hex}"
        self._subscriptions[provider_subscription_id] = plan.key
        self._states[provider_subscription_id] = self.initial_state
        if idempotency_key is not None:
            self._by_idempotency_key[idempotency_key] = provider_subscription_id
        return provider_subscription_id

    def get_subscription_status(
        self, *, provider_subscription_id: str
    ) -> ProviderSubscriptionState:
        if self.status_unavailable:
            raise BillingProviderError("get_subscription_status", "provider unavailable")
        return self._states.get(provider_subscription_id, ProviderSubscriptionState.NOT_FOUND)

    def set_state(self, provider_subscription_id: str, state: ProviderSubscriptionState) -> None:
        self._states[provider_subscription_id] = state

    def change_plan(self, *, provider_subscription_id: str, plan: Plan) -> None:
        self._subscriptions[provider_subscription_id] = plan.key

    def cancel_subscription(self, *, provider_subscription_id: str) -> None:
        self._subscriptions.pop(provider_subscription_id, None)
        if provider_subscription_id in self._states:
            self._states[provider_subscription_id] = ProviderSubscriptionState.CANCELED
