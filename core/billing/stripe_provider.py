"""The Stripe adapter (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1;
docs/ADR/0008-billing-provider.md: "Stripe as the first (and initially
only) concrete implementation").

This is the **only** file in `core/billing` (indeed, in all of `core/`)
that imports `stripe` -- `core/billing/provider.py`'s `BillingProvider`
Protocol and `core/billing/service.py` never reference Stripe's object
model directly (ADR-0008's own binding requirement, "No Core or Product
code depends on Stripe-specific types -- only the adapter does").

`api_key` is supplied by the caller (`core/billing/service.py::_default_provider()`,
which reads it via `infra.secrets.get_secrets_provider().get_required("STRIPE_API_KEY")`
-- this module itself never reads an environment variable or calls
`infra.secrets` directly, matching every other Core module's convention
of receiving configuration through its caller, not resolving it itself).

Uses the modern `stripe.StripeClient` instance API (`client.v1.*`) rather
than the legacy global `stripe.api_key = ...` module attribute -- avoids
mutable global state shared across whatever else in the process might
also use the `stripe` package.
"""

from __future__ import annotations

import uuid

import stripe

from core.billing.errors import BillingProviderError, InvalidWebhookSignatureError
from core.billing.models import Plan


class StripeBillingProvider:
    """A real `BillingProvider` (`core/billing/provider.py`) backed by
    the Stripe API. Every operation creates or mutates real Stripe
    objects when constructed with a real (test-mode or live) API key --
    this class is exercised end-to-end only by
    `tests/core/billing/test_billing_stripe_integration.py`, which skips
    cleanly (mirrors `tests/infra/test_db_integration.py`'s own
    unreachable-dependency convention) when `STRIPE_API_KEY` is not
    configured for the local/CI environment, rather than failing.
    """

    def __init__(self, api_key: str) -> None:
        self._client = stripe.StripeClient(api_key=api_key)

    def create_subscription(self, *, tenant_id: uuid.UUID, plan: Plan) -> str:
        if plan.provider_price_id is None:
            raise BillingProviderError(
                "create_subscription", f"plan {plan.key!r} has no provider_price_id"
            )
        try:
            customer = self._client.v1.customers.create(
                params={"metadata": {"tenant_id": str(tenant_id)}}
            )
            subscription = self._client.v1.subscriptions.create(
                params={"customer": customer.id, "items": [{"price": plan.provider_price_id}]}
            )
        except stripe.StripeError as exc:
            raise BillingProviderError("create_subscription", type(exc).__name__) from exc
        return subscription.id

    def change_plan(self, *, provider_subscription_id: str, plan: Plan) -> None:
        if plan.provider_price_id is None:
            raise BillingProviderError("change_plan", f"plan {plan.key!r} has no provider_price_id")
        try:
            existing = self._client.v1.subscriptions.retrieve(provider_subscription_id)
            item_id = existing["items"]["data"][0]["id"]
            self._client.v1.subscriptions.update(
                provider_subscription_id,
                params={"items": [{"id": item_id, "price": plan.provider_price_id}]},
            )
        except stripe.StripeError as exc:
            raise BillingProviderError("change_plan", type(exc).__name__) from exc

    def cancel_subscription(self, *, provider_subscription_id: str) -> None:
        try:
            self._client.v1.subscriptions.cancel(provider_subscription_id)
        except stripe.StripeError as exc:
            raise BillingProviderError("cancel_subscription", type(exc).__name__) from exc


def verify_stripe_webhook_signature(
    payload: bytes, signature_header: str, webhook_secret: str
) -> stripe.Event:
    """Verify a Stripe webhook delivery's `Stripe-Signature` header
    against `webhook_secret`, returning the parsed event on success --
    docs/IMPLEMENTATION-ROADMAP.md Phase 5.1's own Security Requirement:
    "webhook-from-provider signature verification (reuses 4.3 patterns
    where applicable)". Mirrors `core/webhooks/service.py::compute_signature()`'s
    precedent of being a pure, independently-testable primitive -- no
    HTTP route receives this yet (that is Phase 8's ingress concern);
    this function is what a future route would call.

    Delegates the actual HMAC-with-timestamp-tolerance verification to
    the official `stripe` SDK (`stripe.Webhook.construct_event`) rather
    than hand-rolling Stripe's signature scheme -- the same "reuse the
    vendor's own battle-tested primitive" discipline
    `core/identity/oidc.py` already applies to PyJWT for OIDC token
    verification.
    """
    try:
        event = stripe.Webhook.construct_event(payload, signature_header, webhook_secret)
    except stripe.SignatureVerificationError as exc:
        raise InvalidWebhookSignatureError() from exc
    return event
