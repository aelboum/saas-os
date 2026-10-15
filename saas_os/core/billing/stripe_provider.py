"""The Stripe adapter (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1;
docs/ADR/0008-billing-provider.md: "Stripe as the first (and initially
only) concrete implementation").

This is the **only** file in `saas_os/core/billing` (indeed, in all of `core/`)
that imports `stripe` -- `saas_os/core/billing/provider.py`'s `BillingProvider`
Protocol and `saas_os/core/billing/service.py` never reference Stripe's object
model directly (ADR-0008's own binding requirement, "No Core or Product
code depends on Stripe-specific types -- only the adapter does").

`api_key` is supplied by the caller (`saas_os/core/billing/service.py::_default_provider()`,
which reads it via `saas_os.infra.secrets.get_secrets_provider().get_required("STRIPE_API_KEY")`
-- this module itself never reads an environment variable or calls
`saas_os.infra.secrets` directly, matching every other Core module's convention
of receiving configuration through its caller, not resolving it itself).

Uses the modern `stripe.StripeClient` instance API (`client.v1.*`) rather
than the legacy global `stripe.api_key = ...` module attribute -- avoids
mutable global state shared across whatever else in the process might
also use the `stripe` package.
"""

from __future__ import annotations

import uuid

import stripe

from saas_os.core.billing.errors import BillingProviderError, InvalidWebhookSignatureError
from saas_os.core.billing.models import Plan
from saas_os.core.billing.provider import (
    ProviderCommerceContext,
    ProviderEventNotice,
    ProviderSubscriptionState,
)

# Stripe subscription status -> provider-neutral state (Billing Foundation
# v2 Phase 3). `trialing` and `paused` deliberately map to UNKNOWN: trials
# and pauses are later phases' features, and an unmapped state must never
# be read as active. Any status Stripe adds in future is UNKNOWN too.
_STRIPE_STATES: dict[str, ProviderSubscriptionState] = {
    "active": ProviderSubscriptionState.ACTIVE,
    "incomplete": ProviderSubscriptionState.PENDING,
    "past_due": ProviderSubscriptionState.PAST_DUE,
    "unpaid": ProviderSubscriptionState.PAST_DUE,
    "canceled": ProviderSubscriptionState.CANCELED,
    "incomplete_expired": ProviderSubscriptionState.CANCELED,
}


class StripeBillingProvider:
    """A real `BillingProvider` (`saas_os/core/billing/provider.py`) backed by
    the Stripe API. Every operation creates or mutates real Stripe
    objects when constructed with a real (test-mode or live) API key --
    this class is exercised end-to-end only by
    `tests/core/billing/test_billing_stripe_integration.py`, which skips
    cleanly (mirrors `tests/infra/test_db_integration.py`'s own
    unreachable-dependency convention) when `STRIPE_API_KEY` is not
    configured for the local/CI environment, rather than failing.
    """

    name = "stripe"
    honors_idempotency_keys = True

    def __init__(self, api_key: str) -> None:
        self._client = stripe.StripeClient(api_key=api_key)

    def create_subscription(
        self,
        *,
        tenant_id: uuid.UUID,
        plan: Plan,
        idempotency_key: str | None = None,
        context: ProviderCommerceContext | None = None,
    ) -> str:
        """`idempotency_key` (Phase 3) is forwarded as Stripe's own
        `Idempotency-Key` -- suffixed per request, since the customer and
        the subscription are two separate Stripe requests -- so a retry of
        the same logical operation returns the same Stripe objects instead
        of creating new ones. The returned id is creation only; whether the
        subscription is active is `get_subscription_status()`'s answer."""
        if plan.provider_price_id is None:
            raise BillingProviderError(
                "create_subscription", f"plan {plan.key!r} has no provider_price_id"
            )
        customer_options: dict[str, str] = {}
        subscription_options: dict[str, str] = {}
        if idempotency_key is not None:
            customer_options["idempotency_key"] = f"{idempotency_key}:customer"
            subscription_options["idempotency_key"] = f"{idempotency_key}:subscription"
        try:
            if context is not None and context.provider_customer_ref is not None:
                # Phase 5.3 step 3: the (payer, merchant) customer Core
                # persisted on the billing account. This adapter acts only in
                # the deployment's own Stripe account (no Connect yet); Core
                # constructs it only for the platform tenant's merchant.
                customer_id = context.provider_customer_ref
            else:
                customer_id = self._client.v1.customers.create(
                    params={"metadata": {"tenant_id": str(tenant_id)}},
                    options=customer_options,  # type: ignore[arg-type]
                ).id
            subscription = self._client.v1.subscriptions.create(
                params={"customer": customer_id, "items": [{"price": plan.provider_price_id}]},
                options=subscription_options,  # type: ignore[arg-type]
            )
        except stripe.StripeError as exc:
            raise BillingProviderError("create_subscription", type(exc).__name__) from exc
        return subscription.id

    def ensure_customer(self, *, context: ProviderCommerceContext, idempotency_key: str) -> str:
        """Create the Stripe customer for one (payer, merchant) billing
        account, with a stable idempotency key so a retry returns the same
        customer. Metadata is informational only -- it is never used to
        resolve a tenant (ADR-0008 point 9)."""
        try:
            customer = self._client.v1.customers.create(
                params={"metadata": {"billing_account_id": str(context.payer_billing_account_id)}},
                options={"idempotency_key": idempotency_key},
            )
        except stripe.StripeError as exc:
            raise BillingProviderError("ensure_customer", type(exc).__name__) from exc
        return str(customer.id)

    def get_subscription_status(
        self, *, provider_subscription_id: str
    ) -> ProviderSubscriptionState:
        """Read the subscription back from Stripe and translate its status
        (`_STRIPE_STATES`). A missing subscription is `NOT_FOUND`; any other
        Stripe error raises `BillingProviderError` -- never a guessed state.
        No Stripe object leaves this method."""
        try:
            subscription = self._client.v1.subscriptions.retrieve(provider_subscription_id)
        except stripe.InvalidRequestError as exc:
            if getattr(exc, "code", None) == "resource_missing":
                return ProviderSubscriptionState.NOT_FOUND
            raise BillingProviderError("get_subscription_status", type(exc).__name__) from exc
        except stripe.StripeError as exc:
            raise BillingProviderError("get_subscription_status", type(exc).__name__) from exc
        return _STRIPE_STATES.get(str(subscription.status), ProviderSubscriptionState.UNKNOWN)

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
    where applicable)". Mirrors `saas_os/core/webhooks/service.py::compute_signature()`'s
    precedent of being a pure, independently-testable primitive -- no
    HTTP route receives this yet (that is Phase 8's ingress concern);
    this function is what a future route would call.

    Delegates the actual HMAC-with-timestamp-tolerance verification to
    the official `stripe` SDK (`stripe.Webhook.construct_event`) rather
    than hand-rolling Stripe's signature scheme -- the same "reuse the
    vendor's own battle-tested primitive" discipline
    `saas_os/core/identity/oidc.py` already applies to PyJWT for OIDC token
    verification.

    **Deprecated** for ingestion: it returns the SDK's own `stripe.Event`,
    which ADR-0008 (amendment, point 8) records as a violation. Inbound
    events go through `parse_stripe_event()`, which returns a
    provider-neutral `ProviderEventNotice` (ADR-0048). Kept, unchanged,
    for code that already calls it.
    """
    try:
        event = stripe.Webhook.construct_event(payload, signature_header, webhook_secret)
    except stripe.SignatureVerificationError as exc:
        raise InvalidWebhookSignatureError() from exc
    return event


def _reference(value: object) -> str | None:
    """A provider object reference from a field that holds either the id
    or the expanded object."""
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        return _reference(value.get("id"))
    return None


def _subscription_reference(obj: object) -> str | None:
    """The subscription an event's object concerns: the object itself when
    it is a subscription; otherwise its `subscription` field (checkout
    sessions, and invoices before Stripe API version 2025-03-31), or an
    invoice's `parent.subscription_details.subscription` (since then)."""
    if not isinstance(obj, dict):
        return None
    if obj.get("object") == "subscription":
        return _reference(obj.get("id"))
    direct = _reference(obj.get("subscription"))
    if direct is not None:
        return direct
    parent = obj.get("parent")
    if isinstance(parent, dict):
        details = parent.get("subscription_details")
        if isinstance(details, dict):
            return _reference(details.get("subscription"))
    return None


def parse_stripe_event(
    payload: bytes, signature_header: str, webhook_secret: str
) -> ProviderEventNotice:
    """Verify a Stripe delivery and translate it into a provider-neutral
    `ProviderEventNotice` (docs/ADR/0048-inbound-billing-provider-events.md,
    item 6). The signature, including Stripe's timestamp tolerance, is
    checked by the SDK over the raw bytes before anything in the body is
    read. Any failure -- a bad or missing signature, a stale timestamp, a
    body that is not an event -- is the same `InvalidWebhookSignatureError`,
    which never carries the payload or the secret."""
    try:
        event = stripe.Webhook.construct_event(payload, signature_header, webhook_secret)
        data = event.to_dict()
    except (stripe.SignatureVerificationError, ValueError, KeyError, TypeError) as exc:
        raise InvalidWebhookSignatureError() from exc
    event_id = data.get("id")
    event_type = data.get("type")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_type, str):
        raise InvalidWebhookSignatureError()
    account = data.get("account")
    body = data.get("data")
    return ProviderEventNotice(
        provider=StripeBillingProvider.name,
        event_id=event_id,
        event_type=event_type,
        provider_account_ref=account if isinstance(account, str) and account else None,
        provider_subscription_ref=_subscription_reference(
            body.get("object") if isinstance(body, dict) else None
        ),
    )
