"""Pure unit tests for `core/billing` -- no database or live Stripe
network access needed.

Webhook signature verification (docs/IMPLEMENTATION-ROADMAP.md Phase
5.1's own Security Requirement) is proven non-vacuously: a validly-signed
test payload is constructed *offline* via `stripe.WebhookSignature.generate_signature_header`
(the same primitive stripe-python's own test suite uses -- no network
call), our wrapper is proven to accept it, and proven to reject both a
tampered payload and a wrong secret.
"""

from __future__ import annotations

import inspect
import json
import uuid

import pytest
import stripe
from core.billing.errors import InvalidWebhookSignatureError
from core.billing.provider import BillingProvider, FakeBillingProvider
from core.billing.stripe_provider import StripeBillingProvider, verify_stripe_webhook_signature


def test_fake_billing_provider_satisfies_billing_provider_protocol() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 5.1's own Tests requirement:
    "a substitution test confirming a mock/fake provider adapter
    satisfies the same interface" -- a structural, non-vacuous proof via
    `@runtime_checkable` Protocol isinstance, not merely "it has the same
    method names by convention."""
    assert isinstance(FakeBillingProvider(), BillingProvider)


def test_stripe_billing_provider_satisfies_billing_provider_protocol() -> None:
    provider = StripeBillingProvider(api_key="sk_test_dummy_not_a_real_key")
    assert isinstance(provider, BillingProvider)


def test_core_billing_service_does_not_import_stripe_directly() -> None:
    """docs/ADR/0008-billing-provider.md: "No Core or Product code
    depends on Stripe-specific types -- only the adapter does." Non-vacuous
    documentation of the boundary; the real enforcement is that only
    core/billing/stripe_provider.py imports `stripe` at all.
    """
    import core.billing.provider as provider_module
    import core.billing.service as service_module

    for module in (service_module, provider_module):
        source = inspect.getsource(module)
        assert "import stripe" not in source


def test_fake_billing_provider_create_change_cancel_lifecycle() -> None:
    from core.billing.models import Plan

    provider = FakeBillingProvider()
    plan_a = Plan(key="starter", name="Starter", entitlements={})
    plan_b = Plan(key="pro", name="Pro", entitlements={})

    subscription_id = provider.create_subscription(tenant_id=uuid.uuid4(), plan=plan_a)
    assert subscription_id in provider._subscriptions
    assert provider._subscriptions[subscription_id] == "starter"

    provider.change_plan(provider_subscription_id=subscription_id, plan=plan_b)
    assert provider._subscriptions[subscription_id] == "pro"

    provider.cancel_subscription(provider_subscription_id=subscription_id)
    assert subscription_id not in provider._subscriptions


# --- Webhook signature verification --------------------------------------


def _signed_payload(secret: str) -> tuple[bytes, str]:
    payload = json.dumps(
        {
            "id": "evt_test_123",
            "object": "event",
            "type": "customer.subscription.updated",
            "data": {"object": {"id": "sub_test_123"}},
        }
    ).encode("utf-8")
    header = stripe.WebhookSignature.generate_signature_header(
        payload=payload.decode("utf-8"), secret=secret
    )
    return payload, header


def test_verify_stripe_webhook_signature_accepts_a_validly_signed_payload() -> None:
    secret = "whsec_test_secret_value"
    payload, header = _signed_payload(secret)

    event = verify_stripe_webhook_signature(payload, header, secret)
    assert event["type"] == "customer.subscription.updated"
    assert event["id"] == "evt_test_123"


def test_verify_stripe_webhook_signature_rejects_tampered_payload() -> None:
    secret = "whsec_test_secret_value"
    payload, header = _signed_payload(secret)
    tampered_payload = payload.replace(b"customer.subscription.updated", b"customer.deleted!!!!")

    with pytest.raises(InvalidWebhookSignatureError):
        verify_stripe_webhook_signature(tampered_payload, header, secret)


def test_verify_stripe_webhook_signature_rejects_wrong_secret() -> None:
    payload, header = _signed_payload("whsec_test_secret_value")

    with pytest.raises(InvalidWebhookSignatureError):
        verify_stripe_webhook_signature(payload, header, "whsec_a_completely_different_secret")


def test_verify_stripe_webhook_signature_error_never_contains_the_secret() -> None:
    secret = "whsec_super_secret_value_should_never_leak"
    payload, header = _signed_payload(secret)
    tampered_payload = payload + b"tampered"

    with pytest.raises(InvalidWebhookSignatureError) as excinfo:
        verify_stripe_webhook_signature(tampered_payload, header, secret)
    assert secret not in str(excinfo.value)
