"""ADR-0048 item 6 -- `parse_stripe_event()` verifies a Stripe delivery
over its raw bytes and returns a provider-neutral `ProviderEventNotice`.

Deliveries are signed here exactly as Stripe signs them
(`t=<unix time>,v1=<HMAC-SHA256 of "<t>.<body>">`), so the SDK's own
verification runs unmodified. No network, no database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import pytest

from saas_os.core.billing.errors import InvalidWebhookSignatureError
from saas_os.core.billing.provider import ProviderEventNotice
from saas_os.core.billing.stripe_provider import parse_stripe_event

_SECRET = "whsec_unit_test_only"  # pragma: allowlist secret


def _signed(body: bytes, *, secret: str = _SECRET, at: int | None = None) -> str:
    timestamp = int(time.time()) if at is None else at
    signature = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={signature}"


def _event(obj: dict[str, Any], **extra: Any) -> bytes:
    event = {
        "id": "evt_123",
        "object": "event",
        "type": "customer.subscription.updated",
        "data": {"object": obj},
        **extra,
    }
    return json.dumps(event).encode()


def _parse(body: bytes) -> ProviderEventNotice:
    return parse_stripe_event(body, _signed(body), _SECRET)


def test_a_subscription_event_names_its_subscription() -> None:
    notice = _parse(_event({"object": "subscription", "id": "sub_1", "status": "active"}))
    assert notice == ProviderEventNotice(
        provider="stripe",
        event_id="evt_123",
        event_type="customer.subscription.updated",
        provider_account_ref=None,
        provider_subscription_ref="sub_1",
    )


@pytest.mark.parametrize(
    "obj",
    [
        # An invoice before Stripe API version 2025-03-31.
        {"object": "invoice", "id": "in_1", "subscription": "sub_2"},
        # An invoice since then.
        {
            "object": "invoice",
            "id": "in_1",
            "parent": {"subscription_details": {"subscription": "sub_2"}},
        },
        # A completed checkout session.
        {"object": "checkout.session", "id": "cs_1", "subscription": "sub_2"},
        # An expanded subscription.
        {"object": "invoice", "id": "in_1", "subscription": {"id": "sub_2"}},
    ],
)
def test_other_objects_name_the_subscription_they_concern(obj: dict[str, Any]) -> None:
    assert _parse(_event(obj)).provider_subscription_ref == "sub_2"


def test_an_event_about_no_subscription_names_none() -> None:
    notice = _parse(_event({"object": "customer", "id": "cus_1"}))
    assert notice.provider_subscription_ref is None


def test_a_connected_accounts_event_names_its_account() -> None:
    notice = _parse(_event({"object": "subscription", "id": "sub_1"}, account="acct_9"))
    assert notice.provider_account_ref == "acct_9"


def test_the_notice_holds_no_stripe_object() -> None:
    notice = _parse(_event({"object": "subscription", "id": "sub_1"}))
    for value in vars(notice).values():
        assert value is None or isinstance(value, str)


@pytest.mark.parametrize(
    "header",
    [
        "",
        "t=1,v1=00",
        "garbage",
    ],
)
def test_a_bad_signature_is_refused(header: str) -> None:
    body = _event({"object": "subscription", "id": "sub_1"})
    with pytest.raises(InvalidWebhookSignatureError):
        parse_stripe_event(body, header, _SECRET)


def test_another_secret_is_refused() -> None:
    body = _event({"object": "subscription", "id": "sub_1"})
    other = "whsec_other"  # pragma: allowlist secret
    with pytest.raises(InvalidWebhookSignatureError):
        parse_stripe_event(body, _signed(body, secret=other), _SECRET)


def test_a_tampered_body_is_refused() -> None:
    body = _event({"object": "subscription", "id": "sub_1"})
    header = _signed(body)
    with pytest.raises(InvalidWebhookSignatureError):
        parse_stripe_event(body.replace(b"sub_1", b"sub_2"), header, _SECRET)


def test_a_stale_delivery_is_refused() -> None:
    """Stripe's timestamp tolerance (300 s) refuses an old replay outright."""
    body = _event({"object": "subscription", "id": "sub_1"})
    with pytest.raises(InvalidWebhookSignatureError):
        parse_stripe_event(body, _signed(body, at=int(time.time()) - 3600), _SECRET)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        json.dumps({"object": "event", "type": "x", "data": {}}).encode(),  # no id
        json.dumps({"id": "", "object": "event", "type": "x", "data": {}}).encode(),
        json.dumps({"id": "evt_1", "object": "event", "data": {}}).encode(),  # no type
    ],
)
def test_a_signed_body_that_is_not_an_event_is_refused(body: bytes) -> None:
    with pytest.raises(InvalidWebhookSignatureError):
        parse_stripe_event(body, _signed(body), _SECRET)


def test_the_refusal_never_carries_the_payload_or_the_secret() -> None:
    body = _event({"object": "subscription", "id": "sub_secretive"})
    with pytest.raises(InvalidWebhookSignatureError) as raised:
        parse_stripe_event(body, "t=1,v1=00", _SECRET)
    assert "sub_secretive" not in str(raised.value)
    assert _SECRET not in str(raised.value)
