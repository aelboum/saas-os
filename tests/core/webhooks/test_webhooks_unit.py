"""Pure unit tests for `core/webhooks/service.py` -- no database or
network needed. `compute_signature()`'s correctness (the roadmap's own
"signature verification test" acceptance criterion) is proven against an
independently computed HMAC-SHA256, not merely against the function's own
output.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import pytest
from core.webhooks.errors import InvalidWebhookUrlError
from core.webhooks.service import _encode_event, _validate_url, compute_signature


def test_compute_signature_matches_independently_computed_hmac_sha256() -> None:
    secret = "a-test-signing-secret"
    body = b'{"event_type":"test.event","data":{"x":1}}'

    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    assert compute_signature(secret, body) == f"sha256={expected}"


def test_compute_signature_differs_for_different_secrets() -> None:
    body = b"same body"
    assert compute_signature("secret-a", body) != compute_signature("secret-b", body)


def test_compute_signature_differs_for_different_bodies() -> None:
    secret = "same-secret"
    assert compute_signature(secret, b"body-a") != compute_signature(secret, b"body-b")


def test_compute_signature_is_deterministic() -> None:
    secret = "same-secret"
    body = b"same-body"
    assert compute_signature(secret, body) == compute_signature(secret, body)


def test_encode_event_produces_valid_json_with_expected_shape() -> None:
    """P1.10: the body now carries `event_id` -- the stable replay-ledger
    identity a receiver keys on (`core/webhooks/service.py::trigger_event()`'s
    own docstring) -- alongside the original `event_type`/`data` shape."""
    event_id = uuid.uuid4()
    body = _encode_event(event_id, "order.created", {"order_id": "123"})
    decoded = json.loads(body)
    assert decoded == {
        "event_id": str(event_id),
        "event_type": "order.created",
        "data": {"order_id": "123"},
    }


@pytest.mark.parametrize(
    "url",
    [
        "",
        "not-a-url",
        "ftp://example.com/hook",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http://",
        "x" * 3000,
    ],
)
def test_validate_url_rejects_invalid_urls(url: str) -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/hook",
        "https://example.com/hook",
        "https://example.com:8443/hooks/abc?x=1",
    ],
)
def test_validate_url_accepts_valid_urls(url: str) -> None:
    _validate_url(url)  # does not raise
