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
from core.webhooks.service import (
    _encode_event,
    _validate_destination,
    _validate_url,
    compute_signature,
)

from core.webhooks import service as webhooks_service_module


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
        # Phase J-R1 (J-API-01): literal non-public addresses -- rejected
        # with zero DNS/network I/O, since parsing a literal IP is not a
        # resolution. Reasoned about via `ipaddress`, never a string
        # blacklist -- these are representative, not exhaustive.
        "http://127.0.0.1/hook",  # IPv4 loopback
        "http://127.0.0.1:8080/hook",
        "http://[::1]/hook",  # IPv6 loopback
        "http://169.254.169.254/hook",  # link-local / cloud metadata
        "http://[fe80::1]/hook",  # IPv6 link-local
        "http://10.0.0.5/hook",  # RFC1918 private
        "http://172.16.0.5/hook",  # RFC1918 private
        "http://192.168.1.1/hook",  # RFC1918 private
        "http://0.0.0.0/hook",  # unspecified
        "http://[::]/hook",  # unspecified (IPv6)
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
        "https://8.8.8.8/hook",  # a public literal IPv4 address
    ],
)
def test_validate_url_accepts_valid_urls(url: str) -> None:
    _validate_url(url)  # does not raise


# --- Phase J-R1 (J-API-01): `_validate_destination()` -- the resolver-based
# delivery-time SSRF gate. All tests here inject a fake `resolver` so no
# real DNS/network is ever touched, matching this file's own "no database
# or network needed" pure-unit-test contract.


def test_validate_destination_accepts_a_public_resolved_address() -> None:
    _validate_destination("https://example.com/hook", resolver=lambda host: ["8.8.8.8"])


def test_validate_destination_rejects_a_private_resolved_address() -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination(
            "https://internal.example.com/hook", resolver=lambda host: ["10.0.0.5"]
        )


def test_validate_destination_rejects_a_loopback_resolved_address() -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination(
            "https://sneaky.example.com/hook", resolver=lambda host: ["127.0.0.1"]
        )


def test_validate_destination_rejects_a_metadata_resolved_address() -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination(
            "https://metadata.example.com/hook", resolver=lambda host: ["169.254.169.254"]
        )


def test_validate_destination_rejects_an_ipv6_loopback_resolved_address() -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination("https://sneaky6.example.com/hook", resolver=lambda host: ["::1"])


def test_validate_destination_rejects_an_ipv6_link_local_resolved_address() -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination(
            "https://sneaky6ll.example.com/hook", resolver=lambda host: ["fe80::1"]
        )


def test_validate_destination_rejects_an_unspecified_resolved_address() -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination("https://zero.example.com/hook", resolver=lambda host: ["0.0.0.0"])


def test_validate_destination_rejects_if_any_resolved_address_is_non_public() -> None:
    """A multi-homed hostname is rejected as soon as ANY of its resolved
    addresses is non-public -- not only when all of them are."""
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination(
            "https://multihomed.example.com/hook", resolver=lambda host: ["8.8.8.8", "10.0.0.5"]
        )


def test_validate_destination_rejects_when_resolution_returns_no_addresses() -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination("https://empty.example.com/hook", resolver=lambda host: [])


def test_validate_destination_demonstrates_dns_rebinding_is_caught_on_each_call() -> None:
    """Deterministic proof of DNS-rebinding protection, without depending
    on real external DNS: a stateful fake resolver returns a public
    address the first time (as if this were subscription time) and a
    private address the second time (as if the name were repointed
    afterward) -- `_validate_destination()` is called fresh each time
    (exactly as `_deliver_webhook()` does, on every attempt including
    retries), so the second call must catch what the first could not have
    known about."""
    answers = iter(["8.8.8.8", "10.0.0.5"])

    def rebinding_resolver(host: str) -> list[str]:
        return [next(answers)]

    # 1st call: the public address the resolver hands out "at subscribe time".
    _validate_destination("https://rebinds.example.com/hook", resolver=rebinding_resolver)
    # 2nd call: the private address the same name now resolves to -- caught.
    with pytest.raises(InvalidWebhookUrlError):
        _validate_destination("https://rebinds.example.com/hook", resolver=rebinding_resolver)


def test_default_resolve_hostname_wraps_a_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_default_resolve_hostname()` (the real-DNS default resolver) must
    turn a resolution failure into `InvalidWebhookUrlError`, never let a
    raw `OSError` propagate -- proven here via a monkeypatched
    `socket.getaddrinfo`, so this stays network-free."""

    def _raise(*args: object, **kwargs: object) -> object:
        raise OSError("simulated resolution failure")

    monkeypatch.setattr(webhooks_service_module.socket, "getaddrinfo", _raise)
    with pytest.raises(InvalidWebhookUrlError):
        webhooks_service_module._default_resolve_hostname("unresolvable.example.invalid")
