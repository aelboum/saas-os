"""RE-4: webhook destination policy and failure classification. No network,
no database -- the resolver is injected, `socket.getaddrinfo` is replaced.

The policy judges the *resolved* address the connection will use (and a
literal address at subscription time), never the hostname string: an
address must be globally routable unicast. Audit finding RE-F8: carrier-
grade NAT `100.64.0.0/10` (and with it the `100.100.100.200` metadata
address) used to pass because only `is_private` was consulted.
"""

from __future__ import annotations

import ipaddress
import socket
import uuid

import pytest
from core.webhooks.errors import (
    InvalidWebhookUrlError,
    MalformedWebhookEventError,
    WebhookDestinationRejectedError,
    WebhookDestinationUnresolvedError,
    WebhookPermanentDeliveryError,
)
from core.webhooks.service import (
    _default_resolve_hostname,
    _is_non_public_address,
    _parse_delivery,
    _validate_destination,
    _validate_url,
)

from core.outbox import PermanentEventError

_NON_PUBLIC = [
    # carrier-grade NAT (RFC 6598) -- the RE-F8 regression
    "100.64.0.0",
    "100.64.0.1",
    "100.100.100.200",
    "100.127.255.255",
    # loopback, private, link-local, unspecified
    "127.0.0.1",
    "127.255.255.254",
    "10.0.0.5",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "0.0.0.0",
    "0.1.2.3",
    # multicast, broadcast, reserved, documentation, benchmarking, IETF
    "224.0.0.1",
    "233.252.0.1",
    "239.255.255.250",
    "255.255.255.255",
    "240.0.0.1",
    "192.0.2.1",
    "198.51.100.7",
    "203.0.113.9",
    "198.18.0.1",
    "192.0.0.170",
    # IPv6: loopback, unspecified, link-local, unique-local, site-local,
    # multicast, documentation, discard
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "fec0::1",
    "ff02::1",
    "ff0e::1",
    "2001:db8::1",
    "100::1",
    # IPv6 forms carrying a non-public IPv4: mapped, NAT64, 6to4
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:100.64.0.1",
    "64:ff9b::7f00:1",
    "64:ff9b::a9fe:a9fe",
    "2002:7f00:1::1",
    "2002:a9fe:a9fe::1",
]
_PUBLIC = [
    "8.8.8.8",
    "1.1.1.1",
    "100.63.255.255",  # just below 100.64.0.0/10
    "100.128.0.1",  # just above it
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
]


@pytest.mark.parametrize("address", _NON_PUBLIC)
def test_non_public_addresses_are_refused(address: str) -> None:
    assert _is_non_public_address(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", _PUBLIC)
def test_public_addresses_are_allowed(address: str) -> None:
    assert not _is_non_public_address(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", _NON_PUBLIC)
def test_a_destination_resolving_to_a_non_public_address_is_a_permanent_rejection(
    address: str,
) -> None:
    with pytest.raises(WebhookDestinationRejectedError) as excinfo:
        _validate_destination("https://hooks.example.com/x", resolver=lambda host: [address])
    assert isinstance(excinfo.value, PermanentEventError)
    assert isinstance(excinfo.value, InvalidWebhookUrlError)  # pre-RE-4 callers still catch it


@pytest.mark.parametrize("address", _PUBLIC)
def test_a_destination_resolving_to_a_public_address_is_pinned_to_it(address: str) -> None:
    pinned = _validate_destination("https://hooks.example.com/x", resolver=lambda host: [address])
    assert pinned == ipaddress.ip_address(address)


def test_any_non_public_answer_among_public_ones_refuses_the_destination() -> None:
    with pytest.raises(WebhookDestinationRejectedError):
        _validate_destination(
            "https://hooks.example.com/x", resolver=lambda host: ["8.8.8.8", "100.64.0.1"]
        )


def test_the_policy_is_applied_to_every_resolution_not_cached() -> None:
    """DNS rebinding: the same name answers public, then internal."""
    answers = iter([["8.8.8.8"], ["100.100.100.200"]])
    resolver = lambda host: next(answers)  # noqa: E731
    _validate_destination("https://rebind.example.com/x", resolver=resolver)
    with pytest.raises(WebhookDestinationRejectedError):
        _validate_destination("https://rebind.example.com/x", resolver=resolver)


@pytest.mark.parametrize("address", ["100.64.0.1", "100.100.100.200", "[::ffff:100.64.0.1]"])
def test_a_literal_non_public_address_is_refused_at_subscription_time(address: str) -> None:
    with pytest.raises(InvalidWebhookUrlError):
        _validate_url(f"https://{address}/hook")


def test_an_unresolvable_destination_is_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(*_: object, **__: object) -> object:
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _fail)
    with pytest.raises(WebhookDestinationUnresolvedError) as excinfo:
        _default_resolve_hostname("nowhere.example.com")
    assert not isinstance(excinfo.value, PermanentEventError)


def test_an_empty_resolution_is_transient() -> None:
    with pytest.raises(WebhookDestinationUnresolvedError) as excinfo:
        _validate_destination("https://hooks.example.com/x", resolver=lambda host: [])
    assert not isinstance(excinfo.value, PermanentEventError)


# --- Malformed delivery events ------------------------------------------------------

_SUB, _EVT = str(uuid.uuid4()), str(uuid.uuid4())


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"subscription_id": _SUB},
        {"subscription_id": "nope", "event_id": _EVT, "event_type": "t", "event_data": {}},
        {"subscription_id": _SUB, "event_id": _EVT, "event_type": "", "event_data": {}},
        {"subscription_id": _SUB, "event_id": _EVT, "event_type": 7, "event_data": {}},
        {"subscription_id": _SUB, "event_id": _EVT, "event_type": "t", "event_data": [1]},
        {"subscription_id": _SUB, "event_id": _EVT, "event_type": "t"},
    ],
)
def test_a_malformed_delivery_event_is_permanent(data: dict[str, object]) -> None:
    with pytest.raises(MalformedWebhookEventError) as excinfo:
        _parse_delivery(data)
    assert isinstance(excinfo.value, PermanentEventError)
    assert "nope" not in str(excinfo.value)  # names the problem, never the payload


def test_a_well_formed_delivery_event_is_parsed() -> None:
    parsed = _parse_delivery(
        {"subscription_id": _SUB, "event_id": _EVT, "event_type": "t", "event_data": {"a": 1}}
    )
    assert parsed == (uuid.UUID(_SUB), uuid.UUID(_EVT), "t", {"a": 1})


def test_a_permanent_delivery_error_is_still_a_delivery_error() -> None:
    from core.webhooks.errors import WebhookDeliveryError

    error = WebhookPermanentDeliveryError(uuid.uuid4(), "HTTP 410")
    assert isinstance(error, WebhookDeliveryError)
    assert isinstance(error, PermanentEventError)
