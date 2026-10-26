"""RE-4: webhook destination policy and failure classification. No network,
no database -- the resolver is injected, `socket.getaddrinfo` is replaced.

The policy judges the *resolved* address the connection will use (and a
literal address at subscription time), never the hostname string: an
address must be globally routable unicast. Audit finding RE-F8: carrier-
grade NAT `100.64.0.0/10` (and with it the `100.100.100.200` metadata
address) used to pass because only `is_private` was consulted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import uuid
from collections.abc import Callable

import pytest

from saas_os.core.outbox import PermanentEventError
from saas_os.core.outbox.dispatch import describe_error
from saas_os.core.webhooks.config import get_webhook_security_config
from saas_os.core.webhooks.errors import (
    InvalidWebhookUrlError,
    MalformedWebhookEventError,
    WebhookDestinationRejectedError,
    WebhookDestinationUnresolvedError,
    WebhookPermanentDeliveryError,
)
from saas_os.core.webhooks.service import (
    _default_resolve_hostname,
    _is_non_public_address,
    _parse_delivery,
    _pin_url_to_validated_address,
    _require_allowed_port,
    _validate_destination,
    _validate_url,
)
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.dead_letter import record_dead_letter

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
    from saas_os.core.webhooks.errors import WebhookDeliveryError

    error = WebhookPermanentDeliveryError(uuid.uuid4(), "HTTP 410")
    assert isinstance(error, WebhookDeliveryError)
    assert isinstance(error, PermanentEventError)


# --- Destination errors never carry the URL -----------------------------------------
#
# Both are raised at delivery time, and their message becomes the outbox
# event's `last_error` and a dead-letter entry's `error`. A webhook URL can
# carry a credential or token in its user info, path or query, so neither
# message may contain any part of it -- not even the hostname.

_URL_PASSWORD = "url-password-canary-7731"  # pragma: allowlist secret -- a fake credential
_URL_TOKEN = "url-token-canary-7731"
_HOST = "tenant-canary-7731.example.com"
_SENSITIVE_URL = f"https://hook-user:{_URL_PASSWORD}@{_HOST}/in/{_URL_TOKEN}?token={_URL_TOKEN}"
_PORT_TEXT = "port-canary-7731"  # a port that is no number; `ValueError` quotes it
_CANARIES = (_URL_PASSWORD, _URL_TOKEN, "tenant-canary", "hook-user", "port-canary")
_REJECTED = (
    "Webhook destination rejected by URL security policy "
    "(non-public address, no host, or port not allowed)."
)
_UNRESOLVED = "Webhook destination hostname could not be resolved."


def _rejected_non_public() -> None:
    _validate_destination(_SENSITIVE_URL, resolver=lambda host: ["10.0.0.5"])


def _rejected_no_host() -> None:
    _validate_destination(f"https://hook-user:{_URL_PASSWORD}@/in?token={_URL_TOKEN}")


def _rejected_port(monkeypatch: pytest.MonkeyPatch, port: str) -> None:
    monkeypatch.setenv("WEBHOOK_ALLOWED_PORTS", "443")
    get_webhook_security_config.cache_clear()
    try:
        _require_allowed_port(
            _SENSITIVE_URL.replace(_HOST, f"{_HOST}:{port}"), WebhookDestinationRejectedError
        )
    finally:
        monkeypatch.delenv("WEBHOOK_ALLOWED_PORTS")
        get_webhook_security_config.cache_clear()


def _with_port(port: str) -> str:
    return _SENSITIVE_URL.replace(_HOST, f"{_HOST}:{port}")


def _rejected_malformed_port_with_no_list(monkeypatch: pytest.MonkeyPatch, port: str) -> None:
    monkeypatch.delenv("WEBHOOK_ALLOWED_PORTS", raising=False)
    get_webhook_security_config.cache_clear()
    try:
        _require_allowed_port(_with_port(port), WebhookDestinationRejectedError)
    finally:
        get_webhook_security_config.cache_clear()


def _rejected_by_the_pinning_fallback() -> None:
    _pin_url_to_validated_address(_with_port(_PORT_TEXT), ipaddress.ip_address("93.184.216.34"))


def _unresolved_empty() -> None:
    _validate_destination(_SENSITIVE_URL, resolver=lambda host: [])


def _unresolved_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(*_: object, **__: object) -> object:
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _fail)
    _default_resolve_hostname(_HOST)


_DESTINATION_FAILURES: dict[
    str, tuple[Callable[[pytest.MonkeyPatch], None], type[InvalidWebhookUrlError], str]
] = {
    "non_public_address": (
        lambda mp: _rejected_non_public(),
        WebhookDestinationRejectedError,
        _REJECTED,
    ),
    "no_host": (lambda mp: _rejected_no_host(), WebhookDestinationRejectedError, _REJECTED),
    "port_not_allowed": (
        lambda mp: _rejected_port(mp, "8443"),
        WebhookDestinationRejectedError,
        _REJECTED,
    ),
    "invalid_port": (
        lambda mp: _rejected_port(mp, "99999"),
        WebhookDestinationRejectedError,
        _REJECTED,
    ),
    "port_out_of_range_with_no_list": (
        lambda mp: _rejected_malformed_port_with_no_list(mp, "65536"),
        WebhookDestinationRejectedError,
        _REJECTED,
    ),
    "port_not_a_number_with_no_list": (
        lambda mp: _rejected_malformed_port_with_no_list(mp, _PORT_TEXT),
        WebhookDestinationRejectedError,
        _REJECTED,
    ),
    "pinning_fallback": (
        lambda mp: _rejected_by_the_pinning_fallback(),
        WebhookDestinationRejectedError,
        _REJECTED,
    ),
    "empty_resolution": (
        lambda mp: _unresolved_empty(),
        WebhookDestinationUnresolvedError,
        _UNRESOLVED,
    ),
    "dns_failure": (_unresolved_dns, WebhookDestinationUnresolvedError, _UNRESOLVED),
}


class _RecordingRedis:
    """Stands in for the dead-letter list: keeps what is pushed."""

    def __init__(self) -> None:
        self.pushed: list[str] = []

    async def rpush(self, key: str, value: str) -> int:
        self.pushed.append(value)
        return len(self.pushed)

    async def ltrim(self, key: str, start: int, end: int) -> bool:
        return True


def _linked(exc: BaseException) -> list[BaseException]:
    seen: set[int] = set()
    found: list[BaseException] = []
    pending: list[BaseException | None] = [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        found.append(current)
        pending.extend((current.__cause__, current.__context__))
    return found


@pytest.mark.parametrize("failure", sorted(_DESTINATION_FAILURES))
def test_a_destination_error_names_the_reason_never_the_url(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    raise_it, expected_type, expected_message = _DESTINATION_FAILURES[failure]
    with pytest.raises(InvalidWebhookUrlError) as excinfo:
        raise_it(monkeypatch)
    error = excinfo.value

    # The type, and so the classification, is unchanged...
    assert type(error) is expected_type
    assert isinstance(error, PermanentEventError) is (
        expected_type is WebhookDestinationRejectedError
    )
    # ...no part of the URL is in the error, in anything linked to it, or in
    # the text the outbox and the dead-letter list store...
    stored = describe_error(error)
    redis = _RecordingRedis()
    asyncio.run(
        record_dead_letter(
            redis,  # type: ignore[arg-type]
            JobsConfig(redis_url="redis://unused"),
            function_name="_deliver_webhook",
            payload=None,
            error=error,
            attempts=1,
        )
    )
    assert json.loads(redis.pushed[0])["error"] == stored
    shown = [
        stored,
        *redis.pushed,
        *(f"{item!s} {item!r} {vars(item)!r}" for item in _linked(error)),
    ]
    for text in shown:
        for canary in _CANARIES:
            assert canary not in text, (canary, text)
    # ...and the message names the reason.
    assert str(error) == expected_message
    assert error.args == (expected_message,)
    assert stored == f"{expected_type.__name__}: {expected_message}"


def test_a_rejection_is_told_apart_from_a_resolution_failure() -> None:
    rejected = WebhookDestinationRejectedError(_SENSITIVE_URL)
    unresolved = WebhookDestinationUnresolvedError(_SENSITIVE_URL)
    assert str(rejected) != str(unresolved)
    assert describe_error(rejected).startswith("WebhookDestinationRejectedError: ")
    assert describe_error(unresolved).startswith("WebhookDestinationUnresolvedError: ")
    assert isinstance(rejected, PermanentEventError)
    assert not isinstance(unresolved, PermanentEventError)


def test_a_subscription_time_url_error_still_names_the_url() -> None:
    """Control: only the delivery-time destination errors drop the URL. The
    subscription-time `InvalidWebhookUrlError` answers the caller who just
    supplied the URL, and is unchanged."""
    with pytest.raises(InvalidWebhookUrlError) as excinfo:
        _validate_url("ftp://hooks.example.com/x")
    assert type(excinfo.value) is InvalidWebhookUrlError
    assert "ftp://hooks.example.com/x" in str(excinfo.value)
