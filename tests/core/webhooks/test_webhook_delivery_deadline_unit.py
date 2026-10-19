"""Webhook delivery egress after the ADR-0035 amendment of 2026-10-19.

One delivery attempt has one total deadline (`_DELIVERY_TIMEOUT_SECONDS`)
covering resolution, every address tried and the response status; DNS runs
in a worker thread, not on the event loop; and when connecting to the first
validated address fails before anything is sent, the next one is tried, at
most `_MAX_ADDRESSES_TRIED` in all. http and any port stay allowed
(ADR-0035), and every resolved address must still be public.
"""

from __future__ import annotations

import asyncio
import ipaddress
import threading
import time
import uuid
from collections.abc import Callable

import httpx
import pytest

from saas_os.core.webhooks import service as webhooks_service
from saas_os.core.webhooks.errors import (
    WebhookDeliveryError,
    WebhookDestinationRejectedError,
)

pytestmark = pytest.mark.anyio

_SUBSCRIPTION = uuid.UUID(int=7)
_URL = "https://hooks.example/x"
_REAL_ASYNC_CLIENT = httpx.AsyncClient


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Network:
    """Stands in for httpx: each pinned address answers with a status or
    raises, and every client's timeout and every request are recorded."""

    def __init__(self, answers: dict[str, int | Exception]) -> None:
        self.answers = answers
        self.attempted: list[str] = []
        self.timeouts: list[float] = []
        self.requests: list[httpx.Request] = []

    def client(
        self, *, timeout: float, follow_redirects: bool, trust_env: bool
    ) -> httpx.AsyncClient:
        assert follow_redirects is False and trust_env is False
        self.timeouts.append(timeout)

        def handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            self.attempted.append(host)
            self.requests.append(request)
            answer = self.answers[host]
            if isinstance(answer, Exception):
                raise answer
            return httpx.Response(answer)

        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), timeout=timeout)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    network: _Network,
    resolve: Callable[[str], list[str]],
) -> None:
    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", network.client)
    monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", resolve)


async def _send(url: str = _URL) -> int:
    return await webhooks_service._send_signed(_SUBSCRIPTION, url, "s3cret", b"{}")  # pyright: ignore[reportPrivateUsage]


async def test_a_refused_connection_falls_back_to_the_next_validated_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = _Network({"93.184.216.34": httpx.ConnectError("refused"), "93.184.216.35": 200})
    _install(monkeypatch, network, lambda host: ["93.184.216.35", "93.184.216.34"])
    assert await _send() == 200
    # Lexicographic order: the first refused, the second accepted.
    assert network.attempted == ["93.184.216.34", "93.184.216.35"]
    accepted = network.requests[-1]
    assert accepted.headers["host"] == "hooks.example"
    assert accepted.extensions["sni_hostname"] == "hooks.example"
    assert {"x-webhook-signature", "x-webhook-timestamp"} <= set(accepted.headers)


async def test_a_connect_timeout_also_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    network = _Network({"93.184.216.34": httpx.ConnectTimeout("slow"), "93.184.216.35": 200})
    _install(monkeypatch, network, lambda host: ["93.184.216.34", "93.184.216.35"])
    assert await _send() == 200
    assert network.attempted == ["93.184.216.34", "93.184.216.35"]


@pytest.mark.parametrize(
    "failure",
    [httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("reset"), httpx.WriteError("broken")],
    ids=["read-timeout", "protocol", "write"],
)
async def test_no_fallback_once_the_request_may_have_been_sent(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    network = _Network({"93.184.216.34": failure, "93.184.216.35": 200})
    _install(monkeypatch, network, lambda host: ["93.184.216.34", "93.184.216.35"])
    with pytest.raises(WebhookDeliveryError):
        await _send()
    assert network.attempted == ["93.184.216.34"]


async def test_at_most_two_addresses_are_tried(monkeypatch: pytest.MonkeyPatch) -> None:
    hosts = ["93.184.216.34", "93.184.216.35", "93.184.216.36"]
    network = _Network({host: httpx.ConnectError("refused") for host in hosts})
    _install(monkeypatch, network, lambda host: hosts)
    with pytest.raises(WebhookDeliveryError, match="ConnectError"):
        await _send()
    assert network.attempted == hosts[:2]


async def test_one_non_public_answer_still_refuses_the_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = _Network({"93.184.216.34": 200})
    _install(monkeypatch, network, lambda host: ["93.184.216.34", "10.0.0.7"])
    with pytest.raises(WebhookDestinationRejectedError):
        await _send()
    assert network.attempted == []


async def test_http_and_any_port_are_still_delivered(monkeypatch: pytest.MonkeyPatch) -> None:
    network = _Network({"93.184.216.34": 204})
    _install(monkeypatch, network, lambda host: ["93.184.216.34"])
    assert await _send("http://hooks.example:8080/x") == 204
    assert str(network.requests[0].url) == "http://93.184.216.34:8080/x"


async def test_every_client_timeout_is_capped_by_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = _Network({"93.184.216.34": httpx.ConnectError("refused"), "93.184.216.35": 200})
    _install(monkeypatch, network, lambda host: ["93.184.216.34", "93.184.216.35"])
    assert await _send() == 200
    total = webhooks_service._DELIVERY_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    assert len(network.timeouts) == 2
    assert all(0 < timeout <= total for timeout in network.timeouts)
    assert network.timeouts[1] <= network.timeouts[0]


async def test_slow_resolution_ends_at_the_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()

    def slow(host: str) -> list[str]:
        release.wait(5)
        return ["93.184.216.34"]

    network = _Network({"93.184.216.34": 200})
    _install(monkeypatch, network, slow)
    monkeypatch.setattr(webhooks_service, "_DELIVERY_TIMEOUT_SECONDS", 0.3)
    started = time.monotonic()
    try:
        with pytest.raises(WebhookDeliveryError, match="deadline_expired"):
            await _send()
    finally:
        release.set()
    assert time.monotonic() - started < 2.0
    assert network.attempted == []


async def test_a_slow_response_ends_at_the_total_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The deadline covers the exchange too, not only resolution: a
    receiver that never answers is cut off at the total."""

    class _Hanging(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(30)
            return httpx.Response(200)

    def client(*, timeout: float, follow_redirects: bool, trust_env: bool) -> httpx.AsyncClient:
        # A transport that ignores httpx's own timeouts: only the delivery's
        # total deadline can end it.
        return _REAL_ASYNC_CLIENT(transport=_Hanging(), timeout=None)

    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", client)
    monkeypatch.setattr(
        webhooks_service, "_default_resolve_hostname", lambda host: ["93.184.216.34"]
    )
    monkeypatch.setattr(webhooks_service, "_DELIVERY_TIMEOUT_SECONDS", 0.3)
    started = time.monotonic()
    with pytest.raises(WebhookDeliveryError, match="deadline_expired"):
        await _send()
    assert time.monotonic() - started < 2.0


async def test_resolution_does_not_block_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """While one delivery waits on DNS, other work on the same loop runs."""
    release = threading.Event()

    def blocking(host: str) -> list[str]:
        assert release.wait(5)
        return ["93.184.216.34"]

    network = _Network({"93.184.216.34": 200})
    _install(monkeypatch, network, blocking)
    ticks = 0

    async def other_work() -> None:
        nonlocal ticks
        for _ in range(5):
            await asyncio.sleep(0.01)
            ticks += 1
        release.set()

    status, _ = await asyncio.gather(_send(), other_work())
    assert status == 200
    assert ticks == 5


async def test_the_delivery_seam_is_looked_up_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-vacuity for the tests that patch `_validate_destination_addresses`:
    the delivery path calls the module attribute, so a patch takes effect."""
    calls: list[str] = []

    def patched(url: str, **kwargs: object) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        calls.append(url)
        return [ipaddress.ip_address("93.184.216.34")]

    network = _Network({"93.184.216.34": 200})
    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", network.client)
    monkeypatch.setattr(webhooks_service, "_validate_destination_addresses", patched)
    assert await _send() == 200
    assert calls == [_URL]


def test_the_validated_addresses_are_sorted_and_the_first_is_unchanged() -> None:
    def resolve(host: str) -> list[str]:
        return ["93.184.216.35", "93.184.216.34", "93.184.216.35"]

    addresses = webhooks_service._validate_destination_addresses(_URL, resolver=resolve)  # pyright: ignore[reportPrivateUsage]
    assert addresses == [
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("93.184.216.35"),
    ]
    first = webhooks_service._validate_destination(_URL, resolver=resolve)  # pyright: ignore[reportPrivateUsage]
    assert first == addresses[0]
