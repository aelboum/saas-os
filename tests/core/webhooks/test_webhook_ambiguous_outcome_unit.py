"""Webhook delivery outcomes by phase, over real local sockets (owner
decision of 2026-11-01, ledger row F5; `saas_os/core/webhooks/service.py`).

- Not sent: the connection is refused, the deadline expires before any
  address is tried, no connection is obtained, or the egress proxy refuses
  or cannot open the tunnel. A refused connection moves on to the next
  validated address.
- Possibly sent: the receiver accepted the connection and then closed it,
  read the request and closed it, or answered after the read timeout; the
  deadline expired while an address was being tried. That is
  `WebhookAmbiguousDeliveryError`: at-least-once on the stable `event_id`,
  retried by the outbox within its attempt budget, never recorded as
  delivered, and never moved on to another address.
- A status is a confirmed answer; the permanent/transient table is unchanged.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import uuid
from collections.abc import Awaitable, Callable

import httpcore
import httpx
import pytest

from egress_support import (
    PUBLIC_V4,
    PUBLIC_V4_B,
    LocalServer,
    MappingBackend,
    mapped_transport_factory,
    read_request,
)
from saas_os.core.outbox import AmbiguousOutcomeError, PermanentEventError
from saas_os.core.webhooks import service as webhooks_service
from saas_os.core.webhooks.errors import (
    WebhookAmbiguousDeliveryError,
    WebhookDeliveryError,
)
from saas_os.infra.egress import Deadline
from smtp_fault_server import closed_port

SUBSCRIPTION = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
_URL = "http://hooks.example.test/hook?token=URL-TOKEN-CANARY"
_PAYLOAD = b'{"event_id":"e1","data":{"email":"payload-canary@example.test"}}'
_REAL_ASYNC_CLIENT = httpx.AsyncClient

pytestmark = pytest.mark.anyio

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EGRESS_PROXY_URL", raising=False)


def _route_to(monkeypatch: pytest.MonkeyPatch, backend: MappingBackend) -> None:
    """Every delivery connection goes to the local server `backend` names,
    through httpx's real transport and httpcore's real connection pool."""
    factory = mapped_transport_factory(backend)

    def client(**options: object) -> httpx.AsyncClient:
        return _REAL_ASYNC_CLIENT(transport=factory(ssl.create_default_context()), **options)  # type: ignore[arg-type]

    monkeypatch.setattr(webhooks_service.httpx, "AsyncClient", client)


async def _post(addresses: list[str] | None = None, deadline: float = 5) -> int:
    return await webhooks_service._post_to_validated_addresses(  # pyright: ignore[reportPrivateUsage]
        SUBSCRIPTION,
        _URL,
        [ipaddress.ip_address(a) for a in (addresses or [PUBLIC_V4])],
        _PAYLOAD,
        {"Content-Type": "application/json", "X-Webhook-Signature": "sha256=fake"},
        Deadline.after(deadline),
    )


async def _failure(**options: object) -> WebhookDeliveryError:
    with pytest.raises(WebhookDeliveryError) as excinfo:
        await _post(**options)  # type: ignore[arg-type]
    error = excinfo.value
    shown = f"{error!s} {error!r} {vars(error)!r}"
    for canary in ("URL-TOKEN-CANARY", "payload-canary", "sha256=fake"):
        assert canary not in shown
    # Raised outside the handler: nothing of the request is chained.
    assert error.__cause__ is None and error.__context__ is None
    return error


async def _close_at_once(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    return None


def _read_then(answer: bytes | None, *, delay: float = 0) -> Handler:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server_holder[0], reader)
        if delay:
            await asyncio.sleep(delay)
        if answer is not None:
            writer.write(answer)
            await writer.drain()

    return handler


server_holder: list[LocalServer] = []


async def _serving(handler: Handler) -> LocalServer:
    server = LocalServer(handler)
    server_holder[:] = [server]
    await server.__aenter__()
    return server


async def test_a_refused_connection_was_not_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    _route_to(monkeypatch, MappingBackend(closed_port()))
    error = await _failure()
    assert not isinstance(error, AmbiguousOutcomeError)
    assert str(error).endswith("failed: ConnectError")


async def test_a_refused_address_moves_on_to_the_next_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = await _serving(_read_then(b"HTTP/1.1 204 No Content\r\n\r\n"))
    try:

        async def refuse_first(host: str, timeout: float | None) -> None:
            if host == PUBLIC_V4:
                raise httpcore.ConnectError("refused")

        backend = MappingBackend(server.port, hooks={PUBLIC_V4: refuse_first})
        _route_to(monkeypatch, backend)
        assert await _post([PUBLIC_V4, PUBLIC_V4_B]) == 204
        assert [host for host, _ in backend.connects] == [PUBLIC_V4, PUBLIC_V4_B]
    finally:
        await server.__aexit__()


@pytest.mark.parametrize(
    ("handler", "options"),
    [
        (_close_at_once, {}),
        (_read_then(None), {}),
        (_read_then(b"HTTP/1.1 204 No Content\r\n\r\n", delay=2), {"deadline": 0.5}),
    ],
    ids=["close-before-reading", "read-then-close", "answer-after-the-read-timeout"],
)
async def test_a_failure_once_connected_is_ambiguous_at_least_once(
    monkeypatch: pytest.MonkeyPatch, handler: Handler, options: dict[str, float]
) -> None:
    server = await _serving(handler)
    try:
        backend = MappingBackend(server.port)
        _route_to(monkeypatch, backend)
        error = await _failure(addresses=[PUBLIC_V4, PUBLIC_V4_B], **options)
        # Never a second address: the first may already have the event.
        assert [host for host, _ in backend.connects] == [PUBLIC_V4]
    finally:
        await server.__aexit__()
    assert isinstance(error, WebhookAmbiguousDeliveryError)
    assert isinstance(error, AmbiguousOutcomeError)
    assert error.at_least_once is True and error.retry_within is None
    assert error.phase in {"read", "write", "response", "exchange"}
    assert not isinstance(error, PermanentEventError)


async def test_an_answer_after_the_read_timeout_is_a_read_phase_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = await _serving(_read_then(b"HTTP/1.1 204 No Content\r\n\r\n", delay=2))
    try:
        _route_to(monkeypatch, MappingBackend(server.port))
        error = await _failure(deadline=0.5)
    finally:
        await server.__aexit__()
    assert isinstance(error, WebhookAmbiguousDeliveryError)
    assert (error.reason, error.phase) == ("ReadTimeout", "read")


@pytest.mark.parametrize("status", [200, 204, 429, 503, 400, 410])
async def test_a_status_is_a_confirmed_answer(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    server = await _serving(
        _read_then(f"HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n".encode())
    )
    try:
        _route_to(monkeypatch, MappingBackend(server.port))
        assert await _post() == status
    finally:
        await server.__aexit__()


def test_the_permanent_status_table_is_unchanged() -> None:
    assert webhooks_service._PERMANENT_STATUSES == frozenset({400, 410, 413, 422})  # pyright: ignore[reportPrivateUsage]


def test_each_failure_after_connecting_names_its_phase() -> None:
    assert webhooks_service._ambiguous_phase(httpx.ReadError("x")) == "read"  # pyright: ignore[reportPrivateUsage]
    assert webhooks_service._ambiguous_phase(httpx.WriteTimeout("x")) == "write"  # pyright: ignore[reportPrivateUsage]
    assert webhooks_service._ambiguous_phase(httpx.RemoteProtocolError("x")) == "response"  # pyright: ignore[reportPrivateUsage]
    assert webhooks_service._ambiguous_phase(httpx.DecodingError("x")) == "exchange"  # pyright: ignore[reportPrivateUsage]


# --- The delivery's own deadline ---------------------------------------------


async def _send_signed() -> int:
    return await webhooks_service._send_signed(  # pyright: ignore[reportPrivateUsage]
        SUBSCRIPTION, "https://hooks.example.test/hook", "s3cret", _PAYLOAD
    )


async def test_a_deadline_during_resolution_was_not_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    def slow_resolution(url: str) -> list[ipaddress.IPv4Address]:
        time.sleep(1)
        return [ipaddress.IPv4Address(PUBLIC_V4)]

    posted: list[int] = []

    async def never_called(*args: object, **kwargs: object) -> int:
        posted.append(1)
        return 204

    monkeypatch.setattr(webhooks_service, "_DELIVERY_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(webhooks_service, "_validate_destination_addresses", slow_resolution)
    monkeypatch.setattr(webhooks_service, "_post_once", never_called)
    with pytest.raises(WebhookDeliveryError) as excinfo:
        await _send_signed()
    assert not isinstance(excinfo.value, AmbiguousOutcomeError)
    assert str(excinfo.value).endswith("failed: deadline_expired")
    assert posted == []


async def test_a_deadline_while_an_address_is_tried_is_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def hangs(*args: object, **kwargs: object) -> int:
        await asyncio.sleep(5)
        return 204

    monkeypatch.setattr(webhooks_service, "_DELIVERY_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(
        webhooks_service,
        "_validate_destination_addresses",
        lambda url: [ipaddress.IPv4Address(PUBLIC_V4)],
    )
    monkeypatch.setattr(webhooks_service, "_post_once", hangs)
    with pytest.raises(WebhookAmbiguousDeliveryError) as excinfo:
        await _send_signed()
    assert (excinfo.value.reason, excinfo.value.phase) == ("deadline_expired", "exchange")
