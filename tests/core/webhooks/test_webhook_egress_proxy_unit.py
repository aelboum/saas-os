"""ADR-0059: webhook delivery through the egress proxy.

`_post_to_validated_addresses()` is given an address the destination check
has already accepted, as in a real delivery. A local fake `CONNECT` proxy
relays the tunnel to a local server; the tests observe that the proxy is
given only that address and port (never the URL), that TLS and `Host` stay
on the subscribed hostname, and how a proxy refusal or failure is
classified, with no direct connection either way.
"""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpcore
import pytest

from egress_support import (
    PUBLIC_V4,
    Certificates,
    FakeConnectProxy,
    LocalServer,
    client_context,
    issue_certificates,
    read_request,
    server_context,
)
from saas_os.core.outbox import PermanentEventError
from saas_os.core.webhooks import service as webhooks_service
from saas_os.core.webhooks.errors import WebhookDeliveryError, WebhookDestinationRejectedError
from saas_os.infra.egress import Deadline

pytestmark = pytest.mark.anyio

HOSTNAME = "hooks.example.test"
SUBSCRIPTION = uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def certs(monkeypatch: pytest.MonkeyPatch) -> Certificates:
    """A server certificate for HOSTNAME, trusted by the delivery client."""
    issued = issue_certificates(HOSTNAME)
    monkeypatch.setattr(
        webhooks_service.httpx, "create_ssl_context", lambda: client_context(issued.ca_pem)
    )
    return issued


@pytest.fixture
def connect_attempts(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[str, int]]]:
    attempts: list[tuple[str, int]] = []
    original = httpcore.AnyIOBackend.connect_tcp  # pyright: ignore[reportAttributeAccessIssue] -- the real backend at run time

    async def recording(self: Any, host: str, port: int, *args: Any, **kwargs: Any) -> Any:
        attempts.append((host, port))
        return await original(self, host, port, *args, **kwargs)

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", recording)
    yield attempts


def _server(tls: Certificates | None, tmp_path: Path, sni_seen: list[str]) -> LocalServer:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(holder[0], reader)
        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await writer.drain()

    holder: list[LocalServer] = []
    context = server_context(tls, tmp_path, sni_seen) if tls is not None else None
    server = LocalServer(handler, ssl_context=context)
    holder.append(server)
    return server


async def _deliver(url: str) -> int:
    return await webhooks_service._post_to_validated_addresses(  # pyright: ignore[reportPrivateUsage]
        SUBSCRIPTION,
        url,
        [ipaddress.ip_address(PUBLIC_V4)],
        b"{}",
        {"X-Webhook-Signature": "sha256=fake"},
        Deadline.after(10),
    )


async def test_a_delivery_goes_through_the_proxy_to_the_validated_address(
    certs: Certificates,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    connect_attempts: list[tuple[str, int]],
) -> None:
    sni_seen: list[str] = []
    server = _server(certs, tmp_path, sni_seen)
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        monkeypatch.setattr(webhooks_service, "get_egress_proxy", lambda: fake.proxy)
        status = await _deliver(f"https://{HOSTNAME}/services/T/B/PATH-TOKEN?token=QUERY-TOKEN")

    assert status == 204
    assert fake.heads == [
        f"CONNECT {PUBLIC_V4}:443 HTTP/1.1\r\nHost: {PUBLIC_V4}:443\r\n\r\n".encode()
    ]
    assert sni_seen == [HOSTNAME]
    request = server.heads[0].decode()
    assert request.startswith("POST /services/T/B/PATH-TOKEN?token=QUERY-TOKEN HTTP/1.1\r\n")
    assert f"\r\nHost: {HOSTNAME}\r\n" in request
    assert connect_attempts == [("127.0.0.1", fake.proxy.port)]


async def test_plain_http_is_tunnelled_too_so_the_proxy_never_sees_the_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _server(None, tmp_path, [])
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        monkeypatch.setattr(webhooks_service, "get_egress_proxy", lambda: fake.proxy)
        status = await _deliver(f"http://{HOSTNAME}/hook/PATH-TOKEN?token=QUERY-TOKEN")

    assert status == 204
    assert fake.heads == [
        f"CONNECT {PUBLIC_V4}:80 HTTP/1.1\r\nHost: {PUBLIC_V4}:80\r\n\r\n".encode()
    ]
    assert server.heads[0].decode().startswith("POST /hook/PATH-TOKEN?token=QUERY-TOKEN HTTP/1.1")


async def test_a_refusal_by_the_proxy_is_a_permanent_rejection(
    certs: Certificates,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    connect_attempts: list[tuple[str, int]],
) -> None:
    server = _server(certs, tmp_path, [])
    async with server, FakeConnectProxy(relay_port=server.port, status=403) as fake:
        monkeypatch.setattr(webhooks_service, "get_egress_proxy", lambda: fake.proxy)
        with pytest.raises(WebhookDestinationRejectedError) as excinfo:
            await _deliver(f"https://{HOSTNAME}/x?token=QUERY-TOKEN")

    assert isinstance(excinfo.value, PermanentEventError)
    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None
    assert "QUERY-TOKEN" not in str(excinfo.value) and HOSTNAME not in str(excinfo.value)
    assert server.heads == []
    assert all(attempt == ("127.0.0.1", fake.proxy.port) for attempt in connect_attempts)


async def test_an_unavailable_proxy_is_transient_and_nothing_is_sent_directly(
    monkeypatch: pytest.MonkeyPatch, connect_attempts: list[tuple[str, int]]
) -> None:
    async with FakeConnectProxy() as fake:
        gone = fake.proxy
    monkeypatch.setattr(webhooks_service, "get_egress_proxy", lambda: gone)
    with pytest.raises(WebhookDeliveryError) as excinfo:
        await _deliver(f"https://{HOSTNAME}/x")

    assert not isinstance(excinfo.value, PermanentEventError)
    assert "egress_proxy_unavailable" in str(excinfo.value)
    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None
    assert connect_attempts == [("127.0.0.1", gone.port)]
