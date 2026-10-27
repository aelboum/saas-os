"""ADR-0059: connections through the egress proxy.

A local fake `CONNECT` proxy relays allowed tunnels to a local TLS server
whose certificate names the original hostname. The tests observe, on real
sockets, what the proxy is asked for (only an IP literal and a port), what
the destination sees (SNI and `Host` on the hostname), and that a refusal or
an unreachable proxy never leads to a direct connection.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpcore
import pytest

from egress_support import (
    PUBLIC_V4,
    PUBLIC_V6,
    Certificates,
    FakeConnectProxy,
    LocalServer,
    StaticResolver,
    client_context,
    issue_certificates,
    read_request,
    server_context,
)
from saas_os.infra.egress import (
    Deadline,
    EgressConfigurationError,
    EgressProxy,
    EgressProxyRefusedError,
    EgressProxyUnavailableError,
    EgressRedirectError,
    EgressTLSError,
    StrictEgressClient,
    StrictEgressPolicy,
    get_egress_proxy,
    parse_egress_proxy_url,
)
from saas_os.infra.egress.proxy import _connect_target  # pyright: ignore[reportPrivateUsage]

pytestmark = pytest.mark.anyio

HOSTNAME = "hooks.example.test"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _policy() -> StrictEgressPolicy:
    return StrictEgressPolicy(
        connect_timeout_seconds=5.0, read_timeout_seconds=5.0, max_response_bytes=4096
    )


def _answer(status: str, extra: bytes = b"") -> Any:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server_holder[0], reader)
        writer.write(f"HTTP/1.1 {status}\r\nContent-Length: 2\r\n".encode() + extra + b"\r\nok")
        await writer.drain()

    server_holder: list[LocalServer] = []
    return handler, server_holder


@pytest.fixture
def certs() -> Certificates:
    return issue_certificates(HOSTNAME)


@pytest.fixture
def connect_attempts(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[str, int]]]:
    """Every TCP connection httpcore's default backend opens, proxied or not:
    a direct connection to the destination would show up here."""
    attempts: list[tuple[str, int]] = []
    original = httpcore.AnyIOBackend.connect_tcp  # pyright: ignore[reportAttributeAccessIssue] -- the real backend at run time

    async def recording(self: Any, host: str, port: int, *args: Any, **kwargs: Any) -> Any:
        attempts.append((host, port))
        return await original(self, host, port, *args, **kwargs)

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", recording)
    yield attempts


async def _tls_destination(
    certs: Certificates, tmp_path: Path, status: str = "200 OK", extra: bytes = b""
) -> tuple[LocalServer, list[str]]:
    sni_seen: list[str] = []
    handler, holder = _answer(status, extra)
    server = LocalServer(handler, ssl_context=server_context(certs, tmp_path, sni_seen))
    holder.append(server)
    return server, sni_seen


async def test_a_request_goes_through_a_connect_tunnel_to_the_validated_address(
    certs: Certificates, tmp_path: Path, connect_attempts: list[tuple[str, int]]
) -> None:
    server, sni_seen = await _tls_destination(certs, tmp_path)
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        client = StrictEgressClient(
            _policy(),
            resolver=StaticResolver([[PUBLIC_V4]]),
            ssl_context=client_context(certs.ca_pem),
            proxy=fake.proxy,
        )
        response = await client.post(
            f"https://{HOSTNAME}/hooks/PATH-TOKEN?token=QUERY-TOKEN",
            headers={"Content-Type": "application/json"},
            content=b"{}",
            deadline=Deadline.after(10),
        )

    assert response.status_code == 200
    # The proxy is given the validated IP literal and port, nothing else.
    assert fake.heads == [
        f"CONNECT {PUBLIC_V4}:443 HTTP/1.1\r\nHost: {PUBLIC_V4}:443\r\n\r\n".encode()
    ]
    # TLS and HTTP stay on the hostname.
    assert sni_seen == [HOSTNAME]
    request_line, *header_lines = server.heads[0].decode().split("\r\n")
    assert request_line == "POST /hooks/PATH-TOKEN?token=QUERY-TOKEN HTTP/1.1"
    assert f"Host: {HOSTNAME}" in header_lines
    # The only TCP connection opened was to the proxy.
    assert connect_attempts == [("127.0.0.1", fake.proxy.port)]


async def test_an_ipv6_address_is_bracketed_in_the_connect_request(
    certs: Certificates, tmp_path: Path
) -> None:
    server, _ = await _tls_destination(certs, tmp_path)
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        client = StrictEgressClient(
            _policy(),
            resolver=StaticResolver([[PUBLIC_V6]]),
            ssl_context=client_context(certs.ca_pem),
            proxy=fake.proxy,
        )
        await client.post(
            f"https://{HOSTNAME}/", headers={}, content=b"", deadline=Deadline.after(10)
        )
    assert fake.heads[0].startswith(f"CONNECT [{PUBLIC_V6}]:443 HTTP/1.1\r\n".encode())


async def test_tls_is_verified_on_the_hostname_through_the_tunnel(tmp_path: Path) -> None:
    other = issue_certificates("someone-else.example.test")
    server, _ = await _tls_destination(other, tmp_path)
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        client = StrictEgressClient(
            _policy(),
            resolver=StaticResolver([[PUBLIC_V4]]),
            ssl_context=client_context(other.ca_pem),
            proxy=fake.proxy,
        )
        with pytest.raises(EgressTLSError):
            await client.post(
                f"https://{HOSTNAME}/", headers={}, content=b"", deadline=Deadline.after(10)
            )


async def test_a_refusal_by_the_proxy_is_permanent_and_nothing_else_is_tried(
    certs: Certificates, tmp_path: Path, connect_attempts: list[tuple[str, int]]
) -> None:
    server, _ = await _tls_destination(certs, tmp_path)
    async with server, FakeConnectProxy(relay_port=server.port, status=403) as fake:
        client = StrictEgressClient(
            _policy(),
            resolver=StaticResolver([[PUBLIC_V4, "8.8.8.8"]]),
            ssl_context=client_context(certs.ca_pem),
            proxy=fake.proxy,
        )
        with pytest.raises(EgressProxyRefusedError) as excinfo:
            await client.post(
                f"https://{HOSTNAME}/x?token=QUERY-TOKEN",
                headers={},
                content=b"",
                deadline=Deadline.after(10),
            )
    assert excinfo.value.phase == "destination"
    assert excinfo.value.request_may_have_been_sent is False
    assert "QUERY-TOKEN" not in str(excinfo.value)
    assert server.heads == []
    assert all(attempt == ("127.0.0.1", fake.proxy.port) for attempt in connect_attempts)


@pytest.mark.parametrize(
    "raw_answer",
    [
        b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        b"not http at all\r\n\r\n",
        b"HTTP/1.1 200 Connection established\r\n\r\nunexpected bytes",
        b"",
    ],
)
async def test_a_tunnel_that_is_not_established_is_unavailable_and_fails_closed(
    raw_answer: bytes, connect_attempts: list[tuple[str, int]]
) -> None:
    async with FakeConnectProxy(raw_answer=raw_answer) as fake:
        client = StrictEgressClient(
            _policy(), resolver=StaticResolver([[PUBLIC_V4]]), proxy=fake.proxy
        )
        with pytest.raises(EgressProxyUnavailableError) as excinfo:
            await client.post(
                f"https://{HOSTNAME}/", headers={}, content=b"", deadline=Deadline.after(10)
            )
    assert excinfo.value.request_may_have_been_sent is False
    assert all(attempt == ("127.0.0.1", fake.proxy.port) for attempt in connect_attempts)


async def test_an_unreachable_proxy_fails_closed_without_a_direct_connection(
    connect_attempts: list[tuple[str, int]],
) -> None:
    async with FakeConnectProxy() as fake:
        gone = fake.proxy  # its port is closed once the server stops
    client = StrictEgressClient(_policy(), resolver=StaticResolver([[PUBLIC_V4]]), proxy=gone)
    with pytest.raises(EgressProxyUnavailableError):
        await client.post(
            f"https://{HOSTNAME}/", headers={}, content=b"", deadline=Deadline.after(10)
        )
    assert connect_attempts == [("127.0.0.1", gone.port)]


async def test_a_redirect_through_the_proxy_is_not_followed(
    certs: Certificates, tmp_path: Path
) -> None:
    server, _ = await _tls_destination(
        certs, tmp_path, status="302 Found", extra=b"Location: https://elsewhere.test/\r\n"
    )
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        client = StrictEgressClient(
            _policy(),
            resolver=StaticResolver([[PUBLIC_V4]]),
            ssl_context=client_context(certs.ca_pem),
            proxy=fake.proxy,
        )
        with pytest.raises(EgressRedirectError):
            await client.post(
                f"https://{HOSTNAME}/", headers={}, content=b"", deadline=Deadline.after(10)
            )
    assert len(fake.heads) == 1


async def test_an_environment_proxy_is_still_ignored(
    certs: Certificates, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    server, _ = await _tls_destination(certs, tmp_path)
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        client = StrictEgressClient(
            _policy(),
            resolver=StaticResolver([[PUBLIC_V4]]),
            ssl_context=client_context(certs.ca_pem),
            proxy=fake.proxy,
        )
        response = await client.post(
            f"https://{HOSTNAME}/", headers={}, content=b"", deadline=Deadline.after(10)
        )
    assert response.status_code == 200
    assert len(fake.heads) == 1


def test_a_proxy_and_a_custom_transport_cannot_both_be_given() -> None:
    with pytest.raises(EgressConfigurationError):
        StrictEgressClient(
            _policy(),
            proxy=EgressProxy(host="egress-proxy", port=3128),
            transport_factory=lambda context: None,  # type: ignore[arg-type,return-value]
        )


@pytest.mark.parametrize("host", ["hooks.example.test", "localhost", ""])
def test_the_proxy_is_only_ever_given_an_address(host: str) -> None:
    with pytest.raises(EgressConfigurationError):
        _connect_target(host, 443)


@pytest.mark.parametrize(
    ("value", "proxy"),
    [
        ("http://egress-proxy:3128", EgressProxy("egress-proxy", 3128)),
        ("http://egress-proxy:3128/", EgressProxy("egress-proxy", 3128)),
        ("  http://10.0.0.5:3128  ", EgressProxy("10.0.0.5", 3128)),
    ],
)
def test_a_valid_proxy_url_is_parsed(value: str, proxy: EgressProxy) -> None:
    assert parse_egress_proxy_url(value) == proxy


@pytest.mark.parametrize(
    "value",
    [
        "https://egress-proxy:3128",
        "egress-proxy:3128",
        "http://egress-proxy",
        # pragma: allowlist nextline secret
        "http://user:SECRET@egress-proxy:3128",
        "http://egress-proxy:3128/path",
        "http://egress-proxy:3128?x=1",
        "http://egress-proxy:99999",
        "socks5://egress-proxy:1080",
    ],
)
def test_an_invalid_proxy_url_is_refused_without_repeating_it(value: str) -> None:
    with pytest.raises(EgressConfigurationError) as excinfo:
        parse_egress_proxy_url(value)
    assert "SECRET" not in str(excinfo.value)
    assert "egress-proxy" not in str(excinfo.value)


def test_the_proxy_comes_only_from_egress_proxy_url(monkeypatch: pytest.MonkeyPatch) -> None:
    get_egress_proxy.cache_clear()
    try:
        monkeypatch.delenv("EGRESS_PROXY_URL", raising=False)
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
        assert get_egress_proxy() is None
        get_egress_proxy.cache_clear()
        monkeypatch.setenv("EGRESS_PROXY_URL", "http://egress-proxy:3128")
        assert get_egress_proxy() == EgressProxy("egress-proxy", 3128)
    finally:
        get_egress_proxy.cache_clear()
