"""Strict egress client against real local sockets and real TLS (AI-B, R1/R3/R4).

A `MappingBackend` sends every TCP connect to a local server while recording
the address httpcore was asked to connect to, so these tests observe what
actually reaches the network: the pinned public address, the TLS server name
presented in the handshake (SNI), certificate verification, deadlines and
connection cleanup. No external network is used.
"""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

import httpcore
import httpx
import pytest

from egress_support import (
    PUBLIC_V4,
    PUBLIC_V4_B,
    LocalServer,
    MappingBackend,
    StaticResolver,
    client_context,
    issue_certificates,
    mapped_transport_factory,
    read_request,
    server_context,
    wait_until_disconnected,
)
from saas_os.infra.egress import (
    Deadline,
    EgressRedirectError,
    EgressResponseTooLargeError,
    EgressTimeoutError,
    EgressTLSError,
    StrictEgressClient,
    StrictEgressPolicy,
)

pytestmark = pytest.mark.anyio

HOST = "provider.example"
URL = f"https://{HOST}/v1/messages"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _policy(connect: float = 2.0, read: float = 2.0, max_bytes: int = 1024) -> StrictEgressPolicy:
    return StrictEgressPolicy(
        connect_timeout_seconds=connect, read_timeout_seconds=read, max_response_bytes=max_bytes
    )


async def _respond(writer: asyncio.StreamWriter, status: str, body: bytes, extra: str = "") -> None:
    writer.write(
        f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n{extra}\r\n".encode("ascii") + body
    )
    await writer.drain()


class _Tls:
    def __init__(self, tmp_path: Path, served_name: str = HOST) -> None:
        self.certs = issue_certificates(served_name)
        self.sni_seen: list[str] = []
        self.server_context = server_context(self.certs, tmp_path, self.sni_seen)
        self.client_context = client_context(self.certs.ca_pem)


def _client(
    tls: _Tls,
    backend: MappingBackend,
    policy: StrictEgressPolicy | None = None,
    answers: list[str] | None = None,
    client_ssl: ssl.SSLContext | None = None,
) -> StrictEgressClient:
    return StrictEgressClient(
        policy or _policy(),
        resolver=StaticResolver([answers or [PUBLIC_V4]]),
        transport_factory=mapped_transport_factory(backend),
        ssl_context=client_ssl or tls.client_context,
    )


# --- pinning and TLS identity (R1, R4) ---------------------------------------


async def test_connection_goes_to_the_pinned_address_and_tls_verifies_the_hostname(
    tmp_path: Path,
) -> None:
    tls = _Tls(tmp_path)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        body = await read_request(server, reader)
        await _respond(writer, "200 OK", b'{"echo":' + str(len(body)).encode() + b"}")

    async with LocalServer(handler, tls.server_context) as server:
        backend = MappingBackend(server.port)
        response = await _client(tls, backend).post(
            URL, headers={"x-api-key": "k"}, content=b'{"a":1}', deadline=Deadline.after(5)
        )
    assert response.status_code == 200
    assert response.body == b'{"echo":7}'
    assert [host for host, _ in backend.connects] == [PUBLIC_V4]
    assert tls.sni_seen == [HOST]
    assert b"\r\nhost: provider.example\r\n" in server.heads[0].lower()


async def test_certificate_for_another_name_is_refused_before_any_request_byte(
    tmp_path: Path,
) -> None:
    tls = _Tls(tmp_path, served_name="other.example")

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server, reader)
        await _respond(writer, "200 OK", b"{}")

    async with LocalServer(handler, tls.server_context) as server:
        with pytest.raises(EgressTLSError) as caught:
            await _client(tls, MappingBackend(server.port)).post(
                URL, headers={}, content=b"secret", deadline=Deadline.after(5)
            )
    assert caught.value.request_may_have_been_sent is False
    assert server.heads == []


async def test_certificate_from_an_untrusted_authority_is_refused(tmp_path: Path) -> None:
    tls = _Tls(tmp_path)
    stranger = client_context(issue_certificates(HOST).ca_pem)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server, reader)
        await _respond(writer, "200 OK", b"{}")

    async with LocalServer(handler, tls.server_context) as server:
        with pytest.raises(EgressTLSError):
            await _client(tls, MappingBackend(server.port), client_ssl=stranger).post(
                URL, headers={}, content=b"", deadline=Deadline.after(5)
            )
    assert server.heads == []


async def test_control_without_the_sni_extension_the_pinned_connection_fails(
    tmp_path: Path,
) -> None:
    """The guarantee depends on httpcore honouring `sni_hostname`: the same
    pinned request without the extension is verified against the IP and fails
    (closed), with it the handshake succeeds. This is what the version bounds
    in pyproject.toml and `saas_os.infra.egress.compat` protect."""
    tls = _Tls(tmp_path)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server, reader)
        await _respond(writer, "200 OK", b"{}")

    async with LocalServer(handler, tls.server_context) as server:
        backend = MappingBackend(server.port)
        factory = mapped_transport_factory(backend)
        pinned = f"https://{PUBLIC_V4}/v1/messages"
        async with httpx.AsyncClient(transport=factory(tls.client_context)) as client:
            with pytest.raises(httpx.ConnectError):
                await client.post(pinned, headers={"Host": HOST}, content=b"")
        async with httpx.AsyncClient(transport=factory(tls.client_context)) as client:
            ok = await client.post(
                pinned, headers={"Host": HOST}, content=b"", extensions={"sni_hostname": HOST}
            )
        assert ok.status_code == 200


async def test_redirect_on_a_real_connection_is_not_followed(tmp_path: Path) -> None:
    tls = _Tls(tmp_path)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server, reader)
        await _respond(writer, "302 Found", b"", "Location: https://127.0.0.1/\r\n")

    async with LocalServer(handler, tls.server_context) as server:
        with pytest.raises(EgressRedirectError):
            await _client(tls, MappingBackend(server.port)).post(
                URL, headers={}, content=b"", deadline=Deadline.after(5)
            )
    assert len(server.heads) == 1


# --- deadlines (R3) ------------------------------------------------------------


async def test_read_inactivity_timeout(tmp_path: Path) -> None:
    tls = _Tls(tmp_path)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server, reader)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
        await writer.drain()
        await asyncio.sleep(5)

    async with LocalServer(handler, tls.server_context) as server:
        client = _client(tls, MappingBackend(server.port), policy=_policy(read=0.3))
        started = asyncio.get_running_loop().time()
        with pytest.raises(EgressTimeoutError) as caught:
            await client.post(URL, headers={}, content=b"", deadline=Deadline.after(5))
    assert asyncio.get_running_loop().time() - started < 2
    assert caught.value.phase == "read"
    assert caught.value.request_may_have_been_sent is True


async def test_total_deadline_stops_a_slow_but_steady_server(tmp_path: Path) -> None:
    tls = _Tls(tmp_path)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server, reader)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        for _ in range(1000):
            writer.write(b"x")
            await writer.drain()
            await asyncio.sleep(0.05)

    async with LocalServer(handler, tls.server_context) as server:
        client = _client(tls, MappingBackend(server.port), policy=_policy(read=1.0, max_bytes=4096))
        started = asyncio.get_running_loop().time()
        with pytest.raises(EgressTimeoutError) as caught:
            await client.post(URL, headers={}, content=b"", deadline=Deadline.after(0.8))
    assert asyncio.get_running_loop().time() - started < 2.5
    assert caught.value.phase == "total"


async def test_connect_timeout_falls_through_to_the_next_address_within_the_deadline(
    tmp_path: Path,
) -> None:
    tls = _Tls(tmp_path)

    async def stall(host: str, timeout: float | None) -> None:
        del host
        await asyncio.sleep(timeout or 0)
        raise httpcore.ConnectTimeout("stalled")

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server, reader)
        await _respond(writer, "200 OK", b"{}")

    async with LocalServer(handler, tls.server_context) as server:
        backend = MappingBackend(server.port, hooks={PUBLIC_V4: stall})
        client = _client(
            tls, backend, policy=_policy(connect=0.3), answers=[PUBLIC_V4, PUBLIC_V4_B]
        )
        response = await client.post(URL, headers={}, content=b"", deadline=Deadline.after(3))
    assert response.status_code == 200
    (first_host, first_timeout), (second_host, second_timeout) = backend.connects
    assert (first_host, second_host) == (PUBLIC_V4, PUBLIC_V4_B)
    assert first_timeout is not None and first_timeout <= 0.3
    assert second_timeout is not None and second_timeout <= 0.3


async def test_connect_timeouts_on_every_address_stay_within_one_total_deadline(
    tmp_path: Path,
) -> None:
    tls = _Tls(tmp_path)

    async def stall(host: str, timeout: float | None) -> None:
        del host, timeout
        await asyncio.sleep(10)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader, writer

    async with LocalServer(handler, tls.server_context) as server:
        backend = MappingBackend(server.port, hooks={PUBLIC_V4: stall, PUBLIC_V4_B: stall})
        client = _client(tls, backend, policy=_policy(connect=5), answers=[PUBLIC_V4, PUBLIC_V4_B])
        started = asyncio.get_running_loop().time()
        with pytest.raises(EgressTimeoutError) as caught:
            await client.post(URL, headers={}, content=b"", deadline=Deadline.after(0.5))
    assert asyncio.get_running_loop().time() - started < 2
    assert caught.value.phase == "total"


# --- limits and cleanup ----------------------------------------------------------


async def test_oversized_streamed_body_is_cut_and_the_connection_closed(tmp_path: Path) -> None:
    tls = _Tls(tmp_path)
    disconnected: list[bool] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(server, reader)
        writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        try:
            for _ in range(200):
                writer.write(b"400\r\n" + b"x" * 1024 + b"\r\n")
                await writer.drain()
                await asyncio.sleep(0.01)
        except (ConnectionError, OSError):
            disconnected.append(True)
            return
        disconnected.append(await wait_until_disconnected(reader, 2))

    async with LocalServer(handler, tls.server_context) as server:
        client = _client(tls, MappingBackend(server.port), policy=_policy(max_bytes=4096))
        with pytest.raises(EgressResponseTooLargeError):
            await client.post(URL, headers={}, content=b"", deadline=Deadline.after(10))
        await asyncio.wait_for(server.finished[0].wait(), 5)
    assert disconnected == [True]


async def test_cancellation_closes_the_connection(tmp_path: Path) -> None:
    tls = _Tls(tmp_path)
    got_request = asyncio.Event()
    disconnected: list[bool] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del writer
        await read_request(server, reader)
        got_request.set()
        disconnected.append(await wait_until_disconnected(reader, 3))

    async with LocalServer(handler, tls.server_context) as server:
        client = _client(tls, MappingBackend(server.port), policy=_policy(read=30))
        task = asyncio.create_task(
            client.post(URL, headers={}, content=b"", deadline=Deadline.after(30))
        )
        await asyncio.wait_for(got_request.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(server.finished[0].wait(), 5)
    assert disconnected == [True]
