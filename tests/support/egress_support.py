"""Test helpers for the strict egress client and the AI provider adapters (AI-B).

- Public addresses used as resolver answers (never contacted: connections go
  through a `MappingBackend` or a `MockTransport`).
- `MappingBackend`: an httpcore network backend that sends every TCP connect
  to a local test server while recording the address httpcore asked for, so
  pinning can be observed on a real socket.
- `issue_certificates`: a throw-away CA and a server certificate, for real TLS
  handshakes against a local server.
"""

from __future__ import annotations

import asyncio
import datetime
import ssl
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpcore
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V4_B = "8.8.8.8"
PUBLIC_V6 = "2606:4700:4700::1111"


@dataclass
class StaticResolver:
    """Async resolver returning scripted answers, one list per call (the last
    list repeats). Counts calls."""

    answers: list[list[str]]
    calls: int = 0

    async def __call__(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        index = min(self.calls, len(self.answers) - 1)
        self.calls += 1
        return list(self.answers[index])


def mock_transport_factory(
    handler: Callable[[httpx.Request], Any],
) -> Callable[[ssl.SSLContext], httpx.AsyncBaseTransport]:
    def factory(ssl_context: ssl.SSLContext) -> httpx.AsyncBaseTransport:
        del ssl_context
        return httpx.MockTransport(handler)

    return factory


ConnectHook = Callable[[str, float | None], Awaitable[None]]


class MappingBackend(httpcore.AsyncNetworkBackend):
    """Routes every connect to 127.0.0.1:`port`; records (host, timeout) as
    httpcore requested them. `hooks[host]` runs before connecting, e.g. to
    delay or to raise."""

    def __init__(self, port: int, hooks: dict[str, ConnectHook] | None = None) -> None:
        self.port = port
        self.hooks = hooks or {}
        self.connects: list[tuple[str, float | None]] = []
        # Typed loosely: pyright does not see httpcore's lazily exported backend
        # as an `AsyncNetworkBackend`.
        self._inner: Any = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del port
        self.connects.append((host, timeout))
        hook = self.hooks.get(host)
        if hook is not None:
            await hook(host, timeout)
        return await self._inner.connect_tcp(
            "127.0.0.1", self.port, timeout, local_address, socket_options
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:  # pragma: no cover -- not used
        raise NotImplementedError

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def mapped_transport_factory(
    backend: MappingBackend,
) -> Callable[[ssl.SSLContext], httpx.AsyncBaseTransport]:
    """An httpx transport whose connection pool uses `backend`. Test-only use
    of httpx's private `_pool` attribute, pinned by the version bounds in
    pyproject.toml."""

    def factory(ssl_context: ssl.SSLContext) -> httpx.AsyncBaseTransport:
        transport = httpx.AsyncHTTPTransport(verify=ssl_context, trust_env=False, retries=0)
        transport._pool = httpcore.AsyncConnectionPool(  # pyright: ignore[reportPrivateUsage]
            ssl_context=ssl_context, network_backend=backend, retries=0
        )
        return transport

    return factory


@dataclass(frozen=True)
class Certificates:
    ca_pem: bytes
    cert_pem: bytes
    key_pem: bytes


def issue_certificates(hostname: str) -> Certificates:
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AI-B test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return Certificates(
        ca_pem=ca_cert.public_bytes(serialization.Encoding.PEM),
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def client_context(ca_pem: bytes) -> ssl.SSLContext:
    return ssl.create_default_context(cadata=ca_pem.decode("ascii"))


def server_context(certs: Certificates, tmp_dir: Path, sni_seen: list[str]) -> ssl.SSLContext:
    cert_file = tmp_dir / "server.pem"
    key_file = tmp_dir / "server.key"
    cert_file.write_bytes(certs.cert_pem)
    key_file.write_bytes(certs.key_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_file), str(key_file))

    def remember(_sock: Any, name: str | None, _ctx: Any) -> None:
        sni_seen.append(name or "")

    context.sni_callback = remember
    return context


Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


@dataclass
class LocalServer:
    """A local TCP/TLS server whose connections are handled by `handler`.
    Records the request heads it read and whether each connection ended."""

    handler: Handler
    ssl_context: ssl.SSLContext | None = None
    heads: list[bytes] = field(default_factory=list)
    finished: list[asyncio.Event] = field(default_factory=list)
    _server: asyncio.Server | None = None

    async def __aenter__(self) -> LocalServer:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0, ssl=self.ssl_context)
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        done = asyncio.Event()
        self.finished.append(done)
        try:
            await self.handler(reader, writer)
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            done.set()
            writer.close()


async def read_request(server: LocalServer, reader: asyncio.StreamReader) -> bytes:
    head = await reader.readuntil(b"\r\n\r\n")
    server.heads.append(head)
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    return await reader.readexactly(length) if length else b""


async def wait_until_disconnected(reader: asyncio.StreamReader, timeout: float) -> bool:
    """True if the peer closed the connection within `timeout`."""
    try:
        async with asyncio.timeout(timeout):
            while await reader.read(65536):
                pass
    except TimeoutError:
        return False
    except (ConnectionError, ssl.SSLError, OSError):
        return True
    return True


@dataclass
class FakeConnectProxy:
    """Answers each `CONNECT` with `status` (or `raw_answer`), and relays an
    accepted tunnel to `relay_port` on 127.0.0.1, whatever address was
    asked for. Records every request head it received."""

    relay_port: int = 0
    status: int = 200
    raw_answer: bytes | None = None
    heads: list[bytes] = field(default_factory=list)
    _server: asyncio.Server | None = None
    _port: int = 0

    async def __aenter__(self) -> FakeConnectProxy:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self._port = int(self._server.sockets[0].getsockname()[1])
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    @property
    def proxy(self) -> Any:
        assert self._port, "the fake proxy was never started"
        from saas_os.infra.egress import EgressProxy

        return EgressProxy(host="127.0.0.1", port=self._port)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            self.heads.append(await reader.readuntil(b"\r\n\r\n"))
            if self.raw_answer is not None:
                writer.write(self.raw_answer)
                await writer.drain()
                return
            if self.status != 200:
                writer.write(f"HTTP/1.1 {self.status} No\r\nContent-Length: 0\r\n\r\n".encode())
                await writer.drain()
                return
            up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.relay_port)
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
