"""ADR-0059: reaching the outside through the worker's egress proxy.

The worker has no outbound route. Webhook delivery and the Resend adapter
reach their destinations through a policy-enforcing HTTP `CONNECT` proxy,
configured explicitly by `EGRESS_PROXY_URL` (never by `HTTP_PROXY` or any
other environment proxy variable, which `trust_env=False` keeps ignoring).

The application resolves the destination and validates every address before
connecting, as it always has. With a proxy, the connection to the validated
address is a tunnel: `ProxyTunnelBackend.connect_tcp(ip, port)` connects to
the proxy, sends `CONNECT <ip>:<port>`, and hands the established stream back
to httpcore, which then runs its ordinary direct-connection path over it --
TLS with the `sni_hostname` extension and certificate verification on the
original hostname, and the original `Host` header. httpx's own proxy support
is not used, because httpcore's tunnel verifies TLS against the host of the
`CONNECT` target, which here is the IP address.

So the proxy only ever receives an IP literal and a port. It never resolves a
name, never sees the URL path or query (plain HTTP is tunnelled too), and
enforces its own ranges and ports. A refusal (`403`) is
`EgressProxyRefusedError`; anything else that keeps the tunnel from being
established is `EgressProxyUnavailableError`. Neither is ever followed by a
direct connection.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, cast
from urllib.parse import urlsplit

import httpcore
import httpx

from saas_os.infra.egress.errors import (
    EgressConfigurationError,
    EgressProxyRefusedError,
    EgressProxyUnavailableError,
)

EGRESS_PROXY_URL_ENV = "EGRESS_PROXY_URL"

# A `CONNECT` answer is a status line and a few headers; anything longer is
# not a proxy this module talks to.
_MAX_CONNECT_RESPONSE_BYTES = 8192


@dataclass(frozen=True)
class EgressProxy:
    """The proxy's address on the internal network."""

    host: str
    port: int


def parse_egress_proxy_url(value: str) -> EgressProxy:
    """`http://<host>:<port>` and nothing else: no credentials, path, query
    or fragment, and only plain HTTP to the proxy, which is reached on the
    internal network. Anything else is `EgressConfigurationError`, whose
    message never repeats the value."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        port, parts = None, None
    if (
        parts is None
        or parts.scheme != "http"
        or not parts.hostname
        or port is None
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise EgressConfigurationError("invalid_egress_proxy_url")
    return EgressProxy(host=parts.hostname, port=port)


@lru_cache(maxsize=1)
def get_egress_proxy() -> EgressProxy | None:
    """The configured egress proxy, or `None` when `EGRESS_PROXY_URL` is
    unset or empty (connections are then direct, as before ADR-0059). Read
    once per process; `get_egress_proxy.cache_clear()` re-reads it."""
    value = os.environ.get(EGRESS_PROXY_URL_ENV, "").strip()
    if not value:
        return None
    return parse_egress_proxy_url(value)


def _connect_target(host: str, port: int) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # ADR-0059 R2: the proxy is only ever given a validated address.
        address = None
    if address is None:
        raise EgressConfigurationError("proxy_target_not_an_address")
    literal = f"[{address}]" if address.version == 6 else str(address)
    return f"{literal}:{port}".encode("ascii")


class ProxyTunnelBackend(httpcore.AsyncNetworkBackend):
    """An httpcore network backend whose every TCP connection is a `CONNECT`
    tunnel through `proxy` to the IP address httpcore was asked for."""

    def __init__(
        self, proxy: EgressProxy, inner: httpcore.AsyncNetworkBackend | None = None
    ) -> None:
        self._proxy = proxy
        # httpcore exports a stub `AnyIOBackend` for type checkers when anyio
        # might be missing; httpx depends on anyio, so at run time it is the
        # real backend httpcore itself uses by default.
        self._inner = inner or cast("httpcore.AsyncNetworkBackend", httpcore.AnyIOBackend())

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        target = _connect_target(host, port)
        stream: httpcore.AsyncNetworkStream | None = None
        try:
            stream = await self._inner.connect_tcp(
                self._proxy.host, self._proxy.port, timeout=timeout, local_address=local_address
            )
        except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError):
            pass
        if stream is None:
            raise EgressProxyUnavailableError()
        refused = False
        established = False
        try:
            await stream.write(
                b"CONNECT " + target + b" HTTP/1.1\r\nHost: " + target + b"\r\n\r\n",
                timeout=timeout,
            )
            status = await _read_connect_status(stream, timeout)
            refused = status == 403
            established = 200 <= status <= 299
        except (httpcore.NetworkError, httpcore.TimeoutException, OSError, ValueError):
            pass
        if established:
            return stream
        await stream.aclose()
        if refused:
            raise EgressProxyRefusedError()
        raise EgressProxyUnavailableError()

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise EgressConfigurationError("proxy_unix_socket_unsupported")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


async def _read_connect_status(stream: httpcore.AsyncNetworkStream, timeout: float | None) -> int:
    """Read the proxy's answer to `CONNECT` up to the blank line and return
    its status code. After a `2xx`, bytes after the blank line would belong
    to the tunnel, and a proxy that sends any before the client speaks is
    refused (`ValueError`). Any other answer may carry a body (Squid's `403`
    does, often in the same read); it is the status that counts."""
    received = b""
    while b"\r\n\r\n" not in received:
        chunk = await stream.read(_MAX_CONNECT_RESPONSE_BYTES, timeout=timeout)
        if not chunk:
            raise ValueError("connection closed")
        received += chunk
        if len(received) > _MAX_CONNECT_RESPONSE_BYTES:
            raise ValueError("answer too long")
    head, _, rest = received.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].split(b" ")
    if (
        len(status_line) < 2
        or not status_line[0].startswith(b"HTTP/1.")
        or not status_line[1].isdigit()
    ):
        raise ValueError("not an HTTP answer")
    status = int(status_line[1])
    if 200 <= status <= 299 and rest:
        raise ValueError("data after the answer")
    return status


def tunnel_transport(ssl_context: ssl.SSLContext, proxy: EgressProxy) -> httpx.AsyncHTTPTransport:
    """An httpx transport like the direct one (`verify=ssl_context`,
    `trust_env=False`, no retries) whose connections are tunnels through
    `proxy`. httpx takes no network backend, so its connection pool is
    replaced by an httpcore pool built with the same settings plus the
    tunnel backend; `saas_os.infra.egress.compat` keeps httpx and httpcore
    within the versions this was verified against."""
    transport = httpx.AsyncHTTPTransport(verify=ssl_context, trust_env=False, retries=0)
    transport._pool = httpcore.AsyncConnectionPool(  # pyright: ignore[reportPrivateUsage]
        ssl_context=ssl_context,
        retries=0,
        network_backend=ProxyTunnelBackend(proxy),
    )
    return transport
