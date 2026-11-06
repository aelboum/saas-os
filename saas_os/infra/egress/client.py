"""Strict outbound HTTPS client: public destinations only, pinned to the
validated address, no redirects, no environment proxies, bounded in time and
size (ADR-0054 sections 8a and 8b; AI-B decisions R1, R3, R4).

One `post()` or `get()` call (they share one private request method and so
every step below; `get` sends no body, and the only difference between the
two is the request line and the absence of a body):

1. validates the URL: `https` only, an allowed port, no user information, an
   ASCII hostname (IDNA hostnames must already be encoded);
2. resolves the hostname once (a literal IP is used as is) and rejects the
   destination if **any** answer is not publicly routable;
3. tries the validated addresses in resolver order, connecting to the literal
   address with the original hostname as TLS server name and `Host` header,
   so no second resolution can happen between validation and connection;
4. never follows a redirect, never reads proxy or trust-store settings from
   the environment (`trust_env=False`), asks for an identity-encoded response,
   and reads at most `max_response_bytes` of it.

All of it runs inside one total deadline. Connect and read timeouts are capped
by the time remaining, and every address attempt shares the same deadline.

Neither method retries. After a failure in which `request_may_have_been_sent`
is true the client tries nothing else: a `POST` may not be repeated blindly,
while a `GET` has no effect at the provider and its caller may repeat it. The
response size cap is `max_response_bytes` of the policy the client was built
with, per client and not per call: a caller that must read larger responses
builds its own client with its own policy. A response body is untrusted
bytes; this module parses nothing, and a caller that decodes one (JSON,
text, HTML) bounds and validates it itself. The URL's path is not validated
here either: a caller that puts an identifier into a path validates the
identifier first. `get` is the only method added beside `post`; there is no
public method that takes a verb.

Limitation (stated, not solved): DNS resolution runs `getaddrinfo` in the
event loop's thread pool. Cancelling the wait returns control on time, but the
resolver thread itself cannot be interrupted and runs to completion in the
background.

This client is infrastructure. It knows nothing about tenants, providers or
AI; callers pass headers and bytes. It never logs anything, so headers that
carry credentials and bodies that carry content are never written anywhere.
`httpx` itself logs each request's URL at `INFO`;
`saas_os.infra.observability.configure_logging()` sets the `httpx` logger to
`WARNING`, so that line is not written either.

Its errors are not chained to the `httpx` exception they replace: `httpx`
attaches the request (its headers and body) to its exceptions, so each error
is chosen inside the handler and raised after it, with no `__cause__` and no
`__context__` (`from None` alone would still keep the handled exception as
`__context__`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from functools import partial
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import certifi
import httpx

from saas_os.infra.egress.addresses import (
    IPAddress,
    is_never_trustable,
    is_non_public_address,
    pin_url_to_address,
)
from saas_os.infra.egress.compat import require_supported_http_stack
from saas_os.infra.egress.deadline import Deadline
from saas_os.infra.egress.errors import (
    EgressConfigurationError,
    EgressConnectError,
    EgressDestinationError,
    EgressError,
    EgressProtocolError,
    EgressRedirectError,
    EgressResolutionError,
    EgressResponseTooLargeError,
    EgressTimeoutError,
    EgressTLSError,
)
from saas_os.infra.egress.policy import StrictEgressPolicy
from saas_os.infra.egress.proxy import EgressProxy, tunnel_transport
from saas_os.infra.observability.log_filters import install_sensitive_log_filters

# `httpx` logs each request's URL; keep anything past the origin out of it
# in every process that imports this client.
install_sensitive_log_filters()

AsyncResolver = Callable[[str, int], Awaitable[list[str]]]
TransportFactory = Callable[[ssl.SSLContext], httpx.AsyncBaseTransport]

_MAX_URL_LENGTH = 2048
_MAX_HOSTNAME_LENGTH = 253
_FORBIDDEN_CALLER_HEADERS = frozenset({"host", "content-length", "transfer-encoding"})

# The verbs this client can send. A closed internal type: no public method
# takes a verb, so a caller can never choose one that is not listed here.
_Method = Literal["GET", "POST"]


@dataclass(frozen=True)
class EgressResponse:
    status_code: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


async def default_resolver(hostname: str, port: int) -> list[str]:
    """Every address `hostname` resolves to, in resolver order, without
    duplicates. Runs `getaddrinfo` in the loop's executor (not interruptible)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise EgressResolutionError() from exc
    ordered: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in ordered:
            ordered.append(address)
    return ordered


def _default_transport(ssl_context: ssl.SSLContext) -> httpx.AsyncBaseTransport:
    return httpx.AsyncHTTPTransport(verify=ssl_context, trust_env=False, retries=0)


def _proxied_transport(
    ssl_context: ssl.SSLContext, *, proxy: EgressProxy
) -> httpx.AsyncBaseTransport:
    return tunnel_transport(ssl_context, proxy)


def _default_ssl_context() -> ssl.SSLContext:
    # Explicit trust store: with trust_env=False httpx would not read
    # SSL_CERT_FILE / SSL_CERT_DIR, and this client must not depend on them.
    return ssl.create_default_context(cafile=certifi.where())


def _has_ssl_cause(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ssl.SSLError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


@dataclass(frozen=True)
class _Destination:
    url: str
    hostname: str
    port: int
    literal: IPAddress | None


class StrictEgressClient:
    """See the module docstring. `resolver`, `transport_factory` and
    `ssl_context` are seams for tests; production callers pass only `policy`."""

    def __init__(
        self,
        policy: StrictEgressPolicy,
        *,
        resolver: AsyncResolver | None = None,
        transport_factory: TransportFactory | None = None,
        ssl_context: ssl.SSLContext | None = None,
        proxy: EgressProxy | None = None,
    ) -> None:
        require_supported_http_stack()
        self._policy = policy
        self._resolver = resolver or default_resolver
        if proxy is not None and transport_factory is not None:
            # A proxy replaces the transport; accepting both would let one
            # silently win over the other.
            raise EgressConfigurationError("proxy_with_custom_transport")
        if proxy is not None:
            # ADR-0059: every connection is a `CONNECT` tunnel to the
            # validated address; there is no direct path.
            self._transport_factory: TransportFactory = partial(_proxied_transport, proxy=proxy)
        else:
            self._transport_factory = transport_factory or _default_transport
        self._ssl_context = ssl_context or _default_ssl_context()
        if not self._ssl_context.check_hostname or (
            self._ssl_context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise EgressConfigurationError("tls_verification_disabled")

    @property
    def policy(self) -> StrictEgressPolicy:
        return self._policy

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        content: bytes,
        deadline: Deadline,
    ) -> EgressResponse:
        """`POST` `content` to `url`. See the module docstring."""
        return await self._request("POST", url, headers, content, deadline)

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        deadline: Deadline,
    ) -> EgressResponse:
        """`GET` `url`: no body, and exactly `post`'s policy and guarantees.

        `get` never retries. A `GET` has no effect at the provider, so the
        caller may repeat it after any failure. The response is capped by
        this client's `max_response_bytes` (a cap per client, not per call),
        and its body is untrusted bytes: nothing is parsed here.
        """
        return await self._request("GET", url, headers, None, deadline)

    async def _request(
        self,
        method: _Method,
        url: str,
        headers: Mapping[str, str],
        content: bytes | None,
        deadline: Deadline,
    ) -> EgressResponse:
        # The one entry sequence for every verb: validation, forbidden
        # headers, deadline, resolution and the exchange are not repeated
        # per public method.
        destination = self._validate_url(url)
        for name in headers:
            if name.lower() in _FORBIDDEN_CALLER_HEADERS:
                raise EgressDestinationError("forbidden_header")
        if deadline.expired:
            raise EgressTimeoutError(
                "deadline_expired", phase="total", request_may_have_been_sent=False
            )

        exchange_started = False
        try:
            async with asyncio.timeout(deadline.remaining()):
                addresses = await self._validated_addresses(destination)
                exchange_started = True
                return await self._try_addresses(
                    method, destination, addresses, headers, content, deadline
                )
        except TimeoutError:
            pass  # raised below, outside the handler, so nothing is chained
        raise EgressTimeoutError(
            "deadline_expired", phase="total", request_may_have_been_sent=exchange_started
        )

    # -- validation ------------------------------------------------------

    def _validate_url(self, url: str) -> _Destination:
        if not url or len(url) > _MAX_URL_LENGTH or not url.isascii():
            raise EgressDestinationError("invalid_url")
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise EgressDestinationError("invalid_url") from exc
        if parts.scheme != "https":
            raise EgressDestinationError("scheme_not_allowed")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise EgressDestinationError("userinfo_not_allowed")
        hostname = parts.hostname
        if not hostname or len(hostname) > _MAX_HOSTNAME_LENGTH:
            raise EgressDestinationError("invalid_url")
        effective_port = port if port is not None else 443
        if effective_port not in self._policy.allowed_ports:
            raise EgressDestinationError("port_not_allowed")
        literal: IPAddress | None
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        if literal is not None and is_non_public_address(literal):
            raise EgressDestinationError("non_public_address")
        # The fragment is never sent; drop it rather than carry it.
        without_fragment = urlunsplit(parts._replace(fragment=""))
        return _Destination(without_fragment, hostname, effective_port, literal)

    def _trusted(self, destination: _Destination, address: IPAddress) -> bool:
        if is_never_trustable(address):
            return False
        host = destination.hostname.lower()
        for entry in self._policy.trusted_endpoints:
            if entry.host == host and entry.port == destination.port:
                return any(address in network for network in entry.networks)
        return False

    async def _validated_addresses(self, destination: _Destination) -> list[IPAddress]:
        if destination.literal is not None:
            return [destination.literal]
        raw = await self._resolver(destination.hostname, destination.port)
        if not raw:
            raise EgressResolutionError()
        validated: list[IPAddress] = []
        for item in raw:
            try:
                address = ipaddress.ip_address(item.split("%", 1)[0])
            except ValueError as exc:
                raise EgressDestinationError("invalid_resolved_address") from exc
            # All-or-nothing: one non-public answer that no trust entry covers
            # rejects the destination, so the choice of address can never be
            # steered to a private one.
            if is_non_public_address(address) and not self._trusted(destination, address):
                raise EgressDestinationError("non_public_address")
            if address not in validated:
                validated.append(address)
        return validated

    # -- exchange --------------------------------------------------------

    async def _try_addresses(
        self,
        method: _Method,
        destination: _Destination,
        addresses: list[IPAddress],
        headers: Mapping[str, str],
        content: bytes | None,
        deadline: Deadline,
    ) -> EgressResponse:
        last_error: EgressError = EgressConnectError()
        for address in addresses[: self._policy.max_addresses_tried]:
            if deadline.expired:
                break
            try:
                return await self._exchange(
                    method, destination, address, headers, content, deadline
                )
            except (EgressConnectError, EgressTimeoutError) as exc:
                if exc.request_may_have_been_sent:
                    raise
                last_error = exc  # nothing was sent; try the next validated address
        raise last_error

    async def _exchange(
        self,
        method: _Method,
        destination: _Destination,
        address: IPAddress,
        headers: Mapping[str, str],
        content: bytes | None,
        deadline: Deadline,
    ) -> EgressResponse:
        pinned_url, sni_hostname, host_header = pin_url_to_address(destination.url, address)
        remaining = max(deadline.remaining(), 0.001)
        connect = min(self._policy.connect_timeout_seconds, remaining)
        read = min(self._policy.read_timeout_seconds, remaining)
        timeout = httpx.Timeout(connect=connect, read=read, write=read, pool=connect)
        request_headers = dict(headers)
        request_headers["Host"] = host_header
        request_headers["Accept-Encoding"] = "identity"
        extensions: dict[str, object] = {}
        if destination.literal is None:
            extensions["sni_hostname"] = sni_hostname
        limit = self._policy.max_response_bytes
        failure: EgressError
        try:
            async with (
                httpx.AsyncClient(
                    transport=self._transport_factory(self._ssl_context),
                    trust_env=False,
                    follow_redirects=False,
                    timeout=timeout,
                ) as client,
                client.stream(
                    method,
                    pinned_url,
                    content=content,
                    headers=request_headers,
                    extensions=extensions,
                ) as response,
            ):
                status = response.status_code
                if 300 <= status < 400:
                    raise EgressRedirectError(status)
                encoding = response.headers.get("content-encoding", "identity").strip().lower()
                if encoding not in ("", "identity"):
                    raise EgressProtocolError(
                        "unexpected_content_encoding",
                        phase="response",
                        request_may_have_been_sent=True,
                    )
                declared = response.headers.get("content-length")
                if declared is not None and declared.isdigit() and int(declared) > limit:
                    raise EgressResponseTooLargeError()
                body = bytearray()
                # Non-identity encodings were refused above, so the decoded
                # bytes are the bytes on the wire: no decompression bomb.
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise EgressResponseTooLargeError()
                return EgressResponse(
                    status_code=status,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=bytes(body),
                )
        except EgressError:
            raise
        # Each `httpx` failure is classified here and raised below, after the
        # handler: the `httpx` exception carries the request.
        except httpx.ConnectTimeout:
            failure = EgressTimeoutError(
                "connect_timeout", phase="connect", request_may_have_been_sent=False
            )
        except httpx.PoolTimeout:
            failure = EgressTimeoutError(
                "connect_timeout", phase="connect", request_may_have_been_sent=False
            )
        except httpx.ConnectError as exc:
            failure = EgressTLSError() if _has_ssl_cause(exc) else EgressConnectError()
        except httpx.WriteTimeout:
            failure = EgressTimeoutError(
                "write_timeout", phase="write", request_may_have_been_sent=True
            )
        except httpx.ReadTimeout:
            failure = EgressTimeoutError(
                "read_timeout", phase="read", request_may_have_been_sent=True
            )
        except httpx.HTTPError:
            failure = EgressProtocolError(
                "exchange_failed", phase="exchange", request_may_have_been_sent=True
            )
        raise failure
