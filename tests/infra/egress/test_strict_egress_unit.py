"""Strict egress client: destination policy, pinning, redirects, environment
isolation, limits and deadlines, without sockets (httpx.MockTransport).

AI-B decisions R1 (public destinations only), R3 (deadlines) and R4 (stack
bounds); ADR-0054 sections 8a, 8b. Real-socket and real-TLS behaviour is in
test_strict_egress_socket_unit.py.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import ssl
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpcore
import httpx
import pytest

from egress_support import (
    PUBLIC_V4,
    PUBLIC_V4_B,
    PUBLIC_V6,
    StaticResolver,
    mock_transport_factory,
)
from saas_os.infra.egress import (
    Deadline,
    EgressConfigurationError,
    EgressConnectError,
    EgressDestinationError,
    EgressProtocolError,
    EgressRedirectError,
    EgressResolutionError,
    EgressResponse,
    EgressResponseTooLargeError,
    EgressTimeoutError,
    EgressTLSError,
    StrictEgressClient,
    StrictEgressPolicy,
)
from saas_os.infra.egress import client as client_module

pytestmark = pytest.mark.anyio

URL = "https://provider.example/v1/chat/completions"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(params=["post", "get"])
def verb(request: pytest.FixtureRequest) -> str:
    """Every guarantee below is asserted once per public method (issue 205:
    `get` shares the whole pipeline with `post`, shown by running the same
    assertions through both, not by reading the code)."""
    return str(request.param)


def _policy(**overrides: Any) -> StrictEgressPolicy:
    values: dict[str, Any] = {
        "connect_timeout_seconds": 5.0,
        "read_timeout_seconds": 30.0,
        "max_response_bytes": 1024,
    }
    values.update(overrides)
    return StrictEgressPolicy(**values)


def _ok(request: httpx.Request) -> httpx.Response:
    del request
    return httpx.Response(200, content=b'{"ok":true}')


def _client(
    handler: Callable[[httpx.Request], Any] = _ok,
    resolver: StaticResolver | None = None,
    **policy: Any,
) -> tuple[StrictEgressClient, StaticResolver, list[httpx.Request]]:
    seen: list[httpx.Request] = []
    chosen = resolver or StaticResolver([[PUBLIC_V4]])

    async def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        result = handler(request)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    client = StrictEgressClient(
        _policy(**policy), resolver=chosen, transport_factory=mock_transport_factory(recording)
    )
    return client, chosen, seen


async def _send(
    client: StrictEgressClient, verb: str, url: str = URL, seconds: float = 5.0
) -> EgressResponse:
    """The same call through either public method. A `post` carries a body; a
    `get` carries none and has no parameter for one."""
    deadline = Deadline.after(seconds)
    if verb == "get":
        return await client.get(url, headers={}, deadline=deadline)
    return await client.post(url, headers={}, content=b"{}", deadline=deadline)


async def _send_with(
    client: StrictEgressClient, verb: str, url: str, headers: dict[str, str], seconds: float = 5.0
) -> EgressResponse:
    deadline = Deadline.after(seconds)
    if verb == "get":
        return await client.get(url, headers=headers, deadline=deadline)
    return await client.post(url, headers=headers, content=b"canary-body", deadline=deadline)


# --- URL and destination policy (R1) ----------------------------------------


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://provider.example/v1", "scheme_not_allowed"),
        ("ftp://provider.example/v1", "scheme_not_allowed"),
        ("https://provider.example:8443/v1", "port_not_allowed"),
        ("https://provider.example:80/v1", "port_not_allowed"),
        ("https://user:pw@provider.example/v1", "userinfo_not_allowed"),  # pragma: allowlist secret
        ("https://user@provider.example/v1", "userinfo_not_allowed"),
        ("https://provider.example:99999/v1", "invalid_url"),
        ("https:///v1", "invalid_url"),
        ("", "invalid_url"),
        ("https://exämple.test/v1", "invalid_url"),
        ("https://" + "a" * 2050 + ".test/", "invalid_url"),
    ],
)
async def test_urls_outside_the_policy_are_refused_before_resolution(
    url: str, reason: str, verb: str
) -> None:
    client, resolver, seen = _client()
    with pytest.raises(EgressDestinationError) as caught:
        await _send(client, verb, url)
    assert caught.value.reason == reason
    assert caught.value.request_may_have_been_sent is False
    assert resolver.calls == 0 and seen == []


async def test_another_port_is_allowed_only_by_explicit_policy(verb: str) -> None:
    client, _, seen = _client(allowed_ports=frozenset({443, 8443}))
    await _send(client, verb, "https://provider.example:8443/v1")
    assert seen[0].url.port == 8443
    assert seen[0].headers["host"] == "provider.example:8443"


@pytest.mark.parametrize(
    "literal",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "[::1]",
        "[::]",
        "[fe80::1]",
        "[fc00::1]",
        "[fd00:ec2::254]",
        "[ff02::1]",
        "[fec0::1]",
        "[::ffff:127.0.0.1]",
        "[64:ff9b::7f00:1]",
        "[2002:7f00:1::]",
        "[2001:db8::1]",
    ],
)
async def test_literal_non_public_addresses_are_refused(literal: str, verb: str) -> None:
    client, resolver, seen = _client()
    with pytest.raises(EgressDestinationError) as caught:
        await _send(client, verb, f"https://{literal}/v1")
    assert caught.value.reason == "non_public_address"
    assert resolver.calls == 0 and seen == []


@pytest.mark.parametrize(
    "answer",
    [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fe80::1%eth0",
        "fd00::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "240.0.0.1",
    ],
)
async def test_resolved_non_public_addresses_are_refused(answer: str, verb: str) -> None:
    client, resolver, seen = _client(resolver=StaticResolver([[answer]]))
    with pytest.raises(EgressDestinationError) as caught:
        await _send(client, verb)
    assert caught.value.reason == "non_public_address"
    assert resolver.calls == 1 and seen == []


async def test_one_non_public_answer_among_public_ones_refuses_the_destination(verb: str) -> None:
    client, _, seen = _client(resolver=StaticResolver([[PUBLIC_V4, "10.0.0.5", PUBLIC_V4_B]]))
    with pytest.raises(EgressDestinationError):
        await _send(client, verb)
    assert seen == []


async def test_empty_answers_are_resolution_errors(verb: str) -> None:
    client, _, seen = _client(resolver=StaticResolver([[]]))
    with pytest.raises(EgressResolutionError) as caught:
        await _send(client, verb)
    assert caught.value.request_may_have_been_sent is False
    assert seen == []


async def test_garbage_resolver_answers_are_refused(verb: str) -> None:
    client, _, seen = _client(resolver=StaticResolver([["not-an-address"]]))
    with pytest.raises(EgressDestinationError):
        await _send(client, verb)
    assert seen == []


# --- pinning and TLS identity -------------------------------------------------


async def test_public_ipv4_answer_is_pinned_with_original_tls_name_and_host(verb: str) -> None:
    client, _, seen = _client()
    response = await _send(client, verb)
    assert response.status_code == 200
    request = seen[0]
    assert request.url.host == PUBLIC_V4
    assert request.url.path == "/v1/chat/completions"
    assert request.headers["host"] == "provider.example"
    assert request.extensions["sni_hostname"] == "provider.example"
    assert request.headers["accept-encoding"] == "identity"


async def test_public_ipv6_answer_is_pinned(verb: str) -> None:
    client, _, seen = _client(resolver=StaticResolver([[PUBLIC_V6]]))
    await _send(client, verb)
    assert seen[0].url.host == PUBLIC_V6
    assert seen[0].extensions["sni_hostname"] == "provider.example"


async def test_public_literal_address_is_used_without_sni_override(verb: str) -> None:
    client, resolver, seen = _client()
    await _send(client, verb, f"https://{PUBLIC_V4}/v1")
    assert resolver.calls == 0
    assert seen[0].url.host == PUBLIC_V4
    assert "sni_hostname" not in seen[0].extensions


async def test_each_call_resolves_once_so_a_rebind_cannot_redirect_the_connection(
    verb: str,
) -> None:
    # A resolver that answers public, then private (a rebinding attacker).
    resolver = StaticResolver([[PUBLIC_V4], ["127.0.0.1"]])
    client, _, seen = _client(resolver=resolver)
    await _send(client, verb)
    assert resolver.calls == 1
    assert seen[0].url.host == PUBLIC_V4
    # The next call re-resolves and is refused on the private answer.
    with pytest.raises(EgressDestinationError):
        await _send(client, verb)
    assert len(seen) == 1


async def test_caller_cannot_override_host_or_framing_headers(verb: str) -> None:
    client, _, seen = _client()
    for name in ("Host", "content-length", "Transfer-Encoding", "HOST", "Content-Length"):
        with pytest.raises(EgressDestinationError) as caught:
            await _send_with(client, verb, URL, {name: "x"})
        assert caught.value.reason == "forbidden_header"
        assert caught.value.request_may_have_been_sent is False
    assert seen == []


def test_disabled_certificate_verification_is_refused() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(EgressConfigurationError):
        StrictEgressClient(_policy(), ssl_context=context)


# --- redirects and environment -------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_redirects_are_never_followed(status: int, verb: str) -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(status, headers={"location": "https://127.0.0.1/steal"})

    client, _, seen = _client(redirect)
    with pytest.raises(EgressRedirectError) as caught:
        await _send(client, verb)
    assert caught.value.status_code == status
    assert len(seen) == 1  # the Location was not requested


async def test_client_ignores_environment_proxies_and_follows_no_redirects(
    monkeypatch: pytest.MonkeyPatch,
    verb: str,
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    built: list[dict[str, Any]] = []
    real_client = httpx.AsyncClient

    def recording_client(**kwargs: Any) -> httpx.AsyncClient:
        built.append(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(client_module.httpx, "AsyncClient", recording_client)
    client, _, _ = _client()
    await _send(client, verb)
    assert built[0]["trust_env"] is False
    assert built[0]["follow_redirects"] is False


def test_default_transport_does_not_route_through_environment_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    transport = client_module._default_transport(ssl.create_default_context())  # pyright: ignore[reportPrivateUsage]
    assert type(transport._pool) is httpcore.AsyncConnectionPool  # type: ignore[attr-defined]
    client = httpx.AsyncClient(transport=transport, trust_env=False)
    assert client._mounts == {}  # pyright: ignore[reportPrivateUsage]
    # Control: the same environment does produce proxy routes when trusted.
    trusting = httpx.AsyncClient(trust_env=True)
    assert trusting._mounts  # pyright: ignore[reportPrivateUsage]


def test_default_ssl_context_does_not_read_ssl_cert_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
    context = client_module._default_ssl_context()  # pyright: ignore[reportPrivateUsage]
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


# --- response limits -------------------------------------------------------------


async def test_declared_oversized_response_is_refused(verb: str) -> None:
    def big(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"content-length": "4096"}, content=b"x" * 4096)

    client, _, _ = _client(big)
    with pytest.raises(EgressResponseTooLargeError):
        await _send(client, verb)


async def test_streamed_oversized_response_is_refused_without_reading_it_all(verb: str) -> None:
    produced: list[int] = []

    async def body() -> AsyncIterator[bytes]:
        for _ in range(100):
            produced.append(1)
            yield b"x" * 512

    def big(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=body())

    client, _, _ = _client(big)
    with pytest.raises(EgressResponseTooLargeError):
        await _send(client, verb)
    assert len(produced) < 10


async def test_compressed_responses_are_refused(verb: str) -> None:
    def gzip(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"content-encoding": "gzip"}, content=b"\x1f\x8b")

    client, _, _ = _client(gzip)
    with pytest.raises(EgressProtocolError) as caught:
        await _send(client, verb)
    assert caught.value.reason == "unexpected_content_encoding"


# --- deadlines, retries over addresses, cancellation (R3) -------------------------


async def test_an_expired_deadline_sends_nothing(verb: str) -> None:
    client, resolver, seen = _client()
    deadline = Deadline.after(0.001)
    await asyncio.sleep(0.01)
    with pytest.raises(EgressTimeoutError) as caught:
        if verb == "get":
            await client.get(URL, headers={}, deadline=deadline)
        else:
            await client.post(URL, headers={}, content=b"", deadline=deadline)
    assert caught.value.phase == "total"
    assert resolver.calls == 0 and seen == []


async def test_total_deadline_covers_slow_resolution(verb: str) -> None:
    class SlowResolver(StaticResolver):
        async def __call__(self, hostname: str, port: int) -> list[str]:
            await asyncio.sleep(5)
            return await super().__call__(hostname, port)

    client, _, seen = _client(resolver=SlowResolver([[PUBLIC_V4]]))
    started = asyncio.get_running_loop().time()
    with pytest.raises(EgressTimeoutError) as caught:
        await _send(client, verb, seconds=0.2)
    assert asyncio.get_running_loop().time() - started < 2
    assert caught.value.phase == "total"
    assert caught.value.request_may_have_been_sent is False
    assert seen == []


async def test_total_deadline_stops_a_slow_but_steady_response(verb: str) -> None:
    async def trickle() -> AsyncIterator[bytes]:
        for _ in range(100):
            await asyncio.sleep(0.05)
            yield b"x"

    def slow(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=trickle())

    client, _, _ = _client(slow)
    started = asyncio.get_running_loop().time()
    with pytest.raises(EgressTimeoutError) as caught:
        await _send(client, verb, seconds=0.4)
    assert asyncio.get_running_loop().time() - started < 2
    assert caught.value.phase == "total"
    assert caught.value.request_may_have_been_sent is True


async def test_unreachable_address_falls_through_to_the_next_within_one_deadline(verb: str) -> None:
    def first_refuses(request: httpx.Request) -> httpx.Response:
        if request.url.host == PUBLIC_V4:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, content=b"ok")

    client, _, seen = _client(first_refuses, resolver=StaticResolver([[PUBLIC_V4, PUBLIC_V4_B]]))
    response = await _send(client, verb)
    assert response.status_code == 200
    assert [r.url.host for r in seen] == [PUBLIC_V4, PUBLIC_V4_B]


async def test_addresses_tried_are_bounded_by_policy(verb: str) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client, _, seen = _client(
        refuse,
        resolver=StaticResolver([[PUBLIC_V4, PUBLIC_V4_B, PUBLIC_V6]]),
        max_addresses_tried=2,
    )
    with pytest.raises(EgressConnectError) as caught:
        await _send(client, verb)
    assert caught.value.request_may_have_been_sent is False
    assert len(seen) == 2


async def test_tls_failure_is_not_retried_on_another_address(verb: str) -> None:
    def bad_certificate(request: httpx.Request) -> httpx.Response:
        try:
            raise ssl.SSLCertVerificationError("certificate verify failed")
        except ssl.SSLError as exc:
            raise httpx.ConnectError("tls", request=request) from exc

    client, _, seen = _client(bad_certificate, resolver=StaticResolver([[PUBLIC_V4, PUBLIC_V4_B]]))
    with pytest.raises(EgressTLSError):
        await _send(client, verb)
    assert len(seen) == 1


async def test_failure_after_the_request_may_have_been_sent_is_not_retried(verb: str) -> None:
    def read_timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    client, _, seen = _client(read_timeout, resolver=StaticResolver([[PUBLIC_V4, PUBLIC_V4_B]]))
    with pytest.raises(EgressTimeoutError) as caught:
        await _send(client, verb)
    assert caught.value.phase == "read"
    assert caught.value.request_may_have_been_sent is True
    assert len(seen) == 1


async def test_each_attempt_gets_only_the_remaining_time(verb: str) -> None:
    timeouts: list[dict[str, float]] = []

    def capture(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"])
        return httpx.Response(200)

    client, _, _ = _client(capture)
    await _send(client, verb, seconds=0.5)
    assert all(0 < value <= 0.5 for value in timeouts[0].values())


async def test_cancellation_closes_the_response(verb: str) -> None:
    entered = asyncio.Event()
    closed = asyncio.Event()

    async def never_ends() -> AsyncIterator[bytes]:
        try:
            entered.set()
            await asyncio.sleep(3600)
            yield b""
        finally:
            closed.set()

    def stalls(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=never_ends())

    client, _, _ = _client(stalls)
    task = asyncio.create_task(_send(client, verb, seconds=60))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(closed.wait(), 2)


# --- error hygiene and HTTP stack bounds (R4) -------------------------------------


async def test_errors_do_not_carry_urls_or_headers(verb: str) -> None:
    client, _, _ = _client(resolver=StaticResolver([["10.0.0.1"]]))
    with pytest.raises(EgressDestinationError) as caught:
        await _send_with(
            client,
            verb,
            "https://provider.example/v1/PATH-CANARY?key=secret-in-query",
            {"Authorization": "Bearer canary-secret"},
        )
    text = str(caught.value) + repr(caught.value)
    for fragment in (
        "provider.example",
        "PATH-CANARY",
        "secret-in-query",
        "canary-secret",
        "canary-body",
    ):
        assert fragment not in text


@pytest.mark.parametrize(
    ("module", "version"),
    [
        ("httpcore", "2.0.0"),
        ("httpcore", "1.1.0"),
        ("httpcore", "1.0.8"),
        ("httpx", "0.29.0"),
        ("httpx", "0.27.2"),
        ("httpx", "1.0.0"),
    ],
)
def test_unsupported_http_stack_versions_are_refused(
    monkeypatch: pytest.MonkeyPatch, module: str, version: str
) -> None:
    target = httpcore if module == "httpcore" else httpx
    monkeypatch.setattr(target, "__version__", version)
    with pytest.raises(EgressConfigurationError):
        StrictEgressClient(_policy())


def test_installed_http_stack_is_supported() -> None:
    StrictEgressClient(_policy())


@pytest.mark.parametrize(
    "overrides",
    [
        {"connect_timeout_seconds": 0},
        {"read_timeout_seconds": -1},
        {"max_response_bytes": 0},
        {"allowed_ports": frozenset()},
        {"allowed_ports": frozenset({0})},
        {"max_addresses_tried": 0},
    ],
)
def test_invalid_policies_are_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(EgressConfigurationError):
        _policy(**overrides)


def test_deadline_must_be_positive() -> None:
    with pytest.raises(ValueError):
        Deadline.after(0)


# --- the verb: request line, body, and one shared pipeline (issue 205) -------------


async def test_the_request_line_and_body_match_the_method(verb: str) -> None:
    client, _, seen = _client()
    await _send_with(client, verb, URL + "?page=2", {"X-Api-Key": "k"})
    request = seen[0]
    assert request.method == verb.upper()
    assert request.url.path == "/v1/chat/completions"
    assert request.url.query == b"page=2"
    assert request.headers["x-api-key"] == "k"
    assert request.headers["host"] == "provider.example"
    assert request.headers["accept-encoding"] == "identity"
    if verb == "get":
        # No body and no framing header: nothing can smuggle one in.
        assert request.content == b""
        assert "content-length" not in request.headers
        assert "transfer-encoding" not in request.headers
    else:
        assert request.content == b"canary-body"


def test_get_takes_no_body_and_post_is_unchanged() -> None:
    get = inspect.signature(StrictEgressClient.get)
    post = inspect.signature(StrictEgressClient.post)
    assert list(get.parameters) == ["self", "url", "headers", "deadline"]
    assert all(
        get.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        for name in ("headers", "deadline")
    )
    assert get.parameters["headers"].default is inspect.Parameter.empty
    assert list(post.parameters) == ["self", "url", "headers", "content", "deadline"]
    assert not hasattr(StrictEgressClient, "request")  # no public verb-taking method


async def test_get_refuses_a_body_argument() -> None:
    client, _, seen = _client()
    body: dict[str, Any] = {"content": b"x"}
    with pytest.raises(TypeError):
        await client.get(URL, headers={}, deadline=Deadline.after(5), **body)
    assert seen == []


async def test_both_public_methods_run_through_one_private_request_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A change that gave one method its own pipeline would not be seen by the
    # other verb's assertions above; this ties both to the single method.
    calls: list[tuple[str, bytes | None]] = []

    async def recording(
        self: StrictEgressClient,
        method: str,
        url: str,
        headers: Any,
        content: bytes | None,
        deadline: Deadline,
    ) -> EgressResponse:
        del self, url, headers, deadline
        calls.append((method, content))
        return EgressResponse(status_code=204, headers={}, body=b"")

    monkeypatch.setattr(StrictEgressClient, "_request", recording)
    client, _, _ = _client()
    await _send(client, "post")
    await _send(client, "get")
    assert calls == [("POST", b"{}"), ("GET", None)]


async def test_log_records_of_either_method_carry_only_the_origin(
    verb: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    client, _, _ = _client()
    await _send_with(
        client, verb, "https://provider.example/emails/PATH-CANARY?token=QUERY-CANARY", {}
    )
    text = caplog.text + " ".join(record.getMessage() for record in caplog.records)
    assert "PATH-CANARY" not in text and "QUERY-CANARY" not in text
    assert "canary-body" not in text


def test_the_ai_adapters_egress_protocol_still_declares_only_post() -> None:
    from saas_os.control_plane.inference.adapters import EgressClient

    declared = {name for name in vars(EgressClient) if not name.startswith("_")}
    assert declared == {"post"}
