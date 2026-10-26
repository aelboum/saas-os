"""No request or response data stays reachable from an egress or adapter error.

`httpx` attaches the request (headers with the provider credential, the body
with the prompt) to its exceptions, and a `JSONDecodeError` keeps the whole
document it failed to parse (a provider's answer). An error raised inside an
`except` block keeps the handled exception as `__context__` even with
`from None`, which only hides it from printed tracebacks. These tests walk the
actual exception graph (`__cause__` and `__context__`, recursively) of what
the strict egress client and the provider adapters raise, through the real
`StrictEgressClient` over a mock transport: fake credentials, no network.
The governed service's consumer errors are covered against PostgreSQL in
`test_ai_inference_integration.py`.
"""

from __future__ import annotations

import asyncio
import ssl
import traceback
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from egress_support import PUBLIC_V4, StaticResolver, mock_transport_factory
from saas_os.control_plane.inference.adapters import (
    AdapterError,
    AdapterMessage,
    AdapterRequest,
    AnthropicMessagesAdapter,
    Capability,
    ErrorCategory,
    GeminiGenerateContentAdapter,
    OpaqueCredential,
    OpenAICompatibleAdapter,
    ProviderAdapter,
    ResolvedTarget,
)
from saas_os.infra.egress import (
    Deadline,
    EgressError,
    EgressTimeoutError,
    StrictEgressClient,
    StrictEgressPolicy,
)

pytestmark = pytest.mark.anyio

CANARY = "sk-chain-canary-0123456789"  # pragma: allowlist secret -- a fake key
PROMPT = "chain canary prompt: the tenant's private ticket"
COMPLETION = "chain canary completion: the model's private answer"

ADAPTERS: dict[str, tuple[ProviderAdapter, str]] = {
    "openai": (OpenAICompatibleAdapter(), "https://api.test/v1"),
    "anthropic": (AnthropicMessagesAdapter(), "https://api.test"),
    "gemini": (GeminiGenerateContentAdapter(), "https://api.test/v1beta"),
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def reachable(exc: BaseException) -> list[BaseException]:
    """Every exception reachable from `exc` through `__cause__` and
    `__context__`, whatever `__suppress_context__` says."""
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


def assert_detached(exc: BaseException) -> None:
    """Nothing reachable from `exc` holds request or response data, and
    neither its messages nor its printed traceback name any of it."""
    for item in reachable(exc):
        assert not isinstance(item, httpx.HTTPError), f"{type(item).__name__} holds its request"
        assert getattr(item, "request", None) is None
        assert getattr(item, "doc", None) is None, f"{type(item).__name__} holds a document"
        shown = f"{item!s} {item!r} {vars(item)!r}"
        for canary in (CANARY, PROMPT, COMPLETION):
            assert canary not in shown
    printed = "".join(traceback.format_exception(exc))
    for canary in (CANARY, PROMPT, COMPLETION):
        assert canary not in printed


def _raising(error: Callable[[httpx.Request], Exception]) -> Callable[[httpx.Request], Any]:
    def handler(request: httpx.Request) -> httpx.Response:
        request.read()  # the body with the prompt is now on the request
        raise error(request)

    return handler


def _tls_failure(request: httpx.Request) -> Exception:
    try:
        raise ssl.SSLCertVerificationError("certificate verify failed")
    except ssl.SSLError as exc:
        error = httpx.ConnectError("tls", request=request)
        error.__cause__ = exc
        return error


def _malformed(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=f'{{"answer": "{COMPLETION}"'.encode())


# (handler, category, possibly_accepted): the classification is unchanged by
# dropping the chain.
FAILURES: dict[str, tuple[Callable[[httpx.Request], Any], ErrorCategory, bool]] = {
    "connect": (
        _raising(lambda r: httpx.ConnectError("refused", request=r)),
        ErrorCategory.TRANSIENT_PRE_ACCEPTANCE,
        False,
    ),
    "connect_timeout": (
        _raising(lambda r: httpx.ConnectTimeout("slow", request=r)),
        ErrorCategory.TRANSIENT_PRE_ACCEPTANCE,
        False,
    ),
    "tls": (_raising(_tls_failure), ErrorCategory.ENDPOINT_SECURITY, False),
    "write_timeout": (
        _raising(lambda r: httpx.WriteTimeout("slow", request=r)),
        ErrorCategory.TIMEOUT,
        True,
    ),
    "read_timeout": (
        _raising(lambda r: httpx.ReadTimeout("slow", request=r)),
        ErrorCategory.TIMEOUT,
        True,
    ),
    "read": (
        _raising(lambda r: httpx.ReadError("reset", request=r)),
        ErrorCategory.PROVIDER_ERROR,
        True,
    ),
    "protocol": (
        _raising(lambda r: httpx.RemoteProtocolError("garbled", request=r)),
        ErrorCategory.PROVIDER_ERROR,
        True,
    ),
    "malformed_response": (_malformed, ErrorCategory.MALFORMED_RESPONSE, True),
}


def _client(handler: Callable[[httpx.Request], Any]) -> StrictEgressClient:
    return StrictEgressClient(
        StrictEgressPolicy(
            connect_timeout_seconds=5, read_timeout_seconds=5, max_response_bytes=65536
        ),
        resolver=StaticResolver([[PUBLIC_V4]]),
        transport_factory=mock_transport_factory(handler),
    )


async def _complete(name: str, egress: StrictEgressClient, seconds: float = 5) -> AdapterError:
    adapter, base_url = ADAPTERS[name]
    with pytest.raises(AdapterError) as caught:
        await adapter.complete(
            AdapterRequest(messages=(AdapterMessage("user", PROMPT),), max_output_tokens=16),
            target=ResolvedTarget(base_url, "model-x", frozenset(Capability)),
            credential=OpaqueCredential(CANARY),
            egress=egress,
            deadline=Deadline.after(seconds),
        )
    return caught.value


@pytest.mark.parametrize("failure", sorted(FAILURES))
@pytest.mark.parametrize("name", sorted(ADAPTERS))
async def test_an_adapter_error_holds_no_request_or_response(name: str, failure: str) -> None:
    sent: list[httpx.Request] = []
    handler, category, possibly_accepted = FAILURES[failure]

    def recording(request: httpx.Request) -> Any:
        sent.append(request)
        return handler(request)

    error = await _complete(name, _client(recording))

    # The failure really carried the canaries on its request...
    assert CANARY in " ".join(sent[0].headers.values()) and PROMPT.encode() in sent[0].content
    # ...and none of it is reachable from the error, whose classification stands.
    assert (error.category, error.possibly_accepted) == (category, possibly_accepted)
    assert_detached(error)


@pytest.mark.parametrize("name", sorted(ADAPTERS))
async def test_the_total_deadline_error_holds_no_request(name: str) -> None:
    async def stalled(request: httpx.Request) -> httpx.Response:
        await request.aread()
        await asyncio.sleep(30)
        raise AssertionError("unreachable")

    error = await _complete(name, _client(stalled), seconds=0.2)
    assert (error.category, error.possibly_accepted) == (ErrorCategory.TIMEOUT, True)
    assert_detached(error)


@pytest.mark.parametrize("failure", sorted(set(FAILURES) - {"malformed_response"}))
async def test_a_strict_egress_error_holds_no_request(failure: str) -> None:
    handler, _, possibly_accepted = FAILURES[failure]
    with pytest.raises(EgressError) as caught:
        await _client(handler).post(
            "https://api.test/v1/chat/completions",
            headers={"Authorization": f"Bearer {CANARY}"},
            content=PROMPT.encode(),
            deadline=Deadline.after(5),
        )
    assert caught.value.request_may_have_been_sent is possibly_accepted
    assert_detached(caught.value)


async def test_a_tls_failure_is_still_told_apart_from_a_refused_connection() -> None:
    from saas_os.infra.egress import EgressConnectError, EgressTLSError

    for failure, expected in (("tls", EgressTLSError), ("connect", EgressConnectError)):
        with pytest.raises(EgressError) as caught:
            await _client(FAILURES[failure][0]).post(
                "https://api.test/", headers={}, content=b"", deadline=Deadline.after(5)
            )
        assert type(caught.value) is expected


async def test_the_total_deadline_is_still_reported_as_such() -> None:
    async def stalled(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)
        raise AssertionError("unreachable")

    with pytest.raises(EgressTimeoutError) as caught:
        await _client(stalled).post(
            "https://api.test/", headers={}, content=b"", deadline=Deadline.after(0.2)
        )
    assert (caught.value.reason, caught.value.phase) == ("deadline_expired", "total")
    assert caught.value.request_may_have_been_sent is True
    assert_detached(caught.value)
