"""Provider adapter conformance (AI-B; contracts document section 2).

Both protocol adapters are driven through a recording fake egress, so no
network or provider credential is used. The same conformance cases run for
both: request mapping, response mapping, error normalization (with the
possibly-accepted flag), capability checks before sending, cancellation, and
credential and content hygiene. One end-to-end case drives an adapter through
the real `StrictEgressClient` over a mock transport.

These tests prove adapter behaviour only. They do not make direct adapter use
a governed or production-ready inference path (AI-B decision R2).
"""

from __future__ import annotations

import asyncio
import json
import logging
import pickle
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from egress_support import PUBLIC_V4, StaticResolver, mock_transport_factory
from saas_os.control_plane.inference.adapters import (
    AdapterError,
    AdapterMessage,
    AdapterRequest,
    AdapterResult,
    AnthropicMessagesAdapter,
    Capability,
    ErrorCategory,
    FakeAdapter,
    GeminiGenerateContentAdapter,
    OpaqueCredential,
    OpenAICompatibleAdapter,
    ProviderAdapter,
    ResolvedTarget,
)
from saas_os.infra.egress import (
    Deadline,
    EgressConnectError,
    EgressDestinationError,
    EgressError,
    EgressRedirectError,
    EgressResponse,
    EgressResponseTooLargeError,
    EgressTimeoutError,
    StrictEgressClient,
    StrictEgressPolicy,
)

pytestmark = pytest.mark.anyio

CANARY = "sk-canary-0123456789"
PROMPT = "summarize the canary ticket"
ALL = frozenset(Capability)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class Post:
    url: str
    headers: Mapping[str, str]
    payload: dict[str, Any]


@dataclass
class FakeEgress:
    responses: list[EgressResponse | EgressError] = field(default_factory=list)
    posts: list[Post] = field(default_factory=list)
    block: bool = False

    async def post(
        self, url: str, *, headers: Mapping[str, str], content: bytes, deadline: Deadline
    ) -> EgressResponse:
        del deadline
        self.posts.append(Post(url, dict(headers), json.loads(content)))
        if self.block:
            await asyncio.sleep(3600)
        item = self.responses.pop(0)
        if isinstance(item, EgressError):
            raise item
        return item


def _response(
    status: int, body: object, headers: Mapping[str, str] | None = None
) -> EgressResponse:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return EgressResponse(status_code=status, headers=dict(headers or {}), body=raw)


OPENAI_OK: dict[str, Any] = {
    "model": "gpt-test",
    "choices": [{"message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
    "usage": {
        "prompt_tokens": 11,
        "completion_tokens": 3,
        "prompt_tokens_details": {"cached_tokens": 4},
    },
}
ANTHROPIC_OK: dict[str, Any] = {
    "model": "claude-test",
    "content": [{"type": "text", "text": "hel"}, {"type": "text", "text": "lo"}],
    "stop_reason": "end_turn",
    "usage": {
        "input_tokens": 11,
        "output_tokens": 3,
        "cache_read_input_tokens": 4,
        "cache_creation_input_tokens": 2,
    },
}

GEMINI_OK: dict[str, Any] = {
    "modelVersion": "gemini-test",
    "responseId": "resp-1",
    "candidates": [
        {
            "content": {"role": "model", "parts": [{"text": "hel"}, {"text": "lo"}]},
            "finishReason": "STOP",
        }
    ],
    "usageMetadata": {
        "promptTokenCount": 11,
        "candidatesTokenCount": 3,
        "cachedContentTokenCount": 4,
    },
}


@dataclass(frozen=True)
class Case:
    adapter: ProviderAdapter
    ok_body: dict[str, Any]
    request_id_header: str
    base_url: str


CASES = {
    "openai": Case(OpenAICompatibleAdapter(), OPENAI_OK, "x-request-id", "https://api.test/v1"),
    "anthropic": Case(AnthropicMessagesAdapter(), ANTHROPIC_OK, "request-id", "https://api.test"),
    "gemini": Case(
        GeminiGenerateContentAdapter(), GEMINI_OK, "x-goog-request-id", "https://api.test/v1beta"
    ),
}


@pytest.fixture(params=sorted(CASES))
def case(request: pytest.FixtureRequest) -> Case:
    return CASES[request.param]


def _request(**overrides: Any) -> AdapterRequest:
    values: dict[str, Any] = {
        "messages": (AdapterMessage("user", PROMPT),),
        "max_output_tokens": 64,
    }
    values.update(overrides)
    return AdapterRequest(**values)


def _target(case: Case, capabilities: frozenset[Capability] = ALL) -> ResolvedTarget:
    return ResolvedTarget(base_url=case.base_url, model_id="model-x", capabilities=capabilities)


async def _complete(
    case: Case,
    egress: FakeEgress,
    request: AdapterRequest | None = None,
    target: ResolvedTarget | None = None,
) -> AdapterResult:
    return await case.adapter.complete(
        request or _request(),
        target=target or _target(case),
        credential=OpaqueCredential(CANARY),
        egress=egress,
        deadline=Deadline.after(5),
    )


# --- request and response mapping ------------------------------------------------


async def test_openai_request_mapping() -> None:
    egress = FakeEgress([_response(200, OPENAI_OK, {"x-request-id": "req-1"})])
    await _complete(
        CASES["openai"], egress, _request(system="be brief", temperature=0.2, stop=("END",))
    )
    post = egress.posts[0]
    assert post.url == "https://api.test/v1/chat/completions"
    assert post.headers["Authorization"] == f"Bearer {CANARY}"
    assert post.headers["Content-Type"] == "application/json"
    assert post.payload == {
        "model": "model-x",
        "messages": [
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": PROMPT},
        ],
        "max_tokens": 64,
        "temperature": 0.2,
        "stop": ["END"],
    }


async def test_anthropic_request_mapping() -> None:
    egress = FakeEgress([_response(200, ANTHROPIC_OK)])
    await _complete(
        CASES["anthropic"], egress, _request(system="be brief", temperature=0.2, stop=("END",))
    )
    post = egress.posts[0]
    assert post.url == "https://api.test/v1/messages"
    assert post.headers["x-api-key"] == CANARY
    assert post.headers["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in post.headers
    assert post.payload == {
        "model": "model-x",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": PROMPT}],
        "system": "be brief",
        "temperature": 0.2,
        "stop_sequences": ["END"],
    }


async def test_optional_parameters_are_omitted_when_not_requested(case: Case) -> None:
    egress = FakeEgress([_response(200, case.ok_body)])
    await _complete(case, egress)
    payload = egress.posts[0].payload
    for key in ("temperature", "stop", "stop_sequences", "system"):
        assert key not in payload


async def test_successful_response_mapping(case: Case) -> None:
    egress = FakeEgress([_response(200, case.ok_body, {case.request_id_header: "req-9"})])
    result = await _complete(case, egress)
    assert result.text == "hello"
    assert result.finish_reason == "stop"
    assert result.usage.input_tokens == 11
    assert result.usage.output_tokens == 3
    assert result.usage.cached_input_tokens == 4
    assert result.provider_request_id == "req-9"
    assert result.model in ("gpt-test", "claude-test", "gemini-test")


async def test_anthropic_reports_cache_writes_and_maps_stop_reasons() -> None:
    body = dict(ANTHROPIC_OK, stop_reason="max_tokens")
    result = await _complete(CASES["anthropic"], FakeEgress([_response(200, body)]))
    assert result.usage.cache_write_tokens == 2
    assert result.finish_reason == "length"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("length", "length"),
        ("content_filter", "content_filter"),
        ("tool_calls", "tool_calls"),
        ("weird", "other"),
    ],
)
async def test_openai_finish_reasons(raw: str, expected: str) -> None:
    body = json.loads(json.dumps(OPENAI_OK))
    body["choices"][0]["finish_reason"] = raw
    result = await _complete(CASES["openai"], FakeEgress([_response(200, body)]))
    assert result.finish_reason == expected


async def test_missing_or_invalid_usage_is_reported_as_unknown(case: Case) -> None:
    body = dict(case.ok_body)
    body["usage"] = {
        "prompt_tokens": -1,
        "completion_tokens": "3",
        "input_tokens": "eleven",
        "output_tokens": True,
    }
    body["usageMetadata"] = {"promptTokenCount": -1, "candidatesTokenCount": "3"}
    result = await _complete(case, FakeEgress([_response(200, body)]))
    assert result.usage.input_tokens is None
    assert result.usage.output_tokens is None


# --- error normalization ---------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "category", "possibly_accepted"),
    [
        (400, ErrorCategory.INVALID_REQUEST, False),
        (404, ErrorCategory.INVALID_REQUEST, False),
        (413, ErrorCategory.INVALID_REQUEST, False),
        (422, ErrorCategory.INVALID_REQUEST, False),
        (401, ErrorCategory.PROVIDER_AUTH, False),
        (403, ErrorCategory.PROVIDER_AUTH, False),
        (429, ErrorCategory.RATE_LIMITED, False),
        (500, ErrorCategory.PROVIDER_ERROR, True),
        (502, ErrorCategory.PROVIDER_ERROR, True),
        (503, ErrorCategory.PROVIDER_ERROR, True),
    ],
)
async def test_status_codes_are_normalized(
    case: Case, status: int, category: ErrorCategory, possibly_accepted: bool
) -> None:
    error_body = {"error": {"message": f"echo {CANARY} {PROMPT}"}}
    egress = FakeEgress(
        [_response(status, error_body, {case.request_id_header: "req-e", "retry-after": "7"})]
    )
    if case.adapter.protocol == "gemini_generate_content" and status == 503:
        # Gemini declares 503 UNAVAILABLE as not processed (overloaded).
        category, possibly_accepted = ErrorCategory.PROVIDER_OVERLOADED, False
    with pytest.raises(AdapterError) as caught:
        await _complete(case, egress)
    assert caught.value.category is category
    assert caught.value.possibly_accepted is possibly_accepted
    assert caught.value.status_code == status
    assert caught.value.provider_request_id == "req-e"
    if category is ErrorCategory.RATE_LIMITED:
        assert caught.value.retry_after_seconds == 7.0
    assert CANARY not in str(caught.value) and PROMPT not in str(caught.value)


async def test_anthropic_overloaded_is_declared_not_processed() -> None:
    egress = FakeEgress([_response(529, {"type": "error"})])
    with pytest.raises(AdapterError) as caught:
        await _complete(CASES["anthropic"], egress)
    assert caught.value.category is ErrorCategory.PROVIDER_OVERLOADED
    assert caught.value.possibly_accepted is False


async def test_openai_compatible_529_is_not_assumed_unprocessed() -> None:
    egress = FakeEgress([_response(529, {})])
    with pytest.raises(AdapterError) as caught:
        await _complete(CASES["openai"], egress)
    assert caught.value.category is ErrorCategory.PROVIDER_ERROR
    assert caught.value.possibly_accepted is True


@pytest.mark.parametrize("value", ["Wed, 21 Oct 2015 07:28:00 GMT", "-5", "999999"])
async def test_unusable_retry_after_is_ignored(case: Case, value: str) -> None:
    egress = FakeEgress([_response(429, {}, {"retry-after": value})])
    with pytest.raises(AdapterError) as caught:
        await _complete(case, egress)
    assert caught.value.retry_after_seconds is None


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[1,2]",
        b"\xff\xfe",
        b"{}",
    ],
)
async def test_malformed_success_responses_are_possibly_accepted(case: Case, body: bytes) -> None:
    with pytest.raises(AdapterError) as caught:
        await _complete(case, FakeEgress([_response(200, body)]))
    assert caught.value.category is ErrorCategory.MALFORMED_RESPONSE
    assert caught.value.possibly_accepted is True


@pytest.mark.parametrize(
    "body",
    [
        {"choices": []},
        {"choices": [{"message": "x"}]},
        {"choices": [{"message": {"content": 5}}]},
        {"choices": ["x"]},
    ],
)
async def test_openai_malformed_shapes(body: dict[str, Any]) -> None:
    with pytest.raises(AdapterError) as caught:
        await _complete(CASES["openai"], FakeEgress([_response(200, body)]))
    assert caught.value.category is ErrorCategory.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "body",
    [
        {"content": "text"},
        {"content": [{"type": "text", "text": 5}]},
        {"content": ["x"]},
    ],
)
async def test_anthropic_malformed_shapes(body: dict[str, Any]) -> None:
    with pytest.raises(AdapterError) as caught:
        await _complete(CASES["anthropic"], FakeEgress([_response(200, body)]))
    assert caught.value.category is ErrorCategory.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    ("error", "category", "possibly_accepted"),
    [
        (EgressDestinationError("non_public_address"), ErrorCategory.ENDPOINT_SECURITY, False),
        (EgressRedirectError(302), ErrorCategory.ENDPOINT_SECURITY, True),
        (EgressConnectError(), ErrorCategory.TRANSIENT_PRE_ACCEPTANCE, False),
        (
            EgressTimeoutError(
                "connect_timeout", phase="connect", request_may_have_been_sent=False
            ),
            ErrorCategory.TRANSIENT_PRE_ACCEPTANCE,
            False,
        ),
        (
            EgressTimeoutError("read_timeout", phase="read", request_may_have_been_sent=True),
            ErrorCategory.TIMEOUT,
            True,
        ),
        (EgressResponseTooLargeError(), ErrorCategory.RESPONSE_TOO_LARGE, True),
    ],
)
async def test_egress_failures_are_normalized(
    case: Case, error: EgressError, category: ErrorCategory, possibly_accepted: bool
) -> None:
    with pytest.raises(AdapterError) as caught:
        await _complete(case, FakeEgress([error]))
    assert caught.value.category is category
    assert caught.value.possibly_accepted is possibly_accepted


# --- capability checks before sending ---------------------------------------------


@pytest.mark.parametrize(
    ("request_kwargs", "missing"),
    [
        ({"temperature": 0.5}, Capability.TEMPERATURE),
        ({"stop": ("X",)}, Capability.STOP_SEQUENCES),
        ({"system": "s"}, Capability.SYSTEM_INSTRUCTIONS),
    ],
)
async def test_unsupported_capability_is_refused_before_sending(
    case: Case, request_kwargs: dict[str, Any], missing: Capability
) -> None:
    egress = FakeEgress([_response(200, case.ok_body)])
    with pytest.raises(AdapterError) as caught:
        await _complete(case, egress, _request(**request_kwargs), _target(case, ALL - {missing}))
    assert caught.value.category is ErrorCategory.UNSUPPORTED_CAPABILITY
    assert caught.value.possibly_accepted is False
    assert egress.posts == []


async def test_invalid_requests_are_refused_before_sending(case: Case) -> None:
    egress = FakeEgress([_response(200, case.ok_body)])
    for request in (_request(max_output_tokens=0), _request(messages=())):
        with pytest.raises(AdapterError) as caught:
            await _complete(case, egress, request)
        assert caught.value.category is ErrorCategory.INVALID_REQUEST
    assert egress.posts == []


# --- cancellation, credentials, content hygiene ------------------------------------


async def test_cancellation_propagates(case: Case) -> None:
    egress = FakeEgress(block=True)
    task = asyncio.create_task(_complete(case, egress))
    while not egress.posts:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_credentials_and_content_never_leak(
    case: Case, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    credential = OpaqueCredential(CANARY)
    assert CANARY not in repr(credential) and CANARY not in str(credential)
    with pytest.raises(TypeError):
        pickle.dumps(credential)
    result = await _complete(case, FakeEgress([_response(200, case.ok_body)]))
    assert "hello" not in repr(result)
    assert PROMPT not in repr(_request())
    with pytest.raises(AdapterError) as caught:
        await _complete(case, FakeEgress([_response(500, {"echo": CANARY})]))
    rendered = str(caught.value) + repr(caught.value) + caplog.text
    assert CANARY not in rendered and PROMPT not in rendered


def test_empty_credentials_are_refused() -> None:
    with pytest.raises(ValueError):
        OpaqueCredential("")


# --- end to end through the strict egress client ------------------------------------


def _strict(resolver_answer: str, handler: Any, max_bytes: int = 65536) -> StrictEgressClient:
    return StrictEgressClient(
        StrictEgressPolicy(
            connect_timeout_seconds=5, read_timeout_seconds=5, max_response_bytes=max_bytes
        ),
        resolver=StaticResolver([[resolver_answer]]),
        transport_factory=mock_transport_factory(handler),
    )


async def test_adapter_through_the_strict_egress_client() -> None:
    seen: list[httpx.Request] = []

    def provider(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=OPENAI_OK, headers={"x-request-id": "req-e2e"})

    result = await OpenAICompatibleAdapter().complete(
        _request(),
        target=ResolvedTarget("https://api.test/v1", "model-x", ALL),
        credential=OpaqueCredential(CANARY),
        egress=_strict(PUBLIC_V4, provider),
        deadline=Deadline.after(5),
    )
    assert result.text == "hello" and result.provider_request_id == "req-e2e"
    assert seen[0].url.host == PUBLIC_V4
    assert seen[0].headers["host"] == "api.test"
    assert seen[0].headers["authorization"] == f"Bearer {CANARY}"


async def test_adapter_through_the_strict_egress_client_refuses_private_targets() -> None:
    sent: list[httpx.Request] = []

    def provider(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200)

    with pytest.raises(AdapterError) as caught:
        await AnthropicMessagesAdapter().complete(
            _request(),
            target=ResolvedTarget("https://internal.test", "m", ALL),
            credential=OpaqueCredential(CANARY),
            egress=_strict("127.0.0.1", provider),
            deadline=Deadline.after(5),
        )
    assert caught.value.category is ErrorCategory.ENDPOINT_SECURITY
    assert sent == []


# --- fake provider ---------------------------------------------------------------------


async def test_fake_adapter_is_deterministic_and_scriptable() -> None:
    target = ResolvedTarget("https://unused.test", "fake-model", ALL)
    scripted_error = AdapterError(ErrorCategory.RATE_LIMITED, possibly_accepted=False)
    fake = FakeAdapter([scripted_error])
    egress = FakeEgress()

    async def call() -> AdapterResult:
        return await fake.complete(
            _request(),
            target=target,
            credential=OpaqueCredential(CANARY),
            egress=egress,
            deadline=Deadline.after(5),
        )

    with pytest.raises(AdapterError):
        await call()
    result = await call()
    assert result.text == PROMPT and result.model == "fake-model"
    assert len(fake.calls) == 2 and egress.posts == []
    assert CANARY not in repr(fake.calls)


async def test_fake_adapter_checks_capabilities_like_the_real_ones() -> None:
    text_only = frozenset({Capability.TEXT_INPUT, Capability.TEXT_OUTPUT})
    with pytest.raises(AdapterError) as caught:
        await FakeAdapter().complete(
            _request(temperature=1.0),
            target=ResolvedTarget("https://unused.test", "m", text_only),
            credential=OpaqueCredential(CANARY),
            egress=FakeEgress(),
            deadline=Deadline.after(5),
        )
    assert caught.value.category is ErrorCategory.UNSUPPORTED_CAPABILITY
