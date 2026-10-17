"""The Gemini `generateContent` adapter (AI-G) -- protocol-specific cases.
The generic conformance cases (errors, capability checks before sending,
cancellation, credential and content hygiene, egress failures) run for this
adapter in `test_provider_adapters_unit.py`.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from egress_support import PUBLIC_V4, StaticResolver, mock_transport_factory
from saas_os.control_plane.inference.adapters import (
    AdapterError,
    AdapterMessage,
    AdapterRequest,
    Capability,
    ErrorCategory,
    GeminiGenerateContentAdapter,
    OpaqueCredential,
    ResolvedTarget,
)
from saas_os.infra.egress import Deadline, EgressResponse, StrictEgressClient, StrictEgressPolicy

pytestmark = pytest.mark.anyio

CANARY = "AIza-canary-0123456789"  # pragma: allowlist secret
ADAPTER = GeminiGenerateContentAdapter()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Egress:
    def __init__(self, status: int, body: object, headers: dict[str, str] | None = None) -> None:
        self.status, self.body, self.headers = status, body, headers or {}
        self.calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    async def post(self, url: str, *, headers, content: bytes, deadline) -> EgressResponse:  # type: ignore[no-untyped-def]
        del deadline
        self.calls.append((url, dict(headers), json.loads(content)))
        raw = self.body if isinstance(self.body, bytes) else json.dumps(self.body).encode()
        return EgressResponse(status_code=self.status, headers=self.headers, body=raw)


def _ok(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "candidates": [{"content": {"parts": [{"text": "answer"}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 2},
        "responseId": "resp-42",
        "modelVersion": "gemini-x-001",
    }
    body.update(overrides)
    return body


def _target(model_id: str = "gemini-x") -> ResolvedTarget:
    return ResolvedTarget(
        base_url="https://generativelanguage.googleapis.com/v1beta",
        model_id=model_id,
        capabilities=frozenset(Capability),
    )


async def _run(
    egress: object, request: AdapterRequest | None = None, target: ResolvedTarget | None = None
):
    return await ADAPTER.complete(
        request or AdapterRequest(messages=(AdapterMessage("user", "hi"),), max_output_tokens=32),
        target=target or _target(),
        credential=OpaqueCredential(CANARY),
        egress=egress,  # type: ignore[arg-type]
        deadline=Deadline.after(5),
    )


async def test_request_mapping() -> None:
    egress = _Egress(200, _ok())
    request = AdapterRequest(
        messages=(
            AdapterMessage("user", "q1"),
            AdapterMessage("assistant", "a1"),
            AdapterMessage("user", "q2"),
        ),
        max_output_tokens=100,
        system="be brief",
        temperature=0.3,
        stop=("END",),
    )
    await _run(egress, request)
    ((url, headers, payload),) = egress.calls
    assert url == "https://generativelanguage.googleapis.com/v1beta/models/gemini-x:generateContent"
    assert headers["x-goog-api-key"] == CANARY and "Authorization" not in headers
    assert payload == {
        "contents": [
            {"role": "user", "parts": [{"text": "q1"}]},
            {"role": "model", "parts": [{"text": "a1"}]},
            {"role": "user", "parts": [{"text": "q2"}]},
        ],
        "generationConfig": {"maxOutputTokens": 100, "temperature": 0.3, "stopSequences": ["END"]},
        "systemInstruction": {"parts": [{"text": "be brief"}]},
    }


async def test_response_id_from_the_body_when_no_header() -> None:
    result = await _run(_Egress(200, _ok()))
    assert result.text == "answer" and result.provider_request_id == "resp-42"
    assert result.model == "gemini-x-001"
    assert (result.usage.input_tokens, result.usage.output_tokens) == (5, 2)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("MAX_TOKENS", "length"),
        ("SAFETY", "content_filter"),
        ("RECITATION", "content_filter"),
        ("PROHIBITED_CONTENT", "content_filter"),
        ("OTHER", "other"),
        (None, "other"),
    ],
)
async def test_finish_reasons(raw: str | None, expected: str) -> None:
    body = _ok()
    body["candidates"][0]["finishReason"] = raw
    assert (await _run(_Egress(200, body))).finish_reason == expected


async def test_a_blocked_prompt_is_a_content_filter_with_no_output() -> None:
    body = {"promptFeedback": {"blockReason": "SAFETY"}, "usageMetadata": {"promptTokenCount": 3}}
    result = await _run(_Egress(200, body))
    assert (result.text, result.finish_reason) == ("", "content_filter")
    assert result.usage.input_tokens == 3


async def test_thought_parts_are_not_output() -> None:
    body = _ok()
    body["candidates"][0]["content"]["parts"] = [
        {"text": "thinking...", "thought": True},
        {"text": "final"},
    ]
    assert (await _run(_Egress(200, body))).text == "final"


@pytest.mark.parametrize(
    "candidates",
    [
        "not a list",
        [{"content": {"parts": [{"functionCall": {"name": "x"}}]}}],
        [{"content": {"parts": [{"inlineData": {"data": "AA=="}}]}}],
        [{"content": {"parts": "text"}}],
        [{"content": "text"}],
        ["text"],
    ],
)
async def test_non_text_or_malformed_answers_are_possibly_accepted_errors(
    candidates: object,
) -> None:
    with pytest.raises(AdapterError) as caught:
        await _run(_Egress(200, _ok(candidates=candidates)))
    assert caught.value.category is ErrorCategory.MALFORMED_RESPONSE
    assert caught.value.possibly_accepted is True
    assert caught.value.provider_request_id == "resp-42"


async def test_no_candidates_and_no_block_reason_is_malformed() -> None:
    with pytest.raises(AdapterError) as caught:
        await _run(_Egress(200, {"usageMetadata": {}}))
    assert caught.value.category is ErrorCategory.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "model_id", ["../files", "a/b", "m?alt=sse", "m#x", "", "m:generateContent", "m..x", "-m"]
)
async def test_an_unsafe_model_id_is_refused_before_sending(model_id: str) -> None:
    egress = _Egress(200, _ok())
    with pytest.raises(AdapterError) as caught:
        await _run(egress, target=_target(model_id))
    assert caught.value.category is ErrorCategory.INVALID_REQUEST
    assert egress.calls == []


async def test_503_is_declared_not_processed_and_other_5xx_are_not() -> None:
    with pytest.raises(AdapterError) as overloaded:
        await _run(_Egress(503, {"error": {"status": "UNAVAILABLE"}}))
    assert overloaded.value.category is ErrorCategory.PROVIDER_OVERLOADED
    assert overloaded.value.possibly_accepted is False
    with pytest.raises(AdapterError) as other:
        await _run(_Egress(504, {"error": {"status": "DEADLINE_EXCEEDED"}}))
    assert other.value.possibly_accepted is True


async def test_through_the_strict_egress_client() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=json.dumps(_ok()).encode())

    client = StrictEgressClient(
        StrictEgressPolicy(
            connect_timeout_seconds=5, read_timeout_seconds=5, max_response_bytes=10_000
        ),
        resolver=StaticResolver([[PUBLIC_V4]]),
        transport_factory=mock_transport_factory(handler),
    )
    result = await _run(client)
    assert result.text == "answer"
    (request,) = seen
    assert request.url.host == PUBLIC_V4  # pinned to the validated address
    assert request.headers["host"] == "generativelanguage.googleapis.com"
    assert request.url.path == "/v1beta/models/gemini-x:generateContent"
