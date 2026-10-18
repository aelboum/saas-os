"""Real-provider conformance of one AI protocol adapter (ADR-0054 section
12c, condition 8; `docs/AI-PROVIDER-QUALIFICATION.md`).

Everything else in this directory uses fake providers and fake servers; this
file is the only one that talks to a real provider. It runs the adapter of
one configured protocol through the real `StrictEgressClient` (HTTPS,
validated and pinned addresses, no redirects, no environment proxies) and
pins what the fakes cannot prove: the provider's real response shape, its
usage report, its finish reasons and its error statuses, as SaaS OS maps
them.

**Opt-in and bounded.** Marked `integration`, excluded from
`scripts/check-integration.sh` like the other live-credential tests (a skip
there would be permanent noise), and skipped unless every setting below is
present:

    AI_LIVE_PROTOCOL        openai_chat_completions | anthropic_messages |
                            gemini_generate_content
    AI_LIVE_BASE_URL        e.g. https://api.openai.com/v1
    AI_LIVE_MODEL           the provider's model id
    AI_LIVE_PROVIDER_KEY    the credential, read through the secrets provider
                            (environment or `.env`), never printed
    AI_LIVE_NON_PRODUCTION  must be exactly `yes`: the key belongs to a
                            non-production account or project with a spending
                            limit, and no customer data is involved

Every request sends the fixed prompt below (no customer data) and asks for at
most `_MAX_OUTPUT_TOKENS` output tokens; the whole file sends at most
`_REQUEST_BUDGET` requests, of which the two refusal cases (invalid
credential, unknown model) are normally not billed. Rate limiting is not
provoked on purpose: it would need a burst of billed requests; its mapping is
covered by the adapter unit tests.

    AI_LIVE_PROTOCOL=openai_chat_completions AI_LIVE_BASE_URL=... \\
        AI_LIVE_MODEL=... AI_LIVE_PROVIDER_KEY=... AI_LIVE_NON_PRODUCTION=yes \\
        AI_LIVE_REPORT=ai-live-report.jsonl \\
        pytest -m integration tests/control_plane/inference/test_ai_provider_live_integration.py

`AI_LIVE_REPORT`, if set, receives one JSON line per case with sanitized
fields only (protocol, model, case, outcome category, finish reason, token
counts, whether a provider request id was returned): never the credential,
the prompt, the output or a provider error body.
"""

from __future__ import annotations

import dataclasses
import json
import os
import traceback
from collections.abc import Iterator
from datetime import UTC, datetime
from urllib.parse import urlsplit

import pytest

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
    ResolvedTarget,
)
from saas_os.control_plane.inference.egress_config import ai_egress_settings
from saas_os.infra.egress import Deadline, StrictEgressClient
from saas_os.infra.secrets import get_secrets_provider

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_PROMPT = "Reply with the single word: ready"
_MAX_OUTPUT_TOKENS = 16
_REQUEST_BUDGET = 6
_ADAPTERS = {
    a.protocol: a
    for a in (OpenAICompatibleAdapter(), AnthropicMessagesAdapter(), GeminiGenerateContentAdapter())
}
_sent: list[str] = []


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclasses.dataclass(frozen=True)
class Live:
    protocol: str
    target: ResolvedTarget
    credential: OpaqueCredential
    key: str = dataclasses.field(repr=False)


@pytest.fixture(scope="module")
def live() -> Iterator[Live]:
    protocol = os.environ.get("AI_LIVE_PROTOCOL", "")
    base_url = os.environ.get("AI_LIVE_BASE_URL", "")
    model = os.environ.get("AI_LIVE_MODEL", "")
    if not (protocol and base_url and model):
        pytest.skip("AI_LIVE_PROTOCOL, AI_LIVE_BASE_URL and AI_LIVE_MODEL are not configured")
    if os.environ.get("AI_LIVE_NON_PRODUCTION") != "yes":
        pytest.skip("AI_LIVE_NON_PRODUCTION is not 'yes': refusing to call a provider")
    if protocol not in _ADAPTERS:
        pytest.fail(f"AI_LIVE_PROTOCOL must be one of {sorted(_ADAPTERS)}")
    key = get_secrets_provider().get("AI_LIVE_PROVIDER_KEY")
    if not key:
        pytest.skip("AI_LIVE_PROVIDER_KEY is not configured")
    yield Live(
        protocol=protocol,
        target=ResolvedTarget(
            base_url=base_url.rstrip("/"), model_id=model, capabilities=frozenset(Capability)
        ),
        credential=OpaqueCredential(key),
        key=key,
    )


def _egress(live: Live, **policy: object) -> StrictEgressClient:
    settings = ai_egress_settings()
    port = urlsplit(live.target.base_url).port or 443
    return StrictEgressClient(
        dataclasses.replace(settings.policy, allowed_ports=frozenset({port}), **policy)  # type: ignore[arg-type]
    )


async def _call(
    live: Live,
    case: str,
    *,
    target: ResolvedTarget | None = None,
    credential: OpaqueCredential | None = None,
    max_output_tokens: int = _MAX_OUTPUT_TOKENS,
    deadline_seconds: float | None = None,
    **policy: object,
):  # type: ignore[no-untyped-def]
    assert len(_sent) < _REQUEST_BUDGET, "request budget exhausted"
    _sent.append(case)
    total = deadline_seconds or ai_egress_settings().total_deadline_seconds
    return await _ADAPTERS[live.protocol].complete(
        AdapterRequest(
            messages=(AdapterMessage("user", _PROMPT),), max_output_tokens=max_output_tokens
        ),
        target=target or live.target,
        credential=credential or live.credential,
        egress=_egress(live, **policy),
        deadline=Deadline.after(total),
    )


def _report(live: Live, case: str, **fields: object) -> None:
    path = os.environ.get("AI_LIVE_REPORT")
    if not path:
        return
    line = {
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "protocol": live.protocol,
        "model": live.target.model_id,
        "case": case,
        **fields,
    }
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")


def _assert_no_credential(live: Live, error: BaseException) -> None:
    rendered = "".join(traceback.format_exception(error)) + repr(error) + str(error)
    assert live.key not in rendered


async def test_a_minimal_request_succeeds_with_reported_usage(live: Live) -> None:
    result = await _call(live, "success")
    _report(
        live,
        "success",
        outcome="succeeded",
        finish_reason=result.finish_reason,
        input_tokens=result.usage.input_tokens,
        output_tokens=result.usage.output_tokens,
        provider_request_id=result.provider_request_id is not None,
    )
    assert result.text.strip()
    assert result.finish_reason in ("stop", "length")
    # The provider reports usage: provenance `provider_reported` downstream.
    assert isinstance(result.usage.input_tokens, int) and result.usage.input_tokens > 0
    assert isinstance(result.usage.output_tokens, int) and result.usage.output_tokens > 0
    assert result.provider_request_id


async def test_the_output_bound_is_sent_and_honoured(live: Live) -> None:
    result = await _call(live, "output_bound", max_output_tokens=1)
    _report(
        live,
        "output_bound",
        outcome="succeeded",
        finish_reason=result.finish_reason,
        output_tokens=result.usage.output_tokens,
    )
    assert result.finish_reason == "length"


async def test_an_invalid_credential_is_provider_auth(live: Live) -> None:
    with pytest.raises(AdapterError) as caught:
        await _call(
            live, "invalid_credential", credential=OpaqueCredential("invalid-conformance-key")
        )
    _report(live, "invalid_credential", outcome=caught.value.category.value)
    assert caught.value.category is ErrorCategory.PROVIDER_AUTH
    assert caught.value.possibly_accepted is False


async def test_an_unknown_model_is_an_invalid_request_without_the_credential(live: Live) -> None:
    unknown = dataclasses.replace(live.target, model_id="saas-os-conformance-no-such-model")
    with pytest.raises(AdapterError) as caught:
        await _call(live, "unknown_model", target=unknown)
    _report(live, "unknown_model", outcome=caught.value.category.value)
    assert caught.value.category is ErrorCategory.INVALID_REQUEST
    _assert_no_credential(live, caught.value)


async def test_an_oversized_response_is_refused(live: Live) -> None:
    with pytest.raises(AdapterError) as caught:
        await _call(live, "response_limit", max_response_bytes=64)
    _report(live, "response_limit", outcome=caught.value.category.value)
    assert caught.value.category is ErrorCategory.RESPONSE_TOO_LARGE


async def test_an_expired_deadline_is_a_timeout(live: Live) -> None:
    with pytest.raises(AdapterError) as caught:
        await _call(live, "deadline", deadline_seconds=0.05)
    _report(
        live,
        "deadline",
        outcome=caught.value.category.value,
        possibly_accepted=caught.value.possibly_accepted,
    )
    # Before or after the request was written, depending on where 50 ms ends.
    assert caught.value.category in (ErrorCategory.TIMEOUT, ErrorCategory.TRANSIENT_PRE_ACCEPTANCE)
    _assert_no_credential(live, caught.value)
