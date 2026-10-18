"""Adapter for the Gemini API `generateContent` method (AI-G; ADR-0054 D3)
-- `POST {base_url}/models/{model}:generateContent`, authenticated with the
`x-goog-api-key` header.

Mapping: the system text becomes `systemInstruction`; turns become
`contents` with roles `user` and `model`; `maxOutputTokens`, `temperature`
and `stopSequences` go in `generationConfig`, each only when requested and
declared. Only text parts are read from the answer; any other part (a
function call, inline data) is refused as malformed, because no capability
for it exists. A blocked prompt (`promptFeedback.blockReason`, no candidate)
or a safety stop is `content_filter`. Usage comes from `usageMetadata`
(`promptTokenCount`, `candidatesTokenCount`, `cachedContentTokenCount`); the
provider request id is the `x-goog-request-id` header when present, else the
body's `responseId`.

Errors: 401/403 provider auth; 429 rate limited (`Retry-After` honoured when
numeric); 503 (`UNAVAILABLE`, the documented overload status) is declared
*not processed*; any other 5xx may have been processed. Vertex AI (OAuth,
regional endpoints) is a different protocol and is not served here.
Non-streaming only.
"""

from __future__ import annotations

import re
from typing import ClassVar

from saas_os.control_plane.inference.adapters._common import (
    error_for_status,
    join_url,
    malformed,
    optional_count,
    parse_json_object,
    request_id,
    require_capabilities,
    send_json,
)
from saas_os.control_plane.inference.adapters.base import (
    AdapterRequest,
    AdapterResult,
    AdapterUsage,
    Capability,
    EgressClient,
    FinishReason,
    OpaqueCredential,
    ResolvedTarget,
)
from saas_os.control_plane.inference.adapters.errors import AdapterError, ErrorCategory
from saas_os.infra.egress import Deadline, EgressResponse

# A model id becomes a path segment: no slash, no query, no traversal.
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_REQUEST_ID_HEADER = "x-goog-request-id"
_MAX_REQUEST_ID = 255
_NOT_PROCESSED = frozenset({503})
_FINISH_REASONS: dict[str, FinishReason] = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "RECITATION": "content_filter",
    "BLOCKLIST": "content_filter",
    "PROHIBITED_CONTENT": "content_filter",
    "SPII": "content_filter",
    "IMAGE_SAFETY": "content_filter",
}


def _malformed(response: EgressResponse, provider_request_id: str | None) -> AdapterError:
    error = malformed(response, _REQUEST_ID_HEADER)
    error.provider_request_id = provider_request_id
    return error


class GeminiGenerateContentAdapter:
    protocol: ClassVar[str] = "gemini_generate_content"
    protocol_capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.TEXT_INPUT,
            Capability.TEXT_OUTPUT,
            Capability.SYSTEM_INSTRUCTIONS,
            Capability.TEMPERATURE,
            Capability.STOP_SEQUENCES,
        }
    )

    async def complete(
        self,
        request: AdapterRequest,
        *,
        target: ResolvedTarget,
        credential: OpaqueCredential,
        egress: EgressClient,
        deadline: Deadline,
    ) -> AdapterResult:
        require_capabilities(request, target, self.protocol_capabilities)
        if not _MODEL_ID.fullmatch(target.model_id) or ".." in target.model_id:
            raise AdapterError(ErrorCategory.INVALID_REQUEST, possibly_accepted=False)
        generation: dict[str, object] = {"maxOutputTokens": request.max_output_tokens}
        if request.temperature is not None:
            generation["temperature"] = request.temperature
        if request.stop:
            generation["stopSequences"] = list(request.stop)
        payload: dict[str, object] = {
            "contents": [
                {"role": "model" if m.role == "assistant" else "user", "parts": [{"text": m.text}]}
                for m in request.messages
            ],
            "generationConfig": generation,
        }
        if request.system is not None:
            payload["systemInstruction"] = {"parts": [{"text": request.system}]}

        response = await send_json(
            egress,
            join_url(target.base_url, f"models/{target.model_id}:generateContent"),
            headers={"x-goog-api-key": credential.reveal()},
            payload=payload,
            deadline=deadline,
        )
        if not 200 <= response.status_code < 300:
            raise error_for_status(
                response,
                request_id_header=_REQUEST_ID_HEADER,
                not_processed_statuses=_NOT_PROCESSED,
            )
        body = parse_json_object(response, request_id_header=_REQUEST_ID_HEADER)
        raw_id = body.get("responseId")
        provider_request_id = request_id(response, _REQUEST_ID_HEADER) or (
            raw_id if isinstance(raw_id, str) and 0 < len(raw_id) <= _MAX_REQUEST_ID else None
        )
        usage = body.get("usageMetadata")
        # Thinking tokens (`thoughtsTokenCount`) are generated and billed as
        # output but are not part of `candidatesTokenCount`; leaving them out
        # would under-count usage and the quota.
        output_counts = [
            count
            for count in (
                optional_count(usage, "candidatesTokenCount"),
                optional_count(usage, "thoughtsTokenCount"),
            )
            if count is not None
        ]
        reported = AdapterUsage(
            input_tokens=optional_count(usage, "promptTokenCount"),
            output_tokens=sum(output_counts) if output_counts else None,
            cached_input_tokens=optional_count(usage, "cachedContentTokenCount"),
        )
        model = body.get("modelVersion")
        model_name = model if isinstance(model, str) else None

        candidates = body.get("candidates")
        if candidates is None or candidates == []:
            feedback = body.get("promptFeedback")
            if isinstance(feedback, dict) and isinstance(feedback.get("blockReason"), str):
                return AdapterResult(
                    text="",
                    finish_reason="content_filter",
                    usage=reported,
                    model=model_name,
                    provider_request_id=provider_request_id,
                )
            raise _malformed(response, provider_request_id)
        if not isinstance(candidates, list) or not isinstance(candidates[0], dict):
            raise _malformed(response, provider_request_id)
        first = candidates[0]
        content = first.get("content")
        texts: list[str] = []
        if content is not None:
            if not isinstance(content, dict):
                raise _malformed(response, provider_request_id)
            parts = content.get("parts", [])
            if not isinstance(parts, list):
                raise _malformed(response, provider_request_id)
            for part in parts:
                if not isinstance(part, dict) or not isinstance(part.get("text"), str):
                    raise _malformed(response, provider_request_id)
                if part.get("thought") is True:
                    continue  # model reasoning summaries are not output
                texts.append(part["text"])
        raw_finish = first.get("finishReason")
        finish: FinishReason = (
            _FINISH_REASONS.get(raw_finish, "other") if isinstance(raw_finish, str) else "other"
        )
        return AdapterResult(
            text="".join(texts),
            finish_reason=finish,
            usage=reported,
            model=model_name,
            provider_request_id=provider_request_id,
        )
