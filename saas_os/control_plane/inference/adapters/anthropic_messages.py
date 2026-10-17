"""Adapter for the Anthropic Messages API (`POST {base_url}/v1/messages`).

System instructions are a separate field, not a message; `max_tokens` is
required. HTTP 529 ("overloaded") is declared "not processed". Non-streaming
only (AI-B).
"""

from __future__ import annotations

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
from saas_os.infra.egress import Deadline

ANTHROPIC_VERSION = "2023-06-01"
_REQUEST_ID_HEADER = "request-id"
_NOT_PROCESSED = frozenset({529})
_FINISH_REASONS: dict[str, FinishReason] = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "tool_use": "tool_calls",
    "refusal": "content_filter",
}


class AnthropicMessagesAdapter:
    protocol: ClassVar[str] = "anthropic_messages"
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
        payload: dict[str, object] = {
            "model": target.model_id,
            "max_tokens": request.max_output_tokens,
            "messages": [{"role": m.role, "content": m.text} for m in request.messages],
        }
        if request.system is not None:
            payload["system"] = request.system
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.stop:
            payload["stop_sequences"] = list(request.stop)

        response = await send_json(
            egress,
            join_url(target.base_url, "v1/messages"),
            headers={"x-api-key": credential.reveal(), "anthropic-version": ANTHROPIC_VERSION},
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
        content = body.get("content")
        if not isinstance(content, list):
            raise malformed(response, _REQUEST_ID_HEADER)
        pieces: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                raise malformed(response, _REQUEST_ID_HEADER)
            if block.get("type") == "text":
                text = block.get("text")
                if not isinstance(text, str):
                    raise malformed(response, _REQUEST_ID_HEADER)
                pieces.append(text)
        raw_stop = body.get("stop_reason")
        finish: FinishReason = (
            _FINISH_REASONS.get(raw_stop, "other") if isinstance(raw_stop, str) else "other"
        )
        usage = body.get("usage")
        model = body.get("model")
        return AdapterResult(
            text="".join(pieces),
            finish_reason=finish,
            usage=AdapterUsage(
                input_tokens=optional_count(usage, "input_tokens"),
                output_tokens=optional_count(usage, "output_tokens"),
                cached_input_tokens=optional_count(usage, "cache_read_input_tokens"),
                cache_write_tokens=optional_count(usage, "cache_creation_input_tokens"),
            ),
            model=model if isinstance(model, str) else None,
            provider_request_id=request_id(response, _REQUEST_ID_HEADER),
        )
