"""Adapter for OpenAI-compatible Chat Completions (`POST {base_url}/chat/completions`).

Serves any endpoint that implements the protocol (OpenAI, OpenRouter, a LiteLLM
server, vLLM, Ollama's OpenAI-compatible endpoint, ...). Compatible is not
capable: the target's declared capabilities decide which parameters may be
sent. `max_tokens` is used (not `max_completion_tokens`) because it is the
field compatible servers accept most widely. Non-streaming only (AI-B).
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

_REQUEST_ID_HEADER = "x-request-id"
_FINISH_REASONS: dict[str, FinishReason] = {
    "stop": "stop",
    "length": "length",
    "tool_calls": "tool_calls",
    "function_call": "tool_calls",
    "content_filter": "content_filter",
}


class OpenAICompatibleAdapter:
    protocol: ClassVar[str] = "openai_chat_completions"
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
        messages: list[dict[str, str]] = []
        if request.system is not None:
            messages.append({"role": "system", "content": request.system})
        messages.extend({"role": m.role, "content": m.text} for m in request.messages)
        payload: dict[str, object] = {
            "model": target.model_id,
            "messages": messages,
            "max_tokens": request.max_output_tokens,
        }
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.stop:
            payload["stop"] = list(request.stop)

        response = await send_json(
            egress,
            join_url(target.base_url, "chat/completions"),
            headers={"Authorization": f"Bearer {credential.reveal()}"},
            payload=payload,
            deadline=deadline,
        )
        if not 200 <= response.status_code < 300:
            raise error_for_status(
                response, request_id_header=_REQUEST_ID_HEADER, not_processed_statuses=frozenset()
            )
        body = parse_json_object(response, request_id_header=_REQUEST_ID_HEADER)
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise malformed(response, _REQUEST_ID_HEADER)
        first = choices[0]
        message = first.get("message")
        if not isinstance(message, dict):
            raise malformed(response, _REQUEST_ID_HEADER)
        content = message.get("content")
        if content is None:
            text = ""
        elif isinstance(content, str):
            text = content
        else:
            raise malformed(response, _REQUEST_ID_HEADER)
        raw_finish = first.get("finish_reason")
        finish: FinishReason = (
            _FINISH_REASONS.get(raw_finish, "other") if isinstance(raw_finish, str) else "other"
        )
        usage = body.get("usage")
        details = usage.get("prompt_tokens_details") if isinstance(usage, dict) else None
        model = body.get("model")
        return AdapterResult(
            text=text,
            finish_reason=finish,
            usage=AdapterUsage(
                input_tokens=optional_count(usage, "prompt_tokens"),
                output_tokens=optional_count(usage, "completion_tokens"),
                cached_input_tokens=optional_count(details, "cached_tokens"),
            ),
            model=model if isinstance(model, str) else None,
            provider_request_id=request_id(response, _REQUEST_ID_HEADER),
        )
