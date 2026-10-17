"""Consumer request and result types of governed inference (ADR-0054 Phase
AI-D; AI-INFERENCE-CONTRACTS sections 3, 5 and 7). Exported to products only
through the public interface `saas_os.inference`.

Implemented subset, every omission refused rather than dropped:
- content parts of kind `text` only (`image` raises
  `InferenceUnsupportedCapabilityError`; no capability declares it yet);
- roles `system`, `user`, `assistant` (`tool` and `tools` are refused: SaaS OS
  never executes tools, and no adapter carries tool calls yet);
- `response_format="text"` only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Literal

from saas_os.control_plane.inference.capabilities import Capability

Classification = Literal["none", "tenant_data", "sensitive"]
CLASSIFICATIONS: tuple[str, ...] = ("none", "tenant_data", "sensitive")
CLASSIFICATION_RANK: dict[str, int] = {name: rank for rank, name in enumerate(CLASSIFICATIONS)}

Provenance = Literal["provider_reported", "estimated", "unknown"]
FinishReason = Literal["stop", "length", "tool_calls", "content_filter", "other"]


@dataclass(frozen=True)
class ContentPart:
    """One piece of content and its data classification. The
    classification is required: there is no default (ADR-0055 section 2)."""

    kind: Literal["text", "image"]
    classification: Classification
    text: str | None = field(default=None, repr=False)
    image: object | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Message:
    role: Literal["system", "user", "assistant", "tool"]
    parts: tuple[ContentPart, ...]
    tool_call_id: str | None = None


@dataclass(frozen=True)
class InferenceRequest:
    alias: str
    use_case: str
    messages: tuple[Message, ...]
    max_output_tokens: int
    required_capabilities: frozenset[Capability] = frozenset()
    temperature: float | None = None
    stop: tuple[str, ...] = ()
    tools: tuple[object, ...] = ()
    response_format: Literal["text", "json"] = "text"
    deadline_seconds: float | None = None
    client_request_id: str | None = None


@dataclass(frozen=True)
class UsageReport:
    input_tokens: int | None
    output_tokens: int | None
    cached_input_tokens: int | None
    cache_write_tokens: int | None
    provenance: Provenance
    estimated_cost: Decimal | None = None  # never a billed amount (AI-F)
    currency: str | None = None
    pricing_version: str | None = None


@dataclass(frozen=True)
class InferenceResult:
    request_id: uuid.UUID
    client_request_id: str | None
    alias: str
    provider_key: str
    model_id: str
    output: tuple[ContentPart, ...] = field(repr=False)
    tool_calls: tuple[object, ...]
    finish_reason: FinishReason
    usage: UsageReport
    attempts: int
    fell_back: bool
