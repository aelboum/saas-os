"""Governed AI inference, as a product uses it (ADR-0054 Phase AI-H).

Ordinary consumer code against the public interface `saas_os.inference`
only -- never `saas_os.control_plane.inference` (import-linter forbids a
product from importing it directly). The product:

1. registers the use cases it needs, once, at start-up (Q5: registration
   authorizes nothing);
2. calls `run_inference` with the caller from its own request context, the
   tenant id, an alias configured by the platform operator, and content
   parts that each carry their classification.

Everything else is SaaS OS's decision at call time: the caller's
`ai.inference:run` permission, the tenant's AI policy and grants, the
installation's destination policy, the `ai.inference` entitlement,
concurrency, pre-send evidence and usage.
"""

from __future__ import annotations

import uuid

from saas_os.inference import (
    ContentPart,
    InferenceRequest,
    InferenceResult,
    Message,
    UseCase,
    register_use_case,
    run_inference,
)

SUMMARIZE_NOTE = UseCase(
    name="reference.summarize_note",
    max_classification="tenant_data",
    part_kinds=frozenset({"text"}),
    max_parts=4,
    max_input_bytes=20_000,
)


def register_inference_use_cases() -> None:
    register_use_case(SUMMARIZE_NOTE)


async def summarize_note(
    caller: object, *, tenant_id: uuid.UUID, alias: str, note: str
) -> InferenceResult:
    """Summarize one tenant note. The note is tenant data; the instruction
    is not."""
    return await run_inference(
        caller,
        tenant_id=tenant_id,
        request=InferenceRequest(
            alias=alias,
            use_case=SUMMARIZE_NOTE.name,
            messages=(
                Message("system", (ContentPart("text", "none", text="Summarize in one line."),)),
                Message("user", (ContentPart("text", "tenant_data", text=note),)),
            ),
            max_output_tokens=200,
            client_request_id=f"note-summary-{tenant_id}",
        ),
    )
