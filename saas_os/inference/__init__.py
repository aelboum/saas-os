"""`saas_os.inference` -- the supported public interface of governed AI
inference for products (ADR-0054 section 3, decision Q11; Phase AI-D).

A thin facade over the internal `saas_os.control_plane.inference`: it
re-exports the consumer types, the use-case registration and the two entry
points, and adds nothing -- no parameter, default or path that skips any
step of governed inference (authority, validation and classification,
resolution and eligibility, admission, pre-send evidence, settlement).

Who may import it (import-linter, `tests/architecture/test_ai_inference_boundaries.py`):
products only. SaaS OS Core, Infrastructure and the HTTP layer never do, so
AI inference is invoked by products and never from inside SaaS OS (Q11
candidate C1). The internal package never imports this one.

    from saas_os.inference import (
        ContentPart, InferenceRequest, Message, UseCase, register_use_case, run_inference,
    )

    register_use_case(UseCase(name="support.summarize", max_classification="tenant_data"))
    result = await run_inference(
        caller,  # UserCaller or ServiceAccountCaller of the tenant
        tenant_id=tenant_id,
        request=InferenceRequest(
            alias="default-chat",
            use_case="support.summarize",
            messages=(Message("user", (ContentPart("text", "tenant_data", text=ticket),)),),
            max_output_tokens=512,
        ),
    )

Registration authorizes nothing: the tenant's AI policy must grant the use
case, the classification and a destination, and installation policy must
allow the destination for the classification.
"""

from __future__ import annotations

import uuid

from saas_os.control_plane.inference import service as _service
from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.errors import (
    InferenceCancelledError,
    InferenceCapacityExhaustedError,
    InferenceConnectionError,
    InferenceEndpointSecurityError,
    InferenceEntitlementDeniedError,
    InferenceError,
    InferenceInternalError,
    InferenceInvalidRequestError,
    InferenceNotAuthorizedError,
    InferenceOutcomeUnknownError,
    InferencePolicyDeniedError,
    InferenceProviderAuthError,
    InferenceProviderUnavailableError,
    InferenceQuotaExceededError,
    InferenceRateLimitedError,
    InferenceResponseLimitError,
    InferenceStreamInterruptedError,
    InferenceTimeoutError,
    InferenceUnsupportedCapabilityError,
    UseCaseRegistrationError,
)
from saas_os.control_plane.inference.permissions import AI_PERMISSIONS, register_ai_permissions
from saas_os.control_plane.inference.types import (
    ContentPart,
    InferenceRequest,
    InferenceResult,
    Message,
    UsageReport,
)
from saas_os.control_plane.inference.use_cases import UseCase, register_use_case


async def run_inference(
    caller: object, *, tenant_id: uuid.UUID, request: InferenceRequest
) -> InferenceResult:
    """Governed, non-streaming inference (AI-INFERENCE-CONTRACTS section 5)."""
    return await _service.run_inference(caller, tenant_id=tenant_id, request=request)


async def stream_inference(
    caller: object, *, tenant_id: uuid.UUID, request: InferenceRequest
) -> None:
    """Not enabled (contracts section 6.6): raises
    `InferenceUnsupportedCapabilityError` for every request."""
    await _service.stream_inference(caller, tenant_id=tenant_id, request=request)


__all__ = [
    "AI_PERMISSIONS",
    "Capability",
    "ContentPart",
    "InferenceCancelledError",
    "InferenceCapacityExhaustedError",
    "InferenceConnectionError",
    "InferenceEndpointSecurityError",
    "InferenceEntitlementDeniedError",
    "InferenceError",
    "InferenceInternalError",
    "InferenceInvalidRequestError",
    "InferenceNotAuthorizedError",
    "InferenceOutcomeUnknownError",
    "InferencePolicyDeniedError",
    "InferenceProviderAuthError",
    "InferenceProviderUnavailableError",
    "InferenceQuotaExceededError",
    "InferenceRateLimitedError",
    "InferenceRequest",
    "InferenceResponseLimitError",
    "InferenceResult",
    "InferenceStreamInterruptedError",
    "InferenceTimeoutError",
    "InferenceUnsupportedCapabilityError",
    "Message",
    "UsageReport",
    "UseCase",
    "UseCaseRegistrationError",
    "register_ai_permissions",
    "register_use_case",
    "run_inference",
    "stream_inference",
]
