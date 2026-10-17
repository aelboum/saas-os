"""Normalized consumer errors of governed inference (AI-INFERENCE-CONTRACTS
section 4). Every error carries its category, the request id, the attempt id
and provider request id when there was an attempt, and `retry_after` when a
provider asked for one. Messages never contain content, credentials or
provider error bodies.
"""

from __future__ import annotations

import uuid


class InferenceError(Exception):
    category: str = "internal"

    def __init__(
        self,
        reason: str | None = None,
        *,
        request_id: uuid.UUID | None = None,
        attempt_id: uuid.UUID | None = None,
        provider_request_id: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        self.reason = reason
        self.request_id = request_id
        self.attempt_id = attempt_id
        self.provider_request_id = provider_request_id
        self.retry_after = retry_after
        detail = f": {reason}" if reason else ""
        super().__init__(f"inference {self.category}{detail}")


class InferenceNotAuthorizedError(InferenceError):
    category = "caller_not_authorized"


class InferencePolicyDeniedError(InferenceError):
    category = "policy_denied"


class InferenceInvalidRequestError(InferenceError):
    category = "invalid_request"


class InferenceUnsupportedCapabilityError(InferenceError):
    category = "unsupported_capability"


class InferenceEntitlementDeniedError(InferenceError):
    category = "entitlement_denied"


class InferenceCapacityExhaustedError(InferenceError):
    category = "capacity_exhausted"


class InferenceQuotaExceededError(InferenceError):
    category = "quota_exceeded"


class InferenceRateLimitedError(InferenceError):
    category = "rate_limited"


class InferenceProviderUnavailableError(InferenceError):
    category = "provider_overloaded"


class InferenceProviderAuthError(InferenceError):
    category = "provider_auth"


class InferenceConnectionError(InferenceError):
    category = "transient_pre_acceptance"


class InferenceOutcomeUnknownError(InferenceError):
    category = "possibly_accepted"


class InferenceTimeoutError(InferenceError):
    category = "timeout"


class InferenceCancelledError(InferenceError):
    category = "cancelled"


class InferenceEndpointSecurityError(InferenceError):
    category = "endpoint_security"


class InferenceResponseLimitError(InferenceError):
    category = "response_too_large"


class InferenceStreamInterruptedError(InferenceError):
    category = "stream_interrupted"


class InferenceInternalError(InferenceError):
    category = "internal"


class UseCaseRegistrationError(ValueError):
    """A use case is malformed, or a different definition already holds
    its name."""
