"""Normalized adapter errors (contracts document section 4).

`category` is the normalized error category. `possibly_accepted` is True when
the provider may have accepted (and billed) the request, so a caller must not
retry or fall back. Messages carry the category, the HTTP status and the
provider request id only -- never a credential, a header, a prompt, a
completion or a provider error body.
"""

from __future__ import annotations

import enum

from saas_os.infra.egress import (
    EgressConnectError,
    EgressDestinationError,
    EgressError,
    EgressRedirectError,
    EgressResolutionError,
    EgressResponseTooLargeError,
    EgressTimeoutError,
    EgressTLSError,
)


class ErrorCategory(enum.StrEnum):
    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    PROVIDER_AUTH = "provider_auth"
    RATE_LIMITED = "rate_limited"
    # The provider account's own quota or credit is used up (OpenAI 429
    # `insufficient_quota`): not the SaaS OS token quota, and waiting does
    # not help, so it is never retried on the same destination.
    PROVIDER_QUOTA_EXHAUSTED = "provider_quota_exhausted"
    PROVIDER_OVERLOADED = "provider_overloaded"
    PROVIDER_ERROR = "provider_error"
    TRANSIENT_PRE_ACCEPTANCE = "transient_pre_acceptance"
    TIMEOUT = "timeout"
    ENDPOINT_SECURITY = "endpoint_security"
    RESPONSE_TOO_LARGE = "response_too_large"
    MALFORMED_RESPONSE = "malformed_response"


class AdapterError(Exception):
    def __init__(
        self,
        category: ErrorCategory,
        *,
        possibly_accepted: bool,
        status_code: int | None = None,
        provider_request_id: str | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        self.category = category
        self.possibly_accepted = possibly_accepted
        self.status_code = status_code
        self.provider_request_id = provider_request_id
        self.retry_after_seconds = retry_after_seconds
        detail = f" (HTTP {status_code})" if status_code is not None else ""
        super().__init__(f"provider adapter error: {category.value}{detail}")


def error_from_egress(exc: EgressError) -> AdapterError:
    """Map an egress failure to a normalized adapter error."""
    if isinstance(exc, (EgressDestinationError, EgressRedirectError, EgressTLSError)):
        category = ErrorCategory.ENDPOINT_SECURITY
    elif isinstance(exc, EgressResponseTooLargeError):
        category = ErrorCategory.RESPONSE_TOO_LARGE
    elif isinstance(exc, EgressTimeoutError):
        category = (
            ErrorCategory.TIMEOUT
            if exc.request_may_have_been_sent
            else ErrorCategory.TRANSIENT_PRE_ACCEPTANCE
        )
    elif isinstance(exc, (EgressConnectError, EgressResolutionError)):
        category = ErrorCategory.TRANSIENT_PRE_ACCEPTANCE
    else:
        category = ErrorCategory.PROVIDER_ERROR
    return AdapterError(category, possibly_accepted=exc.request_may_have_been_sent)
