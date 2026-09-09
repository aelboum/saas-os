"""Typed errors for `infra/jobs` (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4)."""

from __future__ import annotations


class JobsConfigurationError(ValueError):
    """Raised when `infra/jobs`'s configuration is invalid (e.g. an
    unreachable/malformed `REDIS_URL`, or a bad retry-policy value).
    Never includes a secret value (docs/SECURITY.md).
    """


class MissingTenantIdError(ValueError):
    """Raised when a `TenantJobPayload` is constructed without a
    non-empty `tenant_id` (docs/MULTI-TENANCY.md section 4: "every job
    payload carries tenant_id").
    """

    def __init__(self) -> None:
        super().__init__(
            "A tenant-scoped job payload requires a non-empty tenant_id "
            "(docs/MULTI-TENANCY.md section 4)."
        )


class InvalidJobPayloadError(TypeError):
    """Raised by `enqueue_job()` when `payload` is neither `None` nor a
    `TenantJobPayload` -- the queue boundary itself enforces the schema-
    level tenant_id check (docs/MULTI-TENANCY.md section 4), not merely
    `TenantJobPayload`'s own constructor. Carries only the function name
    and the offending value's *type name* -- never the payload's contents,
    which could carry application data (docs/SECURITY.md).
    """

    def __init__(self, function_name: str, payload_type: type) -> None:
        self.function_name = function_name
        self.payload_type = payload_type
        super().__init__(
            f"Job {function_name!r}: payload must be a TenantJobPayload or None, "
            f"got {payload_type.__name__!r}."
        )


class JobDeadLetteredError(RuntimeError):
    """Raised (and recorded via `infra.jobs.dead_letter`) when a job has
    exhausted its retry policy. Carries only the function name and
    attempt count -- never the payload or the underlying error's
    arguments, which could echo application data.
    """

    def __init__(self, function_name: str, attempts: int) -> None:
        self.function_name = function_name
        self.attempts = attempts
        super().__init__(f"Job {function_name!r} dead-lettered after {attempts} attempt(s).")
