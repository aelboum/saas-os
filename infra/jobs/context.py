"""Typed job contexts (Foundation Enforcement, FE-5;
docs/ADR/0030-foundation-enforcement.md).

Every registered job declares its kind when it is registered:

    tenant  (`register_tenant_job`)  works on one tenant's data. The payload
            must be a `TenantJobPayload` whose `tenant_id` is a UUID in
            canonical `str(uuid)` form;
            the handler is called as `handler(TenantJobContext, payload)`.
    system  (`register_system_job`)  platform maintenance with no tenant.
            The payload must be `None` (decision D4: the existing `None`
            convention is kept, and the kind decides whether it is valid);
            the handler is called as `handler(SystemJobContext)`.

The worker builds the context from the validated payload before the
handler runs -- a handler never parses a tenant id itself and never sees a
payload that violates its kind. A violation is a permanent contract
failure (`JobContractViolationError`): dead-lettered at once, never
retried, and the handler is never executed.

These types are infrastructure: they carry no tenancy semantics beyond
"which tenant id this job is about". Lifecycle fencing (is the tenant still
open?) stays in Core (`core.tenancy.tenant_job_session`, or a handler's own
documented fence) -- `infra` never imports Core.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass


class JobKind(enum.StrEnum):
    TENANT = "tenant"
    SYSTEM = "system"


@dataclass(frozen=True)
class TenantJobContext:
    tenant_id: uuid.UUID
    correlation_id: str | None = None


@dataclass(frozen=True)
class SystemJobContext:
    correlation_id: str | None = None
