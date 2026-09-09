"""Typed errors for `core/usage` (docs/IMPLEMENTATION-ROADMAP.md Phase
5.2). Every error here carries only identifying metadata -- never a raw
usage-event payload, mirroring `core/notifications/errors.py`'s own
convention.
"""

from __future__ import annotations

import uuid
from decimal import Decimal


class InvalidUsageEventError(ValueError):
    """Raised by `ingest_event()` itself (before enqueueing) when
    `metric`/`quantity`/`occurred_at` fail basic validation -- never
    raised by the job handler, which trusts a payload that already
    passed this check."""


class UsageIngestionError(RuntimeError):
    """Raised by the ingestion job handler when persisting a usage event
    fails -- caught by `infra.jobs`' own retry/dead-letter wrapper, never
    by this module. Identifies the failed attempt by `tenant_id`/`metric`
    only, never the numeric `quantity` or any other payload content."""

    def __init__(self, tenant_id: uuid.UUID, metric: str, reason: str) -> None:
        self.tenant_id = tenant_id
        self.metric = metric
        super().__init__(
            f"Usage event ingestion failed for tenant {tenant_id}, metric {metric!r}: {reason}"
        )


class QuotaExceededError(RuntimeError):
    """Raised by `consume_quota()` (P1.9) when accepting the requested
    quantity would exceed the tenant's configured limit for `metric`.
    Carries only numeric/identifying context -- `tenant_id`, `metric`,
    the usage already recorded, and the configured limit -- never any
    other tenant data, mirroring `UsageIngestionError`'s own convention.
    Distinct from `InvalidUsageEventError` (a caller programming error)
    and from `infra.ratelimit.RateLimitBackendError` (a backend outage,
    api/errors.py's own `service_unavailable()`): this is neither -- it
    is a normal, expected business-limit outcome."""

    def __init__(self, tenant_id: uuid.UUID, metric: str, *, used: Decimal, limit: Decimal) -> None:
        self.tenant_id = tenant_id
        self.metric = metric
        self.used = used
        self.limit = limit
        super().__init__(
            f"Quota exceeded for tenant {tenant_id}, metric {metric!r}: used={used}, limit={limit}."
        )
