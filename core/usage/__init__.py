"""`core/usage` -- canonical usage-event store, on-demand aggregation, and
quota checking (docs/IMPLEMENTATION-ROADMAP.md Phase 5.2;
docs/DATA-ARCHITECTURE.md section 6: "core/usage owns the canonical
usage-event store and aggregation logic").

Owns:
- the tenant-owned `UsageEvent` entity (`core.usage_events`,
  RLS-protected) -- one immutable, append-only usage fact;
- `ingest_event()`, the entrypoint that enqueues persistence through
  `infra.jobs`;
- `USAGE_JOB_FUNCTIONS`, the registered `infra.jobs` handler a worker
  process registers to actually perform ingestion;
- `aggregate_usage()`, an on-demand SQL `SUM` over raw events;
- `check_quota()`, combining `aggregate_usage()` with
  `core.billing.service.get_entitlements()` (read-only measurement);
- `consume_quota()` (P1.9), the atomic check-and-record enforcement
  counterpart -- see its own docstring for why `check_quota()` alone is
  not race-safe as a request-time gate;
- `consume_quota_idempotent()` (P1.11), the client-idempotency-key-aware
  counterpart -- composes `core.idempotency.run_idempotent()` around the
  same underlying check-and-record logic so a client's retried request
  never consumes quota twice (see `core/idempotency/service.py`'s own
  module docstring for the generic mechanism this reuses).

Non-Goals (deliberately not built in this phase -- see individual module
docstrings for the full reasoning behind each):
- No cached/materialized aggregation table -- `aggregate_usage()` always
  recomputes from raw events, satisfying the roadmap's Rollback Strategy
  directly.
- No Stripe or other billing-provider coupling -- `check_quota()` reads
  `core/billing`'s own already-tested entitlement lookup, never a
  provider SDK.
- No HTTP/API surface (Phase 8) and no automatic `core.audit_log` entry
  per usage event (routine, high-volume events -- the same reasoning
  that already keeps `core/webhooks`'/`core/notifications`' routine
  delivery/dispatch out of the audit log).
- No data-retention/deletion policy -- not specified by this phase's
  roadmap text, so none is invented.
"""

from core.usage.errors import InvalidUsageEventError, QuotaExceededError, UsageIngestionError
from core.usage.models import UsageEvent
from core.usage.service import (
    USAGE_JOB_FUNCTIONS,
    QuotaCheckResult,
    aggregate_usage,
    check_quota,
    consume_quota,
    consume_quota_idempotent,
    ingest_event,
)

__all__ = [
    "UsageEvent",
    "ingest_event",
    "aggregate_usage",
    "check_quota",
    "consume_quota",
    "consume_quota_idempotent",
    "QuotaCheckResult",
    "USAGE_JOB_FUNCTIONS",
    "InvalidUsageEventError",
    "UsageIngestionError",
    "QuotaExceededError",
]
