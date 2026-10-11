"""`saas_os/core/usage` -- canonical usage-event store, on-demand aggregation, and
quota checking (docs/IMPLEMENTATION-ROADMAP.md Phase 5.2;
docs/DATA-ARCHITECTURE.md section 6: "saas_os/core/usage owns the canonical
usage-event store and aggregation logic").

Owns:
- the tenant-owned `UsageEvent` entity (`core.usage_events`,
  RLS-protected) -- one immutable, append-only usage fact;
- `ingest_event()`, the entrypoint that records a `saas_os.core.outbox` event in
  the caller's own transaction (RE-1); persistence then runs through
  `saas_os.infra.jobs`;
- `USAGE_JOB_FUNCTIONS`, the registered `saas_os.infra.jobs` handler a worker
  process registers to actually perform ingestion;
- `aggregate_usage()`, an on-demand SQL `SUM` over raw events;
- `aggregate_usage_including_descendants()` (architecture research Phase
  H -- "Hierarchy-Aware Billing & Usage"), a hierarchy-aware rollup over
  `tenant_id` plus its current structural descendants
  (`saas_os.core.tenancy.get_descendant_ids()`) -- reporting/rollup only, never
  used by `check_quota()`/`consume_quota()`'s own enforcement path (see
  its own docstring);
- `check_quota()`, combining `aggregate_usage()` with
  `saas_os.core.billing.service.get_entitlements()` (read-only measurement);
- `consume_quota()` (P1.9), the atomic check-and-record enforcement
  counterpart -- see its own docstring for why `check_quota()` alone is
  not race-safe as a request-time gate;
- `consume_quota_idempotent()` (P1.11), the client-idempotency-key-aware
  counterpart -- composes `saas_os.core.idempotency.run_idempotent()` around the
  same underlying check-and-record logic so a client's retried request
  never consumes quota twice (see `saas_os/core/idempotency/service.py`'s own
  module docstring for the generic mechanism this reuses).

Non-Goals (deliberately not built in this phase -- see individual module
docstrings for the full reasoning behind each):
- No cached/materialized aggregation table -- `aggregate_usage()` always
  recomputes from raw events, satisfying the roadmap's Rollback Strategy
  directly.
- No Stripe or other billing-provider coupling -- `check_quota()` reads
  `saas_os/core/billing`'s own already-tested entitlement lookup, never a
  provider SDK.
- No HTTP/API surface (Phase 8) and no automatic `core.audit_log` entry
  per usage event (routine, high-volume events -- the same reasoning
  that already keeps `saas_os/core/webhooks`'/`saas_os/core/notifications`' routine
  delivery/dispatch out of the audit log).
- No data-retention/deletion policy -- not specified by this phase's
  roadmap text, so none is invented.
"""

from saas_os.core.usage.errors import (
    InvalidUsageEventError,
    QuotaExceededError,
    UsageIngestionError,
)
from saas_os.core.usage.models import UsageEvent
from saas_os.core.usage.reporting import (
    MetricUsage,
    SubscriptionContext,
    SubscriptionUsageReport,
    TenantUsageReport,
    merchant_subscription_usage,
    payer_subscription_usage,
    service_tenant_usage_report,
)
from saas_os.core.usage.service import (
    USAGE_JOB_FUNCTIONS,
    QuotaCheckResult,
    aggregate_usage,
    aggregate_usage_including_descendants,
    check_quota,
    consume_quota,
    consume_quota_idempotent,
    ingest_event,
)

__all__ = [
    "MetricUsage",
    "SubscriptionContext",
    "SubscriptionUsageReport",
    "TenantUsageReport",
    "merchant_subscription_usage",
    "payer_subscription_usage",
    "service_tenant_usage_report",
    "UsageEvent",
    "ingest_event",
    "aggregate_usage",
    "aggregate_usage_including_descendants",
    "check_quota",
    "consume_quota",
    "consume_quota_idempotent",
    "QuotaCheckResult",
    "USAGE_JOB_FUNCTIONS",
    "InvalidUsageEventError",
    "UsageIngestionError",
    "QuotaExceededError",
]
