# ADR-0037: Usage metering semantics (Phase 5.2)

Status: Accepted and implemented
Date: 2026-10-02
Supersedes / Superseded by: — (records and hardens Phase 5.2, `core/usage`; builds on [ADR-0008](0008-billing-provider.md), [ADR-0032](0032-transactional-outbox.md), [ADR-0033](0033-durable-outbox-dispatcher.md), [ADR-0036](0036-outbox-consumer-idempotency.md))

## Context

Phase 5.2 (`core/usage`: ingestion and aggregation feeding entitlement and quota checks) was implemented before Reliability & Events and recorded complete on 2026-09-17. A re-audit against the current code found four defects:

1. **No quantity bounds.** `quantity` is an unconstrained PostgreSQL `numeric`, which accepts `Infinity` and `NaN`. Ingestion checked only `quantity < 0`, so an infinite quantity was stored and made every later `SUM` infinite, permanently exceeding the quota. `NaN` raised an untyped `InvalidOperation`, floats were accepted, and magnitude and precision were unbounded.
2. **`consume_quota_idempotent()` validated nothing.** A negative quantity was recorded as negative usage, lowering the measured total that every quota decision is made against: a quota bypass.
3. **Naive datetimes.** A naive `occurred_at` or aggregation bound was interpreted in the database session's timezone.
4. **A single window bound was ignored.** `check_quota()`/`consume_quota()` given only `since` or only `until` silently used the calendar month instead.

## Decision

**One authoritative ledger: `core.usage_events`.** It is unchanged. There is no second ledger, no counter table and no provider-side copy. Aggregates are always computed from it.

**A usage event** has the following fields:

| Field | Kind | Rule |
|---|---|---|
| `tenant_id` | authoritative | The tenant whose scope recorded it; RLS refuses any other. |
| `metric` | authoritative | Non-blank, at most 100 characters. The same vocabulary as plan entitlement keys. |
| `quantity` | authoritative | Exact `Decimal`, or `int` (converted exactly); never `float` or `bool`. Finite, ≥ 0 (zero is a real, recorded event), < 10¹⁸, at most 18 decimal places. Invalid values are refused, never rounded or clamped. |
| `occurred_at` | authoritative | Timezone-aware, stored in UTC; defaults to now (UTC). A naive value is refused. |
| `created_at` | derived | Set by the database on insert. |
| identity | — | The outbox event id. RE-5 records it in `core.outbox_consumptions` in the same transaction as the usage row, so a repeated delivery never counts twice. |

The same validation runs on every write path: `ingest_event()`, the ingestion consumer, `consume_quota()` and `consume_quota_idempotent()`. A recorded event whose payload fails it (for example one written before this change, or corrupted) is dead-lettered as permanent (`MalformedUsageEventError`). A naive `occurred_at` in such an older event is read as UTC.

**Aggregation:**
- `aggregate_usage(tenant, metric, since, until)` sums the window `[since, until)` (since inclusive, until exclusive) in UTC, under the tenant's RLS scope.
- Bounds must be timezone-aware and given together, with `since <= until`.
- `aggregate_usage_including_descendants()` sums each live descendant under its own scope.

**Quota window.**
- Subscriptions carry no billing period, and none is inferred.
- The default window for `check_quota()`/`consume_quota()` is the current UTC calendar month; otherwise the caller passes an explicit `[since, until)`. A provider-neutral billing period is a future decision.
- `consume_quota()` keeps its per-tenant/metric PostgreSQL advisory lock: read the total, decide, and record in one transaction.

**Latency bound** (the roadmap's acceptance criterion):
- `consume_quota()` usage is visible to the next check immediately after its transaction commits.
- `ingest_event()` usage is recorded asynchronously. When the worker is healthy it is aggregated within one dispatch cycle (`OUTBOX_POLL_SECONDS`, default 10 s) plus queue and execution time. A failed attempt is retried under the outbox backoff (ADR-0033), so it can be later, but it is never lost.

**Boundaries.**
- Entitlements are configured limits on the plan (`core.billing`). Usage is recorded consumption. Quota is the enforcement decision (`consume_quota()`, after authorization and the entitlement check in `require_permission()`). Rate limiting is unrelated.
- No billing-provider usage reporting exists, so Core imports no provider type. A future reporting capability belongs behind `BillingProvider`, fed from this ledger; the ledger never depends on a provider.

**Authority.**
- `ingest_event()` records consumption caused by an operation the caller already authorized, in the caller's transaction (like `append_event()`, ADR-0032).
- `consume_quota()` runs behind `require_permission()`.
- Neither takes a caller argument, and neither grants anything.

**Hierarchy.** Usage is recorded at the tenant where it occurred, and roll-ups are computed live from the ledger. A hierarchy change rewrites nothing.

**Retention and privacy.**
- A row holds only tenant, metric, quantity and times: no personal data, request content or secret, so user erasure has nothing to remove.
- Tenant purge retains it (`DEFERRED_POLICY`: no usage retention period has been decided).

## Consequences

- Callers passing a `float` quantity, a naive datetime or a single window bound now get `InvalidUsageEventError`, where they previously had silently wrong behaviour.
- No schema change.

## Explicitly not part of this decision (deferred)

- Provider usage reporting (e.g. Stripe metered billing).
- A provider-neutral billing period.
- A usage retention period.
- A database `CHECK` constraint on `quantity`. Existing rows are not re-validated; all write paths validate.

## Related

`core/usage/service.py`; `core/usage/errors.py`; `tests/core/usage/test_usage_metering_integration.py`; [ADR-0031](0031-foundation-authority-and-evidence.md).
