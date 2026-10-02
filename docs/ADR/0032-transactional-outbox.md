# ADR-0032: Transactional outbox (Foundation Reliability & Events, RE-1)

Status: Accepted and implemented (RE-1 only; dispatch is RE-2)
Date: 2026-10-02
Supersedes / Superseded by: — (builds on [ADR-0007](0007-background-job-and-workflow-engine.md), [ADR-0030](0030-foundation-enforcement.md) and [ADR-0031](0031-foundation-authority-and-evidence.md))

## Context

Reliability & Events audit finding RE-F1, confirmed against the code at `da87944`:

- `core.webhooks.trigger_event()`, `core.usage.ingest_event()` and `core.notifications.dispatch_notification()` enqueued an ARQ job in Redis directly, outside any database transaction.
- Called after the caller's commit, a Redis failure lost the event. Called inside the caller's transaction, a rollback still delivered it.
- `trigger_event()` fanned out one job per subscription; a Redis failure part-way left some subscribers enqueued, and a caller retry minted a new `event_id`.

## Decision

**One outbox table, written in the caller's transaction.**
- `core.outbox_events` (`core/outbox`) holds every event. It is tenant-owned: `tenant_id` is NOT NULL, the canonical tenant RLS policy is enabled and forced, and the table is registered as `TENANT_OWNED`. There are no system-owned rows; a future system event needs its own classified table.
- `core.outbox.append_event(session, *, tenant_id, event_type, aggregate_type, aggregate_id, payload)` adds and flushes one row on the caller's session. It never opens a session, never commits and never touches Redis, so the event commits exactly when the caller's mutation commits and disappears on rollback.
- It takes no caller: recording an event changes no authority. Authorization stays with the mutation that caused it.
- Payloads must be JSON objects that round-trip unchanged.

**Identity and delivery contract.**
- The event id is generated once, by `append_event()`, and is the row's primary key. Nothing regenerates it.
- Publication will be at-least-once with that stable id, never exactly-once. There is no business-level deduplication key; appending twice records two events.
- Dispatch-state columns (`status`, `attempts`, `next_attempt_at`, `last_error`, `published_at`) and the per-tenant partial index on pending rows exist for RE-2. RE-1 only writes the initial state (`pending`, 0 attempts).

**Producers record events instead of enqueueing.**
- All three producers now take the caller's tenant session as their first argument, are synchronous, check the tenant lifecycle in that transaction (`lock_open_tenant()`), and return outbox event ids.
- Each outbox row corresponds to exactly one existing job: `webhook.delivery` (one row per subscription, sharing one webhook `event_id`), `usage.ingestion`, `notification.dispatch`. Its payload is the data the job handler already consumes.
- A notification's `recipient_email` is stored only as a `core.crypto` envelope bound to the tenant; the handler decrypts it. A plaintext value from a job queued before this change is passed through.

**Privacy.**
- Tenant purge deletes a tenant's outbox rows (new `outbox` purge step; `OPERATIONAL_PURGE`).
- User erasure deletes the user's undispatched notification events.

## Consequences

- **Breaking change for consumers.** `trigger_event`, `ingest_event` and `dispatch_notification` require `session` first, are no longer `async`, no longer take `queue_name`, and return outbox event ids instead of ARQ job ids.
- **Delivery requires the RE-2 dispatcher** ([ADR-0033](0033-durable-outbox-dispatcher.md)). Without it, events stay `pending` and no webhook, usage row or notification is produced; RE-1 must never be deployed without RE-2.
- Usage ingestion now writes one row in the caller's transaction (previously no database write at all).
- The e-mail notification channel requires the field-encryption key.

## Explicitly not part of this decision (deferred)

- Dispatcher, claims/leases, retries, dead-lettering and replay — RE-2.
- Durable webhook delivery records and retry policy — RE-4.
- Consumer idempotency (usage) and notification deduplication — RE-5.

## Related

`core/outbox/`; `infra/db/migrations/versions/8d3f1a6c2e70_create_core_outbox_events_table.py`; `core/webhooks/service.py`; `core/usage/service.py`; `core/notifications/service.py`; `core/tenancy/isolation.py`; `core/tenancy/retention.py`.
