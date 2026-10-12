# ADR-0033: Durable outbox dispatcher, retries and dead-lettering (Foundation Reliability & Events, RE-2)

Status: Accepted and implemented
Date: 2026-10-02
Supersedes / Superseded by: — (completes [ADR-0032](0032-transactional-outbox.md); builds on [ADR-0007](0007-background-job-and-workflow-engine.md) and [ADR-0030](0030-foundation-enforcement.md))

## Context

RE-1 made every webhook, usage and notification event a durable, tenant-owned `core.outbox_events` row, written in the producer's transaction, but nothing published those rows. The audit's RE-F3/RE-F4 findings also stood: ARQ's own failure paths (job timeout, worker crash past `max_tries`, expiry) left no record, and the only dead-letter store was a capped Redis list.

## Decision

**PostgreSQL owns every event's delivery state.** Redis/ARQ only carries work.

**State machine** (`core/outbox/dispatch.py`; database only, no Redis):

| State | Meaning |
|---|---|
| `pending`, unclaimed | due once `next_attempt_at <= now` |
| `pending`, claimed | `claim_token` set; `next_attempt_at` is the lease expiry |
| `published` | terminal: the consumer returned |
| `dead_lettered` | terminal: attempts exhausted, or no consumer for the event type |

- **Claim** — `SELECT … FOR UPDATE SKIP LOCKED`, per tenant under that tenant's RLS scope, a bounded batch with a per-tenant cap and a random starting tenant. A claim increments `attempts`, sets a fresh `claim_token`, and sets `next_attempt_at = now + lease`. Concurrent dispatchers never claim the same row and never wait on each other.
- **Lease** — while claimed, `next_attempt_at` is the lease expiry, so "due" and "stale lease" are one predicate served by RE-1's pending index. A stale lease is simply reclaimed (recording `LeaseExpired` in `last_error`); a stale lease on the final attempt dead-letters the event.
- **Ownership** — every later transition (begin, complete, fail, release) requires the current `claim_token`, under a row lock. A worker whose lease was reclaimed can change nothing.
- **Attempts** — counted at claim time, before the hand-off, so a crash anywhere is still bounded. A failed hand-off to the queue refunds the attempt, so a Redis outage delays events but never exhausts them.
- **Retry** — `min(base · 2^(attempt−1), cap)` plus up to `jitter_ratio` of it. Defaults: 10 attempts, 30 s base, 1 h cap, 10% jitter, 15 min lease. All are `OUTBOX_*` environment tunables (`core/outbox/config.py`). The ARQ `max_tries=3` is no longer the policy for outbox events.
- **Dead letter** — the row itself: status `dead_lettered` with its stable id, payload, attempt count, `last_error` and `updated_at`. `arq:dead-letter` is no longer the record of any outbox event.

**Orchestration** (`api/outbox_dispatcher.py`, worker layer):
- `_dispatch_outbox_cycle` is a system job, scheduled by the worker every `OUTBOX_POLL_SECONDS` (`infra.jobs.queue.system_cron`, which refuses a tenant job).
  - It opens the queue connection first, then claims, then enqueues one `_run_outbox_event` per claim.
  - A failed enqueue releases the claim.
  - Nothing is marked published on enqueue.
- `_run_outbox_event` is a tenant job whose payload is the event's own tenant id plus `{outbox_event_id, claim_token}`.
  - It confirms the claim and renews the lease under the tenant's scope. A closed tenant releases the claim instead.
  - It runs the event type's existing consumer in-process: the same handler, payload and fences, published by each producer module as `OUTBOX_EVENT_HANDLERS`.
  - It records `published`, or the failure. Consumer failures never reach ARQ's retry or the Redis dead-letter list.

**Tenancy.**
- Tenants are enumerated through `core.tenancy.list_open_tenant_ids()`.
- Each tenant's events are read and changed only under its own RLS scope. There is no cross-tenant query and no BYPASSRLS.
- A closed tenant's events are never claimed; the purge removes them. `SUSPENDED` keeps dispatching, matching the existing in-motion-work contract.

**Delivery contract: at-least-once with a stable event id, never exactly-once.** A consumer that ran but whose worker died before `complete_event()` runs again after the lease expires. Consumer deduplication is RE-5.

## Consequences

- One migration (`c4e8b2a71f93`): the nullable `claim_token` column plus `ck_outbox_events_claim_only_pending`. Nothing else is added.
- The production worker now runs a cron (the dispatch cycle) and one more tenant job. `infra.jobs.build_worker` gained `cron_jobs`.
- Retry timing for webhook, usage and notification events is now the outbox policy above, rather than ARQ's three quick tries. The consumers themselves are unchanged. Webhook-specific classification (permanent vs. retryable, `Retry-After`) remains RE-4.
- A consumer whose payload is permanently malformed still uses its full retry budget before dead-lettering. Only an unknown event type dead-letters immediately.
- Each cycle reads the open-tenant list and probes each tenant's pending index. That is cheap per tenant but linear in tenant count. A cross-tenant "due" signal would need a privileged path, and was deliberately not added.
- The lease must exceed queue latency plus the 300 s ARQ job timeout; otherwise live work is redone, though never lost.

## Explicitly not part of this decision (deferred)

- **Replay of dead-lettered events.** They stay durably dead-lettered. Replay needs a typed, authorized and audited operator action, and is left for a later change.
- **Durable webhook delivery records and webhook retry classification** — RE-4.
- **Usage idempotency and notification deduplication** — RE-5.
- **Rate limiting** — RE-3.

## Related

`core/outbox/dispatch.py`; `core/outbox/config.py`; `api/outbox_dispatcher.py`; `api/worker.py`; `infra/jobs/queue.py`; `infra/db/migrations/versions/c4e8b2a71f93_add_outbox_event_claim_token.py`.
