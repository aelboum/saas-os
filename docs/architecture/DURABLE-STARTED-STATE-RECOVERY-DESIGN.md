# Crash recovery with a durable "started" state: design proposal

**Status: design proposal for separate approval, 2026-11-01. Nothing is implemented; current at-least-once behaviour is unchanged.** Prepared on `main` `6fd2dfd`. Owner decision of 2026-11-01: keep at-least-once crash recovery for now, and design a separate migration proposal for recovery that knows whether an external request may already have been sent. Companion: `docs/architecture/EXTERNAL-OUTCOME-CLASSIFICATION-DESIGN.md` (outcome categories, its own pull request).

## 1. Today

An outbox event is claimed with a token and a lease (`claim_due_events`, `saas_os/core/outbox/dispatch.py`); the job renews the lease when it starts (`begin_event_execution`), runs the consumer, then records the outcome (`complete_event` / `fail_event`). If the worker dies at any point before recording, the lease expires and the event is claimed and run again. Consumers suppress a repeat only once their completion is recorded (`core.outbox_consumptions`, ADR-0036). So:

| Crash point | What happens today | Risk |
|---|---|---|
| Before the job starts | Lease expires, event runs | None |
| After the job started, before the external request | Lease expires, event runs | None |
| After the request was sent, before the response | Lease expires, event runs again | **Duplicate** effect (webhook, SMTP e-mail; Resend de-duplicates within 24 hours by key) |
| After the response, before the outcome is recorded | Lease expires, event runs again | **Duplicate**, unless the consumer recorded completion in the same step (database effects, ADR-0036) |

Nothing durable distinguishes the first two rows from the last two, so recovery must assume one case for all. Today it assumes "not sent" and retries (at-least-once, ADR-0033).

## 2. Proposal: a durable started marker per attempt

Immediately **before** a consumer performs an external request, a marker is committed on the event: "claim token T started its external request at time S". It is cleared when the outcome is recorded. On lease expiry the reclaim reads it:

| Marker at reclaim | Meaning | Action |
|---|---|---|
| Absent | The crash came before any external request | Retry as today (safe) |
| Present for the expired claim | The request may have been sent | **Ambiguous**: retry only if the event type's consumer declares a safe idempotency or reconciliation mechanism (Resend within its key window, Stripe); otherwise dead-letter with `last_error` `CrashAfterStart: outcome unknown`, for operator replay |

Writing the marker before the request is deliberately conservative: a crash between the marker and the request is reported ambiguous although nothing was sent, which costs an operator check. It never turns a sent request into a silent retry.

### 2.1 Where the marker lives

- **Option S1 (recommended): two nullable columns on `core.outbox_events`**: `external_started_at timestamptz`, `external_started_claim uuid`. Written and read under the tenant's RLS like every other column of the row; no join on the hot path.
- **Option S2: a tenant-owned table `core.outbox_attempts`** (event id, attempt number, claim token, started at, outcome, finished at). Keeps every attempt's history for audit, at the cost of a row per attempt, its retention and a join at reclaim.

### 2.2 Consumer contract

The marker must be written by code that knows when the external request is about to happen. Two options:

- **Option C1:** a context manager in the job context (`context.external_effect()`) that commits the marker and yields; SaaS OS's own consumers (webhooks, notifications) use it around the send. A consumer that does not use it keeps today's behaviour. Additive change to `TenantJobContext` (public contract).
- **Option C2:** the dispatcher writes the marker before calling any consumer registered as having an external effect. No consumer code change, but the window "marker written, nothing sent yet" grows to the whole consumer, so more crashes are reported ambiguous.

## 3. Idempotency, dead letters and replay

- The marker is per claim: a reclaim with a new token never mistakes an older attempt's marker for its own, and a stale job finds its claim superseded (existing check) and does nothing.
- Consumers with provider idempotency (Resend key within its window, Stripe keys) declare it, and their ambiguous crashes are retried; everything else is dead-lettered.
- Dead-lettered rows keep their payload; `saas-os-operator replay-outbox-events` (`platform.outbox:replay`) returns them to `pending` and would clear the marker, with a platform and a tenant audit row (existing). The operator checks the destination first, as for the F5 timeout.
- Plain arq jobs (not outbox-backed) are out of scope: they have no durable state in PostgreSQL; work that must not be duplicated belongs in the outbox.

## 4. Schema migration (needs approval)

For S1:

- **Upgrade:** add `external_started_at timestamptz NULL` and `external_started_claim uuid NULL` to `core.outbox_events`. Nullable, no default, no backfill: a metadata-only change in PostgreSQL with a brief `ACCESS EXCLUSIVE` lock. The application role already updates these rows (claims, outcomes); RLS policies are row-level and unaffected; no new table, so the isolation registry and the RLS coverage sweep are unchanged.
- **Deployment order:** migrate first; code that does not know the columns ignores them; the new code needs them.
- **Downgrade:** drop both columns. Events that carried a marker fall back to today's at-least-once behaviour; no row is lost.
- **Failure recovery:** a failed upgrade leaves the table unchanged (one transaction).

For S2: create the table (tenant-owned, forced RLS, canonical policy, isolation registry, retention tied to the event's), application role `SELECT, INSERT, UPDATE`; downgrade drops it.

## 5. Tests the implementation needs

- A worker process killed (`SIGKILL`) before the marker: the event is retried once and completes.
- Killed after the marker, before the request: dead-lettered as ambiguous (conservative); a replay delivers once.
- Killed after the request, before recording, for each consumer: webhooks and SMTP dead-lettered; Resend retried with the same key inside its window and dead-lettered after it.
- A stale job with an old claim finds the marker of a newer claim and does nothing.
- A replay clears the marker; a later crash is judged afresh.
- Isolation: a marker is written and read only under its tenant's scope; a job for another tenant cannot see or clear it.
- Migration upgrade and downgrade tests; negative control: ignoring the marker at reclaim makes the "after the request" tests duplicate the effect and fail.

## 6. Decisions for the owner

1. **S1 (columns) or S2 (attempt table).**
2. **C1 (context manager in the job context) or C2 (dispatcher-level registration flag).** Both are additive public-contract changes.
3. Which consumers may declare a safe idempotency mechanism (proposed: Resend within its 24-hour key window, and Stripe; not webhooks or SMTP, unless option W1 of the outcome-classification design is chosen for webhooks).
4. Approval of the migration in section 4.

Until these are decided, crash recovery stays at-least-once, as today.
