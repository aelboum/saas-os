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
- **Failure recovery:** a failed upgrade leaves the table unchanged (one transaction). The reviewed, measured DDL is in section 4a; it replaces this summary where they differ.

For S2: create the table (tenant-owned, forced RLS, canonical policy, isolation registry, retention tied to the event's), application role `SELECT, INSERT, UPDATE`; downgrade drops it.

## 4a. DDL review for approval (owner direction of 2026-11-01: S1 and C1)

**Decided direction (owner, 2026-11-01):** the marker is columns on `core.outbox_events` (S1); the consumer marks the start with an explicit context manager (C1); the marker is committed before the external request begins; a crash after the marker is ambiguous; only explicitly approved and tested idempotent consumers retry it; everything else is dead-lettered for operator reconciliation.

**Status of this section: proposal only. The DDL below is not implemented, no Alembic migration is written, and no runtime code changes. The exact DDL needs its own approval.** Every measurement below was taken by applying the SQL by hand to a throwaway copy of the schema in a disposable PostgreSQL 16.15 container, which was removed afterwards.

This review supersedes the first draft that was here (commit `9435b6b`). Three findings changed it: (1) `NOT VALID` followed by `VALIDATE` in one transaction gains nothing, and Alembic runs a whole upgrade in one transaction, so the validation must be a separate transaction (4a.3); (2) the pair check alone does not bind the marker to the claim, so a second check is proposed (4a.2, decision D1); (3) `SET LOCAL lock_timeout` would otherwise stay in force for every later migration of the same run, so it is reset.

### 4a.1 Existing state (main `6fd2dfd`, migration head `b3d5f7a9c2e4`)

Read from the migrations and confirmed with `\d core.outbox_events` after `saas-os-migrate upgrade`:

| Object | Definition | Source |
|---|---|---|
| `outbox_events_pkey` | btree `(id)` | `8d3f1a6c2e70` |
| `ix_outbox_events_tenant_id` | btree `(tenant_id)` | `8d3f1a6c2e70` |
| `ix_outbox_events_pending` | btree `(tenant_id, next_attempt_at) WHERE status = 'pending'` | `8d3f1a6c2e70` |
| `ck_outbox_events_status`, `ck_outbox_events_attempts_non_negative` | status domain; `attempts >= 0` | `8d3f1a6c2e70` |
| `ck_outbox_events_claim_only_pending` | `claim_token IS NULL OR status = 'pending'` | `c4e8b2a71f93` |
| `claim_token` | `uuid NULL` (`sa.Uuid()`) | `c4e8b2a71f93` |
| `next_attempt_at`, `published_at` | `timestamptz` | `8d3f1a6c2e70` |
| Policy `outbox_events_tenant_isolation` | `FOR ALL USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)`; `ENABLE` and `FORCE ROW LEVEL SECURITY` | `tenant_rls_statements()` in `8d3f1a6c2e70` |
| Application role grants | `saas_os_app`: `SELECT, INSERT, UPDATE, DELETE` at table level, from the schema default privileges of `e99c76057719`; no column-level ACLs; the role is `NOSUPERUSER NOBYPASSRLS` | catalog |

Queries on the table in `saas_os/core/outbox/dispatch.py`: the claim and reclaim query of `claim_due_events()` (`tenant_id = :t AND status = 'pending' AND next_attempt_at <= :at ORDER BY next_attempt_at, id LIMIT n FOR UPDATE SKIP LOCKED`, one tenant at a time) and `_locked_claimed_row()` (`id = :id FOR UPDATE`, used by `begin_event_execution`, `complete_event`, `fail_event`, `release_claim`). Neither filters on a marker column.

### 4a.2 Columns and constraints

| Column | Type | Null | Justification |
|---|---|---|---|
| `external_started_claim` | `uuid` | `NULL` | Same type as `claim_token` (`uuid`, 16 bytes), so `external_started_claim = claim_token` compares without a cast and the model maps it with the same `sa.Uuid()` as `claim_token`. No foreign key: a claim token is not a key. |
| `external_started_at` | `timestamptz` | `NULL` | Same type as `next_attempt_at` and `published_at`; written from the dispatcher's clock (`_now(now)`), like every other timestamp in `dispatch.py`, so tests can inject it. Evidence for the operator ("started at"), not used in any predicate. |

Both are nullable with no default: `NULL` means "no external request started under the current claim", and every existing row is in that state, so there is no backfill.

- **`ck_outbox_events_external_started_pair` (required):** `CHECK ((external_started_at IS NULL) = (external_started_claim IS NULL))`. Both set or both unset. Measured: an update setting only one column fails with `CheckViolation`.
- **`ck_outbox_events_external_started_claim_current` (recommended, decision D1):** `CHECK (external_started_claim IS NULL OR status = 'dead_lettered' OR external_started_claim IS NOT DISTINCT FROM claim_token)`. A pending row's marker must belong to its current claim; a published row has none; a dead-lettered row may keep it as evidence. It makes every transition that changes the claim (reclaim, retry release, complete, replay) clear the marker or fail, so a forgotten clear fails closed instead of leaving a stale marker. `IS NOT DISTINCT FROM` is required: a first version with `=` accepted "published, claim cleared, marker kept", because `marker = NULL` is `NULL` and a `CHECK` passes on `NULL`. Measured with the final form: marker for a foreign claim, retry release without clearing, and published without clearing each fail with `CheckViolation`; dead-lettering with the marker kept is accepted.

### 4a.3 Upgrade: two transactions, in two Alembic revisions

```sql
-- Revision A (normal transactional migration): metadata only.
SET LOCAL lock_timeout = '5s';
ALTER TABLE core.outbox_events
    ADD COLUMN external_started_at timestamptz NULL,
    ADD COLUMN external_started_claim uuid NULL,
    ADD CONSTRAINT ck_outbox_events_external_started_pair
        CHECK ((external_started_at IS NULL) = (external_started_claim IS NULL)) NOT VALID,
    ADD CONSTRAINT ck_outbox_events_external_started_claim_current
        CHECK (external_started_claim IS NULL
               OR status = 'dead_lettered'
               OR external_started_claim IS NOT DISTINCT FROM claim_token) NOT VALID;
RESET lock_timeout;

-- Revision B (inside Alembic's autocommit_block(): its own transaction).
SET lock_timeout = '5s';
ALTER TABLE core.outbox_events VALIDATE CONSTRAINT ck_outbox_events_external_started_pair;
ALTER TABLE core.outbox_events
    VALIDATE CONSTRAINT ck_outbox_events_external_started_claim_current;
RESET lock_timeout;
```

Why this shape:

- **One `ALTER TABLE` statement** in revision A: the `ACCESS EXCLUSIVE` lock is requested once. Measured on 1,000,000 rows (206 MB): 9 to 16 ms, no table rewrite (`pg_relation_filenode` unchanged).
- **`NOT VALID`:** a validated `CHECK` in the same statement scans the table under `ACCESS EXCLUSIVE`: 195 to 200 ms on the same table, against 11 to 16 ms with `NOT VALID`. A `NOT VALID` check is still enforced for every insert and update from the moment it is added; only the existing rows are unchecked.
- **`VALIDATE` in its own transaction:** it scans under `SHARE UPDATE EXCLUSIVE` (146 to 225 ms per constraint), and while it was held a claim (`SELECT ... FOR UPDATE SKIP LOCKED` of 25 rows, then `UPDATE`) ran without waiting. Run in the same transaction as revision A it gains nothing: `pg_locks` showed the `ACCESS EXCLUSIVE` lock still held after `VALIDATE`. `saas_os/infra/db/migrations/env.py` runs a whole `upgrade` in one transaction (`context.begin_transaction()`, no `transaction_per_migration`), so revision B must use `op.get_context().autocommit_block()`; a separate revision alone would not be enough. Validation cannot fail: every existing row has both columns `NULL`.
- **Two revisions, not one:** `autocommit_block()` commits what precedes it. In one revision a failed `VALIDATE` would leave the columns committed but the revision unstamped, and a re-run would fail on `ADD COLUMN`. With two revisions, A is stamped and committed first, and B is re-runnable: validating an already validated constraint is a no-op (measured: 1 ms). The stamping order is Alembic behaviour to be confirmed by the implementation's migration tests.
- **`lock_timeout = '5s'`:** `ADD COLUMN` must wait for every open transaction that touched the table, and while it waits it blocks everyone queued behind it. Measured: with a reader holding `AccessShareLock`, the `ALTER` waited (`AccessExclusiveLock`, not granted), a claim query queued behind it (`RowShareLock`, not granted) and waited 4.0 s; at 5.01 s the `ALTER` failed with `LockNotAvailable` and the claim query ran at once. So the dispatcher stalls at most `lock_timeout`, and a failed attempt changes nothing and can be re-run. `RESET` keeps the setting from applying to later migrations in the same run.

### 4a.4 Locks per statement (observed in `pg_locks` during held transactions)

| Statement | Lock on `core.outbox_events` | Blocks | Measured |
|---|---|---|---|
| A: `ADD COLUMN` x2 + `ADD CONSTRAINT ... NOT VALID` x2 | `AccessExclusiveLock` | everything, including plain `SELECT`; an app-role `SELECT` with `lock_timeout = 1s` failed while it was held | 9 to 16 ms, no rewrite |
| B: `VALIDATE CONSTRAINT` | `ShareUpdateExclusiveLock` | only other DDL, `VACUUM`, `ANALYZE`; not reads, claims or outcomes | 146 to 225 ms each on 1M rows |
| Downgrade `DROP CONSTRAINT` + `DROP COLUMN` | `AccessExclusiveLock` | everything | 7 to 10 ms, no rewrite |
| Runtime marker write (`UPDATE ... WHERE id = ...`) | `RowExclusiveLock` + row lock | only the same row | primary-key lookup |

### 4a.5 Index impact: none needed

The reclaim query was planned with `EXPLAIN (ANALYZE, BUFFERS)` as `saas_os_app` under tenant T1's scope, on 1,000,000 rows across 50 tenants (94 % published, 1 % dead-lettered, 5 % pending: due, claimed, expired leases, future retries), before the DDL, after the DDL with 7,534 expired claims and 3,056 dead-lettered rows carrying markers, and after the downgrade:

| | Plan | Buffers | Execution |
|---|---|---|---|
| Before | `Limit -> LockRows -> Incremental Sort -> Index Scan using ix_outbox_events_pending` (`Index Cond: tenant_id = T1 AND next_attempt_at <= now()`), 33 rows read, 25 returned | 74 to 86 shared hit | 0.205 to 0.313 ms |
| After | identical plan and row counts | 86 shared hit | 0.228 to 0.264 ms |
| After downgrade | identical | 74 shared hit | 0.202 ms |

Two complete runs; the buffer counts varied between runs in both states (86 before the DDL in the first run), with the same access path every time. `_locked_claimed_row()` stays an `Index Scan using outbox_events_pkey` (0.13 to 0.16 ms), and the proposed marker write is an `Update` over an `Index Scan using outbox_events_pkey` (0.22 to 0.30 ms). The marker is only ever read on rows the reclaim query already locked, so no predicate and no index use it. Proposing none also keeps a marker write that changes no indexed column eligible for a heap-only (HOT) update (measured: 69 and 83 of 200 marker writes were HOT in two runs on a densely loaded table, limited by free space on the page; an index on a marker column would make that 0).

### 4a.6 Runtime statements (for the implementation; not part of the DDL)

| Moment | Statement (under the tenant's RLS scope) | Concurrency |
|---|---|---|
| Consumer enters `context.external_effect()` | `UPDATE core.outbox_events SET external_started_at = :at, external_started_claim = :claim, next_attempt_at = :at + :lease WHERE id = :id AND claim_token = :claim AND status = 'pending' AND external_started_claim IS NULL AND next_attempt_at > :at`, committed in its own transaction before the request | 0 rows: claim superseded, lease already expired, or the marker already written; the context manager raises and the request is never sent |
| Outcome recorded (`complete_event`, `fail_event`, `release_claim`, closed-tenant release) | clears both columns with the outcome | same row lock and claim check as today; enforced by D1 |
| Reclaim (`claim_due_events`) of a row whose `external_started_claim` equals its expired `claim_token` | consumer declared safely idempotent: reclaim and clear the marker; otherwise `dead_lettered`, marker kept, `last_error` `CrashAfterStart: outcome unknown; not retried automatically` | inside the existing `FOR UPDATE SKIP LOCKED` transaction |
| Operator replay | clears both columns with the status change | existing replay transaction and audit; enforced by D1 |
| Job outside the outbox | `context.external_effect()` is a no-op | none |

### 4a.7 Concurrent workers, leases and crash recovery

Measured in the throwaway database as `saas_os_app`:

- **Marker write against a reclaim in progress:** the reclaim held the row (`FOR UPDATE`, new `claim_token`, uncommitted); the stale worker's marker write waited on the row (`wait_event` `transactionid`), and after the reclaim committed PostgreSQL re-checked its `WHERE` and updated 0 rows. The stale worker sends nothing.
- **Reclaim against a marker write in progress:** while the current claim's marker write was uncommitted, the reclaim's `SKIP LOCKED` skipped the row (0 rows) instead of waiting; once committed, the next cycle sees the marker.
- **Two jobs with the same claim** (a duplicated queue job): the first marker write updates 1 row, the second 0 (`external_started_claim IS NULL`). Only one sends.
- **Lease renewal:** the marker write moves `next_attempt_at` to `:at + lease` (measured: lease in the future after commit), so the request starts with a full lease, as `begin_event_execution()` does today. With `next_attempt_at > :at` a worker whose lease has already expired cannot start a request.
- **Lease expiry during the request** (request slower than the lease, 900 s by default): the reclaim finds the marker of the expired claim and dead-letters the event (or retries it if idempotent). The original worker's `complete_event()` then finds its claim gone and changes nothing. The request is not repeated silently; the operator sees an ambiguous event that was in fact delivered. Keep the job timeout below the lease.
- **Crash before the marker:** no marker; the event is reclaimed and retried as today.
- **Crash after the marker, before or after transmission:** the two cannot be told apart, by design. The event is retried only for a declared idempotent consumer, otherwise dead-lettered with its marker kept as evidence, and the operator checks the destination before replaying.

### 4a.8 Tenant isolation and RLS

- No new table, no policy change: `outbox_events_tenant_isolation` is row-level and `FOR ALL`, so it covers the new columns. The isolation registry and the RLS coverage sweep are unaffected.
- Privileges, checked as `saas_os_app` (`rolsuper = false`, `rolbypassrls = false`): `has_column_privilege` is true for `SELECT`, `INSERT` and `UPDATE` on both new columns, from the existing table-level grant. No `GRANT` is needed.
- Scope: under T1's scope, writing T2's marker updated 0 rows and reading T2's row returned 0 rows; with no tenant scope, 0 rows with a marker were visible; under T2's own scope the write updated 1 row.

### 4a.9 Downgrade

```sql
-- Revision B downgrade: nothing (the constraints are dropped by revision A's).
-- Revision A downgrade:
SET LOCAL lock_timeout = '5s';
ALTER TABLE core.outbox_events
    DROP CONSTRAINT IF EXISTS ck_outbox_events_external_started_claim_current,
    DROP CONSTRAINT ck_outbox_events_external_started_pair,
    DROP COLUMN external_started_claim,
    DROP COLUMN external_started_at;
RESET lock_timeout;
```

`IF EXISTS` on the claim check lets the downgrade run after the emergency step below. Measured: 7 to 10 ms under `AccessExclusiveLock`, no rewrite; the dropped columns' space is reclaimed as rows are updated or by a later rewrite.

### 4a.10 Data compatibility, deployment order and rollback limitations

- **Existing rows:** unchanged; both columns `NULL`, which means "nothing started". No backfill, no guess.
- **Deployment order:** (1) revision A, (2) revision B, (3) the code that writes and reads markers. Code from before the change runs correctly against the new schema: it never sets a marker, so neither check can fire. The new code's model maps the columns and fails against a database without them, so the migration comes first.
- **Rollback of the code only:** the older code ignores markers. Markers left on pending rows then break its transitions under D1 (a reclaim or outcome that changes `claim_token` without clearing the marker fails the check, and one such row fails the whole claim transaction for every tenant). Before deploying older code over a schema that still has the columns, first run `ALTER TABLE core.outbox_events DROP CONSTRAINT ck_outbox_events_external_started_claim_current` (metadata only); without D1 nothing is needed. The pair check never fires for older code.
- **Downgrade of the schema:** deploy the older code first, then downgrade. Markers are lost: a pending event that carried one falls back to at-least-once recovery and may be sent again; a dead-lettered event keeps its `CrashAfterStart` `last_error` but loses the start time.
- **Failure recovery:** revision A either commits whole or changes nothing (one statement, one transaction); a lock timeout is retried by re-running. Revision B is idempotent.
- **Tests the implementation must add** (section 5, plus): upgrade and downgrade of both revisions on a populated table; the check violations above; a stale-claim marker write updating 0 rows; and the migration-test cleanup rule (no leftover rows that block a later downgrade).

### 4a.11 Decisions requested for the DDL

- **D1:** add `ck_outbox_events_external_started_claim_current` (recommended: a forgotten clear fails closed; cost: the code-rollback step in 4a.10) or only the pair check.
- **D2:** `lock_timeout` value (proposed `5s`: the longest the dispatcher can stall behind a waiting migration).
- **D3:** approve the two-revision shape, including `autocommit_block()` for `VALIDATE`.
- **D4:** approve the exact DDL in 4a.3 and 4a.9 for a separate implementation pull request.

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
4. Approval of the migration: the DDL review in section 4a, with its decisions D1 to D4 (section 4a.11).

Until these are decided, crash recovery stays at-least-once, as today.
