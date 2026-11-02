# Crash recovery with a durable "started" state: design proposal

**Status: design proposal for separate approval, 2026-11-01; DDL review updated 2026-11-02 (owner decisions D1 to D3). Nothing is implemented: no migration exists in the package, no runtime code changes, and the exact DDL awaits separate approval (D4). Current at-least-once behaviour is unchanged.** Prepared on `main` `6fd2dfd`. Owner decision of 2026-11-01: keep at-least-once crash recovery for now, and design a separate migration proposal for recovery that knows whether an external request may already have been sent. Companion: `docs/architecture/EXTERNAL-OUTCOME-CLASSIFICATION-DESIGN.md` (outcome categories, its own pull request).

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
- **Failure recovery:** see section 4a.11. The reviewed, measured DDL is in section 4a; it replaces this summary where they differ.

For S2: create the table (tenant-owned, forced RLS, canonical policy, isolation registry, retention tied to the event's), application role `SELECT, INSERT, UPDATE`; downgrade drops it.

## 4a. DDL review for approval (owner direction of 2026-11-01: S1 and C1)

> **Nothing is implemented.** No migration exists in the package (`saas_os/infra/db/migrations/versions/` is unchanged; head is still `b3d5f7a9c2e4`), no runtime code changes, and the exact DDL below awaits a separate approval (D4). The two proposed revision files are stored as documentation only, with a `.py.txt` suffix, in `docs/architecture/proposals/crash-recovery/`; Alembic, ruff and pytest never load them.

**Decided direction (owner, 2026-11-01):** the marker is columns on `core.outbox_events` (S1); the consumer marks the start with an explicit context manager (C1); the marker is committed before the external request begins; a crash after the marker is ambiguous; only explicitly approved and tested idempotent consumers retry it; everything else is dead-lettered for operator reconciliation.

**Owner decisions of 2026-11-02, applied below:**

- **D1: no claim-matching check.** `ck_outbox_events_external_started_claim_current` (proposed in commit `23fdb51`) is removed; only the paired-value check remains. The marker keeps the claim identity of the external operation even after the event is reclaimed: a marker from an expired claim must stay representable. Stale workers are stopped by conditional writes (`WHERE id = :id AND claim_token = :claim AND status = 'pending'`), not by a constraint.
- **D2:** `lock_timeout = '5s'`.
- **D3:** two revisions: A adds the columns and the `NOT VALID` pair check; B runs `VALIDATE` inside `autocommit_block()`.
- **D4: open.** The exact DDL is not approved yet.

All measurements in this section were taken on 2026-11-02 in a disposable PostgreSQL 16.15 container (`postgres:16-alpine`, removed afterwards), with the two proposal files copied as `.py` into a scratch copy of the migrations directory outside the repository and run through the unchanged `env.py` with Alembic 1.20.0. Two earlier reviews (commits `9435b6b`, `23fdb51`) are superseded where they differ.

### 4a.1 Existing state (main `6fd2dfd`, migration head `b3d5f7a9c2e4`)

| Object | Definition | Source |
|---|---|---|
| `outbox_events_pkey` | btree `(id)` | `8d3f1a6c2e70` |
| `ix_outbox_events_tenant_id` | btree `(tenant_id)` | `8d3f1a6c2e70` |
| `ix_outbox_events_pending` | btree `(tenant_id, next_attempt_at) WHERE status = 'pending'` | `8d3f1a6c2e70` |
| `ck_outbox_events_status`, `ck_outbox_events_attempts_non_negative` | status domain; `attempts >= 0` | `8d3f1a6c2e70` |
| `ck_outbox_events_claim_only_pending` | `claim_token IS NULL OR status = 'pending'` | `c4e8b2a71f93` |
| `claim_token` | `uuid NULL` | `c4e8b2a71f93` |
| Policy `outbox_events_tenant_isolation` | `FOR ALL USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)`; `ENABLE` and `FORCE ROW LEVEL SECURITY` | `8d3f1a6c2e70` |
| Application role | `saas_os_app`, `NOSUPERUSER NOBYPASSRLS`, table-level `SELECT, INSERT, UPDATE, DELETE` | `e99c76057719` default privileges |

`saas_os/infra/db/migrations/env.py` runs every pending revision of one `upgrade` in a single transaction (`context.begin_transaction()`, no `transaction_per_migration`). Queries on the table in `saas_os/core/outbox/dispatch.py`: the claim/reclaim query of `claim_due_events()` and `_locked_claimed_row()` (`id = :id FOR UPDATE`). Neither filters on a marker column.

### 4a.2 Columns and constraint

| Column | Type | Null | Justification |
|---|---|---|---|
| `external_started_claim` | `uuid` | `NULL` | The claim token under which the external request was started. Same type as `claim_token`, so `external_started_claim = claim_token` compares without a cast. Not required to equal the current `claim_token` (D1). No foreign key. |
| `external_started_at` | `timestamptz` | `NULL` | When the marker was committed, from the dispatcher's clock (`_now(now)`), like every timestamp in `dispatch.py`. Operator evidence; never in a predicate. |

`NULL` in both means "no external request started"; every existing row is in that state, so there is no backfill.

**`ck_outbox_events_external_started_pair`:** `CHECK ((external_started_at IS NULL) = (external_started_claim IS NULL))`. Measured: an update that clears only one column fails with `CheckViolation` (scenario 9 in 4a.7).

No other constraint. The states the schema must allow, all measured as representable: pending with no marker; pending with the marker of its current claim (request in flight); pending with the marker of an **expired** claim after a reclaim (idempotent retry; scenario 3a); dead-lettered with the marker kept as evidence (scenario 3b); published with both cleared.

### 4a.3 Upgrade SQL

```sql
-- Revision A (0420025c3b4b): transactional, metadata only.
SET LOCAL lock_timeout = '5s';
ALTER TABLE core.outbox_events
    ADD COLUMN external_started_at timestamptz NULL,
    ADD COLUMN external_started_claim uuid NULL,
    ADD CONSTRAINT ck_outbox_events_external_started_pair
        CHECK ((external_started_at IS NULL) = (external_started_claim IS NULL)) NOT VALID;
RESET lock_timeout;
-- (Alembic then stamps 0420025c3b4b in the same transaction.)

-- Revision B (f0cc2e656d79), inside op.get_context().autocommit_block():
-- Alembic first COMMITs the open transaction (A's DDL and A's stamp),
-- then runs these statements outside any transaction.
SET lock_timeout = '5s';
ALTER TABLE core.outbox_events VALIDATE CONSTRAINT ck_outbox_events_external_started_pair;
RESET lock_timeout;           -- in a finally: also runs when VALIDATE fails
-- (Alembic then begins a new transaction and stamps f0cc2e656d79.)
```

`SET LOCAL` in A ends with the transaction; the `RESET` is still needed because the same transaction carries every later revision of the run. In B the `SET` is session-level, because in autocommit mode each statement is its own transaction and `SET LOCAL` would not reach the `VALIDATE`.

### 4a.4 Downgrade SQL

```sql
-- Revision B downgrade: nothing. A validated constraint cannot be un-validated;
-- the stamp moves back to 0420025c3b4b.
-- Revision A downgrade:
SET LOCAL lock_timeout = '5s';
ALTER TABLE core.outbox_events
    DROP CONSTRAINT ck_outbox_events_external_started_pair,
    DROP COLUMN external_started_claim,
    DROP COLUMN external_started_at;
RESET lock_timeout;
```

### 4a.5 Proposed revision files and dependency chain

| File (documentation only) | Revision | `down_revision` |
|---|---|---|
| `docs/architecture/proposals/crash-recovery/0420025c3b4b_add_outbox_external_started_marker.py.txt` | `0420025c3b4b` (A) | `b3d5f7a9c2e4` |
| `docs/architecture/proposals/crash-recovery/f0cc2e656d79_validate_outbox_external_started_pair.py.txt` | `f0cc2e656d79` (B) | `0420025c3b4b` |

```text
... -> f6a2c8e4b1d9 -> b3d5f7a9c2e4 (main head today)
                          -> 0420025c3b4b  (A: columns + NOT VALID pair check)
                          -> f0cc2e656d79  (B: VALIDATE in autocommit_block)
```

**Re-pointing on implementation.** The ids are real (randomly generated, no collision with the 51 existing revisions or with the open pull requests' ids), but `down_revision` of A must be set to whatever the migration head of `main` is when the implementation is written. Pull requests #192 and #198 add `c5e8a1d3f7b2 -> d7e2a9c4f1b6 -> e8f3b1d5a2c7`; if they merge first, the chain becomes `... b3d5f7a9c2e4 -> c5e8a1d3f7b2 -> d7e2a9c4f1b6 -> e8f3b1d5a2c7 -> 0420025c3b4b -> f0cc2e656d79`, and `_EXPECTED_HEAD` in `tests/infra/db/test_migration_graph_unit.py` moves to B's id. The files are kept out of every tool: the `.py.txt` suffix is not a Python source for ruff (`ruff check .` and `ruff format --check .` pass with them present) or a test module for pytest, and Alembic reads only `saas_os/infra/db/migrations/versions/` (the graph test passes unchanged: 7 tests).

### 4a.6 Migration tests (measured)

Data: 50 tenants and 1,000,000 events (195 MB) seeded at `b3d5f7a9c2e4`: 940,000 published; 10,000 dead-lettered; 50,000 pending, of which 10,000 due and unclaimed, 10,000 claimed with a live lease, 10,000 claimed with an expired lease, 20,000 waiting for a retry. Tenant T1 holds 200 to 400 of each kind.

| Test | Result |
|---|---|
| **A stamped before B's `autocommit_block()` runs.** A `before_cursor_execute` hook, at the moment B's `VALIDATE` was about to run, read `alembic_version_saas_os` from a **separate connection**, then took `SHARE UPDATE EXCLUSIVE` on the table from another session so the `VALIDATE` blocked; 2 s later read it again plus `pg_locks` of the migration backend | Statement log: `UPDATE alembic_version_saas_os SET version_num='0420025c3b4b'` → `COMMIT` → `SET lock_timeout` → `VALIDATE`. The separate connection saw `0420025c3b4b`, both columns, and the constraint `convalidated = false`, before and while `VALIDATE` waited. The migration backend held only `ShareUpdateExclusiveLock` (not granted, `wait_event_type Lock`, no transaction id): A's `AccessExclusiveLock` was already released. After the blocker released (3 s), `VALIDATE` finished and `f0cc2e656d79` was stamped in a third commit |
| Upgrade from `b3d5f7a9c2e4` with the data above | A: `ALTER` 14 to 16 ms; `pg_relation_filenode` unchanged (17777, no rewrite); 1,000,000 rows with both columns `NULL`. B: `VALIDATE` 0.19 to 0.31 s on 1M rows. Final: `f0cc2e656d79`, constraint validated |
| Downgrade B | Stamp only, `0420025c3b4b`; constraint stays validated; columns kept |
| Downgrade A | `ALTER ... DROP` 11 ms, filenode unchanged, 1,000,000 rows kept, stamp `b3d5f7a9c2e4` |
| Re-upgrade A, then B | As above; the down-and-up cycle was repeated before each of the tests below, with the same results |
| Fresh install to head (empty database) | Three commits: (1) all 51 earlier revisions plus A and A's stamp, (2) B's `autocommit_block`, (3) B's stamp. Head `f0cc2e656d79`, constraint validated. Downgrade to `b3d5f7a9c2e4` and re-upgrade on it: OK |
| **B fails on lock timeout:** `SHARE UPDATE EXCLUSIVE` held for 7 s by another session | `VALIDATE` failed after 5.0 s with `LockNotAvailable`; `RESET lock_timeout` still ran; stamp stays `0420025c3b4b`, columns present, constraint `NOT VALID` (still enforced on writes). Re-running `upgrade head` ran only B and succeeded (0.30 s) |
| **B fails on a violating row** (simulated: the check dropped, one dead-lettered row given only `external_started_at`, the check re-added `NOT VALID`) | `VALIDATE` failed with `CheckViolation ... is violated by some row`; stamp stays `0420025c3b4b`. The query in 4a.11 found the one row; after it was fixed, re-running `upgrade head` succeeded |

### 4a.7 Runtime scenarios (measured, two or three sessions as `saas_os_app`)

The statements are the ones proposed in 4a.9; time is passed as a parameter so lease expiry is simulated without waiting. 24 checks, 0 failures:

| # | Scenario | Observed |
|---|---|---|
| 1 | Two concurrent claims of the same due event | Session A locked it; session B's `FOR UPDATE SKIP LOCKED` returned 0 rows without waiting; after A committed, B found nothing due (lease in the future) |
| 2 | Marker write by the current claim; a duplicated job with the same claim | 1 row, then 0 rows (`external_started_claim IS DISTINCT FROM :claim`); only one request may start |
| 3 | Crash after possible transmission, lease expires, reclaim | The reclaim read `external_started_claim = claim_token` (the expired claim): ambiguous |
| 3a | …consumer declared idempotent: reclaimed with a new claim c2 | Row `pending`, `claim_token` c2, marker still c1: **a marker from an expired claim stays representable** |
| 3b | …consumer not idempotent | Dead-lettered, `claim_token` cleared, marker c3 and `external_started_at` kept as evidence |
| 4 | Stale worker c1 after the reclaim: marker write, `complete`, `fail` (all `WHERE id AND claim_token = c1 AND status = 'pending'`) | 0, 0, 0 rows; row unchanged |
| 5 | Current claim c2 writes its own marker (replacing c1's), then completes | Published; claim and marker cleared |
| 6 | Crash before transmission (no marker) | Reclaim saw no marker; retried with a new claim (attempt 2) |
| 7 | Stale marker write racing an uncommitted reclaim | The write waited on the row (`wait_event` `transactionid`, 1.04 s); after the reclaim committed PostgreSQL re-checked `WHERE`: 0 rows; row owned by the new claim, no marker |
| 8 | Reclaim racing an uncommitted marker write | `SKIP LOCKED`: 0 rows in 5 ms, no wait |
| 9 | Clearing only one column | `CheckViolation` on `ck_outbox_events_external_started_pair` |

**Ambiguity rule** that follows from D1: at reclaim, an event is ambiguous if and only if `external_started_claim = claim_token` (the marker belongs to the claim whose lease just expired). A marker from an older claim next to a different `claim_token` means that ambiguity was already resolved (idempotent retry); the current claim never marked, so the event is retried.

**Negative controls** (on a scratch copy of the harness, restored afterwards): removing `AND claim_token = :claim` from the marker write made scenario 7 fail (the stale worker updated 1 row and overwrote the new claim's row); dropping the pair check made scenario 9 fail (half-cleared marker accepted) and check 10c fail. With the original statements and the check restored: 0 failures.

### 4a.8 Tenant isolation and RLS (measured as `saas_os_app`)

- `rolsuper = false`, `rolbypassrls = false`; `has_column_privilege` true for `SELECT`, `INSERT`, `UPDATE` on both new columns from the existing table-level grant. No `GRANT` needed.
- (10a) Under tenant A's scope, tenant B's marked row: `SELECT` 0 rows, `UPDATE` of its marker 0 rows. (10b) With no tenant scope: 0 marked rows visible. (10c) Under B's own scope: its 1 marked row visible and clearable. (10d) Inserting a marked row for B under A's scope: `new row violates row-level security policy`.
- No new table and no policy change: `outbox_events_tenant_isolation` is `FOR ALL` and row-level, so it covers the new columns; the isolation registry and the RLS coverage sweep are unaffected.

### 4a.9 Runtime statements (for the implementation; not part of the DDL)

| Moment | Statement (under the tenant's RLS scope) | 0 rows means |
|---|---|---|
| Consumer enters `context.external_effect()` | `UPDATE core.outbox_events SET external_started_at = :at, external_started_claim = :claim, next_attempt_at = :at + :lease WHERE id = :id AND claim_token = :claim AND status = 'pending' AND next_attempt_at > :at AND external_started_claim IS DISTINCT FROM :claim`, committed before the request | Claim superseded, lease expired, or marker already written by this claim: the context manager raises, no request is sent |
| Outcome: `complete_event`, `fail_event` (retry), `release_claim` | Clear both columns with the outcome, same `claim_token` condition as today | Claim superseded: nothing changes |
| Reclaim in `claim_due_events` when `external_started_claim = claim_token` | Idempotent consumer: new claim, marker kept (3a). Otherwise `dead_lettered`, marker kept, `last_error` `CrashAfterStart: outcome unknown; not retried automatically` (3b) | Inside the existing `FOR UPDATE SKIP LOCKED` transaction |
| Operator replay | Clears both columns with the status change, existing audit | — |

The change from the previous draft: the marker write's last condition is `IS DISTINCT FROM :claim` instead of `IS NULL`, because the marker of an expired claim may legitimately still be there after a reclaim (3a, 5).

### 4a.10 Locks and plans (re-verified)

| Statement | Lock on `core.outbox_events` | Measured |
|---|---|---|
| A: `ADD COLUMN` x2 + `ADD CONSTRAINT ... NOT VALID` | `AccessExclusiveLock` | 14 to 16 ms uncontended, no rewrite |
| B: `VALIDATE CONSTRAINT` | `ShareUpdateExclusiveLock` | 0.19 to 0.31 s on 1M rows. While that lock mode was held by another session, an app-role claim of 25 rows plus a marker update completed in 28.8 ms |
| Downgrade A | `AccessExclusiveLock` | 11 ms, no rewrite |
| Marker write | `RowExclusiveLock` + row lock | primary-key lookup |

**`lock_timeout` 5 s behind an open reader** (an app-role transaction that had read one row, holding `AccessShareLock`): revision A's `ALTER` queued (`AccessExclusiveLock`, not granted); a claim query started after it queued as well (`RowShareLock`, not granted). With the reader held 30 s, the `ALTER` failed at 5.3 s with `LockNotAvailable`, stamp unchanged (`b3d5f7a9c2e4`), and the queued claim then ran (waited 4.47 s, 25 rows). With the reader released after 4 s, the `ALTER` committed right after and the claim ran (waited 1.92 s). So the dispatcher stalls at most `lock_timeout`, and a failed A changes nothing.

**Plans** (`EXPLAIN (ANALYZE, BUFFERS)` as `saas_os_app` under T1's scope, three runs each): before the DDL, and after it with 20,000 expired-claim pending rows and 2,935 dead-lettered rows carrying markers:

| Query | Before | After |
|---|---|---|
| Claim/reclaim (`LIMIT 25 FOR UPDATE SKIP LOCKED`) | `Limit -> LockRows -> Incremental Sort -> Index Scan using ix_outbox_events_pending` (`tenant_id = T1 AND next_attempt_at <= now()`), 201 index rows, 25 returned; 235 to 262 shared buffers; 2.06 to 5.59 ms (first run cold) | identical plan and row counts; 262 shared buffers; 3.01 to 3.24 ms |
| `_locked_claimed_row()` | `LockRows -> Index Scan using outbox_events_pkey`; 0.15 to 0.28 ms | identical; 0.18 to 0.26 ms |

No index is proposed: the marker is read only on rows the reclaim query has already locked, and an index on a marker column would make every marker write a non-HOT update.

### 4a.11 Operational recovery and downgrade limitations

**Deployment order:** (1) revision A, (2) revision B (both by one `saas-os-migrate upgrade`), (3) the code that writes and reads markers. Code from before the change runs correctly on the new schema: it never touches the columns, so the pair check never fires. The new code requires the columns, so the migration comes first.

| Situation | State | What the operator does |
|---|---|---|
| **A failed** (lock timeout) | Nothing changed; stamp is the previous revision | Find the blocking sessions: `SELECT a.pid, a.usename, a.state, a.xact_start, left(a.query, 80) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE l.relation = 'core.outbox_events'::regclass AND l.granted;` End or wait for the long transaction, then re-run `saas-os-migrate upgrade`. Do not raise the timeout without accepting that the dispatcher can stall that long |
| **A succeeded, B failed on lock timeout** | Stamp `0420025c3b4b`; columns present; pair check `NOT VALID` but enforced for every write | The application (old or new code) can run. Re-run `saas-os-migrate upgrade` later; only B runs. Same blocking-session query |
| **A succeeded, B failed with `CheckViolation`** | Same as above; at least one existing row has half a marker (possible only if a row was written while the check was absent, e.g. by a manual change) | List them as the migrations role: `SELECT id, tenant_id, status, external_started_at, external_started_claim FROM core.outbox_events WHERE (external_started_at IS NULL) <> (external_started_claim IS NULL);` Record the ids and values. For each, clear both columns (`SET external_started_at = NULL, external_started_claim = NULL`) unless the missing half is known; if the event is pending and a request may have been sent, dead-letter it for a manual check instead. Re-run `saas-os-migrate upgrade` |
| **Rollback of the code only** | Schema at B | No schema action (no claim-matching check, D1). The older code ignores markers: a pending event whose marker equals its `claim_token` (a crash after a possible request) is retried at-least-once by the older code and may be **sent twice**. Before rolling back, list them (`WHERE status = 'pending' AND external_started_claim = claim_token`) and check their destinations. Rows the older code later reclaims or completes may keep a stale marker; it is harmless when the newer code returns, because ambiguity requires `external_started_claim = claim_token` |
| **Downgrade of the schema** | — | Deploy the older code first, then `saas-os-migrate downgrade b3d5f7a9c2e4` (B: stamp only; A: drops the check and both columns). **Markers are lost**: a pending event that carried one falls back to at-least-once and may be sent again; a dead-lettered `CrashAfterStart` event keeps its `last_error` but loses the start time and claim. Export the marked rows first if the evidence is needed |
| Downgrade B only | Stamp `0420025c3b4b` | Nothing else changes; the constraint stays validated (PostgreSQL has no un-validate), so a later re-upgrade of B is a no-op scan |

Limitations: B's downgrade cannot restore the `NOT VALID` state; a downgrade of A takes `AccessExclusiveLock` (bounded by the same 5 s) and loses the marker data; on a fresh install a failure in B leaves the database at A, not at the previous head, because A and every earlier revision were committed by `autocommit_block()`.

### 4a.12 Tests the implementation must add

Upgrade and downgrade of both revisions on a populated table; the A-stamped-before-B order; B re-run after a failure; the pair-check violation; scenarios 1 to 10 above as integration tests through the real dispatcher; the migration-test cleanup rule (no leftover rows that block a later downgrade); `_EXPECTED_HEAD` moved to B.

### 4a.13 Decisions

- D1, D2, D3: decided 2026-11-02 (above).
- **D4 (open):** approve the exact DDL of 4a.3 and 4a.4 and the revision files of 4a.5 for a separate implementation pull request.

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
4. Approval of the migration: the DDL review in section 4a. D1 to D3 were decided on 2026-11-02; D4, the exact DDL, is open (section 4a.13).

Until these are decided, crash recovery stays at-least-once, as today.
