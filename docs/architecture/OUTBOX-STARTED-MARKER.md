# Outbox started marker (crash recovery, decision D4): implementation notes

**Status: implemented in the pull request that adds this file (branch `feat/outbox-started-marker-d4`, stacked on pull request #203); open, not merged.** Decision D4 (the exact DDL) was approved for implementation by the owner on 2026-11-03. Markers are **off by default** (`OUTBOX_EXTERNAL_EFFECT_MARKERS`), and no SaaS OS consumer uses them yet (section 6), so crash recovery on an installation that only upgrades stays at-least-once (ADR-0033) until a consumer adopts `external_effect()` and the operator turns the setting on.

Sources, which this file does not repeat:

- **Design:** pull request #195, `docs/architecture/DURABLE-STARTED-STATE-RECOVERY-DESIGN.md` on branch `docs/crash-recovery-started-state` (head `f5c9561`). Section numbers below ("#195 4a.9") refer to it.
- **DDL review package and independent reproduction on PostgreSQL 16:** pull request #200, `docs/architecture/crash-recovery-d4/` (`README.md`, `INDEPENDENT-REPRODUCTION.md`, `reproduction/`) on branch `docs/crash-recovery-d4-ddl-review` (head `4dd59be`).

## 1. Decisions applied

| Decision | Date | Applied as |
|---|---|---|
| S1: the marker is two columns on `core.outbox_events` | 2026-11-01 | `external_started_at timestamptz NULL`, `external_started_claim uuid NULL` |
| C1: the consumer marks the start with a context manager | 2026-11-01 | `TenantJobContext.external_effect()` |
| Safe retry after a crash only by an explicit, approved consumer opt-in | 2026-11-02 | No opt-in exists and none can be declared: every ambiguous attempt is dead-lettered (section 4) |
| D1: only the paired-value check, no claim-matching check | 2026-11-02 | `ck_outbox_events_external_started_pair`; stale workers are stopped by conditional writes |
| D2: `lock_timeout = '5s'` | 2026-11-02 | Revisions A and B, and A's downgrade |
| D3: two revisions, `VALIDATE` in B inside `autocommit_block()` | 2026-11-02 | `0420025c3b4b` (A), `f0cc2e656d79` (B) |
| Re-pointing: only A's `down_revision` changes, to the head at implementation | 2026-11-02 | `c3f9e1a7b5d2` (verified with `ScriptDirectory.get_heads()` on `origin/feat/retention-approval-api`, `610ce62`) |
| D4: the exact DDL of #195 4a.3 and 4a.4 | 2026-11-03 | This implementation |

## 2. Schema

| Object | Definition |
|---|---|
| `core.outbox_events.external_started_at` | `timestamptz NULL`, no default |
| `core.outbox_events.external_started_claim` | `uuid NULL`, no default, no foreign key |
| `ck_outbox_events_external_started_pair` | `CHECK ((external_started_at IS NULL) = (external_started_claim IS NULL))`, added `NOT VALID` by A, validated by B |

No index, no grant, no policy change: the table-level grant of the application role and the row-level `FOR ALL` policy `outbox_events_tenant_isolation` cover the new columns. The tenant isolation registry and the RLS sweep are table-level and unchanged.

**One deviation from the proposal file, for the schema inventory.** The proposal added both columns and the check in one hand-written `ALTER TABLE`. `saas_os/infra/db/migrations/schema_inventory.py` reads `op.add_column()` calls and would not have seen them (#200, "Differences": the inventory claims completeness by construction). Revision A therefore runs, in one transaction: `SET LOCAL lock_timeout = '5s'`; `op.add_column()` for each column; the `ADD CONSTRAINT ... NOT VALID` through `op.execute()`; `RESET lock_timeout`. The first `ALTER` takes the `ACCESS EXCLUSIVE` lock within the 5 s timeout and the transaction holds it to its commit, as the single statement did. Re-measured on PostgreSQL 16 with these files (pull request evidence).

## 3. Migrations

```text
... -> a9c3e5f7b1d4 -> c3f9e1a7b5d2 (#203) -> 0420025c3b4b (A) -> f0cc2e656d79 (B)
```

- `saas_os/infra/db/migrations/env.py` runs every pending revision of one `upgrade` in one transaction. B's `autocommit_block()` first commits that transaction (A and every earlier revision of the run, with A's stamp), runs `SET lock_timeout = '5s'`, `VALIDATE`, and `RESET lock_timeout` (in a `finally`) outside any transaction, then stamps B in a new transaction.
- **Deployment order:** (1) `saas-os-migrate upgrade` (A and B); (2) the code of this pull request on every API process, dispatcher and worker; (3) only then, and only once no older dispatcher or worker can claim events (older processes stopped, not drained), `OUTBOX_EXTERNAL_EFFECT_MARKERS=true`. Older code runs correctly on the new schema: it never names the columns.
- **Offline SQL** (`alembic ... --sql`) is not a supported way to apply B: under `psql` without `-v ON_ERROR_STOP=1` a failed `VALIDATE` would be followed by B's stamp (#200, finding F4).

| Failure | State afterwards | What the operator does |
|---|---|---|
| A fails (lock timeout) | The whole `upgrade` transaction rolled back, including earlier revisions of the same run; no column, no check | Find the blocker: `SELECT a.pid, a.usename, a.state, a.xact_start, left(a.query, 80) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE l.relation = 'core.outbox_events'::regclass AND l.granted;` End or wait for it, re-run `saas-os-migrate upgrade`. Claims queue behind A for at most 5 s (also when the migration process itself was killed: its backend waits until the timeout) |
| B fails (lock timeout, e.g. behind an anti-wraparound autovacuum) | Stamp `0420025c3b4b`; columns present; check `NOT VALID` but enforced for every write | The application runs. Re-run `saas-os-migrate upgrade`; only B runs |
| B fails with `CheckViolation` | As above; some row holds half a marker (only possible after a manual change) | As the migrations role: `SELECT id, tenant_id, status, external_started_at, external_started_claim FROM core.outbox_events WHERE (external_started_at IS NULL) <> (external_started_claim IS NULL);` Record the values; clear both columns, or dead-letter a pending event whose request may have been sent; re-run the upgrade |
| Fresh install, B fails | Database at A, not empty | Re-run the upgrade |

**Downgrade (accepted limitation: marker values are lost).** Deploy the older code first, then `saas-os-migrate downgrade c3f9e1a7b5d2` (equivalently `0420025c3b4b-1`), and to nothing older: an older target would also run the downgrades of #203, #198 and #192, which refuse on a populated installation. B's downgrade only moves the stamp (PostgreSQL has no "un-validate"); A's drops the check and both columns, metadata only (no rewrite, every row kept). A pending event that carried a marker falls back to at-least-once and may be sent again; a dead-lettered `CrashAfterStart:` event keeps its `last_error` but loses its start time and claim. Export the marked rows first if the evidence is needed: `SELECT id, tenant_id, status, last_error, external_started_at, external_started_claim FROM core.outbox_events WHERE external_started_claim IS NOT NULL;`.

## 4. Runtime

`saas_os/core/outbox/dispatch.py` (module docstring) and `saas_os/api/outbox_dispatcher.py`:

| Moment | Behaviour |
|---|---|
| Consumer enters `context.external_effect()` | `mark_external_effect_started()`: one committed `UPDATE ... SET external_started_at = :at, external_started_claim = :claim, next_attempt_at = :at + lease WHERE id = :id AND claim_token = :claim AND status = 'pending' AND next_attempt_at > :at AND external_started_claim IS DISTINCT FROM :claim` under the tenant's scope (#195 4a.9). 0 rows (claim superseded, lease expired, or this claim already marked): `ExternalEffectNotStartedError`, the block does not run, and the dispatcher records no outcome for that execution, even if the consumer swallowed the error. Setting off: nothing is written and the block runs as before |
| A second `external_effect()` entry in the same execution, after its marker was written | `ExternalEffectAlreadyStartedError` (a programming error) before the block runs: no second request, nothing written, not a refusal; the execution's outcome is recorded as usual (propagated: dead letter `OutcomeUnknown:`, marker kept; caught and returned: published). With markers off, repeated entries behave as before |
| Reclaim of a lost lease with `external_started_claim = claim_token` | Dead-lettered, claim cleared, marker kept, `last_error` `CrashAfterStart: outcome unknown; not retried automatically`. Takes precedence over the attempt limit |
| Reclaim of a lost lease without the expiring claim's marker | Retried as before (`LeaseExpired: ...`); an older claim's marker does not make it ambiguous |
| `complete_event()`, `release_claim()`, `fail_event()` retry | Both columns cleared with the outcome |
| `fail_event()` for an attempt whose claim marked it (the exception rule, in `fail_event()` itself, against the locked row) | Never a retry: `terminal` dead-letters with the error; anything else (`RetryAfterEventError`, a timeout, any other exception) dead-letters `OutcomeUnknown: <error>`. Marker kept |
| Any other dead letter | Marker kept as evidence |
| Operator replay (`replay-outbox-events`) | Clears both columns with the status change; the next attempt is judged afresh |
| Stale worker (old claim) | Every write names the claim, so it changes nothing |

The setting gates marker **writes** only; markers already stored are read whatever it says. **Rolling back the code** with markers on: turn the setting off first, let in-flight leases expire (or list `WHERE status = 'pending' AND external_started_claim = claim_token` and check those destinations), then deploy the older code, which ignores markers and would retry such an event.

## 5. Evidence

The pull request body records the exact commands and results on its final head: PostgreSQL 16 and Redis 7, the migration tests (`tests/infra/db/test_outbox_started_marker_migration.py`), the runtime tests (`tests/core/outbox/test_outbox_started_marker_integration.py`), real worker processes killed before, during and after the marker (`tests/core/outbox/test_outbox_started_marker_crash_integration.py`), #200's reproduction harness adapted to the real migrations (populated round trip, commit order, lock timeouts, B failure and re-run, migration process crashes), the repository migration gate and negative controls.

## 6. Not implemented here (listed, not decided)

- **No consumer uses `external_effect()` yet.** #195 option C1 names webhooks and notifications. On this branch, #197's outcome classes (`ConfirmedNotSentError`, `AmbiguousOutcomeError` with `at_least_once`, `record_ambiguous_outcome()`) do not exist, so after a marker every transient webhook or e-mail failure (a `503`, a connection refused before any byte was sent) would be dead-lettered instead of retried. Wiring the consumers needs #197 merged and the exception rule's `ConfirmedNotSentError` and `at_least_once` branches (#195 4a.9) added; that is a separate change.
- **The per-consumer safe-retry opt-in** (#195 3.1) and the reclaim deadline `created_at + retry_within`: no consumer is approved, so no registration mechanism is exposed; every ambiguous attempt is dead-lettered.
- **#189** (`ConsumerTimedOut:` dead letters) is not on this branch; when it merges, its dead letter must keep the marker (it goes through `fail_event(terminal=True)` or must follow the same rule).
- **A definitive refusal received after sending** (for example HTTP `429` with `Retry-After`): dead-lettered after a marker, as #195 4a.9 leaves it until a later decision.
- **Query plans** of #195 4a.10 were not re-measured; the claim query does not read the new columns.
