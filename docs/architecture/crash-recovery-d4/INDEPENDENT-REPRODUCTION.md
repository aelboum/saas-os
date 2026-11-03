# Crash recovery D4: independent reproduction on PostgreSQL 16

## Status

**D4 is still not approved and nothing is implemented.** This record adds
evidence only. No migration was added to `saas_os/`, no runtime code was
changed on any branch, and #195 stays unimplemented. The two proposed
revisions were run only in throwaway Alembic environments assembled outside
the repository (the session scratchpad), against disposable
`postgres:16-alpine` containers holding synthetic data, all removed
afterwards. Crash recovery on `main` stays at-least-once.

The reproduction was made on 2026-11-03 (times UTC) by a reviewer that did
not author #195 or this package (#200). None of the authoring agent's
scripts, logs or measurements were reused: every script in
`reproduction/` was written for this record, and every number below was
measured here.

## Environment

| What | Value |
|---|---|
| Server | `PostgreSQL 16.15 on x86_64-pc-linux-musl, compiled by gcc (Alpine 15.2.0) 15.2.0, 64-bit`, image `postgres:16-alpine` `sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`, Docker 29.8.2 on Windows 11, each container capped at 1 GB |
| Containers | `d4r-pg` (items 1 to 8, 10, owner's list), `d4r-pg2` with `d4r-redis` (`redis:7-alpine`, Redis 7.4.11) (item 9), `d4r-pg3` with a new `d4r-redis` (final reruns of items 8 and 10 and the runtime scenarios, then item 11; created after a host reboot removed the earlier containers); roles created with the repository's `01-create-app-role.sh` and `02-create-platform-config-role.sh` |
| Client | Python 3.13.14 (the repository venv), Alembic 1.20.0, SQLAlchemy 2.1.2, psycopg 3.3.6, pytest 9.1.1 |
| Re-pointed chain ("tree R") | `git archive` of #198's head `43cebce` (its four revisions are byte-identical to those at `40a0888` and `03dd1a1`: empty `git diff`), plus the two `.py.txt` files renamed to `.py`, with one line changed in A: `down_revision` `b3d5f7a9c2e4` -> `a9c3e5f7b1d4` (the `Revises:` docstring line was left as is); `_EXPECTED_HEAD` in that copy's graph test set to `f0cc2e656d79` |
| Tested chain ("tree T") | `git archive` of `main` `6fd2dfd` plus the two files renamed to `.py`, unchanged; `_EXPECTED_HEAD` in that copy set to `f0cc2e656d79` |
| Files under test | SHA-256 A `ff660bb1a6f37c40a57b1eab745576d33610bf73af1ce9d2e82ac167eb2a3964`, B `458736d1960603c7f3b29f2accbbcc1b80aed4449d75cb11f93082363668e1ca`: identical to this package's `.py.txt` files and to #195's (`f5c9561`) |
| Migration path | `saas-os-migrate` itself (`python -m saas_os.infra.db.migration_cli`), or `reproduction/migrate_driver.py.txt`, which calls the same two runner functions with SQLAlchemy event listeners for statement timing; `env.py` was not modified (byte-identical to `main`) |
| Server evidence | `ALTER ROLE saas_os SET log_statement = 'all'` and `log_min_duration_statement = 0` for the migrations role, `log_lock_waits = on`; the harness's own sessions turn statement logging off, so the log holds the migration sessions' statements |

## Results

PASS means every check of the item held on the run reported here; reruns
are listed under "Anomalies and reruns". UNVERIFIED means it could not be
reproduced without the unimplemented runtime.

| # | Item (README section 10, then the owner's list) | Result | Evidence |
|---|---|---|---|
| 1 | Graph and head | PASS | Tree R: one head `f0cc2e656d79`, one base, 57 revisions = 57 files, 55 before A; graph unit test 7 passed (tree R and tree T, `_EXPECTED_HEAD` moved); neither id among the 55 distinct revision ids of all 119 remote branches |
| 2 | Offline SQL | PASS | Tree R `--sql` output identical to the bodies of `upgrade.sql` and `downgrade.sql` (pragma suffixes and CR removed); tree T differs only in the stamp line naming A's `down_revision` and the `-- Running` comment |
| 3 | Round trip on populated data | PASS | 1,000,000 events in every listed status; after each of 7 steps: stamp, columns, `convalidated`, 1,000,000 rows, filenode 18436 and the original columns' checksum unchanged; 3,000 marked rows survive the downgrade, their markers are gone |
| 4 | Timing | PASS (measured) | A 4.8 to 9.0 ms (all uncontended runs 1.4 to 9.0 ms); B 231 to 277 ms uncontended; downgrade A 4.6 to 8.6 ms |
| 5 | Order of commits | PASS | While B waited: stamp A, `convalidated = false`, migration backend holding only an ungranted `ShareUpdateExclusiveLock` (and its `virtualxid`), no xid; server log stamp `UPDATE` to `0420025c3b4b` -> `COMMIT` -> `SET` -> `VALIDATE` |
| 6 | Lock observation | PASS | A queued behind a reader, a later claim queued behind A (`RowShareLock` not granted), A failed at 5,003 ms with `55P03`, stamp unchanged, claim then returned 25 rows (waited 4.97 s); during B a claim and an outcome `UPDATE` ran without waiting (25 ms / 4 ms held lock; 100 overlapping iterations, max 14 ms, no lock wait) |
| 7 | B failure and re-run | PASS | `55P03` at 5,003 ms, `SHOW lock_timeout` `0` after the `RESET`, stamp A, re-run ran only B; violating row: `23514`, stamp A, operator query found exactly that row, re-run applied B |
| 8 | RLS and runtime as `saas_os_app` | PASS | 19 checks: role flags, column privileges from the table grant (no column ACL), cross-tenant invisible and unwritable, nothing visible without scope, insert for B under A refused (`42501`), half marker `CheckViolation` |
| 9 | Old code on the new schema | PASS | `main`'s outbox integration tests, unchanged, on the tested chain at `f0cc2e656d79`: 102 passed, 0 skipped; `main`'s functions end to end (append, claim, begin, complete, fail, terminal fail, release, dead letter by attempts, replay): 11 checks; every row's new columns `NULL` |
| 10 | Fresh install, B fails | PASS | One `upgrade head` on an empty database: 55 earlier revisions and A committed together, B failed (`55P03`), stamp A, check `NOT VALID`; re-run applied only B. Happy path: three commits |
| 11 | Migration gate tests with the files in place | PASS with one UNVERIFIED test | Tree R: graph and schema-inventory unit tests 43 passed; 101 of 102 migration integration tests passed (gate, all rollback and migration tests); the reference-consumer test failed in this Windows scratch location with and without A and B (path length), so it is UNVERIFIED here; afterwards `downgrade base` and `upgrade` exit 0 |
| O1 | Migration A and B | PASS | items 2, 3, 5, 10 |
| O2 | Upgrade, downgrade (B only, A, relative `0420025c3b4b-1`), re-upgrade | PASS | item 3 |
| O3 | Constraint validation | PASS | `NOT VALID` after A and still enforced on writes; validated by B; B fails on a violating row; downgrade of B keeps it validated |
| O4 | Lock timeout and retry | PASS | items 6, 7, 10; multi-revision rollback |
| O5 | Concurrent claim/reclaim | PASS | S1, S3, S7, S8 from separate connections, both orderings (reclaim decision is a reconstruction, see below) |
| O6 | RLS | PASS | item 8 |
| O7 | Stale-worker conditional writes | PASS | S4, S7; negative control `nc_claim` detected |
| O8 | Crash scenarios | PASS, with UNVERIFIED parts | real worker processes killed before, during and after the marker (S3, S3c, S6); migration process killed during A and B, B's backend terminated; the runtime that would act on them is not implemented (see "Not verified") |
| O9 | Data preservation and rollback | PASS | item 3; A failure rolls back the whole run, including earlier revisions of that run |

## Method and observations

### Items 1 and 2: graph, head and offline SQL (no database)

- `PYTHONPATH=. python graph_check.py.txt <ids>` in each tree, where `<ids>`
  lists every revision id under `saas_os/infra/db/migrations/versions/` on
  all 119 remote branches (`git ls-tree` of each `origin/*` ref, 55 distinct
  ids). Tree R: one head, `f0cc2e656d79`, one base `e99c76057719`, 57
  revisions for 57 files, chain `f0cc2e656d79 <- 0420025c3b4b <- a9c3e5f7b1d4
  <- e8f3b1d5a2c7 <- d7e2a9c4f1b6 <- c5e8a1d3f7b2 <- b3d5f7a9c2e4`, 55
  revisions before A; no collision. Tree T: 53 revisions, 51 before A, no
  collision.
- `pytest -m "not integration" tests/infra/db/test_migration_graph_unit.py`
  in each tree, with `_EXPECTED_HEAD` set to `f0cc2e656d79`: 7 passed, 7 passed.
- `offline_sql.sh.txt`: `python -m alembic -c alembic.ini upgrade
  a9c3e5f7b1d4:f0cc2e656d79 --sql` and `downgrade f0cc2e656d79:a9c3e5f7b1d4
  --sql` in tree R, the same with `b3d5f7a9c2e4` in tree T, with
  `MIGRATIONS_DATABASE_URL=postgresql+psycopg://offline@offline.invalid/offline`
  (never contacted). The tree R output is identical, line for line, to the
  body of `upgrade.sql` and `downgrade.sql` (the lines after the dashed
  separator, without the `-- pragma: allowlist secret` suffixes; CR removed).
  Tree T differs from tree R in two lines per file: the `-- Running ...`
  comment and the stamp `UPDATE` that names A's `down_revision`.

### Items 3 and 4: round trip and timing on 1,000,000 events

Container `d4r-pg`, tree R, run by `populated.sh.txt 1000000` under the
heavy-run lock (available memory 3,603 MB at the start), 09:05:49 to 09:12:03.

- Seed (`seed.sql`, `psql -v n=1000000`, at `a9c3e5f7b1d4`): 50 tenants,
  1,000,000 events in 30.2 s: 900,000 published; 40,000 dead-lettered;
  20,000 pending due and unclaimed; 10,000 pending claimed with a live lease
  (expires in one day); 10,000 pending claimed with an expired lease; 20,000
  pending waiting for a retry. Heap 229 MB, 274 MB with indexes. Then
  `VACUUM (ANALYZE)` and `CHECKPOINT`, so that autovacuum would not take the
  table's `SHARE UPDATE EXCLUSIVE` lock during the lock measurements.
- Each step is `saas-os-migrate` (`python -m saas_os.infra.db.migration_cli`)
  followed by a snapshot as the migrations role: stamp,
  `information_schema.columns` for both columns, `pg_constraint`
  (`convalidated` and definition), `pg_relation_filenode`, row count, counts
  per status, and a checksum over the original 15 columns
  (`sum(('x' || left(md5(ROW(...)::text), 15))::bit(60)::bigint)`).
- `upgrade head`: stamp `f0cc2e656d79`; both columns `YES` nullable with no
  default; check validated; 1,000,000 rows; filenode 18436 before and after;
  checksum `576291477178979144206158` before and after; no row with a marker.
- Markers set (admin SQL, a data fixture): 1,000 pending live-lease rows and
  1,000 pending expired-lease rows marked with their own `claim_token`;
  1,000 dead-lettered rows with a kept marker; ids and values saved in a
  scratch table. The original columns' checksum did not change.
- `downgrade 0420025c3b4b` (B only): stamp A, check still validated, both
  columns and all 3,000 markers kept.
- `downgrade a9c3e5f7b1d4`: stamp `a9c3e5f7b1d4`, both columns and the check
  gone, 1,000,000 rows, filenode 18436, checksum unchanged, all 3,000 marked
  rows still present.
- `upgrade head` again: as the first upgrade; the 3,000 marked rows now have
  both columns `NULL` (the data loss README section 5 describes).
- Also exercised: `downgrade 0420025c3b4b-1` (Alembic's relative form, "not
  exercised" in #195 4a.11) reached `a9c3e5f7b1d4`; `upgrade head` again.
- Timing, from the server's `duration:` lines of the migration sessions on
  the populated table (uncontended):

| Statement | Lock | Measured (server) |
|---|---|---|
| A: `ALTER TABLE ... ADD COLUMN ... NOT VALID` | `AccessExclusiveLock` | 9.0, 5.8 and 4.8 ms in the round trip; 1.4 to 5.4 ms in the five later uncontended runs |
| B: `VALIDATE CONSTRAINT` | `ShareUpdateExclusiveLock` | 238, 271 and 251 ms in the round trip; 231 to 277 ms in the five later uncontended runs; 381 ms while the two app-role loops of item 6 ran |
| Downgrade A: `DROP CONSTRAINT, DROP COLUMN x2` | `AccessExclusiveLock` | 8.6, 6.4 and 6.0 ms in the round trip; 4.6 to 6.1 ms later |

### Item 5: order of commits (no hook inside Alembic)

`harness.py.txt order`, from `a9c3e5f7b1d4`, 1,000,000 events. Method,
chosen to need no instrumentation of the migration process: an app-role
transaction that has read one row holds `AccessShareLock`; `upgrade head`
starts and A's `ALTER` queues for `AccessExclusiveLock`; a third session's
`LOCK TABLE core.outbox_events IN SHARE UPDATE EXCLUSIVE MODE` then queues
behind A (server log: "Wait queue: 665, 666"). When the reader ends, A gets
its lock, runs and commits; the queued `SHARE UPDATE EXCLUSIVE` request is
granted at that commit, and B's `VALIDATE`, issued after the commit, waits
behind it. Observed from a fourth connection, twice, one second apart, while
B waited: stamp `0420025c3b4b`, both columns present, `convalidated = false`;
the migration backend's locks were exactly an ungranted
`ShareUpdateExclusiveLock` on `core.outbox_events` plus its own `virtualxid`
(no `AccessExclusiveLock`), `wait_event` `Lock/relation`, no `backend_xid`.
Server-side order of the migration session: `SET LOCAL lock_timeout`,
`ALTER ... ADD` (acquired after 1,056 ms), `RESET lock_timeout`, stamp `UPDATE` to
`0420025c3b4b`, `COMMIT`, `BEGIN`, `ROLLBACK`, `SET lock_timeout = '5s'`,
`VALIDATE` (acquired after 2,994 ms, when the third session committed),
`RESET lock_timeout`, `BEGIN ISOLATION LEVEL READ COMMITTED`, stamp `UPDATE` to
`f0cc2e656d79`, `COMMIT`. The run ended at `f0cc2e656d79`, validated.

### Item 6: lock observation with concurrent app-role sessions

`harness.py.txt lock_a never|2` and `scan_b`, 1,000,000 events. The claim is
`main`'s exact claim statement (below) as `saas_os_app` under the tenant's
scope, `LIMIT 25`.

- Reader held: A queued (`AccessExclusiveLock`, not granted); a claim
  started after it queued too (`RowShareLock`, not granted). A failed with
  `LockNotAvailable` (SQLSTATE `55P03`) after 5,003 ms; the stamp stayed
  `a9c3e5f7b1d4` with no column and no check; the queued claim then returned
  25 rows after waiting 4.97 s.
- Reader released 2.0 s after A started waiting: A's `ALTER` completed
  (2,014 ms including the wait), the queued claim returned 25 rows after
  2.02 s, and the run reached `f0cc2e656d79`.
- During B, method 1: from state A, the real statement
  `ALTER TABLE core.outbox_events VALIDATE CONSTRAINT
  ck_outbox_events_external_started_pair` run by hand inside an open
  transaction (scan 0.29 s; the session then held `ShareUpdateExclusiveLock`,
  granted). While it was held, an app-role claim returned 25 rows in 25.0 ms
  and an outcome `UPDATE` of one claimed row took 4.2 ms; rolled back, check
  `NOT VALID` again.
- During B, method 2: the real B (`upgrade head` from A) while two app-role
  loops ran (the claim; an outcome-style `UPDATE` of a pending row that is not
  due, so the loops never row-lock each other) and a sampler read
  `pg_stat_activity` every ~2 ms. 1,346 loop iterations, 100 of them
  overlapping the `VALIDATE` (382.8 ms client-side), slowest overlapping
  14.1 ms, slowest overall 24.2 ms; the sampler saw no session waiting on a
  lock.

### Item 7: B failure and re-run

`harness.py.txt fail_b` and `viol_b`, 1,000,000 events, from state A.

- Lock timeout: another session held `SHARE UPDATE EXCLUSIVE` (6.7 s).
  `VALIDATE` failed with `LockNotAvailable` (`55P03`) after 5,003 ms. On the
  migration session `SHOW lock_timeout` read `5s` after the `SET` and `0`
  after the `RESET` that ran after the failure (the driver reads it on the
  same DBAPI connection; the server log shows the `RESET` after the
  `ERROR`). Stamp `0420025c3b4b`, both columns, check `NOT VALID`; while
  `NOT VALID`, an app-role `UPDATE` setting only `external_started_at`
  raised `CheckViolation`. Re-running `upgrade head` ran only
  `0420025c3b4b -> f0cc2e656d79` and validated the check.
- Violating row: in one admin transaction the check was dropped, one
  dead-lettered row given only `external_started_at`, and the check re-added
  `NOT VALID` with the same definition. `upgrade head` failed with
  `CheckViolation` (`23514`, "is violated by some row"); `RESET` ran; stamp
  A. The README's operator query
  (`WHERE (external_started_at IS NULL) <> (external_started_claim IS NULL)`)
  returned exactly that row; after clearing it, the re-run applied only B.

### Item 8: RLS and grants as `saas_os_app`

`harness.py.txt rls` (19 checks; final run in `d4r-pg3`, 10:08 UTC). `rolsuper` and `rolbypassrls` false;
`has_column_privilege` true for `SELECT`, `INSERT`, `UPDATE` on both columns;
`pg_attribute.attacl` is `NULL` for both (no column-level grant; the table
ACL is `saas_os_app=arwd/saas_os`); `ENABLE` and `FORCE ROW LEVEL SECURITY`;
one policy, `outbox_events_tenant_isolation`, `PERMISSIVE`, command `ALL`,
`USING` on `tenant_id`, no separate `WITH CHECK`. Under tenant A's scope:
B's marked row is invisible (0), clearing its marker updates 0 rows, the
exact marker write on it updates 0 rows. With the scope set to `''`, and on
a new connection that never set it: nothing visible. Under B's scope its
marked row is visible and clearable (both columns, 1 row). Inserting a marked
row for B under A's scope, and moving A's row to B, raise `42501 new row
violates row-level security policy`. Clearing one column, and inserting half
a marker, raise `CheckViolation` on `ck_outbox_events_external_started_pair`.
B's row was unchanged afterwards.

### Item 10: fresh install, B fails

`harness.py.txt fresh_fail` (final run in `d4r-pg3`, 10:08 UTC), empty
database, tree R, one `upgrade head` run. To block B deterministically on a table that does not exist before the
run, a server-side event trigger (`ddl_command_start`, `ALTER TABLE` only,
acting only when the statement is B's `VALIDATE`) pauses that statement 2 s
before it takes its table lock; a blocker session, polling for the check to
become visible, took `SHARE UPDATE EXCLUSIVE` within 20 ms of A's commit
and held it 8 s. The trigger was dropped before the re-run. Result: the first
transaction (`BEGIN` ... `COMMIT`, one `INSERT` and 55 `UPDATE`s of the
stamp: the 55 earlier revisions and A) committed; `VALIDATE` failed with
`LockNotAvailable` 7,012 ms after it started (2 s pause + 5 s
`lock_timeout`); `RESET` ran (`SHOW lock_timeout` = `0`). While B waited and
after the failure: stamp `0420025c3b4b`, check `NOT VALID`, both columns,
tables of the first revision and of #198's revisions present, migration
backend without `AccessExclusiveLock`. The re-run applied only B; check
validated. Happy path (`fresh_ok`, a second empty database): three commits
in the server log: (1) the 55 earlier revisions and A with its stamp,
(2) `VALIDATE` in autocommit, (3) B's stamp; head `f0cc2e656d79`, validated.

### Item 9: `main`'s code, unchanged, on the migrated schema

Containers `d4r-pg2` and `d4r-redis`, tree T (tested chain), under the
heavy-run lock, `item9_old_code.sh.txt`, 09:35 to 09:41 UTC.
`saas-os-migrate upgrade` reached `f0cc2e656d79`. Then `pytest -m
integration` of `main`'s outbox tests, unchanged:
`tests/core/outbox/test_outbox_integration.py`,
`test_outbox_dispatch_integration.py`, `test_outbox_consumption_integration.py`,
`tests/api/test_outbox_dispatcher_integration.py`,
`test_outbox_consumer_idempotency_integration.py`,
`tests/core/platform_authority/test_outbox_replay_integration.py`,
`tests/infra/db/test_outbox_migration_rollback.py` (which downgrades below
the outbox table and upgrades back through A and B) and
`test_outbox_replay_permission_migration.py`: **102 passed**, 0 failed,
0 skipped, 80.8 s. Then `old_code.py.txt` called `main`'s own functions:
`append_event` x5, `claim_due_events`, `begin_event_execution`,
`complete_event`, `fail_event` (retry), `fail_event(terminal=True)`,
`release_claim`, two lost leases ending in a dead letter by exhausted
attempts, and `replay_dead_lettered_events` by an operator holding
`platform.outbox:replay` (2 replayed): 11 checks PASS; every row of the run
and of the table had both new columns `NULL`; end state stamp
`f0cc2e656d79`, check validated.

### Owner's list: runtime behaviour as `saas_os_app` from real connections

`harness.py.txt scenarios normal` (52 checks), four complete runs: on `d4r-pg`
(small data), on `d4r-pg` with the 1,000,000 events present, and as the
final run on `d4r-pg3` before and after the negative controls. Every
concurrent case uses two or three separate connections (threads), and every
crash case a separate OS process killed with `TerminateProcess` (no clean
disconnect, no `COMMIT`). Time is passed as a parameter, so a lease expiry
is simulated without waiting; lease 300 s.

| # | Scenario | Observed |
|---|---|---|
| S1 | Two claims of one due event, both orderings | the first locks and claims it; the second's `FOR UPDATE SKIP LOCKED` returns 0 rows in 14 to 33 ms over the four runs; after the first commits nothing is due for the second; claimed once |
| S2 | Duplicated job, same claim: sequential, and concurrent in both orderings | marker write 1 row, duplicate 0 rows; concurrently the second waits on the row (`Lock/transactionid`) and after the first commits updates 0 rows |
| S3 | Worker commits its marker, process killed, lease expires, reclaim | marker survives the crash; the reclaim sees `external_started_claim = claim_token`: without opt-in, `dead_lettered`, claim cleared, marker kept, `last_error` `CrashAfterStart: outcome unknown; not retried automatically`; with opt-in, `pending` with a new claim c2 and the marker of c1 kept |
| S3c | Worker killed while its marker `UPDATE` is uncommitted | a reclaim meanwhile skips the row (14 to 25 ms, no wait); the server rolls the write back when the process dies; the reclaim then retries it as "never started" |
| S4 | Stale worker c1 after the reclaim | marker write, complete, fail-retry and dead-letter statements of c1 update 0 rows each; `main`'s own row-lock check (`_locked_claimed_row`) refuses c1 and accepts c2; row unchanged |
| S5 | Current claim c2 writes its own marker over c1's, then completes | marker replaced (`IS DISTINCT FROM`); published, claim and both columns cleared |
| S6 | Crash before transmission (no marker) | retried with a new claim, attempt 2, `LeaseExpired` recorded |
| S7 | Stale marker write racing an uncommitted reclaim; the stale worker's clock still inside its lease, so only `claim_token = :claim` can stop it | the write waits on the row; after the reclaim commits PostgreSQL re-checks the `WHERE`: 0 rows; row owned by the new claim, no marker |
| S8 | Reclaim racing an uncommitted marker write (other ordering) | the reclaim skips the row, no wait (13 to 15 ms); the committed marker moved `next_attempt_at` to `at + lease`, so the row is not due at the old expiry; due after the new one, it is ambiguous and dead-lettered |
| S9 | Marker write after the claim's own lease expired | 0 rows (`next_attempt_at > :at`): no request may start |
| S10 | Marker of an old claim c1 next to claim c2 that never marked; c2's lease expires | not ambiguous: plain retry |
| S11 | Clearing only one column (each column) | `CheckViolation` |
| — | Dead letter keeps the marker; replay clears both columns with the status change; the next claim is judged afresh; the `fail_event()` retry form clears both columns | as stated |
| — | Old code's reclaim (no marker check) on a crashed-after-marker event | retried: the duplicate D4 exists to prevent (the rolling-deploy hazard of #195 4a.11) |

Negative controls (final run, each restores itself: the statement variants
exist only in the harness, the dropped check is inside a transaction that is
rolled back, and a full `normal` run passed afterwards, 52 PASS):

| Control | Expected failure | Observed |
|---|---|---|
| `nc_claim`: marker write without `AND claim_token = :claim` | S7 | the stale write updated 1 row and put c1's marker on c2's row: 2 checks FAIL |
| `nc_distinct`: without `AND external_started_claim IS DISTINCT FROM :claim` | S2 | the duplicate write updated 1 row: 1 check FAIL |
| `nc_check`: pair check dropped (admin transaction, `SET LOCAL ROLE saas_os_app`) | S11 | half-cleared marker accepted (1 row): 1 check FAIL; after `ROLLBACK` the check is back and validated |

### Migration crashes, data preservation and rollback

`harness.py.txt crash_migrate` and `multi_rollback`, 1,000,000 events.

- Migration process killed while A waited behind a reader: nothing changed
  (stamp `a9c3e5f7b1d4`, no column, no check). The server backend did not
  notice the dead client while it waited on the lock: it ended 5.0 s after
  the kill, when `lock_timeout` fired.
- Killed while B's `VALIDATE` waited: stamp `0420025c3b4b`, check `NOT
  VALID`; the backend likewise ended 5.0 s after the kill. B's backend
  terminated server-side (`pg_terminate_backend`) while waiting: the run
  failed, stamp `0420025c3b4b`, `NOT VALID`. In both cases the re-run applied
  only B.
- Multi-revision run (throwaway database only: downgraded to
  `b3d5f7a9c2e4`, which README section 5 forbids on a real installation):
  `upgrade head` ran #192's and #198's four revisions and A in one
  transaction; A failed on `lock_timeout` behind a reader; the stamp was
  `b3d5f7a9c2e4` again and #198's two tables did not exist (README section 9,
  row 1). The re-run reached `f0cc2e656d79`.
- Data preservation: item 3 (row count, filenode, checksum of the original
  columns and per-status counts identical before and after every step).

### Item 11: the repository's migration tests with the files in place

`item11_gate.sh.txt` in tree R (re-pointed chain, `_EXPECTED_HEAD` set to
`f0cc2e656d79`), container `d4r-pg3` with an empty database, heavy-run lock,
10:09 to 10:14 UTC.

- Unit: `tests/infra/db/test_migration_graph_unit.py`,
  `tests/core/tenancy/test_isolation_classification.py`,
  `tests/core/tenancy/test_retention_classification.py`: 43 passed.
- `schema_at_head()` (`saas_os/infra/db/migrations/schema_inventory.py`)
  lists 15 columns for `core.outbox_events` and **not** the two new ones:
  it reads only `op.create_table`/`op.add_column`/`op.drop_column` calls,
  and revision A adds the columns with `op.execute`. The classification
  tests above are table-level and pass.
- Integration (`pytest -m integration`):
  `tests/infra/db/test_migration_gate_integration.py`, every other
  `tests/infra/db/test_*migration*.py` and `test_*rollback*.py` (32 files;
  they downgrade through B and A and upgrade back through them), and
  `tests/test_reference_consumer_integration.py` (the third step of
  `scripts/check-migrations.sh`): **101 passed, 1 failed**, 0 skipped,
  243.5 s. The failure is the reference-consumer test: the wheel it builds
  and installs into a new venv did not import (`ModuleNotFoundError: No
  module named 'saas_os'`). Run alone on a copy of #198's tree **without** A
  and B in the same scratch location it also fails, earlier, building the
  wheel (`could not create 'build\bdist.win-amd64\wheel\...\versions\23310e44a21d_...py': No such
  file or directory`, a Windows path-length failure under the deep scratch
  path); a `subst` drive did not help because the test resolves its real
  path. Classified as an environment limit of this local reproduction, not a
  result: UNVERIFIED here. (CI's packaging and migration gates build the
  wheel from the repository's own tree, which does not contain A and B.)
- Leftover rows: after the suite, `saas-os-migrate downgrade b3d5f7a9c2e4`,
  `upgrade`, `downgrade base` and `upgrade` all exited 0 and ended at
  `f0cc2e656d79`: the migration tests left nothing that blocks a downgrade.

## Runtime SQL: exact and reconstructed

| Statement | Source |
|---|---|
| Claim/reclaim `SELECT ... FOR UPDATE SKIP LOCKED` | **Exact**: `main`'s `claim_due_events()` statement compiled with the psycopg dialect (`harness.py.txt`, `CLAIM_SQL`) |
| Row lock `SELECT ... WHERE id = :id FOR UPDATE` | **Exact**: `main`'s `_locked_claimed_row()` (`LOCK_ROW_SQL`) |
| Marker write | **Exact** #195 4a.9: `UPDATE core.outbox_events SET external_started_at = :at, external_started_claim = :claim, next_attempt_at = :at + :lease WHERE id = :id AND claim_token = :claim AND status = 'pending' AND next_attempt_at > :at AND external_started_claim IS DISTINCT FROM :claim` |
| Per-row claim update | **Reconstruction** of the ORM flush of `claim_due_events()`: `UPDATE ... SET attempts, claim_token, next_attempt_at, last_error, updated_at WHERE id = :id` under the row lock |
| Reclaim decision | **Reconstruction** of #195 4a.9: lost lease and `external_started_claim = claim_token` -> dead letter `CrashAfterStart: outcome unknown; not retried automatically`, marker kept, or, with an opt-in, a new claim with the marker kept |
| Complete, fail-retry, dead letter | **Reconstruction** of #195 4a.9 ("clear both columns with the outcome, same `claim_token` condition"; "dead letters keep the marker") as single conditional `UPDATE`s `WHERE id = :id AND claim_token = :claim AND status = 'pending'`; `main`'s own pattern (row lock, then a check in Python) was also checked in S4 |
| Replay | **Reconstruction** of `main`'s `replay_dead_lettered_events()` update plus "clears both columns" |

## Differences from the README and #195

- **Timing.** A's `ALTER` took 1.4 to 9.0 ms here (#195: 14 to 16 ms) and A's
  downgrade 4.6 to 8.6 ms (#195: 11 ms); B's `VALIDATE` 231 to 277 ms
  (#195: 0.19 to 0.31 s). Different hardware and data (heap 229 MB here,
  195 MB in #195); same conclusion: A and its downgrade are metadata-only
  (filenode unchanged), B scans.
- **A behind a reader** failed at 5.0 s here, with the queued claim waiting
  4.97 s (#195: 5.3 s and 4.47 s). Same behaviour.
- **Online statement stream.** Between A's `COMMIT` and B's
  `SET lock_timeout` the online run sends `BEGIN; ROLLBACK;` (SQLAlchemy
  switching the connection to autocommit), every run starts with a
  `BEGIN; ... ROLLBACK;` of dialect checks, and B's stamp transaction is
  `BEGIN ISOLATION LEVEL READ COMMITTED`. README sections 3 and 4 describe
  the offline stream; these extra statements change no state. (The
  `SHOW lock_timeout` statements in the logs are this reproduction's
  instrumentation, not Alembic's.)
- **A killed migration keeps its place in the lock queue until
  `lock_timeout`.** A migration process killed while A or B waited for a
  lock left its server backend waiting until `lock_timeout` fired (5.0 s);
  claims queued behind A stay blocked that long. README section 6 bounds
  the stall by the 5 s timeout, which is what happened; the README does not
  say it also applies to a killed client.
- **Schema inventory.** `schema_at_head()` does not list the two new columns (A adds them with `op.execute`, which the AST inventory does not read). The README says the isolation registry and the RLS coverage sweep are unaffected, which holds (both are table-level), but it does not mention the column inventory. The implementation pull request should either use `op.add_column` or accept and document the gap.
- **#198's head** is `43cebce` today (README: `40a0888`, re-checked
  `03dd1a1`); its migration files are identical across the three.
- **Not in the README, observed:** `downgrade 0420025c3b4b-1` works and
  reaches A's `down_revision` (README: "not exercised" in #195).
- No other difference was found: statement order, lock modes, failure
  states, re-run behaviour, RLS and grants behaved as README sections 4 to 9
  state.

## Anomalies and reruns

Every failure and interruption of this reproduction, in order. None was a
failure of the revisions under test.

1. Item 10, first attempt (08:25 UTC): the harness did not drain the
   migration driver's stderr; the driver blocked on a full pipe in the middle
   of the fresh install. Both of this run's own processes were stopped; the
   uncommitted transaction rolled back (database verified empty). The
   harness was fixed (stderr read by its own thread) and item 10 rerun.
2. Item 10 happy path, first attempt: a wrong database URL in the shell
   command (connection refused, no password); rerun with the right URL.
3. Runtime scenarios, first complete run (08:47): all 52 checks printed
   PASS, but writing the JSON log failed (UUID dictionary keys); rerun after
   the fix.
4. Review of the harness then found check S4's `main`-pattern assertion
   vacuous (it compared the wrong column, so it would have passed whatever
   the row held). Fixed, with a positive control (the current claim must be
   accepted); every result reported for S4 is from the fixed check.
5. Dry run at 20,000 events (not evidence): two `scan_b` checks failed
   because the two load loops row-locked each other's rows, and the
   item 3 size checks failed by design at that size. The outcome loop was
   moved to a row the claim loop never selects; then the 1,000,000-event run.
6. Item 9: `old_code.py.txt` first failed to import the test-support
   module (`PYTHONPATH` list separator under Git Bash and Windows Python); it
   now adds `tests/support` itself; rerun passed. The 102 integration tests
   were not affected.
7. The first final rerun of items 8 and 10 and the scenarios (09:36) lost
   its happy-path fresh install to a script argument error; the next attempt
   (09:43) produced no output and the one after it found the Docker engine
   unavailable: the host was rebooted (no result; containers gone). The
   complete final run is the one at 10:08 UTC on a new `d4r-pg3`.
8. Item 11: the reference-consumer test failed (see item 11); rerun alone twice
   (baseline tree without A and B, and via a `subst` drive), failing both
   times for the path-length reason. It is reported UNVERIFIED, not PASS.

## Not verified

- **The runtime of #195 (UNVERIFIED: not implemented):** the
  `external_effect()` context manager, the dispatcher's reclaim rule, the
  exception rule in `fail_event()`, the per-consumer safe-retry opt-in
  registration, the reclaim deadline `created_at + retry_within`, the
  `OUTBOX_EXTERNAL_EFFECT_MARKERS` setting, crash tests through the real
  worker and consumers. Only the SQL shapes they would issue were run (see
  "Runtime SQL").
- **Anti-wraparound autovacuum blocking B** (finding F8): not measured;
  autovacuum was kept out of the way (`VACUUM (ANALYZE)` after seeding).
- **Query plans** (#195 4a.10): not part of README section 10's list; not
  reproduced.
- **The README's blocking-session query** (section 6) was not run.
- Local `tests/architecture` skips tests that need Caddy and openssl; only
  `tests/architecture/test_doc_references.py` was run locally for this
  record (see the pull request body).
- `tests/test_reference_consumer_integration.py` with A and B in place (item 11).

## Files

In `reproduction/` (text files: not Python modules, not collected by
pytest, not part of the package). Every Python file runs with the venv's
interpreter; the throwaway trees are passed as arguments or as the working
directory.

| File | Purpose |
|---|---|
| `graph_check.py.txt` | Item 1: heads, bases, chain, collisions |
| `offline_sql.sh.txt` | Item 2: `--sql` generation and comparison |
| `migrate_driver.py.txt` | Runs `run_core_migrations()` / `downgrade_core_migrations()` with statement timing and `SHOW lock_timeout` after each `SET`/`RESET` |
| `harness.py.txt` | Items 3, 5 to 8, 10, the runtime scenarios and their negative controls, migration crashes, multi-revision rollback |
| `seed.sql` | The 1,000,000-event data set |
| `populated.sh.txt` | The populated sequence (items 3 to 7, crashes, rollback, scenarios on 1,000,000 rows) |
| `small.sh.txt` | Items 8 and 10 and the scenarios with negative controls, on an empty database |
| `old_code.py.txt`, `item9_old_code.sh.txt` | Item 9 |
| `item11_gate.sh.txt` | Items 1 and 11: the repository's migration tests in tree R |
