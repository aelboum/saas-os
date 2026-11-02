# Crash recovery, decision D4: exact-DDL review package

## Status

**D4 is not approved. Nothing here is implemented.** The files in this
directory are review text, not migrations:

- `0420025c3b4b_add_outbox_external_started_marker.py.txt` and
  `f0cc2e656d79_validate_outbox_external_started_pair.py.txt` are the two
  proposed Alembic revision files, copied byte for byte from pull request
  #195. The `.py.txt` suffix keeps them away from Alembic, ruff, pyright and
  pytest. **Never copy them into `saas_os/infra/db/migrations/versions/`**
  under this package; that is the job of a separate implementation pull
  request, and only after the owner approves D4.
- Both docstrings say the files are stored under
  `docs/architecture/proposals/crash-recovery/`: that is their location in
  #195. This byte-identical copy lives in `docs/architecture/crash-recovery-d4/`;
  the docstrings are left unedited so the files stay byte-identical.
- `upgrade.sql` and `downgrade.sql` are the SQL statements the two revisions
  emit, generated offline (no database) for review. **Do not run them.**

Merging this package into `main` does not approve D4, does not implement it,
and changes no runtime behaviour: crash recovery stays at-least-once.
Pull request #195 (branch `docs/crash-recovery-started-state`, head
`f5c9561`) is the design record and is not modified by this package; its
design document `docs/architecture/DURABLE-STARTED-STATE-RECOVERY-DESIGN.md`
exists only on that branch. Section numbers below ("#195 4a.6") refer to it.

## Purpose

To give the owner one self-contained place to review, for decision D4, the
exact DDL that would be added to `core.outbox_events`, the exact SQL each
revision emits, its lock, transaction, RLS, compatibility and recovery
behaviour, and the evidence that must be reproduced independently before
approval. The design itself (S1 columns, C1 context manager, decisions D1 to
D3, the safe-retry opt-in) is decided in #195 and is not reopened here.

## 1. What the DDL does

| Object | Definition |
|---|---|
| Column `core.outbox_events.external_started_at` | `timestamptz NULL`, no default |
| Column `core.outbox_events.external_started_claim` | `uuid NULL`, no default, no foreign key |
| Constraint `ck_outbox_events_external_started_pair` | `CHECK ((external_started_at IS NULL) = (external_started_claim IS NULL))`, added `NOT VALID` by A, validated by B |

No index, no other constraint (D1: no claim-matching check), no `GRANT`, no
policy change, no backfill. Every existing row gets `NULL` in both columns,
which satisfies the check.

## 2. Revision chain

Revision A `0420025c3b4b` adds the columns and the `NOT VALID` check
(transactional). Revision B `f0cc2e656d79` validates the check inside
`autocommit_block()`. Owner decisions D2 (`lock_timeout = '5s'`) and D3 (two
revisions) are applied.

**Re-pointed chain (owner's re-pointing decision, #195 4a.5):**

```text
b3d5f7a9c2e4 (main head today)
  -> c5e8a1d3f7b2 (#192)
  -> d7e2a9c4f1b6 -> e8f3b1d5a2c7 -> a9c3e5f7b1d4 (#198; a9c3e5f7b1d4 is its head)
  -> 0420025c3b4b (A: columns + NOT VALID pair check)
  -> f0cc2e656d79 (B: VALIDATE in autocommit_block)
```

Re-read on 2026-11-02 for this package (branch heads are point-in-time):
on `origin/feat/permission-grant-migrations` (#198, head `40a0888` when the
SQL was generated, `03dd1a1` at the last re-check) the four revisions chain exactly as above
(`c5e8a1d3f7b2` revises `b3d5f7a9c2e4`; each later one revises the one
before), and `_EXPECTED_HEAD` in `tests/infra/db/test_migration_graph_unit.py`
is `a9c3e5f7b1d4` there and `b3d5f7a9c2e4` on `main`. Pull requests #192 and
#198 are both still open.

**Dependency.** A's `down_revision` becomes `a9c3e5f7b1d4` only if #192 and
#198 merge first, in that chain. The two `.py.txt` files keep
`down_revision` at `b3d5f7a9c2e4` (and `Revises: b3d5f7a9c2e4`), exactly as
they were measured in #195; the implementation pull request changes that one
line and the docstring line (#195 4a.5, steps 1 to 6). If #192 or #198 does
not merge first:

- A's `down_revision` must be the head of `main` at implementation time
  (`_EXPECTED_HEAD` of the graph test), whatever it is; if neither merged, it
  is `b3d5f7a9c2e4`, which is the chain #195 measured.
- If one merges later, it must be re-pointed onto B (or A and B onto it); two
  revisions with the same `down_revision` make two heads and the graph test
  fails.
- The downgrade target changes with it (section 5). The SQL changes only in
  the `version_num` of the two stamp lines that name A's `down_revision` (the
  DDL is identical; see section 3).
- A fresh install commits 55 earlier revisions before B's block on the
  re-pointed chain, 51 on the tested chain.

## 3. How the SQL files were produced

Generated, not hand-written, without any database, on 2026-11-02:

1. A scratch directory outside the repository (the session scratchpad,
   `d4sql/`) received a copy of `saas_os/infra/db/migrations/env.py` and
   `script.py.mako` (byte-identical to `main` `6fd2dfd`, checked with `cmp`),
   the 51 revision files of `main`, the four revision files of #192/#198 read
   with `git show origin/feat/permission-grant-migrations:<path>` (#198 head
   `40a0888`; an independent reviewer regenerated the SQL on `03dd1a1` with
   identical output), and the two `.py.txt` files renamed to `.py`.
2. In that scratch copy only, A's `down_revision` line was changed from
   `b3d5f7a9c2e4` to `a9c3e5f7b1d4` (`diff` shows that one line). The
   repository's `versions/` directory was not touched.
3. `alembic.ini` was copied with `script_location = %(here)s/migrations`.
   `MIGRATIONS_DATABASE_URL` was a placeholder host
   (`postgresql+psycopg://offline@offline.invalid/offline`); offline mode only
   uses it to pick the PostgreSQL dialect and never connects.
4. With Alembic 1.20.0 and SQLAlchemy 2.1.2 from the repository's venv:
   `python -m alembic -c <scratch>/alembic.ini upgrade a9c3e5f7b1d4:f0cc2e656d79 --sql`
   and `... downgrade f0cc2e656d79:a9c3e5f7b1d4 --sql` (both exit 0). The
   output below the header of `upgrade.sql` / `downgrade.sql` is that output,
   with CRLF converted to LF and a `-- pragma: allowlist secret` comment
   appended to the four `alembic_version_saas_os` lines (the repository's
   secret scanner reads revision ids as hex secrets).
5. The same was run on a second scratch copy with the files unmodified (the
   tested chain, `b3d5f7a9c2e4:f0cc2e656d79`). The two outputs differ only in
   the `version_num` `b3d5f7a9c2e4` / `a9c3e5f7b1d4` of the stamp line that
   names A's `down_revision` and in Alembic's `-- Running ...` comment: the
   DDL, `SET`/`RESET` and transaction boundaries are identical.

Offline mode exercises the same `upgrade()`/`downgrade()` bodies and the
same `autocommit_block()` boundaries as online mode: in offline mode
`autocommit_block()` emits `COMMIT;` on entry and `BEGIN;` on exit (Alembic
1.20.0 `MigrationContext.autocommit_block`), where online mode commits the
connection's transaction and begins a new one.

## 4. Upgrade, statement by statement

| # | Statement | Transaction | Lock on `core.outbox_events` |
|---|---|---|---|
| 1 | `BEGIN;` | env.py's transaction; on a real run it also carries every earlier pending revision of the same `upgrade` | none |
| 2 | `SET LOCAL lock_timeout = '5s';` | same | none |
| 3 | `ALTER TABLE core.outbox_events ADD COLUMN external_started_at timestamptz NULL, ADD COLUMN external_started_claim uuid NULL, ADD CONSTRAINT ck_outbox_events_external_started_pair CHECK (...) NOT VALID;` | same | `ACCESS EXCLUSIVE`, held to the `COMMIT` in row 6 |
| 4 | `RESET lock_timeout;` | same | (held) |
| 5 | `UPDATE alembic_version_saas_os`: stamp `a9c3e5f7b1d4` -> `0420025c3b4b` | same: A's stamp | (held) |
| 6 | `COMMIT;` | issued by `autocommit_block()` on entry; A and everything before it is now durable | released |
| 7 | `SET lock_timeout = '5s';` | autocommit, session level | none |
| 8 | `ALTER TABLE core.outbox_events VALIDATE CONSTRAINT ck_outbox_events_external_started_pair;` | autocommit (its own transaction) | `SHARE UPDATE EXCLUSIVE` for the scan |
| 9 | `RESET lock_timeout;` | autocommit; in a `finally`, so it also runs when row 8 fails | none |
| 10 | `BEGIN;` | new transaction after the block | none |
| 11 | `UPDATE alembic_version_saas_os`: stamp `0420025c3b4b` -> `f0cc2e656d79` | same: B's stamp | none |
| 12 | `COMMIT;` | | |

Why `SET LOCAL` plus `RESET` in A: `SET LOCAL` ends with the transaction, but
that transaction also carries every later revision of the same run, so the
`RESET` stops them inheriting the timeout. Why a session `SET` in B: in
autocommit each statement is its own transaction, so `SET LOCAL` would not
reach the `VALIDATE`.

## 5. Downgrade, statement by statement

| # | Statement | Effect |
|---|---|---|
| 1 | `BEGIN;` | one transaction for both revisions |
| 2 | `UPDATE alembic_version_saas_os`: stamp `f0cc2e656d79` -> `0420025c3b4b` | **B: stamp only.** PostgreSQL has no "un-validate"; the constraint stays validated until A drops it |
| 3 | `SET LOCAL lock_timeout = '5s';` | |
| 4 | `ALTER TABLE core.outbox_events DROP CONSTRAINT ck_outbox_events_external_started_pair, DROP COLUMN external_started_claim, DROP COLUMN external_started_at;` | **A:** `ACCESS EXCLUSIVE`; metadata only (dropped columns are marked dropped, the table is not rewritten) |
| 5 | `RESET lock_timeout;` | |
| 6 | `UPDATE alembic_version_saas_os`: stamp `0420025c3b4b` -> `a9c3e5f7b1d4` | stamp to A's `down_revision` |
| 7 | `COMMIT;` | |

**Downgrade target:** A's `down_revision`, and nothing older:
`saas-os-migrate downgrade a9c3e5f7b1d4` (or `0420025c3b4b-1`) on the
re-pointed chain. **Never `downgrade b3d5f7a9c2e4` on the re-pointed chain**:
that would also run the downgrades of #198 and #192, which refuse or fail on
a populated installation (#195 4a.11). `b3d5f7a9c2e4` is the target only on
the tested chain, where #195 measured it.

**Data loss on downgrade:** the values of `external_started_at` and
`external_started_claim` are lost. A pending event that carried a marker
falls back to at-least-once and may be sent again; a dead-lettered
`CrashAfterStart` event keeps its `last_error` but loses its start time and
claim. Export the marked rows first if the evidence matters
(`SELECT id, tenant_id, status, external_started_at, external_started_claim
FROM core.outbox_events WHERE external_started_claim IS NOT NULL;` as the
migrations role). Deploy the older code before downgrading the schema.

## 6. Lock behaviour

| Statement | Mode | Blocks | Is blocked by |
|---|---|---|---|
| A: `ADD COLUMN` x2 (nullable, no default) + `ADD CONSTRAINT ... CHECK ... NOT VALID` | `ACCESS EXCLUSIVE` (the strongest mode of the subcommands) | everything on the table, including plain `SELECT`, the dispatcher's claim query and outcome writes | any open transaction that has touched the table (even an `AccessShareLock` from a read) |
| B: `VALIDATE CONSTRAINT` (CHECK) | `SHARE UPDATE EXCLUSIVE` | other `SHARE UPDATE EXCLUSIVE` or stronger requests: `VACUUM` (including autovacuum), `ANALYZE`, `CREATE INDEX CONCURRENTLY`, other `ALTER TABLE` | the same set, held by others |
| Downgrade A: `DROP CONSTRAINT`, `DROP COLUMN` x2 | `ACCESS EXCLUSIVE` | everything | any open transaction on the table |

A is metadata-only: `ADD COLUMN` without a default does not rewrite the
table and `NOT VALID` skips the scan, so the lock is held for milliseconds
once granted (#195 measured 14 to 16 ms on 1,000,000 rows; not reproduced
here). B scans the table, but its lock mode does not conflict with
`ROW SHARE` (claims, `SELECT ... FOR UPDATE`) or `ROW EXCLUSIVE`
(`INSERT`/`UPDATE`/`DELETE`), so the application keeps running during the
scan.

**`lock_timeout` 5 s.** It bounds only the wait to acquire a lock, not how
long it is held. If A cannot get `ACCESS EXCLUSIVE` within 5 s it fails with
`LockNotAvailable` (SQLSTATE `55P03`); the whole `upgrade` transaction rolls
back and nothing changes. While A waits in the lock queue, later lock
requests on the table queue behind it, so the dispatcher's claims stall for
up to 5 s. Retry guidance: find the blocker with
`SELECT a.pid, a.usename, a.state, a.xact_start, left(a.query, 80) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE l.relation = 'core.outbox_events'::regclass AND l.granted;`,
end or wait for the long transaction, then re-run `saas-os-migrate upgrade`.
Do not raise the timeout without accepting that claims can stall that long.
If B times out, A stays committed and stamped; re-running the upgrade runs
only B.

**Interaction with the outbox dispatcher.** `claim_due_events()` in
`saas_os/core/outbox/dispatch.py` claims rows with
`SELECT ... FOR UPDATE SKIP LOCKED` (line 208 on `main`) and
`_locked_claimed_row()` locks one row `FOR UPDATE`. `SKIP LOCKED` skips
*row* locks only; it does not skip a table-level conflict. The claim query's
`ROW SHARE` table lock therefore waits behind A's granted or queued
`ACCESS EXCLUSIVE` (bounded by A's 5 s), and does not conflict with B's
`SHARE UPDATE EXCLUSIVE`. Neither query reads the new columns, so their plans
do not change (#195 4a.10 measured identical plans; not reproduced here).

**Lock scope inside one `upgrade` run.** `env.py` runs all pending revisions
in one transaction (`context.begin_transaction()`, no
`transaction_per_migration`). If #192/#198 are applied in the same run as A,
their locks are taken earlier in that transaction; A's `SET LOCAL
lock_timeout` covers only A's own statement. Because A is the last revision
before B's `COMMIT`, A's `ACCESS EXCLUSIVE` is held only from A's `ALTER` to
that `COMMIT`.

## 7. RLS and grants

- **Policy.** `core.outbox_events` has `ENABLE` and `FORCE ROW LEVEL SECURITY`
  and the policy `outbox_events_tenant_isolation`, created by
  `tenant_rls_statements()` (`saas_os/infra/db/rls.py`) in revision
  `8d3f1a6c2e70`. The policy has no `FOR` clause (so `FOR ALL`) and a `USING`
  expression on `tenant_id` that also serves as its `WITH CHECK`. It is
  row-level, so it covers the new columns with no change. No table is added,
  so the isolation registry and the RLS coverage sweep are unaffected.
- **Grants.** `8d3f1a6c2e70` contains no `GRANT`. The application role's
  `SELECT, INSERT, UPDATE, DELETE` on the table come from the schema default
  privileges set in `e99c76057719`
  (`ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES`).
  A table-level privilege covers every column, including columns added
  later. No migration on `main` grants or revokes a column-level privilege
  on this table (`grep` of `versions/` for `GRANT`/`REVOKE` with
  `outbox`: no match). So **no column-level `GRANT` is needed**, provided the
  table was created by the role that owns those default privileges. That is
  the evidence check in section 10 (`has_column_privilege`), which #195 4a.8
  reports as true (not reproduced here).

## 8. Compatibility and deploy ordering

- Code from before the change never names the columns: inserts leave them
  `NULL`, updates leave them unchanged, so the pair check never fires. The ORM
  model on `main` does not map them and needs no change for the migration.
- Order (#195 4a.11): (1) A and B, both by one `saas-os-migrate upgrade`;
  (2) the code that writes and reads markers; (3) only then markers switched
  on, after every older dispatcher and worker has stopped. The new code
  requires the columns, so the migration always comes first.
- A code-only rollback needs no schema step. A schema downgrade comes after
  the older code is deployed (section 5).

## 9. Failure and recovery

| Failure | State afterwards | Action |
|---|---|---|
| A fails (lock timeout or any error) | The whole `upgrade` transaction rolled back: no column, no constraint, stamp unchanged (on a multi-revision run, the earlier pending revisions of that run are rolled back too) | Remove the blocker, re-run `saas-os-migrate upgrade` |
| B fails on lock timeout | A committed and stamped (`0420025c3b4b`); columns present; check `NOT VALID` but enforced for every insert and update | The application runs normally. Re-run `saas-os-migrate upgrade` later; only B runs |
| B fails with `CheckViolation` | As above; some row holds half a marker (possible only after a manual change, since the check is enforced from A on) | List rows with `WHERE (external_started_at IS NULL) <> (external_started_claim IS NULL)`, fix them as #195 4a.11 describes, re-run the upgrade |
| Fresh install, B fails | Database at A, not at the previous head: `autocommit_block()` committed every earlier revision and A | Re-run the upgrade |

Validating an already validated constraint is a no-op, so re-running B is
safe.

## 10. Evidence required before approval

Every database measurement in #195 (PostgreSQL 16.15 `postgres:16-alpine`,
Alembic 1.20.0, 1,000,000 events / 195 MB: A 14 to 16 ms with no rewrite,
B 0.19 to 0.31 s; downgrade A 11 ms; 24 runtime checks, 0 failures; lock and
plan observations) was produced by the **authoring agent** in a throwaway
container and was **not independently reproduced**. This package adds no
database measurement: its only checks are file comparisons and offline SQL
generation. Before D4 is approved, a reviewer other than the author should
reproduce, on PostgreSQL 16 with the migration files at the re-pointed chain
(or the chain that will actually ship):

1. **Graph and head.** `ScriptDirectory` sees one head, `f0cc2e656d79`;
   `tests/infra/db/test_migration_graph_unit.py` passes with `_EXPECTED_HEAD`
   moved to it; no revision id collides with `main`.
2. **Offline SQL.** `alembic upgrade <A's down_revision>:f0cc2e656d79 --sql`
   and the matching downgrade reproduce `upgrade.sql` / `downgrade.sql` below
   their headers (modulo the pragma comments and line endings).
3. **Round trip on populated data.** Seed at least 1,000,000 events in every
   status (published, dead-lettered, pending due, claimed with a live and an
   expired lease); `upgrade head`; then set markers on some rows (pending
   with a marker equal to its `claim_token`, dead-lettered with a marker
   kept) and record them; `downgrade <A's down_revision>`;
   `upgrade head` again. After each step check: the stamp,
   `information_schema.columns` for both columns, `pg_constraint.convalidated`,
   the row count, and `pg_relation_filenode('core.outbox_events')` unchanged
   (no rewrite). After the downgrade, confirm the marked rows still exist and
   their marker values are gone (the data loss of section 5).
4. **Timing** of A's `ALTER`, B's `VALIDATE` and A's downgrade on that data
   (statement timestamps or `log_min_duration_statement = 0`).
5. **Order of commits.** From a separate connection, while B's `VALIDATE`
   is held back by another session's `SHARE UPDATE EXCLUSIVE`: the stamp is
   already `0420025c3b4b`, `convalidated = false`, and `pg_locks` shows the
   migration backend waiting for `ShareUpdateExclusiveLock` only (A's
   `AccessExclusiveLock` released).
6. **Lock observation with a concurrent session.** With an open app-role
   transaction that has read one row: A queues for `AccessExclusiveLock`, a
   claim query started after it queues (`RowShareLock`, not granted), A fails
   at about 5 s with `LockNotAvailable`, the stamp is unchanged, and the claim
   then runs. During B's scan: an app-role claim (`FOR UPDATE SKIP LOCKED`)
   and an outcome `UPDATE` complete without waiting.
7. **B failure and re-run.** B blocked past 5 s fails with `LockNotAvailable`,
   `RESET lock_timeout` still runs (check `SHOW lock_timeout` on that
   session), the stamp stays `0420025c3b4b`, and a re-run applies only B.
   Same with one simulated half-marker row (`CheckViolation`).
8. **RLS and runtime, as `saas_os_app`.** `rolsuper` and `rolbypassrls` false;
   `has_column_privilege` true for `SELECT`, `INSERT`, `UPDATE` on both
   columns; under tenant A's scope tenant B's marked row is invisible and
   unwritable; with no scope nothing is visible; inserting a marked row for
   B under A's scope is refused; a half-cleared marker raises
   `CheckViolation`.
9. **Old code on the new schema.** `main`'s current code, unchanged, runs
   against the migrated schema (section 8): append, claim, complete, fail,
   dead-letter and replay an event, and the outbox integration tests pass,
   with both columns left `NULL`.
10. **Fresh install, B fails** (section 9): on an empty database, block B's
    `VALIDATE` past 5 s; the database is left at A (stamp `0420025c3b4b`, every
    earlier revision committed, check `NOT VALID`), and a re-run applies only B.
11. **Migration gate tests** of the repository with the files in place:
    the integration migration tests (upgrade/downgrade, rollback tests,
    schema inventory), leaving no rows that block a later downgrade.

## 11. Preserved crash semantics (unchanged; not part of D4)

D4 adds two columns and a check. It does not change any delivery semantics,
and none of the following depends on approving it:

- **On `main` today, crash recovery is at-least-once for every consumer**
  (ADR-0033; #195 section 1): a lease that expires before the outcome is
  recorded is claimed and run again; a consumer suppresses a repeat only
  once its completion is recorded (ADR-0036, `core.outbox_consumptions`).
- **Webhooks:** at-least-once with a stable event id and receiver
  de-duplication. `event_id` is generated once in `trigger_event()` and stays
  fixed across every retry (`saas_os/core/webhooks/service.py` on `main`,
  docstring of the delivery job, "P1.10"); a duplicate after a crash is
  "at-least-once, which its replay check on the stable `event_id` absorbs"
  (same file, after a 2xx). #195 3.1 keeps this and gives webhooks no
  crash-retry opt-in.
- **Resend:** a retry is safe only with the same idempotency key and an
  identical payload within the provider's guaranteed validity window. On
  `main` the key is derived from the message id (itself derived from the
  outbox event id), and "a retry within Resend's documented 24-hour window is
  not sent again ... after 24 hours, or for a retry whose body differs, a
  resend is a new email" (`saas_os/core/email/resend_provider.py`, module
  docstring, "Duplicates"). #195 3.1: potentially eligible, only inside that
  window, **not enabled**.
- **SMTP:** an ambiguous outcome is never retried automatically. This is
  the policy of #195 3.1 and the behaviour of pull request #197
  (`feat/ambiguous-outcomes`, open: `EmailOutcomeUnknownError` after the
  relay's `354`, "it must not be retried automatically"). **It is not yet
  `main`'s behaviour:** on `main` a connection lost mid-conversation stays
  transient and is retried by the outbox, "so a retry can deliver a
  duplicate" (`saas_os/core/email/smtp_provider.py`, module docstring).
  See finding F7.
- **Stripe and AI inference:** no crash-retry opt-in without separate
  provider-specific evidence (#195 3.1, "Not eligible until provider-specific
  idempotency or reconciliation is demonstrated"). No opt-in mechanism exists
  on `main` at all.

## 12. Review findings

Compared on 2026-11-02 against #195 at `f5c9561` and `main` at `6fd2dfd`.

- **F1 (identity of the files).** Both `.py.txt` files here are
  byte-identical (`cmp`, SHA-256 below) to #195's files under
  `docs/architecture/proposals/crash-recovery/` and to its verbatim
  appendix blocks A.12 and A.13, and both carry #195's file names
  (#195 4a.5 step 1 names the eventual file
  `versions/0420025c3b4b_add_outbox_external_started_marker.py`). A first
  version of this package used a different name for A; it was renamed to
  #195's name before review.
  SHA-256: A `ff660bb1a6f37c40a57b1eab745576d33610bf73af1ce9d2e82ac167eb2a3964`,
  B `458736d1960603c7f3b29f2accbbcc1b80aed4449d75cb11f93082363668e1ca`.
- **F2 (tested chain in the files).** Both files still say
  `b3d5f7a9c2e4` for A's `down_revision`. That is deliberate (#195 4a.5: the
  files stay as measured); the SQL here was generated on the re-pointed chain
  by changing that one line in a scratch copy. Not a defect, but the
  approval should name which text it approves: the files as-is plus the
  one-line re-pointing.
- **F3 (superseded docstring).** B's docstring says "both revision ids and
  `down_revision` must be re-pointed"; #195 4a.5 itself supersedes that
  sentence (ids change only on a collision). The implementation pull request
  should correct the docstring when it removes the "PROPOSAL ONLY" paragraph.
- **F4 (offline SQL under psql).** If the `--sql` output were ever run with
  `psql` *without* `-v ON_ERROR_STOP=1` and B's `VALIDATE` failed, `psql`
  would continue to B's stamp transaction (`BEGIN; UPDATE ...; COMMIT;`) and stamp B
  with the check still `NOT VALID`. The supported online path
  (`saas-os-migrate`) is not affected: the exception propagates and B is not
  stamped (#195 4a.6). A failure in A under `psql` is harmless (the open
  transaction aborts, and B's stamp `UPDATE`, which requires the stamp to be A,
  matches nothing). Suggest that the implementation documents offline SQL as
  unsupported or requires `ON_ERROR_STOP`.
- **F5 (`RESET` semantics, informational).** `RESET lock_timeout` returns to
  the session default (server, database, role or connection-startup value),
  not to a value set earlier in the session. No migration and no part of
  `saas_os/infra/db` sets `lock_timeout` today, so the two are equal; a
  future runner that sets a session `lock_timeout` would have it reset by A
  and B.
- **F6 (moved branch head, informational; SHAs point-in-time).** #195 4a.5
  read #198 at branch head `689b6ce`; this package read `40a0888`, and it was
  `03dd1a1` at the last re-check (2026-11-02). The four revision ids and their
  `down_revision`s are unchanged, and `_EXPECTED_HEAD` there is still
  `a9c3e5f7b1d4`. #192 (head `21ca333`) and #198 are both open.
- **F7 (SMTP semantics on `main`).** The restated rule "SMTP never
  auto-retries an ambiguous outcome" is #197's behaviour and #195's policy,
  not `main`'s (section 11). It does not affect the DDL; it matters only for
  how the restated semantics are worded.
- **F8 (autovacuum, not measured).** B's `SHARE UPDATE EXCLUSIVE` conflicts
  with `VACUUM`. A regular autovacuum yields to a waiting conflicting lock
  request, but an anti-wraparound autovacuum does not, so B can hit its 5 s
  timeout behind one; the remedy is the documented re-run. #195 did not
  measure this case.
- **No discrepancy** was found between #195's SQL listings (4a.3, 4a.4,
  A.3, A.4) and the generated SQL: same statements, order, `SET`/`RESET`
  placement, `COMMIT`/`BEGIN` boundaries and stamps. #195 4a.1's statement
  that the grants come from `e99c76057719`'s default privileges is
  confirmed by reading the migrations (section 7).
