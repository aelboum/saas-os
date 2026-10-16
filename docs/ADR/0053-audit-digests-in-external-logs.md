# ADR-0053: Audit digests in external logs

Status: Accepted (2026-10-16) and implemented — the repository owner chose option C of the decision note: digests of settled windows, kept in external logs, before production.
Date: 2026-10-16
Supersedes / Superseded by: — (decides the external copy ADR-0051 left open)
Related: ADR-0002 (tenant isolation), ADR-0009 (observability backend: the operator's), ADR-0020 (log redaction), ADR-0022 (tenant session boundary), ADR-0045 (platform audit), ADR-0051 (audit table immutability).

## Context

- `core.audit_log` (tenant) and `core.platform_audit_log` (platform) are append-only for the application role, and a test proves it (ADR-0051). Nothing in SaaS OS updates or deletes their rows; both are `SECURITY_RETAIN` in the retention classification.
- The table owner (the migrations role) and superusers can still change or delete rows, and a trigger would not bind them (ADR-0051). Today such a change can only be found by comparing with an old backup, by hand.
- Evidence against those holders needs something they cannot rewrite. **A hash kept in the same database proves nothing**: whoever can change a row can recompute the hash beside it. Only a copy held outside their authority helps.
- ADR-0009 leaves the log backend to the operator. Every SaaS OS process already writes one JSON object per line to stdout (`saas_os.infra.observability`).

The decision note (2026-10-16) listed four options:
- A: keep backups only;
- B: ship every row to an external append-only store;
- C: digests of settled windows, kept in external logs;
- D: an in-database hash chain (rejected: it proves nothing on its own).

The owner chose C.

## Decision

1. **Windows.** Time is cut into fixed UTC windows of `AUDIT_DIGEST_WINDOW_SECONDS` (default 3600; a divisor of 86400, at least 300), aligned to the Unix epoch. A row belongs to the window containing its `created_at`.
2. **Settled.** A window is digested only once the database clock is past its end plus `AUDIT_DIGEST_SETTLE_SECONDS` (default 900, at least 60). `created_at` is the inserting transaction's start time, so a transaction still open at the window's end can add a row to it until it commits. The settle time must exceed the longest transaction that writes audit rows.
3. **Digest.** For each window:
   - every row is serialized canonically: a fixed list of columns per table (format version 1), keys sorted, no whitespace, UUIDs as strings, timestamps in UTC with microseconds, `metadata` as JSON with sorted keys;
   - `core.audit_log`: per tenant, SHA-256 over that tenant's rows in `(created_at, id)` order, one line each. The table's digest is SHA-256 over the `tenant:rows:sha256` lines of the tenants that have rows, sorted by tenant id;
   - `core.platform_audit_log`: SHA-256 over all its rows in the window, in the same order.
4. **Record and chain.** One record per window, with these fields:
   - `format`: `saas-os-audit-digest/1`;
   - `window_start` and `window_end`;
   - `audit_log`: `rows`, `sha256`, and `tenants`, with each tenant's `rows` and `sha256`;
   - `platform_audit_log`: `rows` and `sha256`;
   - `previous`: the digest of the previous window's record, or `null` for the first record.

   A record's digest is SHA-256 of its canonical JSON. The records form one chain.
5. **The log line is the evidence.** The worker writes each record to its log *before* storing it:
   - the event is `audit_digest`;
   - the record is one canonical JSON string in `audit_digest_record`, and its digest is in `audit_digest`.

   A string passes through the JSON formatter and redaction unchanged, so the verifier hashes exactly what was logged. The lines carry no audit content: only window times, row counts, digests and tenant ids.
6. **The table is a cursor, not evidence.** `core.audit_digests` (`window_start` primary key, `window_end`, `digest`, `record`, `created_at`) tells the job where to resume and which digest to chain from.
   - The application role may only `SELECT` and `INSERT` there.
   - Like the platform tables, it is global and unreachable from a tenant-scoped transaction (tenant-context exclusion policy), because records name tenants and their row counts.
   - Whoever can change audit rows can change this table too. A changed table breaks the chain against the external records, and the verifier reports it.
7. **Who computes it.** The `_audit_digest_cycle` system job runs every minute in the existing worker, as a schedule only (`system_cron`), and digests at most `AUDIT_DIGEST_MAX_WINDOWS_PER_RUN` windows (default 24).
   - It uses the application role, with no new privilege on the audit tables: `core.audit_log` is read one tenant at a time under that tenant's RLS scope; `core.platform_audit_log` and `core.tenants` are read from an untenanted session, as the API reads them.
   - There is no `BYPASSRLS` and no `SECURITY DEFINER`.
   - Its first run starts at the window of the oldest audit row, so existing history is covered.
   - A crash between logging and storing re-logs the same record on the next run. The computation is deterministic, so the line is identical.
   - When two workers compute the same window, both log identical lines; the second store fails on the primary key and ends that run.
8. **Verification.** `python -m saas_os.ops.audit_digest verify <file | ->` reads log lines exported **from the external store**. It checks that:
   - each line's digest matches its record;
   - the windows are contiguous, and the chain is unbroken from one first record;
   - each window's rows, recomputed from the database now, match the record, per tenant and for the platform table.

   It prints every finding: `audit_log_changed` (naming the tenant), `platform_audit_log_changed`, `gap`, `chain_broken`, `chain_restarted`, `chain_start_missing`, `conflicting_records`, `record_altered` and `unknown_format`. It also prints the range covered. It exits 0 only when everything matches. It runs as the application role and writes nothing.

## Deployment requirement

The guarantee holds only if the worker's `audit_digest` lines reach a store that the holders of the migrations role and of superuser access cannot change. Concretely:

- Ship the worker's stdout to a log store with append-only or retention-locked storage. Examples: object storage with a compliance-mode retention lock, or a log service in which deleting or editing entries is not possible for the database's administrators.
- The people and credentials that administer the database must not be able to delete, rewrite or shorten the retention of that store. Where one team holds both, the control is absent, not weakened.
- Keep the records at least as long as the audit rows they cover.
- Alert when no `audit_digest` line has arrived for longer than one window plus the settle time plus a margin (about 80 minutes with the defaults). A stopped worker or a broken log pipeline would otherwise leave rows uncovered silently.
- Run the verifier on a schedule, or at least before relying on the audit tables as evidence, with the export taken from the store.

SaaS OS cannot check any of this from inside the deployment. Without such a store, the digests prove nothing against those holders, and this ADR's control is absent. `docs/RUNBOOKS.md` ("Audit digests") carries the steps.

## What it detects, and what it does not

For every window that has a record in the external store, it detects:

- a changed, deleted or inserted audit row, located to the window and, for `core.audit_log`, to the tenant;
- a row moved to another window (a changed `created_at`) or to another tenant;
- a changed or deleted `core.audit_digests` row, which shows up as a chain break once the next record is computed from it;
- a record missing from, altered in, or added to the export: a gap, a digest mismatch, or a chain break.

It does not detect, or not on its own:

- **What was there before.** A digest shows that a window changed, not its earlier content. That comes from a backup (`docs/BACKUP-RESTORE.md`).
- **Rows newer than the last record.** With the defaults, that is up to about 75 minutes of rows. They are covered once their window settles.
- **A holder who controls both the database and the log store,** or who changes rows while the worker or its log shipping is stopped and before the window settles. The missing-records alert covers the second case.
- **A row committed after its window was digested.** Such a row shows as a change. A transaction longer than the settle time is a finding to investigate; the verifier does not treat it as a false positive.
- **A restore from backup.** A restore removes rows written after the backup, so later windows no longer match. That is expected after a disaster recovery. The runbook has the restore recorded together with the verifier's findings, and has the old chain ended (decision 6: the job resumes from the restored table).

## Consequences

- One additive migration (`d3e9a1c47b20`): `core.audit_digests`, global, with a tenant-context exclusion policy. The application role holds only `SELECT` and `INSERT` there, and `tests/infra/db/test_audit_tables_append_only_integration.py` covers it with both audit tables.
- One log line per window: 24 a day with the defaults. A line grows by about 100 bytes for each tenant that wrote audit rows in that window.
- Cost per run with pending windows: for each tenant, one indexed query over the pending range (`ix_audit_log_tenant_created_at`), plus one query over the platform table. A run with nothing settled reads only the cursor.
- A new column on either audit table changes the canonical form. A unit test fails until the column lists and the format version are updated together, so that windows recorded under version 1 still verify.
- Test suites that delete their own audit rows (cleanup with the migrations role) would show as changes if digested. This is a property of the test database only.

## Validation (2026-10-16)

- **Unit** (`tests/core/audit_digest/test_audit_digest_unit.py`). Covers:
  - the column lists name every column of both tables;
  - a row has one canonical form, whatever its key order or timezone;
  - the table digest changes when a tenant drops out, and a record digest when its `previous` does;
  - windows align to the epoch, and bad configuration is refused;
  - a record logged through the real JSON formatter comes back unchanged with its digest;
  - every chain finding is produced by its case, and duplicates count once.
- **Integration** (`tests/core/audit_digest/test_audit_digest_integration.py`, PostgreSQL). The rows are written in 1990 windows with the migrations role, and the verifier runs as the application role. It shows that:
  - each tenant's rows and the platform rows land in their windows;
  - untouched windows verify;
  - each change is found in exactly its window and tenant: an `UPDATE` of a row, a `created_at` moved into the next window (found in both), a deleted platform row, and an inserted row;
  - an altered or missing record is a finding.

  The job test shows that:
  - the job starts at the oldest row and chains across runs;
  - its log lines, formatted as the worker formats them, equal the stored records and verify;
  - a second store of a window is refused;
  - `core.audit_digests` is invisible from a tenant-scoped transaction.
- **Negative controls**, each applied alone and then reverted. Each one fails at least one test:
  - dropping a column from the canonical form;
  - skipping the per-tenant comparison;
  - skipping the platform comparison;
  - not logging the record;
  - not chaining `previous`;
  - reading `core.audit_log` without the tenant scope (RLS then returns nothing);
  - creating the table without the tenant-context exclusion policy (migration downgraded and upgraded).
