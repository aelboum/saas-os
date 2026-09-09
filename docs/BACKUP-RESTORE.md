# Backup, Restore & Disaster Recovery (P1.3 + P2.4)

Operational reference for `infra/db/backup/` (P1.3's primitives, now a
package) and `infra/db/backup/orchestrator.py` (P2.4's production
pipeline: locking, encryption, off-site upload, retention, scheduling).
This is infrastructure/admin tooling only -- never an application-runtime
capability (no API route, tenant-facing tool, AI Control Plane tool, or
Product code may import it; enforced by an import-linter contract
covering the whole `infra.db.backup` package, see
`tests/architecture/test_layer_boundaries.py`).

## Disaster-recovery targets (documented, not enforced)

- **RPO (Recovery Point Objective): 24 hours.** With the default daily
  schedule (`BACKUP_SCHEDULE_HOUR_UTC`), at most one day of writes can be
  lost in a total-loss scenario. Nothing in this codebase *enforces*
  this -- it is an engineering target an operator's actual schedule
  (`BACKUP_SCHEDULE_HOUR_UTC`) and retention (`BACKUP_RETENTION_COUNT`)
  configuration should be checked against, not a guarantee this software
  can make on its own.
- **RTO (Recovery Time Objective): 4 hours.** The measured, real restore
  duration in this repository's own extended drill
  (`tests/infra/db/test_backup_restore_drill_integration.py::test_extended_production_pipeline_runs_twice_from_clean_disposable_environments`)
  against a small drill database was ~1 second for `pg_restore` itself;
  the 4-hour target budgets for a real production database's larger
  size, provisioning a replacement host, and an operator's own manual
  steps -- it is a target to plan capacity against, not a benchmark this
  repository has measured against a production-sized dataset.
- Both are configurable (`BACKUP_RPO_HOURS`/`BACKUP_RTO_HOURS`,
  `infra/db/backup/config.py`) so `docs/BACKUP-RESTORE.md` and an
  operator's actual configuration share one source of truth, but changing
  the number changes nothing else in the system's behavior.

## What is covered

A full-database backup: schema, data, indexes, constraints, sequences,
Row-Level Security policies, `FORCE ROW LEVEL SECURITY`, and
ownership/grants -- everything `pg_dump`'s default full-database dump
captures, including `alembic_version` (so a restore recovers the exact
migration-state pointer along with everything else). This repository
defines no PostgreSQL extensions, so there is nothing extension-related
to restore.

Migrations (`infra/db/migrations/`) remain the sole authority for schema
*evolution*. Backup/restore is the disaster-recovery mechanism for
*total loss*: it replays one exact, previously-verified point-in-time
state rather than re-deriving it by replaying migrations and then
re-inserting data through a second mechanism.

## What is NOT covered (limitations)

- No point-in-time recovery (WAL archiving) -- only discrete, on-demand
  full-database snapshots.
- `restore_backup()` only restores into a **fresh** target database. It
  never overwrites an existing one. To reuse a name, an operator must
  explicitly drop it first (a separate, deliberate action). The
  orchestrator's `restore --confirm-production-restore` flag is a
  deliberate operator acknowledgement, not a bypass of this guarantee --
  no code path in this repository ever overwrites an existing database.
- The backup system has no tenant-selective restore/export capability by
  design (this checkpoint's own requirement) -- restore is always a
  whole-database operation, verified with the same tenant-isolation
  tests the application itself uses, never a capability to extract or
  restore one tenant's data in isolation.
- **Live off-site/S3-compatible provider validation was not performed in
  this environment** -- see Limitations below.

## Prerequisites

- Docker, with access to the target PostgreSQL container (this
  repository's one accepted deployment target is Docker + Docker Compose
  + VPS, `docs/ADR/0010-deployment-target.md`). `pg_dump`/`pg_restore`/
  `psql` run *inside* that container via `docker exec` -- no client
  tooling is required on the host running this script.
- The existing `MIGRATIONS_DATABASE_URL` credential (same role Alembic
  already uses) resolved through the existing `infra.secrets` /
  `infra.db.config.get_migrations_database_config()` path. No new secret
  mechanism is introduced.
- **`age`** (https://age-encryption.org), on the production host's PATH,
  for encryption. Install via the OS package manager (`apt install age`
  on Debian 13+, or download a release binary for older distributions).
- `age-keygen` (ships with `age`) to generate the encryption keypair
  once, out of band -- never something this codebase generates for you.

## Creating a backup (manual, P1.3)

```
python -m infra.db.backup create \
    --container saas-os-db-1 \
    --output-dir /absolute/path/to/backups \
    --label nightly
```

Produces two files: `<db>-<timestamp>-<id>-<label>.pgdump` (the archive,
custom format, compressed) and a matching `.pgdump.json` metadata file
(SHA-256, size, database name, timestamp -- never a credential or
connection string, and never a tenant name/ID/email -- this repository
is single-database, multi-tenant via Row-Level Security, not
database-per-tenant, so there is no tenant identifier to name a backup
after in the first place). Back up the `.json` file alongside the
`.pgdump` file -- restore needs both.

## Running the full production pipeline (P2.4)

```
python -m infra.db.backup.orchestrator run --container saas-os-db-1
```

Sequence: acquire an exclusive lock (`BACKUP_STAGING_DIR/backup.lock`,
see Locking below) -> check free disk space
(`BACKUP_MIN_FREE_BYTES`) -> `pg_dump` -> verify checksum -> **if
off-site is enabled, require a valid `BACKUP_ENCRYPTION_RECIPIENT`
(fail closed otherwise)** -> encrypt with `age` (whenever a recipient is
configured) -> **if off-site is enabled, verify the `.age` ciphertext,
record its checksum in the metadata file, and upload only that
ciphertext** -> apply keep-last-N retention to the off-site destination
-> release the lock. Every step emits a structured log event (see
Observability below).

**Off-site invariant (fail closed, post-audit F-03).** A destination is
never handed anything but a verified `age` ciphertext. If
`BACKUP_OFF_SITE_ENABLED=true` and `BACKUP_ENCRYPTION_RECIPIENT` is unset,
empty, or not an `age1...` key, the run stops with
`OffSiteEncryptionRequiredError` *before* encryption is attempted and
before the destination is contacted -- `backup_failed` is logged, the
exit code is non-zero, and the local `.pgdump` (the local recovery point)
stays on the host untouched. An encryption failure, a missing ciphertext,
or a `.age` file that does not verify as an age ciphertext abort the
same way. There is no plaintext fallback: the plaintext `.pgdump` is never
passed to `destination.upload()` under any condition (the orchestrator
source is guarded against reintroducing one by
`tests/infra/db/test_backup_offsite_fail_closed_unit.py`). Local-only
runs (`BACKUP_OFF_SITE_ENABLED=false`) are unchanged: the artifact is
encrypted when a recipient is configured and stays plaintext when none
is.

### Encryption

Uses `age` (asymmetric, X25519) via subprocess, never a hand-rolled
cipher (`infra/db/backup/encryption.py`). Encryption needs only the
**recipient** (public key, `age1...`) -- the production host that
creates backups never needs anything capable of decrypting them.
Decryption needs the **identity** (private key,
`AGE-SECRET-KEY-1...`), which an operator must generate once
(`age-keygen`) and **keep offline, away from the production host** -- a
compromised production host can encrypt garbage into new backups but
cannot decrypt any existing one. Both values are configured through the
active `SecretsProvider` (`BACKUP_ENCRYPTION_RECIPIENT` /
`BACKUP_ENCRYPTION_IDENTITY`, docs/ADR/0012-secrets-management.md) --
never `os.environ` directly, never logged, never written to backup
metadata.

### Off-site storage

`infra/db/backup/destination.py` defines a `BackupDestination`
abstraction (mirrors this repository's `BillingProvider`/`EmailProvider`
pattern): `LocalBackupDestination` (a second local/mounted path -- a
real but not by itself sufficient DR tier) and
`S3CompatibleBackupDestination` (any S3-API-compatible endpoint: AWS S3,
MinIO, Backblaze B2, Wasabi, Cloudflare R2, etc. -- this repository has
not selected a specific vendor). Configure via
`BACKUP_OFF_SITE_ENABLED=true` plus, through the `SecretsProvider`:
`BACKUP_S3_ENDPOINT_URL`, `BACKUP_S3_BUCKET`, `BACKUP_S3_ACCESS_KEY_ID`,
`BACKUP_S3_SECRET_ACCESS_KEY`, and optionally `BACKUP_S3_REGION` -- **and
`BACKUP_ENCRYPTION_RECIPIENT`, which is mandatory once off-site is
enabled** (see the off-site invariant above). The object a destination
stores is always the `<artifact>.pgdump.age` ciphertext; its SHA-256 is
recorded as `encrypted_sha256` (with `encrypted_size_bytes` and
`encrypted_artifact_path`) in the run's `.pgdump.json` metadata file and
in the `backup_upload_succeeded` log event, so an operator can compare it
against the object the bucket actually holds. `sha256` in the same file
remains the *plaintext* archive's checksum, which the restore path
verifies after decryption; `age` itself authenticates the ciphertext on
decryption, so a tampered object fails to decrypt rather than restoring
silently.

Operational requirements for the bucket/credential (enforced by
convention/IAM configuration, not by this code): a dedicated bucket, a
dedicated credential (never the application's own database or other
provider credentials), least-privilege permissions (put/get/list/delete
on that one bucket only), no public/anonymous access, TLS (inherent --
`boto3` defaults to `https://` and this module never overrides it).

### Retention

```
python -m infra.db.backup prune --output-dir /absolute/path/to/backups --keep-last 7
```

is still the manual, local-only P1.3 command. The production pipeline
applies the same keep-last-N policy automatically
(`BACKUP_RETENTION_COUNT`, default 7) to both the local staging directory
and, if enabled, the off-site destination (`apply_retention()`,
`infra/db/backup/destination.py`) -- sorted by the destination's own
authoritative last-modified timestamp, never a value parsed back out of
a filename. It never deletes the single newest recovery point, even for
a misconfigured `keep_last=0`.

### Scheduling

Runs as a host-level `systemd` timer (`deploy/saas-os-backup.service` +
`deploy/saas-os-backup.timer`) or cron entry -- deliberately **not** a
job on the application's own ARQ worker (`infra/jobs`), because a backup
job that only the worker can run creates a circular recovery dependency
(recovering from total loss would require the very application stack
the backup exists to protect); and deliberately not a new Docker service
with a mounted Docker socket, which would be a new privilege-escalation
surface conflicting with P2.3's network-perimeter hardening. To install:

```
sudo cp deploy/saas-os-backup.service deploy/saas-os-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now saas-os-backup.timer
```

A failed run exits non-zero and is visible via `systemctl status
saas-os-backup.service` / `journalctl -u saas-os-backup.service` --
`systemd` surfaces a failed timer-triggered unit as a failed unit, which
standard host monitoring (a `systemd`-aware alerting agent, or a
`systemctl is-failed` cron check) can alert on. This is an operational
alert, not something this codebase pages anyone about directly.

### Locking (concurrency safety)

An OS-level advisory file lock (`fcntl.flock` on Linux, this
repository's one production target -- `infra/db/backup/lock.py`), not a
PID file: a PID file can go stale (the recorded process died without
cleaning up, and a *different* process is now running under the same
PID); an `flock` held by an open file descriptor is released
automatically by the kernel the instant the holding process exits for
any reason, crash or `SIGKILL` included, with no staleness check ever
required. Non-blocking (`LOCK_EX | LOCK_NB`): a second run that finds
the lock already held fails immediately (`BackupLockError`) rather than
queueing behind the first.

### Observability

Every pipeline step emits exactly one structured log event:
`backup_started`, `backup_succeeded`, `backup_failed`,
`backup_upload_succeeded`, `backup_upload_failed`,
`backup_restore_started`, `backup_restore_succeeded`,
`backup_restore_failed`, `backup_retention_deleted`. Every `extra=`
field is an identifier, count, duration, checksum, or classification
(exception *type name*) -- never a password, connection string,
encryption key, or tenant payload.

### Health / status

```
python -m infra.db.backup.orchestrator status
```

Reports the newest known-good local backup (timestamp + checksum) and,
if off-site is enabled, the newest off-site object. This is
**deliberately not wired into `/readyz`** -- a backup failure is an
operational alert (the scheduler/systemd-timer failure above), never an
API outage; making application availability depend on backup health
would turn a DR mechanism into a new source of application downtime,
the opposite of its purpose.

## Verifying a backup

Checksum verification runs automatically at the start of every restore
and refuses (`ChecksumMismatchError`) a corrupted or tampered artifact
before any restore is attempted. To verify independently at any other
time:

```python
from pathlib import Path
from infra.db.backup import verify_backup_checksum

verify_backup_checksum(Path("/absolute/path/to/backup.pgdump.json"))
```

## Restoring into an isolated target

Manual (P1.3, plaintext artifact already on local disk):

```
python -m infra.db.backup restore \
    --container saas-os-db-1 \
    --metadata /absolute/path/to/backup.pgdump.json \
    --target-database saas_os_restore_check
```

Production pipeline (P2.4, decrypts an encrypted artifact first):

```
python -m infra.db.backup.orchestrator restore \
    --container saas-os-db-1 \
    --metadata /absolute/path/to/backup.pgdump.json \
    --encrypted /absolute/path/to/backup.pgdump.age \
    --target-database saas_os_restore_check \
    --confirm-production-restore
```

`--target-database` is always required and always explicit -- there is
no default target anywhere in this call chain. `--confirm-production-restore`
is a required, deliberate operator acknowledgement; it changes nothing
about the restore's own behavior -- no code path in this repository ever
restores over an existing database regardless of this flag. Sequence:
verify the metadata/artifact exist -> verify checksum -> decrypt (if
`--encrypted` was given) -> create the fresh target database ->
`pg_restore --single-transaction` (a mid-restore failure leaves the
target present but empty, never partially populated) -> the caller runs
the verification steps below. It never touches the live database
`saas_os` runs as.

## Restore verification

A successful `pg_restore` exit code alone is not sufficient. After every
restore, run:

```python
from infra.db.engine import build_engine
from infra.db.config import DatabaseConfig
from infra.db.backup import verify_restored_database
from infra.db.role_guard import validate_application_role

admin_engine = build_engine(
    DatabaseConfig(url="postgresql+psycopg://saas_os:<password>@<host>/saas_os_restore_check")
)
result = verify_restored_database(admin_engine)
assert result.schemas_present == {"core", "control_plane", "self_learning"}
assert result.every_rls_table_has_force_rls
assert result.every_rls_table_has_a_policy

app_engine = build_engine(
    DatabaseConfig(url="postgresql+psycopg://saas_os_app:<password>@<host>/saas_os_restore_check")
)
validate_application_role(app_engine)  # raises UnsafeDatabaseRoleError if unsafe
```

Then confirm tenant isolation directly, using the application's own
`tenant_session_scope()` against the restored database, and confirm the
restored application can actually connect/serve traffic against it
(`/readyz`) where practical. Both are exercised end to end by
`tests/infra/db/test_backup_restore_drill_integration.py` -- run on
demand:

```
pytest -m integration tests/infra/db/test_backup_restore_drill_integration.py
```

`test_full_disaster_recovery_drill` is the original P1.3 drill (plain
backup/restore); `test_extended_production_pipeline_runs_twice_from_clean_disposable_environments`
is the P2.4 extension -- encryption, off-site upload (to a real, local
`LocalBackupDestination`, not the in-memory fake), retention, and a
fail-closed decrypt-then-restore, run **twice**, each pass against its
own brand-new, independently migrated, disposable PostgreSQL container,
demonstrating deterministic repeatability. Measured restore duration in
this environment: ~1 second per pass (a small drill database -- see DR
targets above for how this scales to production sizing expectations).

## Redis: what survives, what doesn't

Redis backs one thing in this system: `infra/jobs` (ARQ) queued/
in-flight background job state -- never rate limiting, idempotency keys,
or sessions, none of which currently exist in this codebase's Redis
usage. `docker-compose.prod.yml`'s `redis` service now runs
`redis-server --appendonly yes` on a named, durable volume
(`redis-data-prod:/data`), replacing the pre-P2.4 configuration that had
no explicit persistence flag and no dedicated volume.

**What this guarantees**: with AOF (`appendonly yes`, default `everysec`
fsync policy), a queued-but-not-yet-executed job survives a Redis
*restart* (the process dies and comes back, e.g. `restart:
unless-stopped`, an OOM kill, a host reboot) with at most ~1 second of
enqueues at risk. Proven against a real, disposable Redis container in
`tests/infra/jobs/test_redis_persistence_integration.py::test_appendonly_redis_on_a_named_volume_survives_a_container_restart`,
which also proves a freshly started worker (simulating "the worker was
restarted too") recovers and executes that job.

**What this does NOT guarantee**:

- **PostgreSQL is the durable system of record.** Any result or side
  effect a job is responsible for producing belongs in PostgreSQL, not
  Redis -- Redis holds only *queue* state (the job is pending / has this
  many attempts left), never application data.
- **A container *recreate* (not a restart) with no persistence loses
  queued jobs.** Proven by contrast in
  `test_redis_without_persistence_loses_a_queued_job_when_recreated` --
  this was this repository's actual pre-P2.4 exposure, which the AOF
  volume above closes for the restart case. A recreate that also
  discards the named volume (e.g. `docker compose down -v`) still loses
  queued jobs -- the volume, not merely the container, is what must
  survive.
- **No silent successful enqueue when Redis is unreachable.**
  `enqueue_job()` raises rather than reporting success for a job that
  was never actually queued anywhere -- proven in
  `test_enqueue_raises_rather_than_silently_succeeding_when_redis_is_unreachable`.
- Redis is never exposed publicly (unchanged from P2.3: no `ports:` on
  the `redis` service -- reachable only as `redis:6379` on the internal
  Docker network).

## Security

- Every backup/off-site secret (`BACKUP_ENCRYPTION_RECIPIENT`,
  `BACKUP_ENCRYPTION_IDENTITY`, `BACKUP_S3_*`) is read exclusively
  through the active `SecretsProvider`
  (docs/ADR/0012-secrets-management.md) -- never `os.environ`/`os.getenv`
  directly anywhere in `infra/db/backup/`, proven by an AST-level test
  (`tests/infra/db/test_backup_config_unit.py`).
- The `age` **identity** (private decryption key) must be kept offline,
  away from the production host, by the operator -- this is a
  host/key-management boundary this codebase cannot enforce in code; it
  is a documented operational requirement.
- No backup filename or off-site object key ever contains a tenant
  name, tenant ID, user ID, email address, API key, or any other secret
  -- opaque, date-based identifiers only (`<database>-<timestamp>-<id>`).
- No structured log event, and no exception message anywhere in the
  backup/restore/encryption/destination code, ever includes a
  credential, connection string, encryption key, or tenant payload --
  only identifiers, counts, durations, checksums, and exception *type
  names*.
- The backup/restore system exposes no tenant-selective capability:
  restore is always whole-database, and every restore is re-verified
  with the same Row-Level Security and tenant-isolation tests the
  application itself relies on.

## Known limitations (what has and hasn't been validated)

**Proven in this environment** (real Docker containers, no mocks):
PostgreSQL backup/checksum/encryption/off-site-upload-to-a-real-local-destination/
retention/restore/schema+RLS verification/tenant-isolation-after-restore,
run twice, deterministically; Redis AOF persistence surviving a
container restart; Redis data loss on a non-persistent container
recreate; fail-closed behavior when Redis is unreachable; the backup
lock rejecting a genuinely concurrent second process; and (post-audit
F-03) that an off-site destination -- fake, real local, and mocked
S3-compatible -- is never called without a valid recipient, a successful
encryption, and a verified ciphertext, and only ever receives that
ciphertext.

**NOT live-validated in this environment** (no external infrastructure
was available):

- A real S3-compatible off-site provider (AWS S3, MinIO, Backblaze B2,
  Wasabi, Cloudflare R2, or any other). `S3CompatibleBackupDestination`
  is unit-tested against a mocked `boto3` client only -- this proves the
  code calls the right SDK methods with the right arguments, not that a
  real bucket/credential/network path works end to end. An operator
  configuring `BACKUP_OFF_SITE_ENABLED=true` for the first time should
  validate one real upload/download/list/delete cycle against their
  actual bucket before relying on it.
- A real ACME/TLS certificate issuance is unrelated to this checkpoint
  (P2.3) and remains out of scope here.
- The stated RPO/RTO targets are documented engineering goals an
  operator's configuration should be checked against -- they are not a
  guarantee this software enforces, and the measured ~1-second restore
  duration was against a small drill database, not a production-sized
  one.
