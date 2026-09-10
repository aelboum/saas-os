"""P1.3 -- PostgreSQL backup, restore, and disaster-recovery primitives.
P2.4 converted this module into a package (`infra/db/backup/`) so its new
production-pipeline submodules -- `encryption.py`, `destination.py`,
`lock.py`, `config.py`, `orchestrator.py` -- inherit the exact same
architectural boundary this file's own docstring already established,
via the *existing* `forbidden_modules = ["infra.db.backup"]` import-linter
contract (reachability-based: forbidding the package forbids every
submodule under it, with no contract edit needed). Every name this
`__init__.py` originally exported is unchanged; `python -m infra.db.backup`
still works via the new `__main__.py` sibling.

Infrastructure/admin tooling, not an application runtime capability
(docs/IMPLEMENTATION-ROADMAP.md P1.3's own Security Boundary: "MUST NOT
become an application runtime capability... no API route, tenant-facing
tool, AI Control Plane tool, Product code, frontend, webhook, or
tenant-accessible job may reach it"). This module is deliberately never
imported by `infra/db/__init__.py` -- it is reachable only via an explicit
`from infra.db.backup import ...`, exactly mirroring how
`infra.secrets.providers` is a real submodule that is not part of
`infra.secrets`'s own public surface. `pyproject.toml`'s "Backup/restore
is not an application-runtime capability" import-linter contract makes
this a structural property (`core`, `products`, `control_plane`, `api`
cannot reach `infra.db.backup` at all), not merely a naming convention --
see `tests/architecture/test_layer_boundaries.py`.

Design (docs/IMPLEMENTATION-ROADMAP.md P1.3's own "Migration strategy"
question): strategy A -- a backup is the *complete* database (schema,
data, indexes, constraints, sequences, RLS policies, FORCE RLS,
ownership/grants -- everything `pg_dump`'s default full-database dump
captures), restored in one step into a *fresh, empty* target database.
The Alembic migration chain (`infra/db/migrations/`) remains the sole
authority for schema *evolution*; backup/restore is a disaster-recovery
mechanism for *total loss*, replaying one exact, previously-verified
point-in-time state rather than re-deriving it by replaying migrations
and then re-inserting data through a second, parallel data-migration
mechanism this repository does not have. `alembic_version` is an
ordinary table `pg_dump` captures like any other -- restoring it restores
the exact migration-state pointer along with everything else, so no
separate `alembic upgrade` step is needed or run after a restore.

Every PostgreSQL client-tool invocation (`pg_dump`/`pg_restore`) goes
through `docker exec <container> ...` rather than assuming a local
`pg_dump`/`pg_restore` binary on `PATH` -- this repository's one accepted
deployment target is Docker + Docker Compose + VPS (`docs/ADR/0010-
deployment-target.md`), and the `postgres:16-alpine` image already always
ships these tools; `docker exec` also connects to the database over the
container's own loopback interface, sidestepping any host-side port
routing entirely. This adds no new dependency anywhere (no
`postgresql-client` package in the dev image, CI, or this repository's
own `pyproject.toml`).

Credentials: `admin_config: infra.db.config.DatabaseConfig` is the
*existing* `get_migrations_database_config()` (`MIGRATIONS_DATABASE_URL`)
value a caller supplies -- this module introduces no new secret-reading
path. The password is extracted once, in memory, and handed to `docker
exec` as an *inherited* environment variable: the argv passed to
`subprocess.run()` contains only the bare name `PGPASSWORD` (`docker exec
-e PGPASSWORD ...`, no `=value`), with the actual value supplied only via
that one subprocess call's own `env=` mapping -- the password is never a
substring of any argv element, so it never appears in a process listing
(`ps`, Task Manager, `docker top`) the way `-e PGPASSWORD=<value>` or a
`postgresql://user:password@host/db` URL argument would.

Database/role/container identifiers are validated (`_validate_identifier`
/`_validate_container_name`) before being formatted into any SQL text or
argv element -- defense in depth on top of the fact that every
`subprocess.run()` call here already passes an explicit argv list, never
`shell=True`, so there is no shell to inject into in the first place.

Restore is deliberately restore-into-a-fresh-target only: `restore_backup()`
`CREATE DATABASE`s the target itself (failing loudly, safely, if a
database of that name already exists -- Postgres has no
`CREATE DATABASE IF NOT EXISTS`) and never drops or overwrites an
existing database. There is no "restore in place" / destructive-replace
mode in this module at all -- an operator who genuinely wants to reuse an
existing name must `DROP DATABASE` it themselves first, a separate,
explicit action this module does not perform on a caller's behalf.
`pg_restore --single-transaction` gives restore its only atomicity
guarantee: either every statement in the archive applies, or the whole
transaction rolls back and the target database is left present but
completely empty -- `restore_backup()` never reports success without a
zero exit code from `pg_restore` itself, and a caller must still run
`verify_restored_database()` before trusting the result (this module
makes no success claim on subprocess exit code alone).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url

from infra.db.config import DatabaseConfig

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SUBPROCESS_TIMEOUT_SECONDS = 300


class BackupError(RuntimeError):
    """Raised for any backup-creation failure. Never includes a password,
    connection string, or `DATABASE_URL`/`MIGRATIONS_DATABASE_URL` value."""


class RestoreError(RuntimeError):
    """Raised for any restore failure -- including a failed safety check
    (checksum mismatch, invalid identifier) that never even attempted a
    restore. Never includes a password or connection string."""


class ChecksumMismatchError(RestoreError):
    """A backup artifact's actual SHA-256 does not match its recorded
    metadata -- the artifact is corrupted or was tampered with. This is a
    `RestoreError` subtype so a caller that only catches `RestoreError`
    still refuses a bad backup; it is never silently downgraded to a
    warning."""


class InvalidIdentifierError(ValueError):
    """Raised when a database/role/container name fails the strict
    identifier pattern this module requires before it is ever formatted
    into SQL text or an argv element."""


def _validate_identifier(name: str, *, label: str) -> str:
    if not _IDENTIFIER_RE.match(name):
        raise InvalidIdentifierError(
            f"{label} {name!r} is not a valid PostgreSQL identifier "
            "(must start with a letter/underscore, alphanumerics/underscore only, "
            "max 63 characters)."
        )
    return name


def _validate_container_name(container: str) -> str:
    if not _CONTAINER_NAME_RE.match(container):
        raise InvalidIdentifierError(f"container name {container!r} is not a valid Docker name.")
    return container


def _validate_backup_directory(directory: Path) -> Path:
    """Refuses a relative path (ambiguous, resolves differently depending
    on the current working directory the caller happens to run from) and
    a path containing a `..` component (defense in depth against path
    traversal, even though no untrusted input reaches this function)."""
    if not directory.is_absolute():
        raise BackupError(f"backup directory {directory!s} must be an absolute path.")
    if ".." in directory.parts:
        raise BackupError(f"backup directory {directory!s} must not contain '..'.")
    return directory


@dataclass(frozen=True)
class BackupMetadata:
    """Everything needed to independently verify and restore a backup --
    and nothing else. No credential, connection string, or raw data value
    ever belongs on this object (docs/IMPLEMENTATION-ROADMAP.md P1.3's
    own Backup Artifact Integrity requirement)."""

    artifact_path: Path
    metadata_path: Path
    database: str
    created_at: str
    sha256: str
    size_bytes: int
    format: str

    def to_json_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["artifact_path"] = str(self.artifact_path)
        data["metadata_path"] = str(self.metadata_path)
        return data


@dataclass(frozen=True)
class RestoreResult:
    target_database: str
    metadata: BackupMetadata


def _sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(
    cmd: list[str],
    *,
    env: dict[str, str],
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> subprocess.CompletedProcess[bytes]:
    # Never shell=True; cmd is always a fixed argv list -- no untrusted
    # value is ever concatenated into a shell command string. stdout
    # defaults to a pipe (never inherited) so a routine `psql -c` call
    # never spills raw command output onto this process's own stdout.
    return subprocess.run(
        cmd,
        env=env,
        stdin=stdin,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        check=False,
    )


def create_backup(
    *,
    container: str,
    admin_config: DatabaseConfig,
    output_dir: Path,
    label: str | None = None,
) -> BackupMetadata:
    """Create a full-database backup (`pg_dump -Fc`, custom format --
    compressed, restorable with `pg_restore`) of the database
    `admin_config` names, via `docker exec <container> pg_dump`.
    `admin_config` should be the existing privileged
    `get_migrations_database_config()` value -- the same role Alembic
    already uses, which (unlike the application runtime role) can see
    every object in the database, so the dump is complete."""
    _validate_container_name(container)
    output_dir = _validate_backup_directory(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    url = make_url(admin_config.url)
    user = url.username or ""
    password = url.password or ""
    database = url.database or ""
    _validate_identifier(user, label="user")
    _validate_identifier(database, label="database")

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    suffix = f"-{label}" if label else ""
    stem = f"{database}-{timestamp}-{uuid.uuid4().hex[:8]}{suffix}"
    artifact_path = output_dir / f"{stem}.pgdump"
    metadata_path = output_dir / f"{stem}.pgdump.json"

    cmd = [
        "docker",
        "exec",
        "-e",
        "PGPASSWORD",
        container,
        "pg_dump",
        "-U",
        user,
        "-h",
        "127.0.0.1",
        "-d",
        database,
        "-Fc",
        "--no-password",
    ]
    with artifact_path.open("wb") as out:
        result = _run(cmd, env={**os.environ, "PGPASSWORD": password}, stdout=out)

    if result.returncode != 0:
        artifact_path.unlink(missing_ok=True)
        raise BackupError(
            f"pg_dump failed for database {database!r} (exit {result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace').strip()[-2000:]}"
        )

    sha256 = _sha256_of_file(artifact_path)
    size_bytes = artifact_path.stat().st_size
    metadata = BackupMetadata(
        artifact_path=artifact_path,
        metadata_path=metadata_path,
        database=database,
        created_at=datetime.now(UTC).isoformat(),
        sha256=sha256,
        size_bytes=size_bytes,
        format="custom",
    )
    metadata_path.write_text(json.dumps(metadata.to_json_dict(), indent=2, sort_keys=True))
    return metadata


def verify_backup_checksum(metadata_path: Path) -> BackupMetadata:
    """Loads `metadata_path`, recomputes the artifact's actual SHA-256,
    and raises `ChecksumMismatchError` if it does not match the recorded
    value -- called unconditionally at the start of `restore_backup()`,
    so a caller cannot restore a corrupted/tampered artifact by mistake.
    A missing artifact or metadata file, or a metadata file that fails to
    parse, is a `BackupError` -- fail closed, never a silent pass."""
    if not metadata_path.is_file():
        raise BackupError(f"backup metadata file not found: {metadata_path!s}")
    try:
        raw = json.loads(metadata_path.read_text())
    except json.JSONDecodeError as exc:
        raise BackupError(f"backup metadata file is not valid JSON: {metadata_path!s}") from exc

    try:
        artifact_path = Path(raw["artifact_path"])
        recorded_sha256 = raw["sha256"]
        database = raw["database"]
        created_at = raw["created_at"]
        size_bytes = raw["size_bytes"]
        fmt = raw["format"]
    except KeyError as exc:
        raise BackupError(f"backup metadata file is missing required field: {exc}") from exc

    if not artifact_path.is_file():
        raise BackupError(f"backup artifact not found: {artifact_path!s}")

    actual_sha256 = _sha256_of_file(artifact_path)
    if actual_sha256 != recorded_sha256:
        raise ChecksumMismatchError(
            f"backup artifact {artifact_path.name!r} failed checksum verification: "
            f"expected {recorded_sha256}, got {actual_sha256}. Refusing to restore."
        )

    actual_size = artifact_path.stat().st_size
    if actual_size != size_bytes:
        raise ChecksumMismatchError(
            f"backup artifact {artifact_path.name!r} size mismatch: "
            f"expected {size_bytes} bytes, got {actual_size}. Refusing to restore."
        )

    return BackupMetadata(
        artifact_path=artifact_path,
        metadata_path=metadata_path,
        database=database,
        created_at=created_at,
        sha256=recorded_sha256,
        size_bytes=size_bytes,
        format=fmt,
    )


def _create_database(*, container: str, user: str, password: str, database: str) -> None:
    """`CREATE DATABASE` has no `IF NOT EXISTS` -- this fails loudly if
    `database` already exists, which is exactly the safety property
    `restore_backup()` relies on: it never overwrites an existing
    database (module docstring)."""
    cmd = [
        "docker",
        "exec",
        "-e",
        "PGPASSWORD",
        container,
        "psql",
        "-U",
        user,
        "-h",
        "127.0.0.1",
        "-d",
        "postgres",
        "--no-password",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        f'CREATE DATABASE "{database}"',
    ]
    result = _run(cmd, env={**os.environ, "PGPASSWORD": password})
    if result.returncode != 0:
        raise RestoreError(
            f"could not create target database {database!r} (exit {result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace').strip()[-2000:]}"
        )


def drop_database_for_drill(*, container: str, admin_config: DatabaseConfig, database: str) -> None:
    """Explicit, separately-named, destructive operation -- used only by
    the disaster-recovery drill to simulate total database loss before
    restoring. Never called by `restore_backup()` itself (module
    docstring: there is no destructive-replace default)."""
    _validate_container_name(container)
    database = _validate_identifier(database, label="database")
    url = make_url(admin_config.url)
    user = _validate_identifier(url.username or "", label="user")
    password = url.password or ""

    cmd = [
        "docker",
        "exec",
        "-e",
        "PGPASSWORD",
        container,
        "psql",
        "-U",
        user,
        "-h",
        "127.0.0.1",
        "-d",
        "postgres",
        "--no-password",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)',
    ]
    result = _run(cmd, env={**os.environ, "PGPASSWORD": password})
    if result.returncode != 0:
        raise RestoreError(
            f"could not drop database {database!r} for the drill (exit {result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace').strip()[-2000:]}"
        )


def restore_backup(
    *,
    container: str,
    admin_config: DatabaseConfig,
    metadata_path: Path,
    target_database: str,
) -> RestoreResult:
    """Restore a checksum-verified backup into a *fresh* `target_database`
    (module docstring: restore-into-a-new-target only, never in place).
    Raises before ever invoking `pg_restore` if the checksum does not
    verify, the target database name is not a valid identifier, or a
    database of that name already exists. `pg_restore --single-transaction`
    means a mid-restore failure leaves `target_database` present but
    empty, never partially restored -- this function still only returns
    a `RestoreResult` on a genuine zero exit code; the caller must run
    `verify_restored_database()` before treating the restore as trusted
    (this function's own return value is not itself a success claim about
    data correctness, only that `pg_restore` reported success)."""
    _validate_container_name(container)
    metadata = verify_backup_checksum(metadata_path)
    target_database = _validate_identifier(target_database, label="target_database")

    url = make_url(admin_config.url)
    user = _validate_identifier(url.username or "", label="user")
    password = url.password or ""

    _create_database(container=container, user=user, password=password, database=target_database)

    cmd = [
        "docker",
        "exec",
        "-i",  # required so `docker exec` actually forwards our stdin (the archive bytes)
        "-e",
        "PGPASSWORD",
        container,
        "pg_restore",
        "-U",
        user,
        "-h",
        "127.0.0.1",
        "-d",
        target_database,
        "--no-password",
        "--single-transaction",
        "--exit-on-error",
    ]
    with metadata.artifact_path.open("rb") as artifact:
        result = _run(cmd, env={**os.environ, "PGPASSWORD": password}, stdin=artifact)

    if result.returncode != 0:
        raise RestoreError(
            f"pg_restore failed for target database {target_database!r} (exit "
            f"{result.returncode}); the target database was left present but empty "
            f"(--single-transaction): "
            f"{result.stderr.decode('utf-8', errors='replace').strip()[-2000:]}"
        )

    return RestoreResult(target_database=target_database, metadata=metadata)


def list_backups(output_dir: Path) -> list[BackupMetadata]:
    """Every checksum-valid backup metadata file in `output_dir`, oldest
    first by `created_at`. A metadata file that fails to load or verify
    is skipped, not raised -- listing/retention must not crash on one bad
    file blocking visibility into every other, valid backup."""
    output_dir = _validate_backup_directory(output_dir)
    results: list[BackupMetadata] = []
    for metadata_path in sorted(output_dir.glob("*.pgdump.json")):
        try:
            results.append(verify_backup_checksum(metadata_path))
        except BackupError:
            continue
    return sorted(results, key=lambda m: m.created_at)


def prune_backups(output_dir: Path, *, keep_last: int) -> list[Path]:
    """Minimal, deterministic retention policy (docs/IMPLEMENTATION-
    ROADMAP.md P1.3's own Retention scope: no cloud vendor integration, no
    object-storage abstraction, no multi-region replication -- a single
    local directory, keep-the-N-most-recent only): deletes both the
    artifact and metadata file of every backup in `output_dir` beyond the
    `keep_last` most recent (by `created_at`), returning the artifact
    paths removed. Never called automatically by `create_backup()` --
    retention is an explicit, separate operation a caller opts into."""
    if keep_last < 1:
        raise ValueError("keep_last must be >= 1")
    backups = list_backups(output_dir)
    to_remove = backups[:-keep_last] if len(backups) > keep_last else []
    removed: list[Path] = []
    for backup in to_remove:
        backup.artifact_path.unlink(missing_ok=True)
        backup.metadata_path.unlink(missing_ok=True)
        removed.append(backup.artifact_path)
    return removed


@dataclass(frozen=True)
class RestoreVerificationResult:
    schemas_present: frozenset[str]
    rls_protected_table_count: int
    every_rls_table_has_force_rls: bool
    every_rls_table_has_a_policy: bool
    alembic_version: str | None


_EXPECTED_SCHEMAS = frozenset({"core", "control_plane", "self_learning"})


def verify_restored_database(engine: Engine) -> RestoreVerificationResult:
    """Structural + security verification a caller runs against the
    *restored* database before trusting it -- "more than pg_restore
    exited 0" (docs/IMPLEMENTATION-ROADMAP.md P1.3's own Restore
    Verification requirement). Queries PostgreSQL's own catalogs
    (`pg_namespace`, `pg_class`, `pg_policies`, `alembic_version`) rather
    than trusting the backup's own claims about itself. Does not check
    tenant data isolation -- that requires seeded fixture data and the
    application's own `tenant_session_scope()`, exercised directly by the
    disaster-recovery drill test, not this generic structural check.
    Queries `alembic_version_saas_os` -- SaaS OS's own version-tracking
    table (docs/ADR/0016), pinned in `infra/db/migrations/env.py`."""
    with engine.connect() as conn:
        schema_rows = conn.execute(
            text("SELECT nspname FROM pg_namespace WHERE nspname = ANY(:names)"),
            {"names": list(_EXPECTED_SCHEMAS)},
        ).all()
        schemas_present = frozenset(row[0] for row in schema_rows)

        rls_rows = conn.execute(
            text(
                "SELECT c.relnamespace::regnamespace::text, c.relname, "
                "c.relrowsecurity, c.relforcerowsecurity "
                "FROM pg_class c WHERE c.relrowsecurity = true"
            )
        ).all()

        policy_rows = conn.execute(
            text(
                "SELECT schemaname || '.' || tablename, COUNT(*) "
                "FROM pg_policies GROUP BY schemaname, tablename"
            )
        ).all()
        policy_counts = {row[0]: row[1] for row in policy_rows}

        alembic_version: str | None
        try:
            alembic_version = conn.execute(
                text("SELECT version_num FROM alembic_version_saas_os")
            ).scalar_one_or_none()
        except Exception:  # noqa: BLE001 -- alembic_version_saas_os missing entirely is a real finding
            alembic_version = None

    every_force = all(row[3] for row in rls_rows)
    every_policy = all(f"{row[0]}.{row[1]}" in policy_counts for row in rls_rows)

    return RestoreVerificationResult(
        schemas_present=schemas_present,
        rls_protected_table_count=len(rls_rows),
        every_rls_table_has_force_rls=every_force,
        every_rls_table_has_a_policy=every_policy,
        alembic_version=alembic_version,
    )


def _cli() -> None:  # pragma: no cover -- thin argparse wrapper, exercised via the functions above
    """`python -m infra.db.backup {create,restore,prune} ...` -- the
    minimal operator entrypoint (docs/BACKUP-RESTORE.md). Deliberately
    not importable from `infra.db`'s own public surface any more than the
    rest of this module is; running it is itself the explicit
    administrative action this module's docstring requires."""
    import argparse

    from infra.db.config import get_migrations_database_config

    parser = argparse.ArgumentParser(prog="python -m infra.db.backup")
    sub = parser.add_subparsers(dest="command", required=True)

    create_p = sub.add_parser("create", help="Create a full-database backup.")
    create_p.add_argument("--container", required=True)
    create_p.add_argument("--output-dir", required=True, type=Path)
    create_p.add_argument("--label", default=None)

    restore_p = sub.add_parser("restore", help="Restore a backup into a fresh target database.")
    restore_p.add_argument("--container", required=True)
    restore_p.add_argument("--metadata", required=True, type=Path)
    restore_p.add_argument("--target-database", required=True)

    prune_p = sub.add_parser("prune", help="Delete all but the N most recent backups.")
    prune_p.add_argument("--output-dir", required=True, type=Path)
    prune_p.add_argument("--keep-last", required=True, type=int)

    args = parser.parse_args()
    admin_config = get_migrations_database_config()

    if args.command == "create":
        metadata = create_backup(
            container=args.container,
            admin_config=admin_config,
            output_dir=args.output_dir,
            label=args.label,
        )
        print(json.dumps(metadata.to_json_dict(), indent=2, sort_keys=True))
    elif args.command == "restore":
        result = restore_backup(
            container=args.container,
            admin_config=admin_config,
            metadata_path=args.metadata,
            target_database=args.target_database,
        )
        print(
            f"Restored into database {result.target_database!r}. "
            "Run verification before trusting it."
        )
    elif args.command == "prune":
        removed = prune_backups(args.output_dir, keep_last=args.keep_last)
        print(f"Removed {len(removed)} backup(s): {[p.name for p in removed]}")


if __name__ == "__main__":  # pragma: no cover
    _cli()
