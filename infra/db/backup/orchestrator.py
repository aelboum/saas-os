"""P2.4 -- the production backup/restore pipeline, orchestrating the
existing P1.3 primitives (`infra/db/backup/__init__.py`'s `create_backup`/
`restore_backup`/`verify_backup_checksum`/`verify_restored_database`,
completely unchanged) with the new P2.4 steps (`lock.py`, `encryption.py`,
`destination.py`, `config.py`):

    backup:
        acquire_lock -> check_disk_space -> create_backup (pg_dump)
            -> verify checksum
            -> [off-site configured] require a valid encryption recipient
            -> encrypt (when a recipient is configured)
            -> [off-site configured] verify the ciphertext, record its
               checksum in the metadata file, upload ONLY the ciphertext
            -> apply_retention -> release_lock

    Off-site invariant (post-audit F-03, fail closed): a destination is
    never handed anything but a verified `age` ciphertext. No recipient,
    an empty/malformed recipient, an encryption failure, or an encrypted
    artifact that does not verify all abort the run *before*
    `destination.upload()` is ever called -- there is no plaintext
    fallback of any kind. A local-only run (no destination) keeps its
    existing semantics: encryption happens when a recipient is
    configured and is skipped when one is not.

    restore (never the default path -- always requires an explicit target
    and, for a *production* target, an explicit confirmation phrase):
        verify existence -> verify checksum -> decrypt
            -> restore_backup (pg_restore, into a fresh target only --
               `infra/db/backup/__init__.py`'s own restore-into-fresh
               guarantee is untouched) -> verify_restored_database (schema
               + RLS) -> caller runs tenant-isolation tests separately
               (this checkpoint's own instruction: the backup system
               itself must not expose tenant-selective restore/access --
               isolation is proven by the *drill*, e.g.
               `tests/infra/db/test_backup_restore_drill_integration.py`,
               using the application's own `tenant_session_scope()`,
               never a capability this module grants).

Every step emits exactly one of the structured events this checkpoint's
own Observability requirement lists (`backup_started`, `backup_succeeded`,
`backup_failed`, `backup_upload_succeeded`, `backup_upload_failed`,
`backup_restore_started`, `backup_restore_succeeded`,
`backup_restore_failed`) -- `extra=` fields are always identifiers/
counts/durations, never a password, connection string, encryption key,
or tenant payload.

This module is part of the `infra.db.backup` package and inherits its
"not an application-runtime capability" boundary unchanged (module
docstring of `infra/db/backup/__init__.py`) -- reachable only via
`python -m infra.db.backup.orchestrator` or an explicit
`from infra.db.backup.orchestrator import ...`, never from `core`,
`products`, `control_plane`, or `api`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from infra.db.backup import (
    BackupError,
    BackupMetadata,
    ChecksumMismatchError,
    RestoreError,
    RestoreResult,
    create_backup,
    list_backups,
    restore_backup,
    verify_backup_checksum,
)
from infra.db.backup.config import BackupPipelineConfig, get_backup_pipeline_config
from infra.db.backup.destination import (
    BackupDestination,
    BackupDestinationError,
    DestinationObject,
    apply_retention,
)
from infra.db.backup.encryption import (
    BackupEncryptionError,
    decrypt_backup_artifact,
    encrypt_backup_artifact,
    validate_recipient,
    verify_encrypted_artifact,
)
from infra.db.backup.lock import BackupLockError, backup_lock
from infra.db.config import DatabaseConfig

logger = logging.getLogger(__name__)

_LOCK_FILE_NAME = "backup.lock"
_DESTINATION_PREFIX = "postgres/"


class BackupPipelineError(RuntimeError):
    """Raised for any orchestration-level failure (locking, disk space,
    or a wrapped failure from a lower-level step). Never includes a
    secret -- the wrapped exception's own message is only ever included
    when that exception's own class already guarantees it is safe
    (`BackupError`/`RestoreError`/`BackupEncryptionError`/
    `BackupDestinationError` all already carry that guarantee)."""


class OffSiteEncryptionRequiredError(BackupPipelineError):
    """Raised when an off-site destination is configured but the run
    cannot produce a verified ciphertext for it -- no/empty/malformed
    `BACKUP_ENCRYPTION_RECIPIENT`, or an encrypted artifact that fails
    `verify_encrypted_artifact()`. Always raised *before*
    `destination.upload()` is called, so nothing leaves the host. Never
    includes the recipient value (a public key, but still configuration
    that has no business in a log line) or any artifact content."""


@dataclass(frozen=True)
class BackupRunResult:
    metadata: BackupMetadata
    encrypted_path: Path | None
    uploaded_key: str | None
    retention_deleted: tuple[str, ...]
    duration_seconds: float
    # SHA-256 of the `.age` ciphertext (also recorded in the metadata file
    # and the `backup_upload_succeeded` event) -- `None` when no
    # encryption happened, which a run with a destination can never be.
    encrypted_sha256: str | None = None


def _check_disk_space(directory: Path, *, min_free_bytes: int) -> None:
    """Pre-flight check (this checkpoint's own Storage Exhaustion
    requirement): refuse to even start `pg_dump` if the staging
    filesystem is already below the configured minimum -- never let a
    backup attempt silently produce (and then have `list_backups()`
    recognize) a truncated artifact for lack of disk space partway
    through."""
    directory.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(directory).free
    if free < min_free_bytes:
        raise BackupPipelineError(
            f"insufficient disk space in {directory.name!r}: {free} bytes free, "
            f"{min_free_bytes} required."
        )


def _sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_off_site_recipient(recipient: str | None) -> str:
    """The F-03 configuration gate for an off-site run: a present,
    well-shaped recipient, checked *before* any encryption attempt and
    before the destination is touched. Wraps `encryption.validate_recipient`
    into the pipeline's own error family so an operator sees one
    unambiguous, secret-free reason: off-site was requested, encryption
    was not configured, nothing was uploaded."""
    try:
        return validate_recipient(recipient)
    except BackupEncryptionError as exc:
        raise OffSiteEncryptionRequiredError(
            "off-site backup is configured but BACKUP_ENCRYPTION_RECIPIENT is missing or "
            "malformed -- refusing to run: an unencrypted artifact must never leave the host."
        ) from exc


def _ciphertext_for_upload(metadata: BackupMetadata, encrypted_path: Path | None) -> Path:
    """The ONLY path an off-site destination may ever receive. Fails
    closed unless `encrypted_path` exists, is distinct from the plaintext
    artifact, and verifies as a real `age` ciphertext -- there is
    deliberately no `encrypted_path or metadata.artifact_path` here, and
    `tests/infra/db/test_backup_offsite_fail_closed_unit.py` fails if one
    is ever reintroduced."""
    if encrypted_path is None:
        raise OffSiteEncryptionRequiredError(
            "off-site backup is configured but no encrypted artifact was produced -- "
            "refusing to upload."
        )
    if encrypted_path.resolve() == metadata.artifact_path.resolve():
        raise OffSiteEncryptionRequiredError(
            "off-site backup is configured but the encrypted artifact path is the plaintext "
            "artifact itself -- refusing to upload."
        )
    try:
        verify_encrypted_artifact(encrypted_path)
    except BackupEncryptionError as exc:
        raise OffSiteEncryptionRequiredError(
            f"off-site backup is configured but the encrypted artifact failed verification "
            f"before upload ({exc}) -- refusing to upload."
        ) from exc
    return encrypted_path


def _record_encrypted_artifact(metadata: BackupMetadata, encrypted_path: Path) -> str:
    """Extend the run's own `.pgdump.json` with the ciphertext's identity
    (`encrypted_artifact_path`, `encrypted_sha256`, `encrypted_size_bytes`)
    so the integrity metadata describes *both* objects: `sha256` remains
    the plaintext archive's checksum -- what `restore_backup()` verifies
    after decryption, unchanged -- and `encrypted_sha256` is the checksum
    of the exact object an off-site destination holds. Additive: every
    existing reader (`verify_backup_checksum`, `list_backups`) ignores the
    extra keys. Returns the ciphertext checksum."""
    encrypted_sha256 = _sha256_of_file(encrypted_path)
    raw = json.loads(metadata.metadata_path.read_text())
    raw["encrypted_artifact_path"] = str(encrypted_path)
    raw["encrypted_sha256"] = encrypted_sha256
    raw["encrypted_size_bytes"] = encrypted_path.stat().st_size
    metadata.metadata_path.write_text(json.dumps(raw, indent=2, sort_keys=True))
    return encrypted_sha256


def run_production_backup(
    *,
    container: str,
    admin_config: DatabaseConfig,
    config: BackupPipelineConfig | None = None,
    recipient: str | None = None,
    destination: BackupDestination | None = None,
) -> BackupRunResult:
    """The full scheduled pipeline (module docstring). `recipient` (the
    `age` public key) and `destination` are explicit, optional
    parameters -- tests substitute a fake recipient/`FakeBackupDestination`;
    the real scheduler entrypoint (`_cli()` below) resolves both from
    `SecretsProvider`/configuration.

    Contract:

    - `destination is None` (local-only, `BACKUP_OFF_SITE_ENABLED=false`):
      the artifact stays on the host; it is encrypted when a recipient is
      configured and left plaintext when none is -- the existing,
      explicitly supported "local-only, not yet a DR backup" mode.
    - `destination is not None` (off-site): a valid recipient is
      **required** (checked before any encryption I/O), encryption must
      succeed, the ciphertext must verify, and ONLY that ciphertext is
      uploaded. Every failure on that path raises before
      `destination.upload()` is called. There is no plaintext fallback
      (post-audit F-03).
    """
    cfg = config or get_backup_pipeline_config()
    lock_path = cfg.staging_dir / _LOCK_FILE_NAME
    started = time.monotonic()

    try:
        with backup_lock(lock_path):
            logger.info("backup_started", extra={"database": admin_config.url.rsplit("/", 1)[-1]})
            try:
                _check_disk_space(cfg.staging_dir, min_free_bytes=cfg.min_free_bytes)
            except BackupPipelineError:
                logger.error("backup_failed", extra={"error_type": "BackupPipelineError"})
                raise
            try:
                metadata = create_backup(
                    container=container, admin_config=admin_config, output_dir=cfg.staging_dir
                )
                verify_backup_checksum(metadata.metadata_path)  # fail closed before encrypting
            except (BackupError, ChecksumMismatchError) as exc:
                logger.error("backup_failed", extra={"error_type": type(exc).__name__})
                raise

            # F-03 gate 1 of 2: off-site requires encryption configuration.
            # Decided here -- after the local recovery point exists, before
            # any encryption attempt, and before the destination is touched.
            if destination is not None:
                try:
                    _require_off_site_recipient(recipient)
                except OffSiteEncryptionRequiredError:
                    logger.error(
                        "backup_failed", extra={"error_type": "OffSiteEncryptionRequiredError"}
                    )
                    raise

            encrypted_path: Path | None = None
            encrypted_sha256: str | None = None
            uploaded_key: str | None = None
            upload_source: Path | None = None
            if recipient:
                try:
                    encrypted_path = encrypt_backup_artifact(
                        metadata.artifact_path, recipient=recipient
                    )
                except BackupEncryptionError as exc:
                    logger.error("backup_failed", extra={"error_type": type(exc).__name__})
                    raise

            if destination is not None:
                # F-03 gate 2 of 2: only a verified ciphertext may be
                # uploaded -- never `metadata.artifact_path`. Decided before
                # the ciphertext is recorded in the metadata file and before
                # the destination is touched.
                try:
                    upload_source = _ciphertext_for_upload(metadata, encrypted_path)
                except OffSiteEncryptionRequiredError:
                    logger.error(
                        "backup_failed", extra={"error_type": "OffSiteEncryptionRequiredError"}
                    )
                    raise
            elif encrypted_path is not None:
                # Local-only, encrypted: the same format verification, so a
                # non-ciphertext output is a failure here too, never a
                # silently recorded "encrypted" artifact.
                try:
                    verify_encrypted_artifact(encrypted_path)
                except BackupEncryptionError as exc:
                    logger.error("backup_failed", extra={"error_type": type(exc).__name__})
                    raise

            if encrypted_path is not None:
                encrypted_sha256 = _record_encrypted_artifact(metadata, encrypted_path)

            if destination is not None:
                assert upload_source is not None  # established by the gate above
                uploaded_key = f"{_DESTINATION_PREFIX}{upload_source.name}"
                try:
                    destination.upload(upload_source, uploaded_key)
                    logger.info(
                        "backup_upload_succeeded",
                        extra={
                            "object_key": uploaded_key,
                            "size_bytes": upload_source.stat().st_size,
                            "encrypted_sha256": encrypted_sha256,
                        },
                    )
                except BackupDestinationError as exc:
                    logger.error(
                        "backup_upload_failed",
                        extra={"error_type": type(exc).__name__, "object_key": uploaded_key},
                    )
                    raise

            retention_deleted: tuple[str, ...] = ()
            if destination is not None:
                retention_deleted = tuple(
                    apply_retention(
                        destination, prefix=_DESTINATION_PREFIX, keep_last=cfg.retention_count
                    )
                )

            duration = time.monotonic() - started
            logger.info(
                "backup_succeeded",
                extra={
                    "duration_seconds": round(duration, 2),
                    "artifact_size_bytes": metadata.size_bytes,
                    "checksum": metadata.sha256,
                    "encrypted": encrypted_path is not None,
                    "encrypted_sha256": encrypted_sha256,
                    "uploaded": uploaded_key is not None,
                },
            )
            return BackupRunResult(
                metadata=metadata,
                encrypted_path=encrypted_path,
                uploaded_key=uploaded_key,
                retention_deleted=retention_deleted,
                duration_seconds=duration,
                encrypted_sha256=encrypted_sha256,
            )
    except BackupLockError as exc:
        logger.error("backup_failed", extra={"error_type": "BackupLockError"})
        raise BackupPipelineError(str(exc)) from exc


@dataclass(frozen=True)
class RestoreRunResult:
    result: RestoreResult
    duration_seconds: float


def run_production_restore(
    *,
    container: str,
    admin_config: DatabaseConfig,
    metadata_path: Path,
    target_database: str,
    identity: str | None = None,
    encrypted_path: Path | None = None,
) -> RestoreRunResult:
    """Fail-closed restore orchestration (module docstring's required
    order). `target_database` is always required and always explicit --
    there is no default target anywhere in this call chain, mirroring
    `infra/db/backup/__init__.py::restore_backup`'s own "never restore
    over an existing database" guarantee, which this function does not
    change or bypass. If `encrypted_path`/`identity` are given, the
    artifact is decrypted first, into the same directory as
    `metadata_path`, before the existing checksum-then-restore path runs
    unchanged."""
    started = time.monotonic()
    logger.info("backup_restore_started", extra={"target_database": target_database})
    try:
        if encrypted_path is not None:
            if not identity:
                raise BackupPipelineError(
                    "an encrypted artifact was given but no decryption identity was provided."
                )
            plaintext_path = encrypted_path.with_suffix("")
            try:
                decrypt_backup_artifact(
                    encrypted_path, identity=identity, output_path=plaintext_path
                )
            except BackupEncryptionError as exc:
                logger.error("backup_restore_failed", extra={"error_type": type(exc).__name__})
                raise

        try:
            result = restore_backup(
                container=container,
                admin_config=admin_config,
                metadata_path=metadata_path,
                target_database=target_database,
            )
        except (RestoreError, ChecksumMismatchError) as exc:
            logger.error("backup_restore_failed", extra={"error_type": type(exc).__name__})
            raise

        duration = time.monotonic() - started
        logger.info(
            "backup_restore_succeeded",
            extra={"target_database": target_database, "duration_seconds": round(duration, 2)},
        )
        return RestoreRunResult(result=result, duration_seconds=duration)
    except BackupPipelineError:
        raise


@dataclass(frozen=True)
class BackupHealthStatus:
    """What `docs/BACKUP-RESTORE.md`'s own "When was the last successful
    backup?" operational question resolves to (this checkpoint's own
    Backup Health requirement) -- deliberately not wired into `/readyz`
    (a backup failure is an operational alert, never an API outage, this
    checkpoint's own explicit instruction)."""

    newest_local_backup_at: str | None
    newest_local_backup_checksum: str | None
    newest_off_site_object_key: str | None
    newest_off_site_uploaded_at: str | None


def get_backup_health(
    *, staging_dir: Path, destination: BackupDestination | None = None
) -> BackupHealthStatus:
    local_backups = list_backups(staging_dir)
    newest_local = local_backups[-1] if local_backups else None

    newest_off_site: DestinationObject | None = None
    if destination is not None:
        objects = sorted(
            destination.list_objects(_DESTINATION_PREFIX), key=lambda o: o.last_modified
        )
        newest_off_site = objects[-1] if objects else None

    return BackupHealthStatus(
        newest_local_backup_at=newest_local.created_at if newest_local else None,
        newest_local_backup_checksum=newest_local.sha256 if newest_local else None,
        newest_off_site_object_key=newest_off_site.key if newest_off_site else None,
        newest_off_site_uploaded_at=newest_off_site.last_modified if newest_off_site else None,
    )


def _cli() -> None:  # pragma: no cover -- thin argparse wrapper, exercised via the functions above
    """`python -m infra.db.backup.orchestrator {run,restore,status}` --
    the production entrypoint a host-level systemd timer/cron job invokes
    (`docs/BACKUP-RESTORE.md`). Resolves the `age` recipient and the
    off-site destination from `SecretsProvider`/`BackupPipelineConfig`;
    never accepts a secret value as a command-line argument (would appear
    in a process listing)."""
    import argparse
    import sys

    from infra.db.config import get_migrations_database_config
    from infra.secrets import get_secrets_provider

    parser = argparse.ArgumentParser(prog="python -m infra.db.backup.orchestrator")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run the full scheduled backup pipeline.")
    run_p.add_argument("--container", required=True)

    restore_p = sub.add_parser("restore", help="Restore an encrypted or plain backup.")
    restore_p.add_argument("--container", required=True)
    restore_p.add_argument("--metadata", required=True, type=Path)
    restore_p.add_argument("--target-database", required=True)
    restore_p.add_argument("--encrypted", type=Path, default=None)
    restore_p.add_argument(
        "--confirm-production-restore",
        action="store_true",
        help="Required no-op flag an operator must pass deliberately; this command never "
        "restores over an existing database regardless (infra/db/backup's own guarantee).",
    )

    sub.add_parser("status", help="Report the newest known-good local/off-site recovery point.")

    args = parser.parse_args()
    admin_config = get_migrations_database_config()
    cfg = get_backup_pipeline_config()
    secrets = get_secrets_provider()

    destination: BackupDestination | None = None
    if cfg.off_site_enabled:
        from infra.db.backup.destination import S3CompatibleBackupDestination

        destination = S3CompatibleBackupDestination()

    if args.command == "run":
        recipient = secrets.get("BACKUP_ENCRYPTION_RECIPIENT")
        result = run_production_backup(
            container=args.container,
            admin_config=admin_config,
            config=cfg,
            recipient=recipient,
            destination=destination,
        )
        print(
            f"Backup complete in {result.duration_seconds:.1f}s: "
            f"{result.metadata.artifact_path.name} (sha256={result.metadata.sha256[:12]}...)"
        )
    elif args.command == "restore":
        if not args.confirm_production_restore:
            print(
                "Refusing to restore without --confirm-production-restore "
                "(no database is ever overwritten regardless -- this flag is a "
                "deliberate operator acknowledgement, not a safety bypass).",
                file=sys.stderr,
            )
            raise SystemExit(2)
        identity = secrets.get("BACKUP_ENCRYPTION_IDENTITY") if args.encrypted else None
        restore_result = run_production_restore(
            container=args.container,
            admin_config=admin_config,
            metadata_path=args.metadata,
            target_database=args.target_database,
            identity=identity,
            encrypted_path=args.encrypted,
        )
        print(
            f"Restore complete in {restore_result.duration_seconds:.1f}s into "
            f"{restore_result.result.target_database!r}. Run verify_restored_database() "
            "and the tenant-isolation checks before trusting it."
        )
    elif args.command == "status":
        status = get_backup_health(staging_dir=cfg.staging_dir, destination=destination)
        print(
            f"newest local backup:    {status.newest_local_backup_at or 'none'}\n"
            f"newest off-site object: {status.newest_off_site_object_key or 'none'} "
            f"({status.newest_off_site_uploaded_at or 'n/a'})"
        )


if __name__ == "__main__":  # pragma: no cover
    _cli()
