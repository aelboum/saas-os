"""P2.4 -- the off-site backup destination abstraction: `local backup !=
DR backup` (this checkpoint's own required distinction). A backup that
never leaves the VPS its own database runs on is not a disaster-recovery
backup -- it is lost in the exact scenario (total VPS loss) DR exists to
survive.

Mirrors this repository's own established provider-abstraction pattern
(`core.billing.provider.BillingProvider`/`FakeBillingProvider`/
`StripeBillingProvider`; `core.email.provider.EmailProvider`/
`FakeEmailProvider`; `core/email/smtp_provider.py`'s `SmtpEmailProvider`)
exactly: one `@runtime_checkable Protocol`, one in-memory `Fake*`
implementation every test uses by default, and one real implementation
-- here, a generic S3-compatible object-storage destination (works
against AWS S3, MinIO, Backblaze B2, Wasabi, Cloudflare R2, or any other
S3-API-compatible endpoint via `endpoint_url`; this repository has not
selected a specific vendor, and this module does not either, per this
checkpoint's own "do not hard-code AWS/S3/Backblaze/Wasabi unless already
selected" instruction). `LocalBackupDestination` is a second, real,
non-fake implementation -- copying to a second local/mounted path is a
legitimate destination tier (e.g. a mounted network share), just never a
sufficient *sole* tier for DR (see module docstring above).

Credentials for the real destination are read through
`infra.secrets.get_secrets_provider()` only -- `BACKUP_S3_ENDPOINT_URL`,
`BACKUP_S3_BUCKET`, `BACKUP_S3_ACCESS_KEY_ID`, `BACKUP_S3_SECRET_ACCESS_KEY`
-- never `os.environ` directly, and none of them is ever logged. This
repository's off-site credential is dedicated to backups specifically
(this checkpoint's own "do not reuse application object-storage
credentials" -- no other module in this repository currently uses object
storage at all, so there is nothing to accidentally share with).

Uses `boto3` (the official AWS SDK, also the de facto standard client for
any S3-compatible API) -- a new runtime dependency, justified the same
way `stripe`/`httpx` were when a phase genuinely needed a real external
integration (`pyproject.toml`'s own dependency-comment convention):
hand-rolling AWS SigV4 request signing to avoid one well-maintained
official library would be reinventing a wheel with real correctness/
security risk, the same reasoning this checkpoint's own "do not invent
cryptography" applies to `age` in `encryption.py`.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from infra.secrets import get_secrets_provider

logger = logging.getLogger(__name__)


class BackupDestinationError(RuntimeError):
    """Raised for any destination failure (upload/list/delete/download).
    Never includes a credential, endpoint URL with embedded credentials,
    or bucket contents -- only an operation name and a short
    classification (mirrors `core/email/errors.py::EmailProviderError`'s
    convention exactly)."""

    def __init__(self, operation: str, reason: str) -> None:
        self.operation = operation
        super().__init__(f"Backup destination operation {operation!r} failed: {reason}")


@dataclass(frozen=True)
class DestinationObject:
    """One object as a destination reports it back -- key, size, and the
    destination's own last-modified timestamp (ISO 8601). Never the
    object's own bytes; this is listing/retention metadata only."""

    key: str
    size_bytes: int
    last_modified: str


@runtime_checkable
class BackupDestination(Protocol):
    """The one interface `orchestrator.py` uploads/lists/deletes/downloads
    through. `key` is always an opaque, pre-built object identifier
    (`config.py`'s own naming scheme) -- this Protocol has no opinion on
    naming, only transport."""

    def upload(self, local_path: Path, key: str) -> None:
        """Upload `local_path` (already encrypted -- this destination
        layer never sees plaintext tenant data) under `key`. Must raise
        `BackupDestinationError` on any failure -- never a raw
        provider/transport exception."""
        ...

    def download(self, key: str, local_path: Path) -> None:
        """Download `key` to `local_path`. Raises `BackupDestinationError`
        if `key` does not exist or the transfer fails."""
        ...

    def list_objects(self, prefix: str) -> list[DestinationObject]:
        """Every object under `prefix`, in no particular guaranteed order
        -- callers needing a specific order (retention) sort explicitly."""
        ...

    def delete_object(self, key: str) -> None:
        """Delete `key`. Idempotent: deleting an already-absent key is not
        an error (mirrors this repository's other idempotent revoke/
        unsubscribe operations, e.g. `core.identity.sessions.revoke_session`)."""
        ...


class FakeBackupDestination:
    """An in-memory `BackupDestination` -- no network access, no
    credentials. What every test in this repository uses by default
    (mirrors `core.billing.provider.FakeBillingProvider`'s identical
    role)."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        self._last_modified: dict[str, str] = {}

    def upload(self, local_path: Path, key: str) -> None:
        if not local_path.is_file():
            raise BackupDestinationError("upload", "local file does not exist")
        self._objects[key] = local_path.read_bytes()
        import datetime as _dt

        self._last_modified[key] = _dt.datetime.now(_dt.UTC).isoformat()

    def download(self, key: str, local_path: Path) -> None:
        if key not in self._objects:
            raise BackupDestinationError("download", "object not found")
        local_path.write_bytes(self._objects[key])

    def list_objects(self, prefix: str) -> list[DestinationObject]:
        return [
            DestinationObject(key=key, size_bytes=len(data), last_modified=self._last_modified[key])
            for key, data in self._objects.items()
            if key.startswith(prefix)
        ]

    def delete_object(self, key: str) -> None:
        self._objects.pop(key, None)
        self._last_modified.pop(key, None)


class LocalBackupDestination:
    """A second local (or mounted network share) path -- a real, non-fake
    destination, but never a *sufficient sole* DR tier by itself (module
    docstring). `root` must be an absolute path, mirroring
    `infra/db/backup/__init__.py::_validate_backup_directory`'s own
    discipline (never validated twice with different rules)."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise BackupDestinationError("configure", "destination root must be an absolute path")
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str) -> Path:
        # Object-storage keys are always POSIX-style, slash-separated
        # identifiers regardless of host OS -- checking `key.startswith("/")`
        # explicitly (in addition to `Path(key).is_absolute()`) rejects a
        # POSIX-absolute-looking key even when this code happens to run on
        # Windows, where `Path("/etc/passwd").is_absolute()` is False.
        if ".." in Path(key).parts or Path(key).is_absolute() or key.startswith("/"):
            raise BackupDestinationError("resolve", "object key must be a safe relative path")
        return self._root / key

    def upload(self, local_path: Path, key: str) -> None:
        if not local_path.is_file():
            raise BackupDestinationError("upload", "local file does not exist")
        target = self._path_for(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local_path, target)

    def download(self, key: str, local_path: Path) -> None:
        source = self._path_for(key)
        if not source.is_file():
            raise BackupDestinationError("download", "object not found")
        shutil.copyfile(source, local_path)

    def list_objects(self, prefix: str) -> list[DestinationObject]:
        results: list[DestinationObject] = []
        for path in self._root.rglob("*"):
            if not path.is_file():
                continue
            key = str(path.relative_to(self._root)).replace("\\", "/")
            if key.startswith(prefix):
                stat = path.stat()
                import datetime as _dt

                results.append(
                    DestinationObject(
                        key=key,
                        size_bytes=stat.st_size,
                        last_modified=_dt.datetime.fromtimestamp(
                            stat.st_mtime, tz=_dt.UTC
                        ).isoformat(),
                    )
                )
        return results

    def delete_object(self, key: str) -> None:
        self._path_for(key).unlink(missing_ok=True)


@dataclass(frozen=True)
class S3DestinationConfig:
    endpoint_url: str
    bucket: str
    access_key_id: str
    secret_access_key: str
    region: str = "us-east-1"


def get_s3_destination_config() -> S3DestinationConfig:
    """Resolves every value through `infra.secrets.get_secrets_provider()`
    -- module docstring. Raises `BackupDestinationError` (not a bare
    `LookupError`) if any required value is missing, so a misconfigured
    off-site destination fails with the same error family every other
    destination failure does."""
    secrets = get_secrets_provider()
    endpoint_url = secrets.get("BACKUP_S3_ENDPOINT_URL")
    bucket = secrets.get("BACKUP_S3_BUCKET")
    access_key_id = secrets.get("BACKUP_S3_ACCESS_KEY_ID")
    secret_access_key = secrets.get("BACKUP_S3_SECRET_ACCESS_KEY")
    missing = [
        name
        for name, value in (
            ("BACKUP_S3_ENDPOINT_URL", endpoint_url),
            ("BACKUP_S3_BUCKET", bucket),
            ("BACKUP_S3_ACCESS_KEY_ID", access_key_id),
            ("BACKUP_S3_SECRET_ACCESS_KEY", secret_access_key),
        )
        if not value
    ]
    if missing:
        raise BackupDestinationError("configure", f"missing configuration: {', '.join(missing)}")
    assert endpoint_url and bucket and access_key_id and secret_access_key
    return S3DestinationConfig(
        endpoint_url=endpoint_url,
        bucket=bucket,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        region=secrets.get("BACKUP_S3_REGION") or "us-east-1",
    )


class S3CompatibleBackupDestination:
    """The one real off-site `BackupDestination` -- any S3-API-compatible
    endpoint (module docstring). TLS is inherent: `boto3`/`botocore`
    default to `https://` and this module never overrides that. The
    bucket is dedicated to backups (an operational/IAM convention this
    module cannot enforce in code, documented in `docs/BACKUP-RESTORE.md`);
    credentials are read once, through `SecretsProvider`, never stored
    anywhere but this instance's own boto3 client."""

    def __init__(self, config: S3DestinationConfig | None = None) -> None:
        import boto3  # local import: boto3 is only required when an S3 destination is actually used

        cfg = config or get_s3_destination_config()
        self._bucket = cfg.bucket
        self._client = boto3.client(
            "s3",
            endpoint_url=cfg.endpoint_url,
            aws_access_key_id=cfg.access_key_id,
            aws_secret_access_key=cfg.secret_access_key,
            region_name=cfg.region,
        )

    def upload(self, local_path: Path, key: str) -> None:
        if not local_path.is_file():
            raise BackupDestinationError("upload", "local file does not exist")
        try:
            self._client.upload_file(str(local_path), self._bucket, key)
        except Exception as exc:  # noqa: BLE001 -- normalized, never the raw botocore exception
            raise BackupDestinationError("upload", type(exc).__name__) from exc

    def download(self, key: str, local_path: Path) -> None:
        try:
            self._client.download_file(self._bucket, key, str(local_path))
        except Exception as exc:  # noqa: BLE001
            raise BackupDestinationError("download", type(exc).__name__) from exc

    def list_objects(self, prefix: str) -> list[DestinationObject]:
        try:
            paginator = self._client.get_paginator("list_objects_v2")
            results: list[DestinationObject] = []
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    results.append(
                        DestinationObject(
                            key=obj["Key"],
                            size_bytes=obj["Size"],
                            last_modified=obj["LastModified"].isoformat(),
                        )
                    )
            return results
        except Exception as exc:  # noqa: BLE001
            raise BackupDestinationError("list_objects", type(exc).__name__) from exc

    def delete_object(self, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self._bucket, Key=key)
        except Exception as exc:  # noqa: BLE001
            raise BackupDestinationError("delete_object", type(exc).__name__) from exc


def apply_retention(destination: BackupDestination, *, prefix: str, keep_last: int) -> list[str]:
    """Destination-agnostic keep-last-N retention (this checkpoint's own
    "prefer a simple deterministic keep-last-N policy"). Works identically
    against `FakeBackupDestination`/`LocalBackupDestination`/
    `S3CompatibleBackupDestination` -- retention logic itself never knows
    which one it is talking to.

    Sorted by `last_modified` (the destination's own authoritative
    timestamp, never a value parsed back out of the key/filename -- this
    checkpoint's own "do not trust only the filename"). Never deletes the
    single newest object regardless of `keep_last` -- even `keep_last=0`
    (an operator misconfiguration) still leaves the newest recovery point
    in place, satisfying "never delete all known valid recovery points"
    structurally rather than by trusting the caller's own input.
    """
    if keep_last < 1:
        keep_last = 1
    objects = sorted(destination.list_objects(prefix), key=lambda o: o.last_modified)
    to_delete = objects[:-keep_last] if len(objects) > keep_last else []
    deleted: list[str] = []
    for obj in to_delete:
        destination.delete_object(obj.key)
        deleted.append(obj.key)
        logger.info(
            "backup_retention_deleted",
            extra={"object_key": obj.key, "object_size_bytes": obj.size_bytes},
        )
    return deleted
