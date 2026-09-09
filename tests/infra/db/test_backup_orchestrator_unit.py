"""Unit tests for `infra.db.backup.orchestrator` -- exercised against a
fake `create_backup`/`restore_backup` (no real `pg_dump`/`docker`
needed here; the real pipeline against a real PostgreSQL container is
proven by the extended drill in
`tests/infra/db/test_backup_restore_drill_integration.py`), a real `age`
round-trip (skipped if unavailable), and `FakeBackupDestination`.
Verifies: structured log events fire and never leak secrets/payloads,
the disk-space pre-check fails closed, the lock prevents a concurrent
`run_production_backup()` call, and `get_backup_health()`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from infra.db.backup import BackupMetadata
from infra.db.backup.config import BackupPipelineConfig
from infra.db.backup.destination import FakeBackupDestination
from infra.db.backup.encryption import (
    AGE_CIPHERTEXT_HEADER,
    encrypted_artifact_path,
    validate_recipient,
)
from infra.db.backup.lock import backup_lock
from infra.db.backup.orchestrator import (
    BackupPipelineError,
    get_backup_health,
    run_production_backup,
)
from infra.db.config import DatabaseConfig

_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None
requires_age = pytest.mark.skipif(not _AGE_AVAILABLE, reason="age/age-keygen not installed")

# Well-shaped, synthetic, never a real key -- enough for the orchestration-
# level tests below, which patch the `age` subprocess out (post-audit F-03:
# an off-site destination now *requires* a recipient, so these tests must
# supply one; the fail-closed contract itself is proven in
# tests/infra/db/test_backup_offsite_fail_closed_unit.py).
_SHAPED_RECIPIENT = "age1" + "q" * 58


@pytest.fixture()
def fake_encryptor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stands in for the real `age` subprocess: honours the recipient-shape
    rule and writes a correctly-headed synthetic ciphertext."""

    def encrypt(artifact_path: Path, *, recipient: str) -> Path:
        validate_recipient(recipient)
        output = encrypted_artifact_path(artifact_path)
        output.write_bytes(
            AGE_CIPHERTEXT_HEADER + b"\n-> synthetic:" + artifact_path.read_bytes()[::-1]
        )
        return output

    monkeypatch.setattr("infra.db.backup.orchestrator.encrypt_backup_artifact", encrypt)


def _admin_config() -> DatabaseConfig:
    return DatabaseConfig(url="postgresql://admin:pw@localhost:5432/saas_os")


def _fake_metadata(staging_dir: Path) -> BackupMetadata:
    artifact_path = staging_dir / "saas_os-20260101000000-deadbeef.pgdump"
    metadata_path = staging_dir / "saas_os-20260101000000-deadbeef.pgdump.json"
    artifact_path.write_bytes(b"fake pg_dump bytes")
    metadata = BackupMetadata(
        artifact_path=artifact_path,
        metadata_path=metadata_path,
        database="saas_os",
        created_at="2026-01-01T00:00:00+00:00",
        sha256="0" * 64,
        size_bytes=artifact_path.stat().st_size,
        format="custom",
    )
    # The real `create_backup()` always writes the metadata file next to
    # the artifact; the orchestrator extends it with the ciphertext's
    # checksum after encryption (post-audit F-03), so the fake must too.
    metadata_path.write_text(json.dumps(metadata.to_json_dict(), indent=2, sort_keys=True))
    return metadata


@pytest.fixture()
def patched_backup_primitives(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Patches `create_backup`/`verify_backup_checksum` at the point
    `orchestrator.py` imported them -- no real `pg_dump`/Docker needed for
    these orchestration-level tests."""
    metadata = _fake_metadata(tmp_path)

    def fake_create_backup(*, container: str, admin_config: DatabaseConfig, output_dir: Path):
        return metadata

    def fake_verify_backup_checksum(metadata_path: Path):
        return metadata

    monkeypatch.setattr("infra.db.backup.orchestrator.create_backup", fake_create_backup)
    monkeypatch.setattr(
        "infra.db.backup.orchestrator.verify_backup_checksum", fake_verify_backup_checksum
    )
    return metadata


def test_run_production_backup_succeeds_without_encryption_or_upload(
    tmp_path: Path, patched_backup_primitives: BackupMetadata
) -> None:
    config = BackupPipelineConfig(staging_dir=tmp_path)
    result = run_production_backup(container="db-1", admin_config=_admin_config(), config=config)
    assert result.metadata == patched_backup_primitives
    assert result.encrypted_path is None
    assert result.uploaded_key is None
    assert result.retention_deleted == ()


@requires_age
def test_run_production_backup_encrypts_when_recipient_given(
    tmp_path: Path, patched_backup_primitives: BackupMetadata
) -> None:
    keygen = subprocess.run(["age-keygen"], capture_output=True, text=True, check=True)
    recipient = next(
        line.split(":", 1)[1].strip()
        for line in keygen.stderr.splitlines()
        if line.startswith("Public key:")
    )
    config = BackupPipelineConfig(staging_dir=tmp_path)
    result = run_production_backup(
        container="db-1", admin_config=_admin_config(), config=config, recipient=recipient
    )
    assert result.encrypted_path is not None
    assert result.encrypted_path.is_file()


def test_run_production_backup_uploads_and_applies_retention_when_destination_given(
    tmp_path: Path, patched_backup_primitives: BackupMetadata, fake_encryptor: None
) -> None:
    destination = FakeBackupDestination()
    config = BackupPipelineConfig(staging_dir=tmp_path, retention_count=1)
    # Seed one older object so retention has something to delete.
    older = tmp_path / "older.pgdump.age"
    older.write_bytes(AGE_CIPHERTEXT_HEADER + b"\nolder")
    destination.upload(older, "postgres/older.pgdump.age")

    result = run_production_backup(
        container="db-1",
        admin_config=_admin_config(),
        config=config,
        recipient=_SHAPED_RECIPIENT,
        destination=destination,
    )
    assert result.uploaded_key is not None
    assert result.uploaded_key.endswith(".pgdump.age")
    assert result.uploaded_key in {o.key for o in destination.list_objects("postgres/")}
    assert "postgres/older.pgdump.age" in result.retention_deleted


def test_run_production_backup_fails_closed_on_insufficient_disk_space(
    tmp_path: Path, patched_backup_primitives: BackupMetadata
) -> None:
    config = BackupPipelineConfig(staging_dir=tmp_path, min_free_bytes=2**62)
    with pytest.raises(BackupPipelineError, match="insufficient disk space"):
        run_production_backup(container="db-1", admin_config=_admin_config(), config=config)


def test_run_production_backup_rejects_concurrent_execution(
    tmp_path: Path, patched_backup_primitives: BackupMetadata
) -> None:
    config = BackupPipelineConfig(staging_dir=tmp_path)
    lock_path = tmp_path / "backup.lock"
    with backup_lock(lock_path):
        with pytest.raises(BackupPipelineError, match="already"):
            run_production_backup(container="db-1", admin_config=_admin_config(), config=config)


def test_structured_events_never_include_secrets_or_payload_bytes(
    tmp_path: Path,
    patched_backup_primitives: BackupMetadata,
    fake_encryptor: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = BackupPipelineConfig(staging_dir=tmp_path)
    destination = FakeBackupDestination()
    with caplog.at_level("INFO"):
        run_production_backup(
            container="db-1",
            admin_config=_admin_config(),
            config=config,
            recipient=_SHAPED_RECIPIENT,
            destination=destination,
        )
    events = {r.message for r in caplog.records}
    assert "backup_started" in events
    assert "backup_succeeded" in events
    assert "backup_upload_succeeded" in events

    full_text = "\n".join(f"{r.message} {r.__dict__}" for r in caplog.records)
    assert "admin" not in full_text  # DatabaseConfig URL user/credential
    assert "pw@" not in full_text
    assert "fake pg_dump bytes" not in full_text
    assert _SHAPED_RECIPIENT not in full_text  # a key value is never a log field


def test_get_backup_health_reports_newest_local_backup(tmp_path: Path) -> None:
    import hashlib
    import json

    artifact_path = tmp_path / "saas_os-20260101000000-deadbeef.pgdump"
    metadata_path = tmp_path / "saas_os-20260101000000-deadbeef.pgdump.json"
    artifact_path.write_bytes(b"real bytes so the checksum matches")
    sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    metadata = BackupMetadata(
        artifact_path=artifact_path,
        metadata_path=metadata_path,
        database="saas_os",
        created_at="2026-01-01T00:00:00+00:00",
        sha256=sha256,
        size_bytes=artifact_path.stat().st_size,
        format="custom",
    )
    metadata_path.write_text(json.dumps(metadata.to_json_dict()))

    status = get_backup_health(staging_dir=tmp_path)
    assert status.newest_local_backup_at == "2026-01-01T00:00:00+00:00"
    assert status.newest_local_backup_checksum == sha256


def test_get_backup_health_with_no_backups_reports_none(tmp_path: Path) -> None:
    status = get_backup_health(staging_dir=tmp_path)
    assert status.newest_local_backup_at is None
    assert status.newest_local_backup_checksum is None
    assert status.newest_off_site_object_key is None


def test_get_backup_health_reports_newest_off_site_object(tmp_path: Path) -> None:
    destination = FakeBackupDestination()
    older = tmp_path / "a.pgdump"
    older.write_bytes(b"a")
    destination.upload(older, "postgres/a.pgdump")

    status = get_backup_health(staging_dir=tmp_path, destination=destination)
    assert status.newest_off_site_object_key == "postgres/a.pgdump"
