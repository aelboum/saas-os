"""Unit tests for `infra.db.backup`'s pure/filesystem-only logic -- no
database, no Docker, no subprocess needed. Uses real temporary files
(`tmp_path`) rather than mocks wherever a real file suffices (checksum
verification is filesystem-and-hashlib logic, not something a mock adds
value over). The real `pg_dump`/`pg_restore` execution path, RLS
restoration, and role semantics are proven separately, against a real
PostgreSQL container, in `tests/infra/db/test_backup_restore_drill_integration.py`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from infra.db.backup import (
    BackupError,
    BackupMetadata,
    ChecksumMismatchError,
    InvalidIdentifierError,
    _validate_backup_directory,
    _validate_container_name,
    _validate_identifier,
    list_backups,
    prune_backups,
    verify_backup_checksum,
)

# --- Identifier / path validation -------------------------------------


@pytest.mark.parametrize("name", ["saas_os", "saas_os_app", "_leading_underscore", "a", "T3nant"])
def test_valid_identifiers_are_accepted(name: str) -> None:
    assert _validate_identifier(name, label="x") == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "1starts_with_digit",
        "has-a-dash",
        "has a space",
        "has;semicolon",
        "has'quote",
        'has"doublequote',
        "has/slash",
        "DROP TABLE x;--",
        "a" * 64,  # 64 chars: over the 63-char Postgres identifier limit
    ],
)
def test_invalid_identifiers_are_rejected(name: str) -> None:
    with pytest.raises(InvalidIdentifierError):
        _validate_identifier(name, label="x")


@pytest.mark.parametrize("name", ["saas-os-db-1", "p13_drill_db", "a", "a.b-c_9"])
def test_valid_container_names_are_accepted(name: str) -> None:
    assert _validate_container_name(name) == name


@pytest.mark.parametrize("name", ["", "-leading-dash", "has space", "has;semicolon", "$(rm -rf /)"])
def test_invalid_container_names_are_rejected(name: str) -> None:
    with pytest.raises(InvalidIdentifierError):
        _validate_container_name(name)


def test_relative_backup_directory_is_rejected() -> None:
    with pytest.raises(BackupError, match="absolute"):
        _validate_backup_directory(Path("relative/backups"))


def test_backup_directory_with_dotdot_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match=r"\.\."):
        _validate_backup_directory(tmp_path / ".." / "escape")


def test_absolute_clean_backup_directory_is_accepted(tmp_path: Path) -> None:
    assert _validate_backup_directory(tmp_path) == tmp_path


# --- Checksum verification (real files, no mocks) -----------------------


def _write_backup(tmp_path: Path, *, content: bytes = b"fake-pgdump-bytes") -> tuple[Path, Path]:
    artifact_path = tmp_path / "widgets-20260101T000000Z.pgdump"
    metadata_path = tmp_path / "widgets-20260101T000000Z.pgdump.json"
    artifact_path.write_bytes(content)
    metadata = BackupMetadata(
        artifact_path=artifact_path,
        metadata_path=metadata_path,
        database="widgets",
        created_at="2026-01-01T00:00:00+00:00",
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        format="custom",
    )
    metadata_path.write_text(json.dumps(metadata.to_json_dict()))
    return artifact_path, metadata_path


def test_valid_backup_passes_checksum_verification(tmp_path: Path) -> None:
    _artifact, metadata_path = _write_backup(tmp_path)
    result = verify_backup_checksum(metadata_path)
    assert result.database == "widgets"
    assert result.sha256 == hashlib.sha256(b"fake-pgdump-bytes").hexdigest()


def test_corrupted_artifact_fails_checksum_verification(tmp_path: Path) -> None:
    artifact_path, metadata_path = _write_backup(tmp_path)
    artifact_path.write_bytes(b"tampered-bytes-different-content")
    with pytest.raises(ChecksumMismatchError):
        verify_backup_checksum(metadata_path)


def test_truncated_artifact_fails_checksum_verification_on_size(tmp_path: Path) -> None:
    artifact_path, metadata_path = _write_backup(tmp_path, content=b"0123456789" * 100)
    artifact_path.write_bytes(b"0123456789" * 50)  # truncated -- different size AND checksum
    with pytest.raises(ChecksumMismatchError):
        verify_backup_checksum(metadata_path)


def test_missing_artifact_is_rejected(tmp_path: Path) -> None:
    artifact_path, metadata_path = _write_backup(tmp_path)
    artifact_path.unlink()
    with pytest.raises(BackupError, match="not found"):
        verify_backup_checksum(metadata_path)


def test_missing_metadata_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="not found"):
        verify_backup_checksum(tmp_path / "does-not-exist.pgdump.json")


def test_corrupt_metadata_json_is_rejected(tmp_path: Path) -> None:
    metadata_path = tmp_path / "corrupt.pgdump.json"
    metadata_path.write_text("{ not valid json")
    with pytest.raises(BackupError, match="not valid JSON"):
        verify_backup_checksum(metadata_path)


def test_metadata_missing_required_field_is_rejected(tmp_path: Path) -> None:
    metadata_path = tmp_path / "incomplete.pgdump.json"
    metadata_path.write_text(json.dumps({"database": "widgets"}))
    with pytest.raises(BackupError, match="missing required field"):
        verify_backup_checksum(metadata_path)


def test_checksum_error_messages_never_contain_a_password_or_connection_string(
    tmp_path: Path,
) -> None:
    artifact_path, metadata_path = _write_backup(tmp_path)
    artifact_path.write_bytes(b"tampered")
    with pytest.raises(ChecksumMismatchError) as excinfo:
        verify_backup_checksum(metadata_path)
    message = str(excinfo.value).lower()
    for needle in ("password", "://", "@"):
        assert needle not in message


# --- Retention (real files, no mocks) ------------------------------------


def _seed_backup(tmp_path: Path, *, stem: str, created_at: str) -> None:
    content = stem.encode()
    artifact_path = tmp_path / f"{stem}.pgdump"
    metadata_path = tmp_path / f"{stem}.pgdump.json"
    artifact_path.write_bytes(content)
    metadata = BackupMetadata(
        artifact_path=artifact_path,
        metadata_path=metadata_path,
        database="widgets",
        created_at=created_at,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        format="custom",
    )
    metadata_path.write_text(json.dumps(metadata.to_json_dict()))


def test_list_backups_orders_oldest_first(tmp_path: Path) -> None:
    _seed_backup(tmp_path, stem="c", created_at="2026-01-03T00:00:00+00:00")
    _seed_backup(tmp_path, stem="a", created_at="2026-01-01T00:00:00+00:00")
    _seed_backup(tmp_path, stem="b", created_at="2026-01-02T00:00:00+00:00")

    backups = list_backups(tmp_path)
    assert [b.created_at for b in backups] == [
        "2026-01-01T00:00:00+00:00",
        "2026-01-02T00:00:00+00:00",
        "2026-01-03T00:00:00+00:00",
    ]


def test_list_backups_skips_a_corrupt_entry_without_crashing(tmp_path: Path) -> None:
    _seed_backup(tmp_path, stem="good", created_at="2026-01-01T00:00:00+00:00")
    (tmp_path / "bad.pgdump.json").write_text("{ not json")

    backups = list_backups(tmp_path)
    assert [b.database for b in backups] == ["widgets"]


def test_prune_backups_keeps_only_the_n_most_recent(tmp_path: Path) -> None:
    for i, day in enumerate(["01", "02", "03", "04"]):
        _seed_backup(tmp_path, stem=f"backup-{i}", created_at=f"2026-01-{day}T00:00:00+00:00")

    removed = prune_backups(tmp_path, keep_last=2)
    assert len(removed) == 2

    remaining = list_backups(tmp_path)
    assert [b.created_at for b in remaining] == [
        "2026-01-03T00:00:00+00:00",
        "2026-01-04T00:00:00+00:00",
    ]
    # both files of every pruned backup are actually gone from disk
    for path in removed:
        assert not path.exists()
        assert not Path(str(path) + ".json").exists()


def test_prune_backups_is_a_no_op_when_under_the_limit(tmp_path: Path) -> None:
    _seed_backup(tmp_path, stem="only-one", created_at="2026-01-01T00:00:00+00:00")
    removed = prune_backups(tmp_path, keep_last=5)
    assert removed == []
    assert len(list_backups(tmp_path)) == 1


def test_prune_backups_rejects_a_non_positive_keep_last(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="keep_last"):
        prune_backups(tmp_path, keep_last=0)
