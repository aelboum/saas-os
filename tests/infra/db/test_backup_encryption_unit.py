"""Unit tests for `infra.db.backup.encryption` -- real `age` binary
round-trips (skipped cleanly if `age` is not installed), and pure
validation logic that needs no binary at all. No database, no Docker.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from infra.db.backup.encryption import (
    BackupEncryptionError,
    decrypt_backup_artifact,
    encrypt_backup_artifact,
    encrypted_artifact_path,
)

_AGE_AVAILABLE = shutil.which("age") is not None
_AGE_KEYGEN_AVAILABLE = shutil.which("age-keygen") is not None

requires_age = pytest.mark.skipif(
    not (_AGE_AVAILABLE and _AGE_KEYGEN_AVAILABLE),
    reason="age/age-keygen not installed on PATH",
)


@pytest.fixture()
def age_keypair() -> tuple[str, str]:
    """A real, freshly generated (recipient, identity) pair -- never a
    fixed key checked into the repo."""
    result = subprocess.run(["age-keygen"], capture_output=True, text=True, timeout=30, check=True)
    identity = None
    recipient = None
    for line in result.stdout.splitlines():
        if line.startswith("AGE-SECRET-KEY-1"):
            identity = line.strip()
    for line in result.stderr.splitlines():
        if line.startswith("Public key:"):
            recipient = line.split(":", 1)[1].strip()
    assert identity and recipient
    return recipient, identity


def test_encrypted_artifact_path_appends_suffix(tmp_path: Path) -> None:
    artifact = tmp_path / "db-20260101-abcd1234.pgdump"
    assert encrypted_artifact_path(artifact) == tmp_path / "db-20260101-abcd1234.pgdump.age"


@requires_age
def test_encrypt_then_decrypt_round_trips_the_original_bytes(
    tmp_path: Path, age_keypair: tuple[str, str]
) -> None:
    recipient, identity = age_keypair
    artifact = tmp_path / "backup.pgdump"
    original_bytes = b"not a real pg_dump -- just round-trip payload bytes \x00\x01\x02"
    artifact.write_bytes(original_bytes)

    encrypted_path = encrypt_backup_artifact(artifact, recipient=recipient)
    assert encrypted_path.is_file()
    assert encrypted_path.read_bytes() != original_bytes

    decrypted_path = tmp_path / "restored.pgdump"
    decrypt_backup_artifact(encrypted_path, identity=identity, output_path=decrypted_path)
    assert decrypted_path.read_bytes() == original_bytes


@requires_age
def test_decrypt_with_wrong_identity_is_rejected(
    tmp_path: Path, age_keypair: tuple[str, str]
) -> None:
    recipient, _correct_identity = age_keypair
    _wrong_recipient, wrong_identity = subprocess_keypair()
    artifact = tmp_path / "backup.pgdump"
    artifact.write_bytes(b"secret payload")
    encrypted_path = encrypt_backup_artifact(artifact, recipient=recipient)

    with pytest.raises(BackupEncryptionError):
        decrypt_backup_artifact(
            encrypted_path, identity=wrong_identity, output_path=tmp_path / "out.pgdump"
        )
    assert not (tmp_path / "out.pgdump").exists()


def subprocess_keypair() -> tuple[str, str]:
    result = subprocess.run(["age-keygen"], capture_output=True, text=True, timeout=30, check=True)
    identity = next(
        line.strip() for line in result.stdout.splitlines() if line.startswith("AGE-SECRET-KEY-1")
    )
    recipient = next(
        line.split(":", 1)[1].strip()
        for line in result.stderr.splitlines()
        if line.startswith("Public key:")
    )
    return recipient, identity


def test_encrypt_rejects_missing_recipient(tmp_path: Path) -> None:
    artifact = tmp_path / "backup.pgdump"
    artifact.write_bytes(b"data")
    with pytest.raises(BackupEncryptionError, match="RECIPIENT"):
        encrypt_backup_artifact(artifact, recipient="")


def test_encrypt_rejects_malformed_recipient(tmp_path: Path) -> None:
    artifact = tmp_path / "backup.pgdump"
    artifact.write_bytes(b"data")
    with pytest.raises(BackupEncryptionError, match="RECIPIENT"):
        encrypt_backup_artifact(artifact, recipient="not-an-age-key")


def test_encrypt_rejects_missing_artifact(tmp_path: Path) -> None:
    with pytest.raises(BackupEncryptionError, match="not found"):
        encrypt_backup_artifact(
            tmp_path / "does-not-exist.pgdump",
            recipient="age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        )


def test_decrypt_rejects_missing_identity(tmp_path: Path) -> None:
    encrypted = tmp_path / "backup.pgdump.age"
    encrypted.write_bytes(b"ciphertext")
    with pytest.raises(BackupEncryptionError, match="identity"):
        decrypt_backup_artifact(encrypted, identity="", output_path=tmp_path / "out.pgdump")


def test_decrypt_rejects_malformed_identity(tmp_path: Path) -> None:
    encrypted = tmp_path / "backup.pgdump.age"
    encrypted.write_bytes(b"ciphertext")
    with pytest.raises(BackupEncryptionError, match="identity"):
        decrypt_backup_artifact(
            encrypted, identity="not-an-age-identity", output_path=tmp_path / "out.pgdump"
        )


def test_decrypt_rejects_missing_encrypted_artifact(tmp_path: Path) -> None:
    with pytest.raises(BackupEncryptionError, match="not found"):
        decrypt_backup_artifact(
            tmp_path / "missing.pgdump.age",
            identity="AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
            output_path=tmp_path / "out.pgdump",
        )


@requires_age
def test_no_key_value_appears_in_any_raised_exception_message(
    tmp_path: Path, age_keypair: tuple[str, str]
) -> None:
    """The recipient/identity values themselves must never leak into an
    exception message (module docstring's own security guarantee)."""
    recipient, identity = age_keypair
    artifact = tmp_path / "backup.pgdump"
    artifact.write_bytes(b"data")
    encrypted_path = encrypt_backup_artifact(artifact, recipient=recipient)

    corrupted = tmp_path / "corrupted.pgdump.age"
    corrupted.write_bytes(b"not valid age ciphertext at all")
    with pytest.raises(BackupEncryptionError) as excinfo:
        decrypt_backup_artifact(corrupted, identity=identity, output_path=tmp_path / "out.pgdump")
    assert identity not in str(excinfo.value)
    assert "AGE-SECRET-KEY" not in str(excinfo.value)
    encrypted_path.unlink(missing_ok=True)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permission bits only")
@requires_age
def test_identity_temp_file_is_owner_only_and_cleaned_up(
    tmp_path: Path, age_keypair: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    recipient, identity = age_keypair
    artifact = tmp_path / "backup.pgdump"
    artifact.write_bytes(b"data")
    encrypted_path = encrypt_backup_artifact(artifact, recipient=recipient)

    observed_modes: list[int] = []
    original_chmod = Path.chmod

    def spy_chmod(self: Path, mode: int) -> None:
        observed_modes.append(mode)
        original_chmod(self, mode)

    monkeypatch.setattr(Path, "chmod", spy_chmod)
    decrypt_backup_artifact(encrypted_path, identity=identity, output_path=tmp_path / "out.pgdump")
    assert observed_modes == [stat.S_IRUSR | stat.S_IWUSR]

    # No leftover age-identity-*.txt file survives the call.
    import tempfile

    leftover = list(Path(tempfile.gettempdir()).glob("age-identity-*.txt"))
    assert leftover == []
