"""Post-audit F-03 -- off-site backup fails closed without encryption.

The production-readiness re-audit found that `run_production_backup()`
encrypted only `if recipient:` and then uploaded
`encrypted_path or metadata.artifact_path` -- so with off-site enabled and
`BACKUP_ENCRYPTION_RECIPIENT` unset, empty, or malformed, the plaintext
`pg_dump` archive left the host. These tests pin the corrected contract:

    off-site destination configured
        -> a valid `age1...` recipient is REQUIRED (checked before any I/O)
        -> encryption must succeed
        -> the ciphertext must verify as a real age file
        -> ONLY that ciphertext is handed to `destination.upload()`
        -> any failure above aborts with zero uploads

and that local-only backups keep their existing semantics. Every test uses
synthetic bytes and, where a real key is needed, a freshly generated
throwaway `age` keypair -- never a real key, never real tenant data.

`create_backup`/`verify_backup_checksum` are patched at the point the
orchestrator imported them (same approach as
`tests/infra/db/test_backup_orchestrator_unit.py`) -- no `pg_dump`/Docker
needed. Where a test does not need the real `age` binary, a *fake
encryptor* that writes a correctly-headed synthetic ciphertext is
patched in, so the pipeline-level invariants are proven hermetically on
every machine; the real-`age` tests are additionally marked
`requires_age`.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import infra.db.backup.orchestrator as orchestrator_module
import pytest
from infra.db.backup import BackupMetadata, verify_backup_checksum
from infra.db.backup.config import BackupPipelineConfig
from infra.db.backup.destination import (
    FakeBackupDestination,
    LocalBackupDestination,
    S3CompatibleBackupDestination,
    S3DestinationConfig,
)
from infra.db.backup.encryption import (
    AGE_CIPHERTEXT_HEADER,
    BackupEncryptionError,
    decrypt_backup_artifact,
    encrypted_artifact_path,
    validate_recipient,
    verify_encrypted_artifact,
)
from infra.db.backup.orchestrator import (
    BackupRunResult,
    OffSiteEncryptionRequiredError,
    run_production_backup,
)
from infra.db.config import DatabaseConfig

_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None
requires_age = pytest.mark.skipif(not _AGE_AVAILABLE, reason="age/age-keygen not installed")

# A `pg_dump -Fc` archive starts with these bytes -- the synthetic artifact
# below is recognisably "plaintext" to every assertion here.
_PLAINTEXT = b"PGDMP\x01\x0e\x00synthetic-tenant-data-never-real\n" * 4
# Well-shaped but synthetic: passes `validate_recipient()`'s shape check,
# is not, and has never been, a real public key.
_SHAPED_RECIPIENT = "age1" + "q" * 58
# Shaped like an age *identity* -- the private half an operator could
# paste by mistake. Must be rejected and must never be echoed anywhere.
_SYNTHETIC_IDENTITY_MISTAKE = "AGE-SECRET-KEY-1" + "SYNTHETICNEVERREAL" * 3


def _admin_config() -> DatabaseConfig:
    # Synthetic placeholder DSN (same fixture shape as every other backup
    # test); never a real credential.
    # pragma: allowlist nextline secret
    return DatabaseConfig(url="postgresql://admin:pw@localhost:5432/saas_os")


def _write_synthetic_backup(staging_dir: Path) -> BackupMetadata:
    """A plaintext artifact plus a *real* metadata file whose checksum
    matches -- so the tests that exercise the restore contract can run the
    unpatched `verify_backup_checksum()` against it."""
    staging_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = staging_dir / "saas_os-20260101T000000Z-f03f03f0.pgdump"
    metadata_path = staging_dir / "saas_os-20260101T000000Z-f03f03f0.pgdump.json"
    artifact_path.write_bytes(_PLAINTEXT)
    metadata = BackupMetadata(
        artifact_path=artifact_path,
        metadata_path=metadata_path,
        database="saas_os",
        created_at="2026-01-01T00:00:00+00:00",
        sha256=hashlib.sha256(_PLAINTEXT).hexdigest(),
        size_bytes=artifact_path.stat().st_size,
        format="custom",
    )
    metadata_path.write_text(json.dumps(metadata.to_json_dict(), indent=2, sort_keys=True))
    return metadata


@pytest.fixture()
def staged_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BackupMetadata:
    metadata = _write_synthetic_backup(tmp_path)

    def fake_create_backup(*, container: str, admin_config: DatabaseConfig, output_dir: Path):
        return metadata

    monkeypatch.setattr(orchestrator_module, "create_backup", fake_create_backup)
    return metadata


@pytest.fixture()
def fake_encryptor(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replaces the `age` subprocess with a deterministic stand-in that
    honours the real recipient-shape rule and writes a correctly-headed
    synthetic ciphertext. Records every recipient it was called with."""
    calls: list[str] = []

    def encrypt(artifact_path: Path, *, recipient: str) -> Path:
        validate_recipient(recipient)
        calls.append(recipient)
        output = encrypted_artifact_path(artifact_path)
        output.write_bytes(
            AGE_CIPHERTEXT_HEADER + b"\n-> synthetic:" + artifact_path.read_bytes()[::-1]
        )
        return output

    monkeypatch.setattr(orchestrator_module, "encrypt_backup_artifact", encrypt)
    return calls


class RecordingDestination:
    """`FakeBackupDestination` plus a full record of every `upload()` call
    (path *and* the bytes as they were at upload time) -- what the
    plaintext-never-leaves assertions inspect."""

    def __init__(self) -> None:
        self._inner = FakeBackupDestination()
        self.uploads: list[tuple[Path, bytes]] = []

    def upload(self, local_path: Path, key: str) -> None:
        self.uploads.append((local_path, local_path.read_bytes()))
        self._inner.upload(local_path, key)

    def download(self, key: str, local_path: Path) -> None:
        self._inner.download(key, local_path)

    def list_objects(self, prefix: str):
        return self._inner.list_objects(prefix)

    def delete_object(self, key: str) -> None:
        self._inner.delete_object(key)


def _run(
    *,
    staging_dir: Path,
    recipient: str | None,
    destination: object | None,
) -> BackupRunResult:
    return run_production_backup(
        container="db-1",
        admin_config=_admin_config(),
        config=BackupPipelineConfig(staging_dir=staging_dir),
        recipient=recipient,
        destination=destination,  # type: ignore[arg-type] -- duck-typed Protocol
    )


def _generate_age_keypair() -> tuple[str, str]:
    result = subprocess.run(["age-keygen"], capture_output=True, text=True, timeout=30, check=True)
    identity = next(line.strip() for line in result.stdout.splitlines() if line.startswith("AGE-"))
    recipient = next(
        line.split(":", 1)[1].strip()
        for line in result.stderr.splitlines()
        if line.startswith("Public key:")
    )
    return recipient, identity


# --- Tests 1-3: missing / empty / malformed recipient -> no upload -----------


@pytest.mark.parametrize(
    "recipient",
    [None, "", "   ", "\n", "not-an-age-key", "age", "AGE1UPPERCASE", _SYNTHETIC_IDENTITY_MISTAKE],
    ids=[
        "missing",
        "empty",
        "whitespace",
        "newline",
        "malformed",
        "prefix-only",
        "wrong-case",
        "identity",
    ],
)
def test_off_site_without_a_valid_recipient_fails_before_any_upload(
    tmp_path: Path,
    staged_backup: BackupMetadata,
    fake_encryptor: list[str],
    caplog: pytest.LogCaptureFixture,
    recipient: str | None,
) -> None:
    destination = RecordingDestination()
    with caplog.at_level("INFO"):
        with pytest.raises(OffSiteEncryptionRequiredError) as excinfo:
            _run(staging_dir=tmp_path, recipient=recipient, destination=destination)

    assert destination.uploads == [], "destination.upload() must never be reached"
    assert destination.list_objects("postgres/") == []
    assert fake_encryptor == [], "encryption is never attempted with an invalid recipient"
    assert not encrypted_artifact_path(staged_backup.artifact_path).exists()
    # Fail closed is loud: the failure event fires, and the plaintext artifact
    # (the local recovery point) still exists untouched on the host.
    assert "backup_failed" in {record.message for record in caplog.records}
    assert "backup_upload_succeeded" not in {record.message for record in caplog.records}
    assert staged_backup.artifact_path.read_bytes() == _PLAINTEXT

    # Secrets/values boundary: neither the (mistaken) identity, nor the
    # artifact bytes, nor the DSN credential appear in the error or logs.
    everything = str(excinfo.value) + "\n".join(f"{r.message} {r.__dict__}" for r in caplog.records)
    if recipient and len(recipient.strip()) >= 8:  # short ids ("age") are ordinary words
        assert recipient not in everything
    assert "PGDMP" not in everything
    assert "pw@" not in everything and "admin" not in everything


# --- Test 4: valid recipient -> exactly one upload, ciphertext only ----------


def _assert_only_ciphertext_uploaded(
    destination: RecordingDestination, result: BackupRunResult, metadata: BackupMetadata
) -> bytes:
    assert len(destination.uploads) == 1
    uploaded_path, uploaded_bytes = destination.uploads[0]
    assert uploaded_path == result.encrypted_path
    assert uploaded_path.name.endswith(".pgdump.age")
    assert uploaded_path != metadata.artifact_path
    assert result.uploaded_key is not None and result.uploaded_key.endswith(".pgdump.age")
    assert not result.uploaded_key.endswith(".pgdump")
    assert uploaded_bytes.startswith(AGE_CIPHERTEXT_HEADER)
    assert uploaded_bytes != _PLAINTEXT
    assert _PLAINTEXT not in uploaded_bytes
    assert b"PGDMP" not in uploaded_bytes
    # Integrity metadata now describes the uploaded object too, while the
    # plaintext checksum the restore path verifies is untouched.
    assert result.encrypted_sha256 == hashlib.sha256(uploaded_bytes).hexdigest()
    recorded = json.loads(metadata.metadata_path.read_text())
    assert recorded["sha256"] == hashlib.sha256(_PLAINTEXT).hexdigest()
    assert recorded["encrypted_sha256"] == result.encrypted_sha256
    assert recorded["encrypted_size_bytes"] == len(uploaded_bytes)
    assert Path(recorded["encrypted_artifact_path"]) == uploaded_path
    return uploaded_bytes


def test_off_site_with_a_valid_recipient_uploads_exactly_the_ciphertext_hermetic(
    tmp_path: Path, staged_backup: BackupMetadata, fake_encryptor: list[str]
) -> None:
    destination = RecordingDestination()
    result = _run(staging_dir=tmp_path, recipient=_SHAPED_RECIPIENT, destination=destination)

    assert fake_encryptor == [_SHAPED_RECIPIENT]
    _assert_only_ciphertext_uploaded(destination, result, staged_backup)
    # The existing restore-side integrity check still accepts the metadata
    # file after the additive encrypted_* keys were recorded.
    assert verify_backup_checksum(staged_backup.metadata_path).sha256 == staged_backup.sha256


@requires_age
def test_off_site_with_a_real_age_recipient_uploads_a_real_ciphertext_that_restores(
    tmp_path: Path, staged_backup: BackupMetadata
) -> None:
    """Real `age`: the uploaded object is genuine ciphertext, the only
    object in the destination, and -- the restore contract -- decrypting
    the *downloaded* object with the identity yields a plaintext that
    passes the unchanged `verify_backup_checksum()`."""
    recipient, identity = _generate_age_keypair()
    destination = RecordingDestination()
    result = _run(staging_dir=tmp_path, recipient=recipient, destination=destination)
    uploaded_bytes = _assert_only_ciphertext_uploaded(destination, result, staged_backup)

    # Simulate the DR scenario: every local copy is gone; only the off-site
    # ciphertext survives. Download it and restore-decrypt it in place.
    assert result.encrypted_path is not None and result.uploaded_key is not None
    staged_backup.artifact_path.unlink()
    result.encrypted_path.unlink()
    downloaded = tmp_path / "downloaded" / result.encrypted_path.name
    downloaded.parent.mkdir()
    destination.download(result.uploaded_key, downloaded)
    assert downloaded.read_bytes() == uploaded_bytes

    decrypt_backup_artifact(downloaded, identity=identity, output_path=staged_backup.artifact_path)
    assert staged_backup.artifact_path.read_bytes() == _PLAINTEXT
    assert verify_backup_checksum(staged_backup.metadata_path).sha256 == staged_backup.sha256


@requires_age
def test_local_destination_receives_only_the_ciphertext(
    tmp_path: Path, staged_backup: BackupMetadata
) -> None:
    """The real, on-disk `LocalBackupDestination`: whatever lands under its
    root is age ciphertext, never the archive."""
    recipient, _identity = _generate_age_keypair()
    root = tmp_path / "off-site-root"
    result = _run(
        staging_dir=tmp_path / "staging",
        recipient=recipient,
        destination=LocalBackupDestination(root),
    )
    assert result.uploaded_key is not None
    landed = [p for p in root.rglob("*") if p.is_file()]
    assert len(landed) == 1
    assert landed[0].name.endswith(".pgdump.age")
    assert landed[0].read_bytes().startswith(AGE_CIPHERTEXT_HEADER)
    assert b"PGDMP" not in landed[0].read_bytes()


# --- Test 5: encryption failure -> no upload --------------------------------


def test_encryption_failure_aborts_before_any_upload(
    tmp_path: Path, staged_backup: BackupMetadata, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_encrypt(artifact_path: Path, *, recipient: str) -> Path:
        raise BackupEncryptionError("age encryption failed (exit 1): CompletedProcess")

    monkeypatch.setattr(orchestrator_module, "encrypt_backup_artifact", failing_encrypt)
    destination = RecordingDestination()
    with pytest.raises(BackupEncryptionError):
        _run(staging_dir=tmp_path, recipient=_SHAPED_RECIPIENT, destination=destination)
    assert destination.uploads == []


@requires_age
def test_real_age_rejects_a_well_shaped_but_invalid_recipient_before_any_upload(
    tmp_path: Path, staged_backup: BackupMetadata
) -> None:
    """`_SHAPED_RECIPIENT` passes the shape gate but is not a real key: the
    real `age` binary fails, and that failure still means zero uploads."""
    destination = RecordingDestination()
    with pytest.raises(BackupEncryptionError):
        _run(staging_dir=tmp_path, recipient=_SHAPED_RECIPIENT, destination=destination)
    assert destination.uploads == []
    assert not encrypted_artifact_path(staged_backup.artifact_path).exists()


# --- Test 6: no plaintext fallback, ever -------------------------------------


def test_a_broken_encryptor_returning_the_plaintext_path_is_refused(
    tmp_path: Path, staged_backup: BackupMetadata, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The historical dangerous branch, simulated from the other side: an
    encryptor that (claims success but) hands back the plaintext artifact.
    The upload gate must refuse it on identity, not trust the caller."""
    monkeypatch.setattr(
        orchestrator_module,
        "encrypt_backup_artifact",
        lambda artifact_path, *, recipient: artifact_path,
    )
    destination = RecordingDestination()
    with pytest.raises(OffSiteEncryptionRequiredError):
        _run(staging_dir=tmp_path, recipient=_SHAPED_RECIPIENT, destination=destination)
    assert destination.uploads == []


def test_an_encrypted_artifact_that_is_not_ciphertext_is_refused(
    tmp_path: Path, staged_backup: BackupMetadata, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `.age`-named file whose bytes are the plaintext (a copy, a
    truncated write, a wrong tool) never reaches the destination."""

    def copy_not_encrypt(artifact_path: Path, *, recipient: str) -> Path:
        output = encrypted_artifact_path(artifact_path)
        output.write_bytes(artifact_path.read_bytes())
        return output

    monkeypatch.setattr(orchestrator_module, "encrypt_backup_artifact", copy_not_encrypt)
    destination = RecordingDestination()
    with pytest.raises(OffSiteEncryptionRequiredError, match="failed verification"):
        _run(staging_dir=tmp_path, recipient=_SHAPED_RECIPIENT, destination=destination)
    assert destination.uploads == []


def test_a_missing_encrypted_artifact_is_refused(
    tmp_path: Path, staged_backup: BackupMetadata, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator_module,
        "encrypt_backup_artifact",
        lambda artifact_path, *, recipient: encrypted_artifact_path(artifact_path),  # never written
    )
    destination = RecordingDestination()
    with pytest.raises(OffSiteEncryptionRequiredError):
        _run(staging_dir=tmp_path, recipient=_SHAPED_RECIPIENT, destination=destination)
    assert destination.uploads == []


def test_orchestrator_source_has_no_plaintext_fallback_expression() -> None:
    """Structural guard against reintroducing `encrypted_path or
    metadata.artifact_path` (or any `or`-fallback over `encrypted_path`)
    and against `metadata.artifact_path` ever being an argument to an
    `upload(...)` call anywhere in the orchestrator."""
    tree = ast.parse(inspect.getsource(orchestrator_module))

    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            operand_names = {
                child.id
                for value in node.values
                for child in ast.walk(value)
                if isinstance(child, ast.Name)
            }
            assert "encrypted_path" not in operand_names, ast.unparse(node)

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "upload"
        ):
            for argument in node.args:
                for child in ast.walk(argument):
                    assert not (
                        isinstance(child, ast.Attribute) and child.attr == "artifact_path"
                    ), f"plaintext artifact passed to upload(): {ast.unparse(node)}"


# --- Test 7: local-only semantics unchanged --------------------------------


def test_local_only_without_a_recipient_still_succeeds_and_uploads_nothing(
    tmp_path: Path, staged_backup: BackupMetadata, fake_encryptor: list[str]
) -> None:
    result = _run(staging_dir=tmp_path, recipient=None, destination=None)
    assert result.encrypted_path is None
    assert result.encrypted_sha256 is None
    assert result.uploaded_key is None
    assert result.retention_deleted == ()
    assert fake_encryptor == []
    assert staged_backup.artifact_path.read_bytes() == _PLAINTEXT
    assert "encrypted_sha256" not in json.loads(staged_backup.metadata_path.read_text())


def test_local_only_with_a_recipient_encrypts_and_uploads_nothing(
    tmp_path: Path, staged_backup: BackupMetadata, fake_encryptor: list[str]
) -> None:
    result = _run(staging_dir=tmp_path, recipient=_SHAPED_RECIPIENT, destination=None)
    assert result.encrypted_path is not None and result.encrypted_path.is_file()
    assert result.uploaded_key is None
    assert result.encrypted_sha256 == hashlib.sha256(result.encrypted_path.read_bytes()).hexdigest()
    assert json.loads(staged_backup.metadata_path.read_text())["encrypted_sha256"] == (
        result.encrypted_sha256
    )


# --- Test 8: secrets boundary ------------------------------------------------


def test_orchestrator_resolves_encryption_keys_only_through_the_secrets_provider() -> None:
    """The scheduler entrypoint reads `BACKUP_ENCRYPTION_RECIPIENT` /
    `BACKUP_ENCRYPTION_IDENTITY` via `get_secrets_provider().get(...)` and
    nothing in the orchestrator touches `os.environ`/`os.getenv`."""
    source = inspect.getsource(orchestrator_module)
    tree = ast.parse(source)
    attribute_accesses = {
        f"{node.value.id}.{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
    }
    assert "os.environ" not in attribute_accesses
    assert "os.getenv" not in attribute_accesses

    secret_reads: dict[str, str] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "secrets"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            secret_reads[str(node.args[0].value)] = ast.unparse(node)
    assert "BACKUP_ENCRYPTION_RECIPIENT" in secret_reads
    assert "BACKUP_ENCRYPTION_IDENTITY" in secret_reads
    assert "secrets = get_secrets_provider()" in source


def test_failure_messages_and_events_never_carry_a_key_value(
    tmp_path: Path, staged_backup: BackupMetadata, caplog: pytest.LogCaptureFixture
) -> None:
    """A recipient value never appears in any exception raised by the
    gate, and an identity pasted into the recipient slot by mistake is
    neither accepted nor echoed."""
    for value in ("tampered-" + _SHAPED_RECIPIENT, _SYNTHETIC_IDENTITY_MISTAKE):
        with pytest.raises(BackupEncryptionError) as excinfo:
            validate_recipient(value)
        assert value not in str(excinfo.value)

    with caplog.at_level("INFO"):
        with pytest.raises(OffSiteEncryptionRequiredError) as gate_error:
            _run(
                staging_dir=tmp_path,
                recipient=_SYNTHETIC_IDENTITY_MISTAKE,
                destination=RecordingDestination(),
            )
    logged = "\n".join(f"{r.message} {r.__dict__}" for r in caplog.records)
    assert _SYNTHETIC_IDENTITY_MISTAKE not in logged
    assert _SYNTHETIC_IDENTITY_MISTAKE not in str(gate_error.value)
    assert "AGE-SECRET-KEY" not in logged and "AGE-SECRET-KEY" not in str(gate_error.value)


# --- S3-compatible destination contract (mocked boto3, no credentials) -------


def _s3_destination_with_mock(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[S3CompatibleBackupDestination, MagicMock]:
    mock_client = MagicMock()
    mock_client.get_paginator.return_value.paginate.return_value = []
    mock_boto3 = MagicMock()
    mock_boto3.client.return_value = mock_client
    monkeypatch.setitem(__import__("sys").modules, "boto3", mock_boto3)
    destination = S3CompatibleBackupDestination(
        S3DestinationConfig(
            endpoint_url="https://s3.example.invalid",
            bucket="synthetic-backups",
            access_key_id="AKIASYNTHETIC",
            secret_access_key="synthetic-not-a-real-secret",  # pragma: allowlist secret
        )
    )
    return destination, mock_client


def test_s3_destination_receives_only_the_ciphertext(
    tmp_path: Path,
    staged_backup: BackupMetadata,
    fake_encryptor: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination, mock_client = _s3_destination_with_mock(monkeypatch)
    result = _run(staging_dir=tmp_path, recipient=_SHAPED_RECIPIENT, destination=destination)

    assert result.encrypted_path is not None
    mock_client.upload_file.assert_called_once_with(
        str(result.encrypted_path), "synthetic-backups", result.uploaded_key
    )
    uploaded_local_path = Path(mock_client.upload_file.call_args.args[0])
    assert uploaded_local_path.name.endswith(".pgdump.age")
    assert uploaded_local_path.read_bytes().startswith(AGE_CIPHERTEXT_HEADER)


def test_s3_destination_is_never_called_without_a_recipient(
    tmp_path: Path,
    staged_backup: BackupMetadata,
    fake_encryptor: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination, mock_client = _s3_destination_with_mock(monkeypatch)
    with pytest.raises(OffSiteEncryptionRequiredError):
        _run(staging_dir=tmp_path, recipient=None, destination=destination)
    mock_client.upload_file.assert_not_called()
    mock_client.delete_object.assert_not_called()


# --- The verification primitive itself ---------------------------------------


def test_verify_encrypted_artifact_accepts_a_real_age_header(tmp_path: Path) -> None:
    good = tmp_path / "x.pgdump.age"
    good.write_bytes(AGE_CIPHERTEXT_HEADER + b"\n-> synthetic body")
    verify_encrypted_artifact(good)  # no raise


@pytest.mark.parametrize(
    ("name", "content", "reason"),
    [
        ("x.pgdump.age", _PLAINTEXT, "header mismatch"),
        ("x.pgdump.age", b"", "header mismatch"),
        ("x.pgdump.age", AGE_CIPHERTEXT_HEADER, "truncated"),
        ("x.pgdump", AGE_CIPHERTEXT_HEADER + b"\nbody", "suffix"),
    ],
    ids=["plaintext-bytes", "empty", "header-only", "wrong-suffix"],
)
def test_verify_encrypted_artifact_rejects_non_ciphertext(
    tmp_path: Path, name: str, content: bytes, reason: str
) -> None:
    candidate = tmp_path / name
    candidate.write_bytes(content)
    with pytest.raises(BackupEncryptionError, match=reason):
        verify_encrypted_artifact(candidate)


def test_verify_encrypted_artifact_rejects_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(BackupEncryptionError, match="not found"):
        verify_encrypted_artifact(tmp_path / "absent.pgdump.age")
