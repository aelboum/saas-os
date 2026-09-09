"""P2.4 -- backup artifact encryption via `age` (https://age-encryption.org),
invoked as an external CLI subprocess -- this module never implements or
touches cryptographic primitives itself (this checkpoint's own "do not
invent cryptography"). `age` was chosen over GPG for the same reason
`core/email/smtp_provider.py` chose stdlib `smtplib` over a heavier
alternative: a single small, modern, actively-maintained tool with no
legacy keyring/trust-web baggage, widely packaged (Debian/Alpine/Homebrew),
and already installed as this repository's one new production-host
prerequisite (documented in `docs/BACKUP-RESTORE.md`) -- mirroring how
`infra/db/backup/__init__.py` already treats `docker`/`pg_dump` as host
prerequisites rather than bundled dependencies.

**Key model (asymmetric, X25519)**: encryption uses only the *recipient*
(public) key -- `age1...` -- so the production host that creates backups
never needs to hold anything capable of decrypting them. Decryption needs
the *identity* (private) key -- `AGE-SECRET-KEY-1...` -- which an operator
should keep **offline, away from the production host** (this checkpoint's
own required documented boundary): a compromised production host can
encrypt garbage into new backups but cannot decrypt any existing one.
Both values are read through `infra.secrets.get_secrets_provider()` --
`BACKUP_ENCRYPTION_RECIPIENT` and `BACKUP_ENCRYPTION_IDENTITY` -- never
`os.environ` directly, and neither is ever logged, included in an
exception, or written to backup metadata (`BackupMetadata` in
`infra/db/backup/__init__.py` is untouched by this module; encryption
happens as a separate step *after* a `BackupMetadata`-described artifact
already exists on disk).

The identity (private key) is only ever needed transiently, during a
restore, and is passed to `age` via a temporary file created with
owner-only permissions (`0600`) in the most private temp directory
available, deleted in a `finally` block -- never left behind, never
passed as a CLI argument (which would appear in a process listing),
never written to the artifact's own directory.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

_AGE_BINARY = "age"
_SUBPROCESS_TIMEOUT_SECONDS = 300
_ENCRYPTED_SUFFIX = ".age"
_RECIPIENT_PREFIX = "age1"

# The fixed first line of every age (v1) ciphertext, per the age format
# specification (https://age-encryption.org/v1). A `pg_dump -Fc` archive,
# by contrast, begins with the bytes `PGDMP`. `verify_encrypted_artifact()`
# uses this to refuse -- before any upload -- a file that merely *claims*
# to be the encrypted artifact (post-audit F-03).
AGE_CIPHERTEXT_HEADER = b"age-encryption.org/v1"


class BackupEncryptionError(RuntimeError):
    """Raised for any encryption/decryption failure, or when the `age`
    binary is not available. Never includes the recipient/identity value
    or raw `age` stderr verbatim (which could, in principle, echo a
    malformed key argument back) -- only a fixed classification."""


def _require_age_binary() -> str:
    path = shutil.which(_AGE_BINARY)
    if not path:
        raise BackupEncryptionError(
            "the 'age' binary is not installed or not on PATH -- see "
            "docs/BACKUP-RESTORE.md's host prerequisites."
        )
    return path


def validate_recipient(recipient: str | None) -> str:
    """The one place the shape of `BACKUP_ENCRYPTION_RECIPIENT` is decided:
    a non-empty `age1...` public key. Returns the value unchanged on
    success; raises `BackupEncryptionError` (never echoing the value) for
    `None`, empty/whitespace, or anything not shaped like an age recipient.
    Pure -- no filesystem, no `age` binary -- so `orchestrator.py` can run
    it as a configuration gate *before* any dump/encrypt/upload I/O."""
    if recipient is None or not recipient.strip() or not recipient.startswith(_RECIPIENT_PREFIX):
        raise BackupEncryptionError("BACKUP_ENCRYPTION_RECIPIENT is missing or malformed.")
    return recipient


def encrypted_artifact_path(artifact_path: Path) -> Path:
    return artifact_path.with_name(artifact_path.name + _ENCRYPTED_SUFFIX)


def verify_encrypted_artifact(encrypted_path: Path) -> None:
    """Fail closed unless `encrypted_path` is a real, non-empty age
    ciphertext: it must exist, carry the `.age` suffix, begin with the age
    v1 header, and contain more than the header alone. This is a *format*
    check (is this file actually ciphertext?), not a cryptographic one --
    `age` itself authenticates the payload on decryption. The orchestrator
    runs it on every artifact immediately before an off-site upload, so a
    plaintext `pg_dump` archive (or an empty/truncated file) can never be
    the object that leaves the host (post-audit F-03)."""
    if not encrypted_path.is_file():
        raise BackupEncryptionError(f"encrypted artifact not found: {encrypted_path.name}")
    if encrypted_path.suffix != _ENCRYPTED_SUFFIX:
        raise BackupEncryptionError(
            f"encrypted artifact {encrypted_path.name!r} does not carry the "
            f"{_ENCRYPTED_SUFFIX!r} suffix."
        )
    with encrypted_path.open("rb") as handle:
        header = handle.read(len(AGE_CIPHERTEXT_HEADER))
    if header != AGE_CIPHERTEXT_HEADER:
        raise BackupEncryptionError(
            f"encrypted artifact {encrypted_path.name!r} is not an age ciphertext "
            "(header mismatch)."
        )
    if encrypted_path.stat().st_size <= len(AGE_CIPHERTEXT_HEADER):
        raise BackupEncryptionError(
            f"encrypted artifact {encrypted_path.name!r} is truncated (header only)."
        )


def encrypt_backup_artifact(artifact_path: Path, *, recipient: str) -> Path:
    """Encrypt `artifact_path` in place to `<artifact_path>.age`, using
    only the public recipient string (never a private key -- module
    docstring). The plaintext artifact is left untouched by this function;
    the caller decides whether/when to remove it. The returned path has
    already passed `verify_encrypted_artifact()` -- a non-ciphertext output
    is deleted and reported as a failure, never returned."""
    age_binary = _require_age_binary()
    validate_recipient(recipient)
    if not artifact_path.is_file():
        raise BackupEncryptionError(f"artifact not found: {artifact_path.name}")

    output_path = encrypted_artifact_path(artifact_path)
    cmd = [age_binary, "--encrypt", "--recipient", recipient, "--output", str(output_path)]
    with artifact_path.open("rb") as stdin:
        result = subprocess.run(
            cmd,
            stdin=stdin,
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    if result.returncode != 0:
        output_path.unlink(missing_ok=True)
        raise BackupEncryptionError(
            f"age encryption failed (exit {result.returncode}): "
            f"{type(result).__name__}"  # never result.stderr -- see module docstring
        )
    if not output_path.is_file() or output_path.stat().st_size == 0:
        output_path.unlink(missing_ok=True)
        raise BackupEncryptionError("age reported success but produced no output.")
    try:
        verify_encrypted_artifact(output_path)
    except BackupEncryptionError:
        output_path.unlink(missing_ok=True)
        raise
    return output_path


def decrypt_backup_artifact(encrypted_path: Path, *, identity: str, output_path: Path) -> Path:
    """Decrypt `encrypted_path` to `output_path` using `identity` (the
    private key). `identity` is written to a `0600` temporary file for
    the duration of this one subprocess call only, in the OS's own
    private temp directory, and is always removed -- even on failure
    (module docstring: never logged, never a CLI argument, never left
    behind)."""
    age_binary = _require_age_binary()
    if not identity or not identity.startswith("AGE-SECRET-KEY-1"):
        raise BackupEncryptionError("the decryption identity is missing or malformed.")
    if not encrypted_path.is_file():
        raise BackupEncryptionError(f"encrypted artifact not found: {encrypted_path.name}")

    fd, identity_file_name = tempfile.mkstemp(prefix="age-identity-", suffix=".txt")
    identity_file = Path(identity_file_name)
    try:
        os.close(fd)
        identity_file.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 -- owner read/write only
        identity_file.write_text(identity + "\n", encoding="ascii")

        cmd = [
            age_binary,
            "--decrypt",
            "--identity",
            str(identity_file),
            "--output",
            str(output_path),
            str(encrypted_path),
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    finally:
        identity_file.unlink(missing_ok=True)

    if result.returncode != 0:
        output_path.unlink(missing_ok=True)
        raise BackupEncryptionError(
            f"age decryption failed (exit {result.returncode}) -- wrong identity, "
            "corrupted artifact, or the 'age' binary reported an error."
        )
    if not output_path.is_file() or output_path.stat().st_size == 0:
        output_path.unlink(missing_ok=True)
        raise BackupEncryptionError("age reported success but produced no output.")
    return output_path
