"""S-01 (BANK-SEC-01/02) -- exceptions for `saas_os.core.crypto`.

Every exception here carries only non-secret metadata (a format version, a
key version/identifier, an algorithm name) -- never plaintext, never key
material, never raw ciphertext bytes, and never the underlying
cryptography library's own exception text (which can vary by version and
is not a value this module controls). Key versions/identifiers are
explicitly *not* secret (`saas_os/core/crypto/keys.py`'s own docstring) and are
safe to include.
"""

from __future__ import annotations


class EncryptionError(Exception):
    """Base class for every `saas_os.core.crypto` failure. Callers that only need
    to fail closed on "anything went wrong" may catch this alone."""


class EncryptionKeyUnavailableError(EncryptionError):
    """Raised when the required key material could not be obtained from
    the configured `KeyProvider` -- a missing/misconfigured secret, not a
    cryptographic failure. `saas_os.core.crypto` never falls back to plaintext or
    a default key when this occurs (fail closed, BANK-SEC-02 design
    requirement 8)."""

    def __init__(self, key_version: str) -> None:
        self.key_version = key_version
        super().__init__(f"Encryption key material for version {key_version!r} is unavailable.")


class UnknownKeyVersionError(EncryptionError):
    """Raised when a ciphertext envelope names a key version the current
    `KeyProvider` cannot resolve -- e.g. decrypting with an older
    application deployment than the one that encrypted the value, or a
    key version that was never configured here. Never a reason to fall
    back to an unauthenticated or unversioned interpretation of the
    ciphertext."""

    def __init__(self, key_version: str) -> None:
        self.key_version = key_version
        super().__init__(f"Unknown encryption key version: {key_version!r}.")


class MalformedCiphertextError(EncryptionError):
    """Raised when a stored value does not parse as a `saas_os.core.crypto`
    ciphertext envelope at all (wrong number of fields, invalid base64,
    etc.). Never includes the offending value itself -- a malformed
    envelope may be an attacker's crafted input, and echoing it back
    serves no legitimate purpose."""


class UnsupportedCiphertextVersionError(EncryptionError):
    """Raised when a ciphertext envelope's format version is not one this
    build of `saas_os.core.crypto` understands -- e.g. data written by a future
    application version, or a deliberately downgraded/forged version tag.
    Fails closed rather than guessing at a compatible interpretation."""

    def __init__(self, format_version: str) -> None:
        self.format_version = format_version
        super().__init__(f"Unsupported ciphertext format version: {format_version!r}.")


class DecryptionAuthenticationError(EncryptionError):
    """Raised when AEAD authentication fails -- the ciphertext, nonce, or
    associated data was tampered with, or the wrong key/associated data
    was used to decrypt an otherwise well-formed envelope. Deliberately
    reports only that authentication failed, not which of those was the
    cause -- distinguishing them would tell an attacker more than a
    generic failure does, and the underlying `cryptography` library's own
    `InvalidTag` carries no additional safe detail regardless."""
