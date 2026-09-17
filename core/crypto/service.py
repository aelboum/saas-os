"""S-01 (BANK-SEC-01/02) -- `EncryptionService`: application-level
authenticated encryption for sensitive database-stored values.

**What this answers, and what it does not.** `infra.secrets.SecretsProvider`
answers "how does the application obtain configuration/secret material" --
this module answers "how does the application encrypt/decrypt sensitive
*application data* before/after database persistence" (this phase's own
directive, verbatim). Nothing here reads an environment variable or a
`.env` file directly; `core/crypto/keys.py`'s `KeyProvider` (itself built
on `infra.secrets`) is the only source of key material this module knows
about.

**Algorithm**: AES-256-GCM (`cryptography.hazmat.primitives.ciphers.
aead.AESGCM`, from `pyca/cryptography` -- already an installed dependency,
`pyproject.toml`'s own comment on `PyJWT[crypto]`, promoted to an explicit
top-level dependency by this phase since `core.crypto` now imports it
directly rather than only transitively through PyJWT). AES-GCM is a
standard, widely-reviewed AEAD (authenticated encryption with associated
data) construction -- this module implements no cryptographic primitive
of its own, no custom MAC-then-encrypt combination, nothing "home-grown"
(this phase's own explicit prohibition).

**Nonce**: 12 bytes (96 bits), generated fresh via `os.urandom()` for
every single `encrypt()` call -- the standard, NIST SP 800-38D-recommended
nonce length and generation method for AES-GCM, never reused, never
derived from the plaintext or the key. A 96-bit random nonce keeps the
probability of an accidental collision negligible for any encryption
volume one key version here is realistically expected to see before
S-02's (future, out of scope) key-rotation workflow retires it.

**Associated data (AAD)**: `encrypt()`/`decrypt()` both accept an
optional `associated_data: bytes` -- passed straight to `AESGCM` unmodified,
never inspected, parsed, or given any meaning by this module. A caller
that wants to bind a ciphertext to, e.g., a tenant id and a credential
purpose builds that context into `associated_data` itself (encoding it is
the caller's responsibility, not this module's -- BANK-SEC-02's own
"do not make speculative changes to current domain models" and "the
service doesn't know about tenants"). Decrypting with different
associated data than the value was encrypted with fails exactly the same
way a wrong key does: `DecryptionAuthenticationError`, not a distinct
error that would tell an attacker which check failed.

**Plaintext lifetime**: treated as sensitive throughout, but this module
makes no claim of secure memory zeroization -- CPython strings and
`bytes` objects are immutable and can be copied/retained by the
interpreter, garbage collector, or swap in ways pure Python code cannot
prevent (a realistic threat model, per this phase's own instruction, not
an impossible guarantee). What this module *does* guarantee: plaintext
is never logged, never included in an exception, never part of the
ciphertext envelope, and never returned from `encrypt()` (only the
opaque envelope string is).

**Authorization**: this module is not an authorization mechanism.
Successful decryption proves only that the caller supplied a value this
`KeyProvider` can resolve and that was not tampered with -- it is not
proof the caller is entitled to see the plaintext. Callers remain subject
to whatever tenant/RBAC boundary already governs the domain object the
encrypted value lives on (`core.rbac`, `core.tenancy`'s RLS) exactly as
before this module existed; `EncryptionService` sits *inside* that
boundary, never in place of it.

**Fail closed, always**: every failure mode (`core/crypto/errors.py`)
raises rather than returning plaintext, a default value, or silently
skipping encryption. There is no code path from "key material
unavailable" or "ciphertext malformed" to a plaintext fallback anywhere
in this module.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.crypto import envelope
from core.crypto.errors import DecryptionAuthenticationError, MalformedCiphertextError
from core.crypto.keys import KeyProvider, get_key_provider

_NONCE_LENGTH_BYTES = 12


class EncryptionService:
    """Encrypts/decrypts application data for persistence. Stateless
    apart from its `KeyProvider` -- safe to construct per call site or
    share; holds no plaintext, no key material, and no per-instance
    cache of either."""

    def __init__(self, key_provider: KeyProvider | None = None) -> None:
        self._key_provider = key_provider or get_key_provider()

    def encrypt(self, plaintext: bytes, *, associated_data: bytes | None = None) -> str:
        """Encrypt `plaintext` under the `KeyProvider`'s current key
        version. Returns the opaque envelope string
        (`core/crypto/envelope.py`) -- never the raw ciphertext bytes,
        so a caller cannot accidentally persist an un-self-describing
        value with no recorded key version. Raises
        `EncryptionKeyUnavailableError` (via the `KeyProvider`) if no
        current key can be resolved -- never encrypts under a
        placeholder/default key."""
        key_version = self._key_provider.current_key_version()
        key = self._key_provider.key_for_version(key_version)
        nonce = os.urandom(_NONCE_LENGTH_BYTES)
        ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        return envelope.encode(
            key_version=key_version, nonce=nonce, ciphertext_and_tag=ciphertext_and_tag
        )

    def decrypt(self, envelope_str: str, *, associated_data: bytes | None = None) -> bytes:
        """Decrypt an envelope string previously returned by `encrypt()`.
        Raises `MalformedCiphertextError`/`UnsupportedCiphertextVersionError`
        (via `core/crypto/envelope.py`) if `envelope_str` is not a
        well-formed envelope this build understands, `UnknownKeyVersionError`/
        `EncryptionKeyUnavailableError` (via the `KeyProvider`) if the
        named key version cannot be resolved, and
        `DecryptionAuthenticationError` if AEAD authentication fails --
        wrong key, wrong `associated_data`, or tampered ciphertext/nonce,
        deliberately indistinguishable from each other in the raised
        error. Every failure mode raises; there is no fallback return
        value."""
        parsed = envelope.decode(envelope_str)
        key = self._key_provider.key_for_version(parsed.key_version)
        try:
            return AESGCM(key).decrypt(parsed.nonce, parsed.ciphertext_and_tag, associated_data)
        except InvalidTag as exc:
            raise DecryptionAuthenticationError from exc

    def encrypt_str(self, plaintext: str, *, associated_data: bytes | None = None) -> str:
        """Convenience wrapper for the common case of encrypting a UTF-8
        string (e.g. a bearer token) rather than raw bytes."""
        return self.encrypt(plaintext.encode("utf-8"), associated_data=associated_data)

    def decrypt_str(self, envelope_str: str, *, associated_data: bytes | None = None) -> str:
        """Convenience wrapper for the common case of decrypting back to
        a UTF-8 string. Raises `MalformedCiphertextError` if the
        decrypted plaintext is not valid UTF-8 -- this should never
        happen for a value this module itself encrypted via
        `encrypt_str()`, and indicates either a genuine bug or a crafted
        ciphertext that happened to authenticate (only possible if the
        attacker already has the key, at which point confidentiality is
        already lost and this is not the relevant failure mode)."""
        plaintext_bytes = self.decrypt(envelope_str, associated_data=associated_data)
        try:
            return plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MalformedCiphertextError("Decrypted plaintext is not valid UTF-8.") from exc
