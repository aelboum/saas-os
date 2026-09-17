"""S-01 (BANK-SEC-01/02) -- the versioned ciphertext envelope format.

A `core.crypto.EncryptionService.encrypt()` result is a single, plain
text string (safe for an ordinary `String`/`Text` database column, an
`.env` value, or a JSON field -- no binary-safety concerns at the storage
layer): four `:`-separated, URL-safe-base64-encoded fields --

    efv1:<key_version>:<nonce>:<ciphertext_and_tag>

- `efv1` -- the *format* version (**e**ncrypted **f**ield **v**ersion 1):
  governs this module's own parsing/algorithm choice, never confused with
  the *key* version below. A future format change (a different AEAD
  construction, a different field layout) bumps this and
  `_SUPPORTED_FORMAT_VERSIONS`; `decode()` fails closed
  (`UnsupportedCiphertextVersionError`) on anything else, including a
  downgrade to a since-abandoned earlier version this build no longer
  trusts.
- `key_version` -- an opaque, non-secret identifier
  (`core/crypto/keys.py`'s own docstring: key versions are not secret) a
  `KeyProvider` uses to resolve the actual key material this value was
  encrypted under. Never a database primary key or anything else
  meaningful outside `core.crypto` -- just enough for `KeyProvider` to
  find the right key at decrypt time, which is the whole point of
  carrying it: it is what makes future key rotation possible without
  redesigning this format (BANK-SEC-02's own explicit S-02 boundary --
  rotation itself is not implemented here).
- `nonce` -- the 96-bit (12-byte) value `EncryptionService.encrypt()`
  generated fresh via `os.urandom()` for this one encryption -- never
  reused, never derived from the plaintext or from key material. Carried
  alongside the ciphertext because AES-GCM decryption requires the exact
  nonce encryption used; a nonce is not itself secret.
- `ciphertext_and_tag` -- `cryptography`'s `AESGCM.encrypt()` return
  value, which is the actual ciphertext with its 128-bit authentication
  tag already appended (the library's own standard AES-GCM output shape,
  not a `core.crypto` design choice) -- one opaque blob, never split
  apart here.

No key material is ever part of this envelope -- only a version
identifying which key to ask `KeyProvider` for (BANK-SEC-02 design
requirement 4).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from core.crypto.errors import MalformedCiphertextError, UnsupportedCiphertextVersionError

_FORMAT_VERSION = "efv1"
_SUPPORTED_FORMAT_VERSIONS = frozenset({_FORMAT_VERSION})
_FIELD_COUNT = 4


@dataclass(frozen=True)
class ParsedEnvelope:
    """The decoded fields of one ciphertext envelope -- never constructed
    directly outside this module; use `encode()`/`decode()`."""

    format_version: str
    key_version: str
    nonce: bytes
    ciphertext_and_tag: bytes


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64decode(data: str, *, field_name: str) -> bytes:
    # `base64.urlsafe_b64decode()` has no `validate` parameter and
    # silently *discards* non-alphabet characters rather than raising
    # (found by this module's own test suite) -- `base64.b64decode()`
    # with `altchars=b"-_"` (the URL-safe alphabet) and `validate=True`
    # is the strict equivalent that actually rejects malformed input
    # instead of parsing it into an unintended byte string.
    try:
        return base64.b64decode(data.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MalformedCiphertextError(
            f"Ciphertext envelope field {field_name!r} is not valid base64."
        ) from exc


def encode(*, key_version: str, nonce: bytes, ciphertext_and_tag: bytes) -> str:
    """Build one envelope string. `key_version` must be non-empty and
    must not itself contain `:` (both enforced here, fail closed *before*
    producing an envelope, rather than after -- an envelope built from an
    invalid `key_version` would be permanently undecryptable the moment
    it exists, since `decode()` rejects the same two cases; catching it
    here means a misconfigured `KeyProvider` fails the `encrypt()` call
    itself instead of silently corrupting a value at the point of
    persistence) -- `core/crypto/keys.py`'s own key-version identifiers
    are plain short tokens (e.g. `"v1"`), never free-form text, so
    neither restriction is practical to hit under correct configuration."""
    if not key_version:
        raise ValueError("key_version must not be empty.")
    if ":" in key_version:
        raise ValueError(f"key_version must not contain ':', got: {key_version!r}")
    return ":".join(
        (
            _FORMAT_VERSION,
            key_version,
            _b64encode(nonce),
            _b64encode(ciphertext_and_tag),
        )
    )


def decode(envelope: str) -> ParsedEnvelope:
    """Parse and validate one envelope string. Fails closed
    (`MalformedCiphertextError`/`UnsupportedCiphertextVersionError`) on
    anything that is not exactly this module's own well-formed output --
    never partially decodes a malformed value."""
    parts = envelope.split(":")
    if len(parts) != _FIELD_COUNT:
        raise MalformedCiphertextError(
            f"Ciphertext envelope must have exactly {_FIELD_COUNT} ':'-separated "
            f"fields, got {len(parts)}."
        )
    format_version, key_version, nonce_b64, ciphertext_b64 = parts
    if format_version not in _SUPPORTED_FORMAT_VERSIONS:
        raise UnsupportedCiphertextVersionError(format_version)
    if not key_version:
        raise MalformedCiphertextError("Ciphertext envelope's key_version field is empty.")
    nonce = _b64decode(nonce_b64, field_name="nonce")
    ciphertext_and_tag = _b64decode(ciphertext_b64, field_name="ciphertext")
    if len(nonce) != 12:
        raise MalformedCiphertextError(
            f"Ciphertext envelope's nonce must be 12 bytes, got {len(nonce)}."
        )
    if not ciphertext_and_tag:
        raise MalformedCiphertextError("Ciphertext envelope's ciphertext field is empty.")
    return ParsedEnvelope(
        format_version=format_version,
        key_version=key_version,
        nonce=nonce,
        ciphertext_and_tag=ciphertext_and_tag,
    )
