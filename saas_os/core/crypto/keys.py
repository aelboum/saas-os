"""S-01 (BANK-SEC-01/02) -- key material abstraction for `saas_os.core.crypto`.

`KeyProvider` is the narrow boundary between `EncryptionService`
(`saas_os/core/crypto/service.py`) and however key material is actually supplied
-- deliberately not AWS KMS/Azure Key Vault/GCP KMS/HashiCorp Vault/a
cloud-specific mechanism (BANK-SEC-02 design requirement 3): nothing in
`saas_os.core.crypto` depends on a specific key-management product, only on this
interface. A future concrete implementation backed by one of those is a
new class implementing this same `KeyProvider` ABC -- not a redesign of
`EncryptionService` or the ciphertext envelope format.

**Key versions are not secret.** `current_key_version()`'s return value
and `key_for_version()`'s `key_version` argument are opaque identifiers
(e.g. `"v1"`) that travel in plaintext inside every ciphertext envelope
(`saas_os/core/crypto/envelope.py`) -- they say *which* key was used, never what
that key's material is. Safe to log, safe in an exception message, safe
in an audit record.

**Relationship to `saas_os.infra.secrets.SecretsProvider`** (the critical
distinction this phase's own directive draws): `SecretsProvider` answers
"how does the application obtain configuration/secret material" --
`KeyProvider` answers "how does `saas_os.core.crypto` obtain the specific key
material it needs to encrypt/decrypt one application-data value." This
module's one concrete implementation, `SecretsBackedKeyProvider`, is
*built on* `SecretsProvider` (it asks `saas_os.infra.secrets.get_secrets_provider()`
for the raw key bytes) without merging the two responsibilities:
`SecretsProvider` is never told about ciphertext envelopes, key versions,
or encryption at all, and `EncryptionService` never reads an environment
variable or a Docker secrets file directly -- both remain true only
because this module sits between them.

**S-02 (key rotation) boundary**: this module resolves a key *by version*
and distinguishes "the current version to encrypt new values under" from
"a specific historical version to decrypt an old value under" -- the two
operations a rotation scheme needs -- but implements no rotation
workflow, no automatic re-encryption, and no key retirement. That remains
explicitly out of scope for this phase (BANK-SEC-02's own directive).
"""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from functools import lru_cache

from saas_os.core.crypto.errors import EncryptionKeyUnavailableError, UnknownKeyVersionError
from saas_os.infra.secrets import get_secrets_provider

_KEY_BYTES_LENGTH = 32  # AES-256: cryptography.hazmat's AESGCM key length, in bytes.
_ACTIVE_KEY_VERSION_SECRET_NAME = "FIELD_ENCRYPTION_ACTIVE_KEY_VERSION"  # pragma: allowlist secret


def _key_secret_name(key_version: str) -> str:
    # e.g. key_version "v1" -> secret name "FIELD_ENCRYPTION_KEY_V1". Only
    # ever called with a `key_version` this module itself produced or
    # validated (`SecretsBackedKeyProvider`'s own callers), never with
    # untrusted input directly -- see that class's docstring.
    return f"FIELD_ENCRYPTION_KEY_{key_version.upper()}"


class KeyProvider(ABC):
    """Provider-agnostic key material retrieval for `saas_os.core.crypto`.
    `EncryptionService` depends on this interface only -- never on a
    concrete implementation or on where key material actually comes
    from (mirrors `saas_os.infra.secrets.SecretsProvider`'s own documented
    discipline, deliberately, for the same reason)."""

    @abstractmethod
    def current_key_version(self) -> str:
        """The key version `EncryptionService.encrypt()` should use for a
        *new* encryption. Fails closed (raises, never returns a sentinel
        or falls back to an unversioned/default key) if no active version
        is configured."""
        raise NotImplementedError

    @abstractmethod
    def key_for_version(self, key_version: str) -> bytes:
        """The raw 32-byte AES-256 key material for `key_version`, used
        by both `encrypt()` (for `current_key_version()`'s own result)
        and `decrypt()` (for whatever version a ciphertext envelope
        names). Raises `UnknownKeyVersionError` if this version cannot be
        resolved -- never returns a different key silently, never falls
        back to a default."""
        raise NotImplementedError


class SecretsBackedKeyProvider(KeyProvider):
    """The one concrete `KeyProvider` this phase implements: reads key
    material through `saas_os.infra.secrets.get_secrets_provider()`, exactly like
    every other secret-consuming module in this codebase
    (`saas_os/infra/db/backup/encryption.py`'s own `BACKUP_ENCRYPTION_RECIPIENT`/
    `_IDENTITY` is the closest existing precedent). Suitable for both the
    development (`.env`) and Docker/host production
    (`saas_os.infra.secrets.EnvironmentSecretsProvider`) implementations that
    `saas_os.infra.secrets` already selects between -- this class never knows or
    cares which one is active.

    Configuration (two secrets, both required at first use, never at
    import time -- consistent with every other config-reading module
    here):

    - `FIELD_ENCRYPTION_ACTIVE_KEY_VERSION` -- the version new
      encryptions use (e.g. `v1`).
    - `FIELD_ENCRYPTION_KEY_<VERSION>` (e.g. `FIELD_ENCRYPTION_KEY_V1`)
      -- that version's raw key material, standard base64 (`+`/`/`
      alphabet, matching `base64.b64decode`'s default -- distinct from
      `saas_os/core/crypto/envelope.py`'s own URL-safe alphabet, chosen here only
      because it is the more common convention for a hand-configured
      32-byte value) encoding exactly 32 bytes.

    Raises `EncryptionKeyUnavailableError` (never falls back to a
    default/hard-coded key -- BANK-SEC-02 design requirement 8) if either
    secret is absent, and `EncryptionKeyUnavailableError` again if a
    configured key does not decode to exactly 32 bytes -- a
    misconfiguration must fail loudly, not silently truncate/pad into a
    weaker or different key than an operator intended.
    """

    def current_key_version(self) -> str:
        provider = get_secrets_provider()
        value = provider.get(_ACTIVE_KEY_VERSION_SECRET_NAME)
        if not value:
            raise EncryptionKeyUnavailableError(key_version="<active>")
        return value

    def key_for_version(self, key_version: str) -> bytes:
        provider = get_secrets_provider()
        raw = provider.get(_key_secret_name(key_version))
        if not raw:
            raise UnknownKeyVersionError(key_version)
        try:
            key_bytes = base64.b64decode(raw, validate=True)
        except (ValueError, UnicodeDecodeError) as exc:
            raise EncryptionKeyUnavailableError(key_version=key_version) from exc
        if len(key_bytes) != _KEY_BYTES_LENGTH:
            raise EncryptionKeyUnavailableError(key_version=key_version)
        return key_bytes


@lru_cache
def get_key_provider() -> KeyProvider:
    """Cached process-wide `KeyProvider` singleton, mirroring
    `saas_os.infra.secrets.get_secrets_provider()`'s and every `saas_os/infra/db`-style
    `get_*_config()`'s own caching convention. Tests that need a
    different `KeyProvider` construct one directly and pass it to
    `EncryptionService(key_provider=...)` instead of touching this
    cache (the same pattern `saas_os.infra.db.session.session_scope()`'s own
    `session_factory` parameter already establishes)."""
    return SecretsBackedKeyProvider()
