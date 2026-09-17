"""`core/crypto` -- application-level authenticated encryption for
sensitive database-stored values (S-01, BANK-SEC-01/02;
`docs/ADR/0019-application-level-field-encryption.md`).

    domain/service code
        -> EncryptionService.encrypt()/.decrypt() (this module's public
           surface)
            -> KeyProvider (core/crypto/keys.py)
                -> infra.secrets.SecretsProvider (key material only --
                   SecretsProvider itself knows nothing about encryption)

Distinct from, and never a replacement for, `infra.secrets.SecretsProvider`:
that module answers "how does the application obtain configuration/secret
material"; this module answers "how does the application encrypt/decrypt
sensitive application data before/after database persistence"
(`core/crypto/service.py`'s own docstring has the full account).

This is the only public import surface for this package -- `core/crypto/
{envelope,keys,service,errors}.py` are implementation detail modules
consumers should not import directly, mirroring `infra/secrets`'s own
"only this module is the public surface" discipline.

`core.crypto` does not import `products` or `control_plane`, and does not
import any AI/LLM framework -- the same boundary rules as every other
`core` module (docs/ARCHITECTURE.md section 2).

Usage:

    from core.crypto import EncryptionService

    service = EncryptionService()
    envelope = service.encrypt_str("some-bearer-token")
    # ... persist `envelope` (a plain string) ...
    plaintext = service.decrypt_str(envelope)
"""

from core.crypto.errors import (
    DecryptionAuthenticationError,
    EncryptionError,
    EncryptionKeyUnavailableError,
    MalformedCiphertextError,
    UnknownKeyVersionError,
    UnsupportedCiphertextVersionError,
)
from core.crypto.keys import KeyProvider, get_key_provider
from core.crypto.service import EncryptionService

__all__ = [
    "EncryptionService",
    "KeyProvider",
    "get_key_provider",
    "EncryptionError",
    "EncryptionKeyUnavailableError",
    "UnknownKeyVersionError",
    "MalformedCiphertextError",
    "UnsupportedCiphertextVersionError",
    "DecryptionAuthenticationError",
]
