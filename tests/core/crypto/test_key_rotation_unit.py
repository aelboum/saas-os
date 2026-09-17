"""S-02 (BANK-SEC-01/03) -- key-version lifecycle: rotating the active
encryption key while retaining the ability to decrypt ciphertext produced
under a previous version. Uses the same `FakeKeyProvider` pattern
`test_service_unit.py` establishes -- an in-memory `KeyProvider`, never
`infra.secrets` or the environment.

The one invariant every test here ultimately exists to prove:
`EncryptionService.decrypt()` resolves the key version *embedded in the
ciphertext*, never the provider's current active version -- rotating the
active key must never change how an existing ciphertext is decrypted, and
must never let a value silently decrypt (or fail to decrypt) under the
wrong key merely because that key happens to be "current" right now.
"""

from __future__ import annotations

import pytest
from core.crypto.envelope import decode
from core.crypto.errors import EncryptionKeyUnavailableError, UnknownKeyVersionError
from core.crypto.keys import KeyProvider
from core.crypto.service import EncryptionService

_KEY_V1 = b"1" * 32
_KEY_V2 = b"2" * 32


class MutableFakeKeyProvider(KeyProvider):
    """An in-memory `KeyProvider` whose `keys`/`active` can be changed
    after construction -- models an operator rotating configuration
    live, without touching `infra.secrets`."""

    def __init__(self, keys: dict[str, bytes], *, active: str) -> None:
        self.keys = dict(keys)
        self.active = active

    def current_key_version(self) -> str:
        return self.active

    def key_for_version(self, key_version: str) -> bytes:
        try:
            return self.keys[key_version]
        except KeyError:
            raise UnknownKeyVersionError(key_version) from None


# --- rotation lifecycle -------------------------------------------------


def test_rotation_lifecycle_v1_then_v2_both_remain_decryptable() -> None:
    provider = MutableFakeKeyProvider({"v1": _KEY_V1}, active="v1")
    service = EncryptionService(key_provider=provider)

    envelope_v1 = service.encrypt(b"encrypted-under-v1")
    assert decode(envelope_v1).key_version == "v1"

    # Rotate: v2 becomes active, v1 stays available.
    provider.keys["v2"] = _KEY_V2
    provider.active = "v2"

    envelope_v2 = service.encrypt(b"encrypted-under-v2")
    assert decode(envelope_v2).key_version == "v2"

    # Both remain decryptable through the same service/provider.
    assert service.decrypt(envelope_v1) == b"encrypted-under-v1"
    assert service.decrypt(envelope_v2) == b"encrypted-under-v2"


def test_exact_version_selection_v1_ciphertext_uses_v1_even_when_v2_is_active() -> None:
    provider = MutableFakeKeyProvider({"v1": _KEY_V1, "v2": _KEY_V2}, active="v1")
    service = EncryptionService(key_provider=provider)
    envelope_v1 = service.encrypt(b"payload")

    provider.active = "v2"  # rotate -- v1 ciphertext already exists

    # Decrypting v1 ciphertext must succeed using v1's key, not v2's,
    # even though v2 is now the active version.
    assert service.decrypt(envelope_v1) == b"payload"


def test_rotating_active_version_does_not_alter_existing_ciphertext() -> None:
    provider = MutableFakeKeyProvider({"v1": _KEY_V1, "v2": _KEY_V2}, active="v1")
    service = EncryptionService(key_provider=provider)
    envelope_before = service.encrypt(b"stable-payload")

    provider.active = "v2"

    # The stored envelope string itself is immutable -- rotation is a
    # provider-configuration change, never a rewrite of existing data.
    assert service.decrypt(envelope_before) == b"stable-payload"
    assert decode(envelope_before).key_version == "v1"


# --- no cross-version fallback -------------------------------------------


def test_no_fallback_to_active_key_when_ciphertext_version_is_unavailable() -> None:
    """The explicit "no fallback" property: active=v2 (available),
    ciphertext=v1 (its key has been removed/retired) -- decryption must
    fail with `UnknownKeyVersionError`, never silently succeed or fail
    differently by attempting v2's key against v1's ciphertext."""
    provider = MutableFakeKeyProvider({"v1": _KEY_V1, "v2": _KEY_V2}, active="v1")
    service = EncryptionService(key_provider=provider)
    envelope_v1 = service.encrypt(b"payload")

    # Retire v1: it's gone, v2 is active and available.
    del provider.keys["v1"]
    provider.active = "v2"

    with pytest.raises(UnknownKeyVersionError) as exc_info:
        service.decrypt(envelope_v1)

    assert exc_info.value.key_version == "v1"


def test_missing_historical_key_fails_closed_not_silently_skipped() -> None:
    provider = MutableFakeKeyProvider({"v1": _KEY_V1}, active="v1")
    service = EncryptionService(key_provider=provider)
    envelope_v1 = service.encrypt(b"old-payload")

    del provider.keys["v1"]  # simulate v1 having been retired

    with pytest.raises(UnknownKeyVersionError):
        service.decrypt(envelope_v1)


# --- missing active key: fail closed at encrypt time, no fallback --------


def test_missing_active_key_fails_closed_on_encrypt_even_with_historical_keys_present() -> None:
    """active=v2 configured but v2's own key material is absent, while
    v1's key material *is* present -- `encrypt()` must fail closed
    (never silently encrypt under v1, and never generate a key)."""
    provider = MutableFakeKeyProvider({"v1": _KEY_V1}, active="v2")

    service = EncryptionService(key_provider=provider)

    with pytest.raises(UnknownKeyVersionError):
        service.encrypt(b"payload")


def test_encrypt_after_broken_rotation_does_not_fall_back_to_previous_active_key() -> None:
    """Same scenario as above, phrased as an explicit non-fallback
    proof: rotate active to v2 without configuring v2's key, and confirm
    the resulting ciphertext -- there must be none -- was never produced
    under v1."""
    provider = MutableFakeKeyProvider({"v1": _KEY_V1}, active="v1")
    service = EncryptionService(key_provider=provider)

    provider.active = "v2"  # broken rotation: v2 key never configured

    with pytest.raises(UnknownKeyVersionError):
        service.encrypt(b"payload")


# --- key-version validation ------------------------------------------------


def test_empty_active_version_fails_closed() -> None:
    class _EmptyVersionProvider(KeyProvider):
        def current_key_version(self) -> str:
            return ""

        def key_for_version(self, key_version: str) -> bytes:
            return _KEY_V1

    service = EncryptionService(key_provider=_EmptyVersionProvider())

    with pytest.raises(ValueError, match="key_version"):
        service.encrypt(b"payload")


def test_active_version_containing_delimiter_fails_closed() -> None:
    class _UnsafeVersionProvider(KeyProvider):
        def current_key_version(self) -> str:
            return "v1:evil"

        def key_for_version(self, key_version: str) -> bytes:
            return _KEY_V1

    service = EncryptionService(key_provider=_UnsafeVersionProvider())

    with pytest.raises(ValueError, match="key_version"):
        service.encrypt(b"payload")


# --- key identity / determinism within one provider -----------------------


def test_key_material_for_a_version_is_deterministic_within_one_provider() -> None:
    """The same version identifier must resolve to the same key material
    every time within one provider configuration -- `SecretsBackedKeyProvider`
    is a pure function of whatever `infra.secrets` currently returns for a
    fixed secret name, so this holds structurally; this test documents and
    proves the invariant `EncryptionService` itself relies on (encrypting
    and later decrypting under "the same v1" depends on it)."""
    provider = MutableFakeKeyProvider({"v1": _KEY_V1}, active="v1")

    first = provider.key_for_version("v1")
    second = provider.key_for_version("v1")

    assert first == second


def test_encrypt_then_decrypt_relies_on_stable_key_identity_for_the_same_version() -> None:
    provider = MutableFakeKeyProvider({"v1": _KEY_V1}, active="v1")
    service = EncryptionService(key_provider=provider)

    envelope = service.encrypt(b"payload")
    # No configuration change at all -- "v1" must still mean the same key.
    assert service.decrypt(envelope) == b"payload"


# --- missing active key entirely (no version configured at all) -----------


def test_no_active_version_configured_fails_closed_never_generates_a_key() -> None:
    class _NoActiveVersionProvider(KeyProvider):
        def current_key_version(self) -> str:
            raise EncryptionKeyUnavailableError(key_version="<active>")

        def key_for_version(self, key_version: str) -> bytes:
            raise EncryptionKeyUnavailableError(key_version=key_version)

    service = EncryptionService(key_provider=_NoActiveVersionProvider())

    with pytest.raises(EncryptionKeyUnavailableError):
        service.encrypt(b"payload")
