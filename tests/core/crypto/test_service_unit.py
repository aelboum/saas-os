"""S-01 (BANK-SEC-01/02) -- `saas_os.core.crypto.EncryptionService`: the security
properties BANK-SEC-02 requires are guaranteed. Uses a `FakeKeyProvider`
(a direct `KeyProvider` implementation, the same "substitute a fake
provider against the real abstraction" pattern `saas_os/core/billing`'s own
`FakeBillingProvider` already establishes) -- never touches
`saas_os.infra.secrets` or the environment, so these tests exercise
`EncryptionService` in isolation from key *storage* concerns (those are
`tests/core/crypto/test_keys_unit.py`'s job)."""

from __future__ import annotations

import base64

import pytest

from saas_os.core.crypto.envelope import decode, encode
from saas_os.core.crypto.errors import (
    DecryptionAuthenticationError,
    EncryptionKeyUnavailableError,
    MalformedCiphertextError,
    UnknownKeyVersionError,
    UnsupportedCiphertextVersionError,
)
from saas_os.core.crypto.keys import KeyProvider
from saas_os.core.crypto.service import EncryptionService

_KEY_V1 = b"1" * 32
_KEY_V2 = b"2" * 32


class FakeKeyProvider(KeyProvider):
    """In-memory `KeyProvider` for tests -- never reads `saas_os.infra.secrets`
    or the environment. `keys` maps version -> 32-byte key material;
    `active` is the version `current_key_version()` returns."""

    def __init__(self, keys: dict[str, bytes], *, active: str) -> None:
        self._keys = keys
        self._active = active

    def current_key_version(self) -> str:
        return self._active

    def key_for_version(self, key_version: str) -> bytes:
        try:
            return self._keys[key_version]
        except KeyError:
            raise UnknownKeyVersionError(key_version) from None


class _NoKeyProvider(KeyProvider):
    """A `KeyProvider` with no configured key at all -- proves
    `EncryptionService` fails closed rather than encrypting under a
    default/placeholder key when key material is unavailable."""

    def current_key_version(self) -> str:
        raise EncryptionKeyUnavailableError(key_version="<active>")

    def key_for_version(self, key_version: str) -> bytes:
        raise EncryptionKeyUnavailableError(key_version=key_version)


@pytest.fixture
def service() -> EncryptionService:
    return EncryptionService(key_provider=FakeKeyProvider({"v1": _KEY_V1}, active="v1"))


# --- functional: round trip -------------------------------------------------


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"x",
        b"a normal bearer-token-shaped string of moderate length",
        b"y" * 10_000,
        "unicode: café, 中文, \U0001f512".encode(),
        bytes(range(256)) * 8,  # every byte value, binary-safe
    ],
)
def test_encrypt_decrypt_round_trip(service: EncryptionService, plaintext: bytes) -> None:
    envelope = service.encrypt(plaintext)

    assert service.decrypt(envelope) == plaintext


def test_str_convenience_round_trip(service: EncryptionService) -> None:
    plaintext = "a bearer token: café \U0001f512"

    envelope = service.encrypt_str(plaintext)

    assert service.decrypt_str(envelope) == plaintext


def test_repeated_encryption_of_same_plaintext_produces_distinct_ciphertext(
    service: EncryptionService,
) -> None:
    """Randomized-nonce requirement: encrypting the same plaintext twice
    must never produce the same envelope (which would leak that two
    stored values are equal, and would indicate nonce reuse -- an AES-GCM
    correctness/security failure)."""
    plaintext = b"same plaintext every time"

    envelopes = {service.encrypt(plaintext) for _ in range(20)}

    assert len(envelopes) == 20
    nonces = {decode(e).nonce for e in envelopes}
    assert len(nonces) == 20


# --- integrity: tampering must fail -----------------------------------------


def test_tampered_ciphertext_fails(service: EncryptionService) -> None:
    envelope = service.encrypt(b"original plaintext")
    parsed = decode(envelope)
    tampered_ciphertext = bytes(
        parsed.ciphertext_and_tag[:-1] + bytes([parsed.ciphertext_and_tag[-1] ^ 0xFF])
    )
    tampered = encode(
        key_version=parsed.key_version, nonce=parsed.nonce, ciphertext_and_tag=tampered_ciphertext
    )

    with pytest.raises(DecryptionAuthenticationError):
        service.decrypt(tampered)


def test_tampered_nonce_fails(service: EncryptionService) -> None:
    envelope = service.encrypt(b"original plaintext")
    parsed = decode(envelope)
    tampered_nonce = bytes(parsed.nonce[:-1] + bytes([parsed.nonce[-1] ^ 0xFF]))
    tampered = encode(
        key_version=parsed.key_version,
        nonce=tampered_nonce,
        ciphertext_and_tag=parsed.ciphertext_and_tag,
    )

    with pytest.raises(DecryptionAuthenticationError):
        service.decrypt(tampered)


def test_tampered_authentication_tag_fails(service: EncryptionService) -> None:
    """The AES-GCM tag is the trailing 16 bytes of `ciphertext_and_tag`;
    flipping a bit there specifically (not in the ciphertext body) must
    still fail authentication."""
    envelope = service.encrypt(b"original plaintext")
    parsed = decode(envelope)
    body, tag = parsed.ciphertext_and_tag[:-16], parsed.ciphertext_and_tag[-16:]
    tampered_tag = bytes(tag[:-1] + bytes([tag[-1] ^ 0xFF]))
    tampered = encode(
        key_version=parsed.key_version, nonce=parsed.nonce, ciphertext_and_tag=body + tampered_tag
    )

    with pytest.raises(DecryptionAuthenticationError):
        service.decrypt(tampered)


def test_tampered_associated_data_fails(service: EncryptionService) -> None:
    envelope = service.encrypt(b"original plaintext", associated_data=b"original-context")

    with pytest.raises(DecryptionAuthenticationError):
        service.decrypt(envelope, associated_data=b"tampered-context")


def test_missing_associated_data_at_decrypt_fails_if_present_at_encrypt(
    service: EncryptionService,
) -> None:
    envelope = service.encrypt(b"original plaintext", associated_data=b"some-context")

    with pytest.raises(DecryptionAuthenticationError):
        service.decrypt(envelope)  # no associated_data supplied


def test_matching_associated_data_succeeds(service: EncryptionService) -> None:
    envelope = service.encrypt(b"original plaintext", associated_data=b"matching-context")

    assert service.decrypt(envelope, associated_data=b"matching-context") == b"original plaintext"


# --- key handling ------------------------------------------------------------


def test_correct_key_version_decrypts() -> None:
    service = EncryptionService(
        key_provider=FakeKeyProvider({"v1": _KEY_V1, "v2": _KEY_V2}, active="v2")
    )
    envelope = service.encrypt(b"payload")

    assert decode(envelope).key_version == "v2"
    assert service.decrypt(envelope) == b"payload"


def test_unknown_key_version_fails(service: EncryptionService) -> None:
    envelope = service.encrypt(b"payload")
    parsed = decode(envelope)
    forged = encode(
        key_version="v99-does-not-exist",
        nonce=parsed.nonce,
        ciphertext_and_tag=parsed.ciphertext_and_tag,
    )

    with pytest.raises(UnknownKeyVersionError):
        service.decrypt(forged)


def test_missing_key_material_fails_closed_on_encrypt() -> None:
    service = EncryptionService(key_provider=_NoKeyProvider())

    with pytest.raises(EncryptionKeyUnavailableError):
        service.encrypt(b"payload")


def test_wrong_key_fails_to_decrypt() -> None:
    encryptor = EncryptionService(key_provider=FakeKeyProvider({"v1": _KEY_V1}, active="v1"))
    envelope = encryptor.encrypt(b"payload")
    # Same key *version* name, but different actual key material -- the
    # realistic "wrong key" scenario (e.g. misconfigured environment).
    wrong_key_service = EncryptionService(
        key_provider=FakeKeyProvider({"v1": b"9" * 32}, active="v1")
    )

    with pytest.raises(DecryptionAuthenticationError):
        wrong_key_service.decrypt(envelope)


# --- version handling --------------------------------------------------------


def test_unsupported_format_version_fails_closed(service: EncryptionService) -> None:
    envelope = service.encrypt(b"payload")
    forged = envelope.replace("efv1:", "efv2:", 1)

    with pytest.raises(UnsupportedCiphertextVersionError):
        service.decrypt(forged)


def test_malformed_envelope_fails_closed(service: EncryptionService) -> None:
    with pytest.raises(MalformedCiphertextError):
        service.decrypt("this-is-not-an-envelope")


# --- security boundary --------------------------------------------------------


def test_key_material_never_appears_in_the_ciphertext_envelope(service: EncryptionService) -> None:
    envelope = service.encrypt(b"payload")

    assert base64.b64encode(_KEY_V1).decode() not in envelope
    assert _KEY_V1 not in envelope.encode("latin-1", errors="ignore")


def test_plaintext_is_not_included_in_any_raised_exception(service: EncryptionService) -> None:
    secret_plaintext = b"this-must-never-leak-into-an-exception"
    envelope = service.encrypt(secret_plaintext)
    parsed = decode(envelope)
    tampered = encode(
        key_version=parsed.key_version,
        nonce=parsed.nonce,
        ciphertext_and_tag=b"\x00" * len(parsed.ciphertext_and_tag),
    )

    with pytest.raises(DecryptionAuthenticationError) as exc_info:
        service.decrypt(tampered)

    assert secret_plaintext not in str(exc_info.value).encode()
    assert secret_plaintext.decode() not in repr(exc_info.value)


def test_plaintext_is_not_included_in_the_envelope_string(service: EncryptionService) -> None:
    secret_plaintext = b"this-plaintext-must-never-appear-verbatim"

    envelope = service.encrypt(secret_plaintext)

    assert secret_plaintext not in envelope.encode("latin-1", errors="ignore")


def test_decryption_error_does_not_distinguish_tamper_reason() -> None:
    """Wrong key and tampered ciphertext must raise the *same* exception
    type with no distinguishing detail -- telling an attacker which check
    failed would leak information a generic failure does not."""
    service_a = EncryptionService(key_provider=FakeKeyProvider({"v1": _KEY_V1}, active="v1"))
    service_b = EncryptionService(key_provider=FakeKeyProvider({"v1": b"9" * 32}, active="v1"))
    envelope = service_a.encrypt(b"payload")

    with pytest.raises(DecryptionAuthenticationError) as wrong_key_exc:
        service_b.decrypt(envelope)

    parsed = decode(envelope)
    tampered = encode(
        key_version=parsed.key_version,
        nonce=parsed.nonce,
        ciphertext_and_tag=b"\x00" * len(parsed.ciphertext_and_tag),
    )
    with pytest.raises(DecryptionAuthenticationError) as tampered_exc:
        service_a.decrypt(tampered)

    assert type(wrong_key_exc.value) is type(tampered_exc.value)


# --- tenant-style binding via associated data --------------------------------


def test_associated_data_can_bind_ciphertext_to_a_context_like_a_tenant_id() -> None:
    """Demonstrates the AAD mechanism BANK-SEC-02 asks be evaluated for
    tenant binding, without EncryptionService knowing anything about
    tenants itself: the caller builds the context bytes."""
    service = EncryptionService(key_provider=FakeKeyProvider({"v1": _KEY_V1}, active="v1"))
    tenant_a_context = b"tenant:11111111-1111-1111-1111-111111111111"
    tenant_b_context = b"tenant:22222222-2222-2222-2222-222222222222"

    envelope = service.encrypt(b"tenant-a-secret", associated_data=tenant_a_context)

    # Correct context decrypts.
    assert service.decrypt(envelope, associated_data=tenant_a_context) == b"tenant-a-secret"
    # Moving the same ciphertext "to" a different tenant's context fails --
    # this is the property that matters: a ciphertext cannot be
    # reinterpreted under a different tenant's binding.
    with pytest.raises(DecryptionAuthenticationError):
        service.decrypt(envelope, associated_data=tenant_b_context)
