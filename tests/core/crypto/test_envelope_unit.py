"""S-01 (BANK-SEC-01/02) -- `saas_os.core.crypto.envelope`'s versioned ciphertext
format: encode/decode round trip, and every malformed/hostile input
`decode()` must fail closed on rather than partially interpret."""

from __future__ import annotations

import base64

import pytest

from saas_os.core.crypto.envelope import decode, encode
from saas_os.core.crypto.errors import MalformedCiphertextError, UnsupportedCiphertextVersionError


def test_encode_decode_round_trip() -> None:
    envelope = encode(
        key_version="v1", nonce=b"0" * 12, ciphertext_and_tag=b"ciphertext-and-tag-bytes"
    )

    parsed = decode(envelope)

    assert parsed.format_version == "efv1"
    assert parsed.key_version == "v1"
    assert parsed.nonce == b"0" * 12
    assert parsed.ciphertext_and_tag == b"ciphertext-and-tag-bytes"


def test_envelope_is_plain_colon_delimited_text_not_binary() -> None:
    envelope = encode(key_version="v1", nonce=b"\x00" * 12, ciphertext_and_tag=b"\xff\xfe\x00\x01")

    assert isinstance(envelope, str)
    envelope.encode("ascii")  # must not raise: safe for a text DB column
    assert envelope.count(":") == 3


def test_binary_safe_nonce_and_ciphertext_round_trip() -> None:
    nonce = bytes(range(12))
    ciphertext = bytes(range(256)) * 4  # every byte value, several times over

    parsed = decode(encode(key_version="v1", nonce=nonce, ciphertext_and_tag=ciphertext))

    assert parsed.nonce == nonce
    assert parsed.ciphertext_and_tag == ciphertext


def test_key_version_containing_colon_is_rejected() -> None:
    with pytest.raises(ValueError, match="key_version"):
        encode(key_version="v1:evil", nonce=b"0" * 12, ciphertext_and_tag=b"x")


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "not-an-envelope-at-all",
        "efv1:v1:only-three-fields",
        "efv1:v1:one:two:three:extra-field",
        "efv1::"
        + base64.urlsafe_b64encode(b"x").decode()
        + ":"
        + base64.urlsafe_b64encode(b"y").decode(),
    ],
)
def test_malformed_envelope_fails_closed(malformed: str) -> None:
    with pytest.raises(MalformedCiphertextError):
        decode(malformed)


def test_non_base64_field_fails_closed() -> None:
    with pytest.raises(MalformedCiphertextError):
        decode("efv1:v1:not-valid-base64!!!:" + base64.urlsafe_b64encode(b"y").decode())


def test_unsupported_format_version_fails_closed() -> None:
    envelope = encode(key_version="v1", nonce=b"0" * 12, ciphertext_and_tag=b"x")
    forged = envelope.replace("efv1:", "efv99:", 1)

    with pytest.raises(UnsupportedCiphertextVersionError):
        decode(forged)


def test_wrong_nonce_length_fails_closed() -> None:
    short_nonce_b64 = base64.urlsafe_b64encode(b"tooshort").decode()
    ciphertext_b64 = base64.urlsafe_b64encode(b"x").decode()

    with pytest.raises(MalformedCiphertextError):
        decode(f"efv1:v1:{short_nonce_b64}:{ciphertext_b64}")


def test_empty_ciphertext_field_fails_closed() -> None:
    nonce_b64 = base64.urlsafe_b64encode(b"0" * 12).decode()

    with pytest.raises(MalformedCiphertextError):
        decode(f"efv1:v1:{nonce_b64}:")
