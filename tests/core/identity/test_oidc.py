"""OIDC ID token validation tests (docs/IMPLEMENTATION-ROADMAP.md Phase
3.2 section 12 "Security Test Matrix > OIDC"). Pure unit tests -- no
database, no network: `core.identity.oidc._jwk_client` is monkeypatched to
a fake, in-memory JWKS keyed by `kid`, so real RSA keys generated in this
file (via `cryptography`, already a transitive dependency of
`PyJWT[crypto]`) stand in for a real provider's signing keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

import jwt
import pytest
from core.identity.errors import (
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidNonceError,
    InvalidSignatureError,
    MalformedTokenError,
    MissingSubjectError,
    TokenExpiredError,
    UnknownSigningKeyError,
    UnsupportedAlgorithmError,
)
from core.identity.oidc import validate_id_token
from core.identity.provider import OIDCProviderConfig
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from jwt.exceptions import PyJWKClientError

_ISSUER = "https://idp.example.test"
_CLIENT_ID = "test-client"
_JWKS_URI = f"{_ISSUER}/oauth/v2/keys"
_KID = "test-key-1"

_KeyPair = tuple[RSAPrivateKey, RSAPublicKey]


def _config() -> OIDCProviderConfig:
    return OIDCProviderConfig(
        issuer=_ISSUER, client_id=_CLIENT_ID, audience=_CLIENT_ID, jwks_uri=_JWKS_URI
    )


class _FakeSigningKey:
    def __init__(self, key: object) -> None:
        self.key = key


class _FakeJWKClient:
    """Stands in for `jwt.PyJWKClient` -- resolves a signing key by the
    token's own `kid` header from an in-memory `{kid: public_key}` map,
    the same per-kid selection behavior a real JWKS lookup performs."""

    def __init__(self, keys_by_kid: dict[str, object]) -> None:
        self._keys_by_kid = keys_by_kid

    def get_signing_key_from_jwt(self, token: str) -> _FakeSigningKey:
        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self._keys_by_kid:
            raise PyJWKClientError(f"Unable to find a signing key that matches: {kid!r}")
        return _FakeSigningKey(self._keys_by_kid[kid])


@pytest.fixture
def keypair() -> _KeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def patch_jwk_client(monkeypatch: pytest.MonkeyPatch, keypair: _KeyPair):
    """Registers `keypair`'s public key under `_KID` by default; returns a
    function tests can call again to register additional keys under other
    kids (for the multi-key JWKS-selection test)."""
    _, public_key = keypair
    keys_by_kid: dict[str, object] = {_KID: public_key}
    fake_client = _FakeJWKClient(keys_by_kid)
    monkeypatch.setattr("core.identity.oidc._jwk_client", lambda jwks_uri: fake_client)
    return keys_by_kid


def _claims(**overrides: object) -> dict[str, object]:
    now = int(time.time())
    base = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "sub": f"user-{uuid.uuid4().hex[:8]}",
        "iat": now,
        "exp": now + 300,
    }
    base.update(overrides)
    return base


def _sign(
    private_key: RSAPrivateKey, claims: dict[str, object], *, kid: str = _KID, alg: str = "RS256"
) -> str:
    return jwt.encode(claims, private_key, algorithm=alg, headers={"kid": kid})


def _make_none_alg_token(claims: dict[str, object]) -> str:
    """Hand-crafted `alg: none` token -- PyJWT's own `encode()` refuses to
    produce one, which is itself a good sign, but the attack this guards
    against is a token an *attacker* crafted, not one this library
    produced -- so the defense must reject it structurally, not rely on
    never being asked to encode one."""

    def b64(obj: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    header: dict[str, object] = {"alg": "none", "typ": "JWT"}
    return f"{b64(header)}.{b64(claims)}."


def _make_hs256_forged_token(claims: dict[str, object], hmac_key: bytes, *, kid: str = _KID) -> str:
    """Hand-crafted `alg: HS256` token, HMAC-signed directly with `hmac_key`
    (bypassing PyJWT's own `encode()`, which refuses to use a PEM-shaped
    key as an HMAC secret -- a real attacker is under no such obligation,
    since they are not using this library's encode path at all)."""

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
    signature = hmac.new(hmac_key, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64(signature)}"


# --- Happy path --------------------------------------------------------


def test_valid_token_is_accepted(keypair: _KeyPair, patch_jwk_client: dict[str, object]) -> None:
    private_key, _ = keypair
    claims = _claims(email="user@example.test")
    token = _sign(private_key, claims)

    identity = validate_id_token(token, _config())

    assert identity.issuer == _ISSUER
    assert identity.subject == claims["sub"]
    assert identity.email == "user@example.test"
    assert identity.raw_claims["sub"] == claims["sub"]


def test_valid_token_without_email_claim_has_none_email(
    keypair: _KeyPair, patch_jwk_client: dict[str, object]
) -> None:
    private_key, _ = keypair
    token = _sign(private_key, _claims())

    identity = validate_id_token(token, _config())

    assert identity.email is None


# --- Signature / key selection -----------------------------------------


def test_invalid_signature_is_rejected(
    keypair: _KeyPair, patch_jwk_client: dict[str, object]
) -> None:
    wrong_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Signed with a DIFFERENT private key than the one registered under
    # this kid -- verification against the registered public key must fail.
    token = _sign(wrong_private_key, _claims())

    with pytest.raises(InvalidSignatureError):
        validate_id_token(token, _config())


def test_unknown_signing_key_is_rejected(
    keypair: _KeyPair, patch_jwk_client: dict[str, object]
) -> None:
    private_key, _ = keypair
    token = _sign(private_key, _claims(), kid="never-registered-kid")

    with pytest.raises(UnknownSigningKeyError) as excinfo:
        validate_id_token(token, _config())
    assert excinfo.value.kid == "never-registered-kid"


def test_jwks_key_selection_uses_the_matching_kid_not_any_registered_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-vacuous proof of per-kid selection: register TWO keys under two
    different kids, sign with the second key/kid, and confirm validation
    succeeds -- i.e. the lookup is genuinely keyed by `kid`, not just
    "whichever key happens to be loaded"."""
    key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_client = _FakeJWKClient({"kid-a": key_a.public_key(), "kid-b": key_b.public_key()})
    monkeypatch.setattr("core.identity.oidc._jwk_client", lambda jwks_uri: fake_client)

    token = _sign(key_b, _claims(), kid="kid-b")

    identity = validate_id_token(token, _config())
    assert identity.subject is not None

    # The other key alone must not validate a token signed by key_b.
    cross_signed = _sign(key_b, _claims(), kid="kid-a")
    with pytest.raises(InvalidSignatureError):
        validate_id_token(cross_signed, _config())


# --- Claims validation ---------------------------------------------------


def test_wrong_issuer_is_rejected(keypair: _KeyPair, patch_jwk_client: dict[str, object]) -> None:
    private_key, _ = keypair
    token = _sign(private_key, _claims(iss="https://not-the-configured-issuer.test"))

    with pytest.raises(InvalidIssuerError):
        validate_id_token(token, _config())


def test_wrong_audience_is_rejected(keypair: _KeyPair, patch_jwk_client: dict[str, object]) -> None:
    private_key, _ = keypair
    token = _sign(private_key, _claims(aud="some-other-client"))

    with pytest.raises(InvalidAudienceError):
        validate_id_token(token, _config())


def test_expired_token_is_rejected(keypair: _KeyPair, patch_jwk_client: dict[str, object]) -> None:
    private_key, _ = keypair
    now = int(time.time())
    token = _sign(private_key, _claims(iat=now - 7200, exp=now - 3600))

    with pytest.raises(TokenExpiredError):
        validate_id_token(token, _config())


def test_missing_subject_is_rejected(
    keypair: _KeyPair, patch_jwk_client: dict[str, object]
) -> None:
    private_key, _ = keypair
    claims = _claims()
    del claims["sub"]
    token = _sign(private_key, claims)

    with pytest.raises(MissingSubjectError):
        validate_id_token(token, _config())


def test_empty_subject_is_rejected(keypair: _KeyPair, patch_jwk_client: dict[str, object]) -> None:
    private_key, _ = keypair
    token = _sign(private_key, _claims(sub=""))

    with pytest.raises(MissingSubjectError):
        validate_id_token(token, _config())


def test_nonce_mismatch_is_rejected(keypair: _KeyPair, patch_jwk_client: dict[str, object]) -> None:
    private_key, _ = keypair
    token = _sign(private_key, _claims(nonce="expected-nonce"))

    with pytest.raises(InvalidNonceError):
        validate_id_token(token, _config(), expected_nonce="a-different-nonce")


def test_matching_nonce_is_accepted(keypair: _KeyPair, patch_jwk_client: dict[str, object]) -> None:
    private_key, _ = keypair
    token = _sign(private_key, _claims(nonce="expected-nonce"))

    identity = validate_id_token(token, _config(), expected_nonce="expected-nonce")
    assert identity.subject is not None


def test_no_nonce_check_when_not_requested(
    keypair: _KeyPair, patch_jwk_client: dict[str, object]
) -> None:
    private_key, _ = keypair
    token = _sign(private_key, _claims(nonce="whatever"))

    identity = validate_id_token(token, _config())  # expected_nonce omitted
    assert identity.subject is not None


# --- Malformed input -----------------------------------------------------


def test_malformed_token_is_rejected() -> None:
    with pytest.raises(MalformedTokenError):
        validate_id_token("this-is-not-a-jwt", _config())


def test_empty_string_token_is_rejected() -> None:
    with pytest.raises(MalformedTokenError):
        validate_id_token("", _config())


# --- Algorithm restriction / confusion / downgrade ------------------------


def test_unsupported_algorithm_is_rejected(
    keypair: _KeyPair, patch_jwk_client: dict[str, object]
) -> None:
    private_key, _ = keypair
    # ES256 and RS256 are accepted; HS384 (symmetric, and not in the
    # allow-list) must not be.
    token = jwt.encode(
        _claims(),
        "some-shared-secret-that-is-well-over-the-forty-eight-byte-minimum-length",
        algorithm="HS384",
        headers={"kid": _KID},
    )

    with pytest.raises(UnsupportedAlgorithmError) as excinfo:
        validate_id_token(token, _config())
    assert excinfo.value.alg == "HS384"


def test_algorithm_confusion_rs256_to_hs256_downgrade_is_rejected(
    keypair: _KeyPair, patch_jwk_client: dict[str, object]
) -> None:
    """The classic RS256->HS256 confusion attack: an attacker signs a
    forged token with HS256, using the provider's *public* key bytes as if
    they were an HMAC secret (something an attacker can always obtain,
    since it's public by definition). This must be rejected before any
    signature verification is attempted -- verifying it (and having it
    coincidentally fail) would still be the wrong defense; the algorithm
    itself must never be attacker-selectable.
    """
    _, public_key = keypair
    from cryptography.hazmat.primitives import serialization

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    forged = _make_hs256_forged_token(_claims(), public_pem)

    with pytest.raises(UnsupportedAlgorithmError) as excinfo:
        validate_id_token(forged, _config())
    assert excinfo.value.alg == "HS256"


def test_none_algorithm_is_rejected() -> None:
    token = _make_none_alg_token(_claims())

    with pytest.raises(UnsupportedAlgorithmError) as excinfo:
        validate_id_token(token, _config())
    assert excinfo.value.alg == "none"


# --- No secret/token leakage ----------------------------------------------


def _make_forged_signature_token(private_key: RSAPrivateKey) -> str:
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _sign(other_key, _claims())


def _make_expired_token(private_key: RSAPrivateKey) -> str:
    now = int(time.time())
    return _sign(private_key, _claims(iat=now - 7200, exp=now - 3600))


@pytest.mark.parametrize(
    "make_bad_token",
    [lambda private_key: "not-a-jwt-at-all", _make_forged_signature_token, _make_expired_token],
)
def test_raw_token_never_appears_in_a_raised_exception(
    keypair: _KeyPair, patch_jwk_client: dict[str, object], make_bad_token
) -> None:
    private_key, _ = keypair
    token = make_bad_token(private_key)

    with pytest.raises(Exception) as excinfo:  # noqa: PT011 -- deliberately broad, checking every failure path
        validate_id_token(token, _config())

    assert token not in str(excinfo.value)
    assert token not in repr(excinfo.value)
