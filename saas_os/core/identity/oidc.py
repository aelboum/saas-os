"""OIDC ID token validation (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2;
docs/ADR/0005-identity-build-vs-buy.md).

Standards-based JWT/OIDC validation only -- no ZITADEL-specific behavior is
hardcoded here (ADR-0005's "Future Migration/Extension Path": a swap to a
different OIDC-compliant IdP must be a configuration change, not a
platform-wide rewrite). All cryptographic verification is delegated
entirely to PyJWT[crypto] (`pyproject.toml`) -- this module never
implements its own signature/algorithm logic, and never logs or includes a
raw token in any exception (docs/SECURITY.md).

Algorithm confusion / downgrade defense (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.2 section 7): the acceptable algorithm set (`_ACCEPTED_ALGORITHMS`,
asymmetric only) is fixed here, server-side, and checked *before* any
signature-verification attempt against the token's own (attacker-
controlled) `alg` header -- a token asserting `alg: none` or `alg: HS256`
(the classic RS256->HS256 confusion attack, which would let an attacker
sign with the provider's *public* key as if it were an HMAC secret) is
rejected before `PyJWKClient` is ever consulted. `jwt.decode`'s own
`algorithms=` allow-list is a second, independent layer of the same
defense.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    MissingRequiredClaimError,
    PyJWKClientError,
)
from jwt.exceptions import InvalidAudienceError as _PyJWTInvalidAudienceError
from jwt.exceptions import InvalidIssuerError as _PyJWTInvalidIssuerError
from jwt.exceptions import (
    InvalidSignatureError as _PyJWTInvalidSignatureError,
)
from jwt.exceptions import InvalidTokenError as _PyJWTInvalidTokenError

from saas_os.core.identity.errors import (
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidNonceError,
    InvalidSignatureError,
    MalformedTokenError,
    MissingSubjectError,
    OIDCExchangeError,
    TokenExpiredError,
    UnknownSigningKeyError,
    UnsupportedAlgorithmError,
)
from saas_os.core.identity.login_transactions import PKCE_CODE_CHALLENGE_METHOD
from saas_os.core.identity.provider import (
    OIDCFlowEndpoints,
    OIDCProviderConfig,
    get_oidc_client_secret,
    get_oidc_flow_endpoints,
    get_oidc_provider_config,
)

# Asymmetric only -- a symmetric algorithm (HS256) would let anyone holding
# just the public client_id/audience (not a secret) forge a token, since
# HMAC verification uses the same key as signing. See module docstring.
_ACCEPTED_ALGORITHMS = ("RS256", "ES256")


@dataclass(frozen=True)
class VerifiedIdentity:
    """The minimal, standards-based result of a verified ID token -- exactly
    the claims `saas_os/core/identity` needs to resolve a platform user. Never
    carries the raw token."""

    issuer: str
    subject: str
    email: str | None
    raw_claims: dict[str, object] = field(repr=False)
    # True only when the provider asserted the standard `email_verified`
    # claim as the JSON boolean `true` (OIDC Core 5.1); anything else --
    # absent, `false`, a string -- is not a verification (ADR-0046).
    email_verified: bool = False
    # True only when the token's `amr` claim (RFC 8176) shows more than one
    # factor: `mfa` itself, or a password together with a possession or
    # inherence factor. Absent or unrecognized: false (ADR-0049).
    multi_factor: bool = False
    # The token's `auth_time` claim (OIDC Core 2): when the person last
    # actively authenticated at the provider. `None` when absent.
    authenticated_at: datetime | None = None


@lru_cache
def _jwk_client(jwks_uri: str) -> PyJWKClient:
    # PyJWKClient fetches and caches signing keys internally (by kid) and
    # is safe to reuse across validations -- cached per jwks_uri so
    # multiple provider configs (e.g. across tests) don't share a client.
    return PyJWKClient(jwks_uri)


def validate_id_token(
    token: str,
    config: OIDCProviderConfig,
    *,
    expected_nonce: str | None = None,
) -> VerifiedIdentity:
    """Verify `token` is a valid OIDC ID token issued by `config`'s
    provider, and return the minimal identity claims.

    Validates, in order: JWT well-formedness, algorithm (allow-listed,
    asymmetric only), signature (via the provider's JWKS, looked up by
    `kid`), issuer, audience, expiration, and the required `sub` claim.
    `expected_nonce` is optional -- pass it only when the caller tracked a
    nonce for this authentication attempt, as the login flow
    (`saas_os/api/auth/routes.py::callback`) does with the `nonce` its login
    transaction recorded; omitted, no nonce check is performed.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except DecodeError as exc:
        raise MalformedTokenError() from exc

    alg = unverified_header.get("alg")
    if alg not in _ACCEPTED_ALGORITHMS:
        raise UnsupportedAlgorithmError(alg)

    try:
        signing_key = _jwk_client(config.jwks_uri).get_signing_key_from_jwt(token)
    except PyJWKClientError as exc:
        raise UnknownSigningKeyError(unverified_header.get("kid")) from exc
    except DecodeError as exc:
        raise MalformedTokenError() from exc

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(_ACCEPTED_ALGORITHMS),
            issuer=config.issuer,
            audience=config.audience,
            options={"require": ["sub"]},
        )
    except ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except _PyJWTInvalidIssuerError as exc:
        raise InvalidIssuerError() from exc
    except _PyJWTInvalidAudienceError as exc:
        raise InvalidAudienceError() from exc
    except MissingRequiredClaimError as exc:
        raise MissingSubjectError() from exc
    except _PyJWTInvalidSignatureError as exc:
        raise InvalidSignatureError() from exc
    except DecodeError as exc:
        raise MalformedTokenError() from exc
    except _PyJWTInvalidTokenError as exc:
        # Any other standards-based rejection PyJWT performs (not-before,
        # invalid key/algorithm mismatch caught a second time here) --
        # collapsed to a signature error rather than echoing PyJWT's own
        # message, which may quote attacker-controlled token content.
        raise InvalidSignatureError() from exc

    subject = claims.get("sub")
    if not subject:
        raise MissingSubjectError()

    if expected_nonce is not None and claims.get("nonce") != expected_nonce:
        raise InvalidNonceError()

    return VerifiedIdentity(
        issuer=claims["iss"],
        subject=subject,
        email=claims.get("email"),
        raw_claims=claims,
        email_verified=claims.get("email_verified") is True,
        multi_factor=is_multi_factor(claims.get("amr")),
        authenticated_at=_auth_time(claims.get("auth_time")),
    )


# RFC 8176 method references for a possession or inherence factor -- a
# factor of another kind than a password. Not `pin` (knowledge, like a
# password) and not `user` (user presence: ZITADEL reports a security key
# used alone as `["user"]`, and a user-verified passkey as
# `["user", "mfa"]`).
_SECOND_FACTORS = frozenset(
    {"otp", "hwk", "swk", "sms", "tel", "sc", "face", "fpt", "iris", "retina"}
)
# The provider's own statement that more than one factor was used; ZITADEL
# adds it whenever there are two or more (docs/architecture/
# PRODUCT-OWNED-AUTHENTICATION-ARCHITECTURE.md, gate 4).
_SELF_SUFFICIENT = frozenset({"mfa"})


def is_multi_factor(amr: object) -> bool:
    """Whether an `amr` claim (RFC 8176) shows more than one factor: `mfa`,
    or a password (`pwd`) with a possession or inherence factor. Anything
    malformed, absent or single-factor is not."""
    if not isinstance(amr, list) or not all(isinstance(m, str) for m in amr):
        return False
    methods = {m.strip().lower() for m in amr}
    if methods & _SELF_SUFFICIENT:
        return True
    return "pwd" in methods and bool(methods & _SECOND_FACTORS)


def _auth_time(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


# --- P2.2: Authorization Code Flow (browser login) ---------------------------

# `email` (OIDC Core 5.4) asks the provider for the `email` and
# `email_verified` claims: invitation acceptance compares a verified
# email with the invited one (ADR-0046). They are never an identity key.
_DEFAULT_SCOPES = ("openid", "email")
_TOKEN_EXCHANGE_TIMEOUT_SECONDS = 10.0


def build_authorization_url(
    config: OIDCProviderConfig,
    endpoints: OIDCFlowEndpoints,
    *,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
    scopes: tuple[str, ...] = _DEFAULT_SCOPES,
) -> str:
    """The URL the browser is redirected to (pure function, no I/O).
    Carries `state`, `nonce`, and the PKCE `code_challenge` with
    `code_challenge_method=S256` -- never the `code_verifier`, never a
    client secret. `redirect_uri` is the deployment's configured,
    allowlisted callback (`saas_os/api/auth/config.py`), never a browser-supplied
    value."""
    if "openid" not in scopes:
        scopes = ("openid", *scopes)
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": PKCE_CODE_CHALLENGE_METHOD,
        }
    )
    return f"{endpoints.authorization_endpoint}?{query}"


def _token_http_client() -> httpx.Client:
    """The one place the token-exchange HTTP client is constructed --
    tests substitute an `httpx.MockTransport`-backed client here."""
    return httpx.Client(timeout=_TOKEN_EXCHANGE_TIMEOUT_SECONDS)


def exchange_authorization_code(
    config: OIDCProviderConfig,
    endpoints: OIDCFlowEndpoints,
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    client_secret: str | None,
) -> str:
    """Server-side `grant_type=authorization_code` exchange (RFC 6749 §4.1.3
    + RFC 7636 §4.5). Returns the raw ID token string for
    `validate_id_token()` to verify -- this function itself trusts nothing
    in the response beyond its shape. `client_secret` (if the client is
    confidential) travels only in the POST body to the provider's
    discovered `token_endpoint`, over the client's own TLS; the code and
    verifier likewise. Nothing here is logged. Every failure -- transport
    error, non-2xx status, unparseable body, missing `id_token` -- raises
    `OIDCExchangeError` with a fixed classification, never the provider's
    response body (which may echo the code or carry an error description
    the caller has no need to see)."""
    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": config.client_id,
        "code_verifier": code_verifier,
    }
    if client_secret:
        form["client_secret"] = client_secret

    try:
        with _token_http_client() as client:
            response = client.post(
                endpoints.token_endpoint,
                data=form,
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise OIDCExchangeError(f"transport error ({type(exc).__name__})") from exc

    if response.status_code >= 500:
        raise OIDCExchangeError("provider unavailable")
    if response.status_code != 200:
        raise OIDCExchangeError("provider rejected the authorization code")
    try:
        body = response.json()
    except ValueError as exc:
        raise OIDCExchangeError("provider response was not JSON") from exc
    id_token = body.get("id_token") if isinstance(body, dict) else None
    if not isinstance(id_token, str) or not id_token:
        raise OIDCExchangeError("provider response carried no id_token")
    return id_token


# --- Phase 2 (ADR-0023): the concrete `IdentityProvider` adapter -------------
#
# Delegates directly to the module functions above -- no second
# implementation, no duplicated security logic. Structural typing
# (`saas_os.core.identity.provider.IdentityProvider` is a `Protocol`) means this
# class satisfies it without importing or subclassing it, which also
# avoids a circular import (`provider.py` is imported by this module, not
# the other way round).


class OIDCIdentityProvider:
    """The current, and only, `IdentityProvider` implementation: the
    standards-based OIDC logic already in this module, wrapped so
    `saas_os/api/auth/routes.py` depends on the small Protocol rather than these
    free functions directly. ZITADEL is *an* OIDC-compliant issuer this
    can point at via `config.issuer` -- nothing here is ZITADEL-specific
    (ADR-0005, ADR-0023)."""

    def __init__(self, config: OIDCProviderConfig, endpoints: OIDCFlowEndpoints) -> None:
        self._config = config
        self._endpoints = endpoints

    def get_config(self) -> OIDCProviderConfig:
        return self._config

    def get_flow_endpoints(self) -> OIDCFlowEndpoints:
        return self._endpoints

    def build_authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
        scopes: tuple[str, ...] = _DEFAULT_SCOPES,
    ) -> str:
        return build_authorization_url(
            self._config,
            self._endpoints,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            scopes=scopes,
        )

    def exchange_authorization_code(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> str:
        # Client secret resolved here, at the moment of use -- never
        # cached on this object -- exactly `get_oidc_client_secret()`'s
        # own documented discipline, unchanged by this wrapper.
        return exchange_authorization_code(
            self._config,
            self._endpoints,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            client_secret=get_oidc_client_secret(),
        )

    def validate_id_token(
        self, token: str, *, expected_nonce: str | None = None
    ) -> VerifiedIdentity:
        return validate_id_token(token, self._config, expected_nonce=expected_nonce)


@lru_cache
def get_identity_provider() -> OIDCIdentityProvider:
    """The process-wide `IdentityProvider` singleton -- deterministic
    construction from the same cached config/discovery
    (`get_oidc_provider_config()`/`get_oidc_flow_endpoints()`) the rest of
    `saas_os/core/identity` already resolves, not a runtime provider registry or
    factory (ADR-0023: no plugin framework). Tests call
    `get_identity_provider.cache_clear()` after `monkeypatch.setenv(...)`,
    mirroring the two functions it composes."""
    return OIDCIdentityProvider(get_oidc_provider_config(), get_oidc_flow_endpoints())
