"""OIDC provider configuration (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2;
docs/ADR/0005-identity-build-vs-buy.md; docs/ADR/0023-...: Phase 2
provider-neutral identity boundary).

Provider-agnostic on purpose: nothing on `OIDCProviderConfig` is
ZITADEL-specific (ADR-0005's "Future Migration/Extension Path" -- a swap to
a different OIDC-compliant IdP must be a configuration change inside
`core/identity`, not a platform-wide rewrite). The JWKS location is
resolved via standard OIDC Discovery (`{issuer}/.well-known/openid-configuration`,
an RFC-defined document every conformant provider serves, ZITADEL included)
rather than a guessed, vendor-specific path -- discovery uses the stdlib
`urllib`, so no new HTTP-client dependency is introduced for it.

`client_secret` is never a field on `OIDCProviderConfig`: ID-token
validation (the relying-party side of an already-completed OIDC flow)
never needs it, and only the authorization-code exchange does.
`get_oidc_client_secret()` below is therefore a separate function, read
through `infra.secrets` at the moment the exchange needs it
(`core/identity/oidc.py::OIDCIdentityProvider.exchange_authorization_code`)
-- never at import, never cached on a config object, never logged. That
keeps the "no unused secret access" discipline this codebase follows: a
deployment that only validates tokens resolves no secret at all.

`OIDC_ISSUER_URL` / `OIDC_CLIENT_ID` (Phase 2 -- formerly `ZITADEL_ISSUER_URL`
/ `ZITADEL_CLIENT_ID`) are the env var names `.env.example` documents,
read through `infra.secrets` like every other credential
(docs/ADR/0012-secrets-management.md), never `os.environ` directly.
`core/identity` is SaaS-OS's own OIDC relying-party boundary: it reads only
these provider-neutral names. ZITADEL remains the current, self-hosted
implementation behind that boundary, but its own server configuration
(`ZITADEL_MASTERKEY`, `ZITADEL_EXTERNALDOMAIN`, etc.) is deployment
infrastructure (`docker-compose.yml`) -- a different concern this module
never reads.

`IdentityProvider` (below) is the small Protocol the HTTP auth layer
(`api/auth/routes.py`) actually depends on -- exactly the five operations
it calls, nothing about password management, MFA, account linking, user
administration, refresh tokens, provider-side logout, management APIs,
SCIM, provisioning, social login, or authorization (all of that remains
either non-existent or explicitly owned elsewhere: `core/rbac` owns
authorization, `core/identity/sessions.py` owns the platform session).
This is deliberately not a plugin/registry framework -- there is exactly
one configured provider per deployment, selected by which issuer
`OIDC_ISSUER_URL` names, the same as before this phase.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from urllib.error import URLError

from infra.secrets import SecretsProvider, get_secrets_provider

if TYPE_CHECKING:
    # Import-time only (this module is imported by `core/identity/oidc.py`,
    # so a real runtime import here would be circular) -- `from __future__
    # import annotations` above means every annotation is a string at
    # runtime regardless; this makes the name resolvable for pyright.
    from core.identity.oidc import VerifiedIdentity

_DISCOVERY_PATH = "/.well-known/openid-configuration"
_DISCOVERY_TIMEOUT_SECONDS = 5

# Phase 2 (ADR-0023): the provider-neutral names SaaS-OS identity reads.
_ISSUER_VAR = "OIDC_ISSUER_URL"
_CLIENT_ID_VAR = "OIDC_CLIENT_ID"
_CLIENT_SECRET_VAR = "OIDC_CLIENT_SECRET"  # pragma: allowlist secret

# The pre-Phase-2 names -- no longer read for their own values (a hard
# cutover: this repository has no known external deployment yet, so no
# compatibility alias is introduced), but still checked for *presence*
# alongside the new names so a deployment that hasn't finished migrating
# gets a fail-closed configuration error rather than silent, undocumented
# precedence of one namespace over the other.
_LEGACY_ISSUER_VAR = "ZITADEL_ISSUER_URL"
_LEGACY_CLIENT_ID_VAR = "ZITADEL_CLIENT_ID"
_LEGACY_CLIENT_SECRET_VAR = "ZITADEL_CLIENT_SECRET"  # pragma: allowlist secret


class OIDCConfigurationError(ValueError):
    """Raised when OIDC provider configuration is missing or invalid, or
    when the provider's discovery document cannot be fetched/parsed. Never
    includes a secret value (docs/SECURITY.md)."""


@dataclass(frozen=True)
class OIDCProviderConfig:
    """A resolved, standards-shaped OIDC relying-party configuration.
    `audience` defaults to `client_id` (the standard OIDC convention: an ID
    token's `aud` claim is the client the token was issued to)."""

    issuer: str
    client_id: str
    audience: str
    jwks_uri: str


def _discover_jwks_uri(issuer: str) -> str:
    """Fetch `jwks_uri` from the provider's standard OIDC discovery
    document. Not ZITADEL-specific -- any OIDC-compliant provider serves
    this at `{issuer}/.well-known/openid-configuration` (RFC 8414 /
    OpenID Connect Discovery 1.0). `issuer` is trusted deployment
    configuration (`OIDC_ISSUER_URL`), never end-user input, but its
    scheme is still restricted to http(s) as cheap defense in depth against
    a misconfigured value being used to fetch an unintended URL scheme.
    """
    if not issuer.startswith(("https://", "http://")):
        raise OIDCConfigurationError(f"OIDC issuer must be an http(s) URL, got: {issuer!r}")

    url = f"{issuer}{_DISCOVERY_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=_DISCOVERY_TIMEOUT_SECONDS) as response:  # noqa: S310 -- issuer is trusted deployment config, scheme-checked above
            document = json.load(response)
    except (URLError, TimeoutError, OSError) as exc:
        raise OIDCConfigurationError(
            f"Could not fetch OIDC discovery document from {url}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise OIDCConfigurationError(
            f"OIDC discovery document at {url} is not valid JSON: {exc}"
        ) from exc

    jwks_uri = document.get("jwks_uri")
    if not jwks_uri:
        raise OIDCConfigurationError(f"OIDC discovery document at {url} has no 'jwks_uri'")
    return jwks_uri


def _reject_if_both_set(secrets_provider: SecretsProvider, legacy_name: str, new_name: str) -> None:
    """Fail closed (ADR-0023 Phase 2) if both a pre-Phase-2 `ZITADEL_*`
    variable and its `OIDC_*` replacement are set -- never silently prefer
    one namespace over the other. A deployment with only the legacy name
    set already fails on its own, at the `get_required(new_name)` call
    site below: the legacy name is simply never read for its value."""
    if secrets_provider.get(legacy_name) and secrets_provider.get(new_name):
        raise OIDCConfigurationError(
            f"Both {legacy_name!r} and {new_name!r} are set. This is ambiguous -- "
            f"SaaS-OS identity now reads only {new_name!r} (docs/ADR/0023-...); "
            f"remove {legacy_name!r} from your environment."
        )


def _oidc_provider_config_from_env() -> OIDCProviderConfig:
    provider = get_secrets_provider()
    _reject_if_both_set(provider, _LEGACY_ISSUER_VAR, _ISSUER_VAR)
    _reject_if_both_set(provider, _LEGACY_CLIENT_ID_VAR, _CLIENT_ID_VAR)
    issuer = provider.get_required(_ISSUER_VAR).rstrip("/")
    client_id = provider.get_required(_CLIENT_ID_VAR)
    jwks_uri = _discover_jwks_uri(issuer)
    return OIDCProviderConfig(
        issuer=issuer,
        client_id=client_id,
        audience=client_id,
        jwks_uri=jwks_uri,
    )


@lru_cache
def get_oidc_provider_config() -> OIDCProviderConfig:
    """Cached configuration singleton, resolved once (including the
    discovery-document fetch). Tests that need a different configuration
    should call `get_oidc_provider_config.cache_clear()` after
    `monkeypatch.setenv(...)`, mirroring `infra.db.config`."""
    return _oidc_provider_config_from_env()


# --- P2.2: Authorization Code Flow endpoints + client secret -----------------


@dataclass(frozen=True)
class OIDCFlowEndpoints:
    """The two provider endpoints the browser login flow (P2.2) needs
    beyond `OIDCProviderConfig.jwks_uri`: where to send the browser, and
    where the server exchanges the authorization code. Both come from
    the same standard discovery document -- never hard-coded, never
    provider-specific (ADR-0005)."""

    authorization_endpoint: str
    token_endpoint: str


def _fetch_discovery_document(issuer: str) -> dict[str, object]:
    if not issuer.startswith(("https://", "http://")):
        raise OIDCConfigurationError(f"OIDC issuer must be an http(s) URL, got: {issuer!r}")
    url = f"{issuer}{_DISCOVERY_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=_DISCOVERY_TIMEOUT_SECONDS) as response:  # noqa: S310 -- issuer is trusted deployment config, scheme-checked above
            document = json.load(response)
    except (URLError, TimeoutError, OSError) as exc:
        raise OIDCConfigurationError(
            f"Could not fetch OIDC discovery document from {url}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise OIDCConfigurationError(
            f"OIDC discovery document at {url} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise OIDCConfigurationError(f"OIDC discovery document at {url} is not a JSON object")
    return document


def _usable_endpoint(document: dict[str, object], name: str, *, issuer: str) -> str:
    """An endpoint from the discovery document is usable only if it is an
    `https://` URL -- or `http://` when the issuer itself is `http://`
    (a local development provider). A confidential exchange over plain
    HTTP against an HTTPS issuer is a misconfiguration, refused here."""
    value = document.get(name)
    allowed_schemes = ("https://", "http://") if issuer.startswith("http://") else ("https://",)
    if not isinstance(value, str) or not value.startswith(allowed_schemes):
        raise OIDCConfigurationError(f"OIDC discovery document has no usable {name!r}")
    return value


def _discover_flow_endpoints(issuer: str) -> OIDCFlowEndpoints:
    document = _fetch_discovery_document(issuer)
    return OIDCFlowEndpoints(
        authorization_endpoint=_usable_endpoint(document, "authorization_endpoint", issuer=issuer),
        token_endpoint=_usable_endpoint(document, "token_endpoint", issuer=issuer),
    )


@lru_cache
def get_oidc_flow_endpoints() -> OIDCFlowEndpoints:
    """Cached, discovered once, for the issuer `get_oidc_provider_config()`
    resolves. Separate from that function (rather than new fields on
    `OIDCProviderConfig`) so ID-token validation's own configuration and
    tests are unchanged by P2.2."""
    return _discover_flow_endpoints(get_oidc_provider_config().issuer)


def get_oidc_client_secret() -> str | None:
    """The relying-party client secret, read through `infra.secrets` at
    the moment the token exchange needs it (P2.2) -- never at import,
    never cached on a config object, never logged. `None` means the
    client is registered as a *public* client: the exchange then relies
    on PKCE alone (still mandatory, `S256`), which is the OIDC-standard
    posture for a public client and never a downgrade of an otherwise
    confidential one -- a deployment that registers a confidential client
    must configure the secret."""
    provider = get_secrets_provider()
    _reject_if_both_set(provider, _LEGACY_CLIENT_SECRET_VAR, _CLIENT_SECRET_VAR)
    value = provider.get(_CLIENT_SECRET_VAR)
    return value or None


# --- Phase 2 (ADR-0023): the provider-neutral boundary ----------------------


@runtime_checkable
class IdentityProvider(Protocol):
    """Exactly the operations `api/auth/routes.py` needs from an OIDC
    identity provider -- application behavior, not a raw HTTP/JWKS client
    (docs/ADR/0023-...). `@runtime_checkable` so a substitution test can
    assert `isinstance(fake, IdentityProvider)` alongside the real
    adapter, mirroring `core/billing/provider.py::BillingProvider`'s own
    shape and the same "prove the abstraction isn't leaky" discipline.

    Deliberately does not cover: password management, MFA, account
    linking, user administration, refresh tokens, provider-side logout,
    provider management APIs, SCIM, provisioning, social login, or
    authorization -- none of these has a call site in this codebase.
    `core/identity/sessions.py` owns the platform session; `core/rbac`
    owns authorization; neither is reachable through this Protocol.
    """

    def get_config(self) -> OIDCProviderConfig:
        """The resolved provider configuration (issuer, client_id,
        audience, jwks_uri)."""
        ...

    def get_flow_endpoints(self) -> OIDCFlowEndpoints:
        """Where to send the browser, and where to exchange the
        authorization code -- both from the provider's own discovery
        document."""
        ...

    def build_authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
        scopes: tuple[str, ...] = ...,
    ) -> str:
        """The URL to redirect the browser to. Pure/no I/O."""
        ...

    def exchange_authorization_code(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> str:
        """Server-side authorization-code exchange. Returns the raw ID
        token string. The client secret (if any) is resolved internally,
        at the moment of use -- never a parameter here, never cached."""
        ...

    def validate_id_token(
        self, token: str, *, expected_nonce: str | None = None
    ) -> VerifiedIdentity:
        """Verify `token` and return the minimal identity claims. Same
        validation this codebase already performs (issuer/audience/
        expiry/subject/nonce/algorithm-allowlist/signature) -- this
        Protocol does not re-implement or weaken it."""
        ...
