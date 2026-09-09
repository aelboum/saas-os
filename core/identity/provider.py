"""OIDC provider configuration (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2;
docs/ADR/0005-identity-build-vs-buy.md).

Provider-agnostic on purpose: nothing on `OIDCProviderConfig` is
ZITADEL-specific (ADR-0005's "Future Migration/Extension Path" -- a swap to
a different OIDC-compliant IdP must be a configuration change inside
`core/identity`, not a platform-wide rewrite). The JWKS location is
resolved via standard OIDC Discovery (`{issuer}/.well-known/openid-configuration`,
an RFC-defined document every conformant provider serves, ZITADEL included)
rather than a guessed, vendor-specific path -- discovery uses the stdlib
`urllib`, so no new HTTP-client dependency is introduced for it.

`client_secret` is deliberately NOT read here: Phase 3.2 implements ID
token *validation* only (the relying-party side of an already-completed
OIDC flow), not the authorization-code exchange that would need it -- that
belongs to the HTTP/API integration layer (Phase 8, out of this phase's
scope). Reading a secret this phase never uses would violate the "no
unused secret access" discipline this codebase otherwise follows.

`ZITADEL_ISSUER_URL` / `ZITADEL_CLIENT_ID` are the env var names
`.env.example` already documents (Phase 1.1) -- read through
`infra.secrets` like every other credential (docs/ADR/0012-secrets-management.md),
never `os.environ` directly.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from urllib.error import URLError

from infra.secrets import get_secrets_provider

_DISCOVERY_PATH = "/.well-known/openid-configuration"
_DISCOVERY_TIMEOUT_SECONDS = 5


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
    configuration (`ZITADEL_ISSUER_URL`), never end-user input, but its
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


def _oidc_provider_config_from_env() -> OIDCProviderConfig:
    provider = get_secrets_provider()
    issuer = provider.get_required("ZITADEL_ISSUER_URL").rstrip("/")
    client_id = provider.get_required("ZITADEL_CLIENT_ID")
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
    value = get_secrets_provider().get("ZITADEL_CLIENT_SECRET")
    return value or None
