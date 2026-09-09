"""Non-secret HTTP authentication settings (P2.2). Read directly from the
environment like every other non-secret tunable in this repository
(`core/email/config.py`, `infra/ratelimit/config.py`); the OIDC client
secret is never here -- `core.identity.provider.get_oidc_client_secret()`
reads it through `infra.secrets` at the moment of use.

`OIDC_REDIRECT_URI` is the deployment's one allowlisted callback -- the
browser never chooses it (an open-redirect / code-interception defense:
the provider only sends the authorization code to this exact URI, and
the same value is sent again in the token exchange, so a mismatch is
rejected provider-side too). `AUTH_POST_LOGIN_PATH` is a fixed,
same-origin, absolute *path* ("/" by default): a `next=` style
browser-supplied destination is deliberately not supported.

`AUTH_COOKIE_SECURE` defaults to true and can only be turned off outside
`ENVIRONMENT=production` -- a production deployment cannot be configured
into sending the session cookie over plain HTTP, so P2.3's TLS work
changes nothing here except that the default becomes reachable.

`TRUST_PROXY_HEADERS` (P2.3, default `false`) governs whether
`api/auth/routes.py::_resolve_client_address` reads `X-Forwarded-For` at
all for the pre-login rate limit key -- see that function's own docstring
for the trust model. It is set to `true` only in
`docker-compose.prod.yml`'s `backend` service, never in the development
compose or in this module's own default, so existing dev/test behavior
(`request.client.host`) is unchanged unless a deployment explicitly
declares it sits behind the trusted reverse proxy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

_DEFAULT_COOKIE_NAME = "saas_os_session"
_DEFAULT_POST_LOGIN_PATH = "/"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class AuthConfigurationError(ValueError):
    """Raised for a missing/invalid non-secret auth setting. Never
    includes a secret -- none of these fields is one."""


@dataclass(frozen=True)
class AuthHttpConfig:
    redirect_uri: str
    cookie_name: str = _DEFAULT_COOKIE_NAME
    cookie_secure: bool = True
    post_login_path: str = _DEFAULT_POST_LOGIN_PATH
    environment: str = "development"
    trust_proxy_headers: bool = False

    def __post_init__(self) -> None:
        parts = urlsplit(self.redirect_uri)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            raise AuthConfigurationError("OIDC_REDIRECT_URI must be an absolute http(s) URL.")
        if parts.scheme == "http" and self.environment == "production":
            raise AuthConfigurationError("OIDC_REDIRECT_URI must use https in production.")
        if not self.cookie_name or not self.cookie_name.isidentifier():
            raise AuthConfigurationError(
                "AUTH_COOKIE_NAME must be a non-empty identifier-like cookie name."
            )
        if not self.cookie_secure and self.environment == "production":
            raise AuthConfigurationError("AUTH_COOKIE_SECURE cannot be disabled in production.")
        if (
            not self.post_login_path.startswith("/")
            or self.post_login_path.startswith("//")
            or "\\" in self.post_login_path
            or ":" in self.post_login_path.split("?", 1)[0]
        ):
            raise AuthConfigurationError(
                "AUTH_POST_LOGIN_PATH must be a same-origin absolute path (e.g. '/app')."
            )

    @property
    def login_transaction_cookie_name(self) -> str:
        return f"{self.cookie_name}_login"


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise AuthConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


def _auth_http_config_from_env() -> AuthHttpConfig:
    redirect_uri = os.environ.get("OIDC_REDIRECT_URI")
    if not redirect_uri:
        raise AuthConfigurationError(
            "OIDC_REDIRECT_URI is not set. Copy .env.example to .env and set the deployment's "
            "callback URL (see docs/ADR/0005-identity-build-vs-buy.md)."
        )
    secure_raw = os.environ.get("AUTH_COOKIE_SECURE")
    trust_proxy_raw = os.environ.get("TRUST_PROXY_HEADERS")
    return AuthHttpConfig(
        redirect_uri=redirect_uri,
        cookie_name=os.environ.get("AUTH_COOKIE_NAME", _DEFAULT_COOKIE_NAME),
        cookie_secure=(
            _parse_bool("AUTH_COOKIE_SECURE", secure_raw) if secure_raw is not None else True
        ),
        post_login_path=os.environ.get("AUTH_POST_LOGIN_PATH", _DEFAULT_POST_LOGIN_PATH),
        environment=os.environ.get("ENVIRONMENT", "development"),
        trust_proxy_headers=(
            _parse_bool("TRUST_PROXY_HEADERS", trust_proxy_raw)
            if trust_proxy_raw is not None
            else False
        ),
    )


@lru_cache
def get_auth_http_config() -> AuthHttpConfig:
    """Process-wide cached singleton. Tests call
    `get_auth_http_config.cache_clear()` after `monkeypatch.setenv(...)`."""
    return _auth_http_config_from_env()
