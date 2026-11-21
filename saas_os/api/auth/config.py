"""Non-secret HTTP authentication settings (P2.2). Read directly from the
environment like every other non-secret tunable in this repository
(`saas_os/core/email/config.py`, `saas_os/infra/ratelimit/config.py`); the OIDC client
secret is never here -- `saas_os.core.identity.provider.get_oidc_client_secret()`
reads it through `saas_os.infra.secrets` at the moment of use.

`OIDC_REDIRECT_URI` is the deployment's one allowlisted callback -- the
browser never chooses it (an open-redirect / code-interception defense:
the provider only sends the authorization code to this exact URI, and
the same value is sent again in the token exchange, so a mismatch is
rejected provider-side too). `AUTH_POST_LOGIN_PATH` is a fixed,
same-origin, absolute *path* ("/" by default): a `next=` style
browser-supplied destination is deliberately not supported.

`PUBLIC_APP_ORIGIN` (ADR-0024) is the browser-visible origin the whole
application -- product frontend and this backend -- is served on. When it
is set, the callback is *derived* from it
(`saas_os.infra.edge.resolve_callback_url`: `<origin>/auth/callback`) instead of
being configured twice, which is what makes the single-origin runtime
reusable: a consuming product sets one origin rather than hand-maintaining
a redirect URI, a frontend API base URL and a proxy configuration that must
all agree. `OIDC_REDIRECT_URI` remains supported and unchanged on its own
(a deployment whose callback genuinely is not on the application origin);
setting both to values that disagree is a fail-closed error, never silent
precedence.

`AUTH_POST_LOGIN_PATH` is where the single-origin boundary stops. SaaS-OS
sends the browser to a fixed, same-origin path after login and nothing
more -- what that path renders (an authenticated entry point, a dashboard,
a tenant selector) is the product frontend's decision, and no SaaS-OS
module knows or encodes it.

`OIDC_POST_LOGOUT_REDIRECT_URI` (ADR-0064, optional) is where the identity
provider returns the browser after `POST /auth/logout/redirect` ended its
session. Unset, RP-initiated logout is off. Set, it must be an absolute
URL on the application's own origin (`PUBLIC_APP_ORIGIN`, or the callback's
origin), `https` in production, without credentials or a fragment: it is
configuration, never read from a request, so it cannot become an open
redirect. The provider must have the identical value registered.

`AUTH_COOKIE_SECURE` defaults to true and can only be turned off outside
`ENVIRONMENT=production` -- a production deployment cannot be configured
into sending the session cookie over plain HTTP, so P2.3's TLS work
changes nothing here except that the default becomes reachable.

`TRUST_PROXY_HEADERS` (P2.3, default `false`) governs whether
`saas_os/api/auth/routes.py::_resolve_client_address` reads `X-Forwarded-For` at
all for the pre-login rate limit key -- see that function's own docstring
for the trust model. It is set to `true` only in
`docker-compose.prod.yml`'s `backend` service, never in the development
compose or in this module's own default, so existing dev/test behavior
(`request.client.host`) is unchanged unless a deployment explicitly
declares it sits behind the trusted reverse proxy. The billing events
router (ADR-0048) keys its pre-verification rate limit the same way,
through `trust_proxy_headers_from_env()` and `resolve_client_address()`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

from fastapi import Request

from saas_os.infra.edge import (
    PublicAppOriginError,
    normalize_public_app_origin,
    resolve_callback_url,
)

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
    public_app_origin: str | None = None
    # ADR-0064: where the identity provider sends the browser after it ended
    # its own session. `None` means RP-initiated logout is off: the browser
    # logout route then ends only the SaaS-OS session.
    post_logout_redirect_uri: str | None = None

    def __post_init__(self) -> None:
        # ADR-0024: when a browser-visible origin is declared, the callback
        # must be *on* it. This is the same fail-closed check
        # `_auth_http_config_from_env()` already performs while resolving the
        # two settings -- repeated here so a directly constructed config
        # (tests, a consuming project's own composition root) cannot bypass
        # it either.
        if self.public_app_origin is not None:
            try:
                resolve_callback_url(
                    public_app_origin=self.public_app_origin,
                    redirect_uri=self.redirect_uri,
                    environment=self.environment,
                )
            except PublicAppOriginError as exc:
                raise AuthConfigurationError(str(exc)) from exc
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
        if self.post_logout_redirect_uri is not None:
            self._check_post_logout_redirect_uri(self.post_logout_redirect_uri)

    def _check_post_logout_redirect_uri(self, value: str) -> None:
        """ADR-0064: a fixed, configured URI on this application's own
        origin -- the origin of `PUBLIC_APP_ORIGIN`, or of the callback when
        only `OIDC_REDIRECT_URI` is set. Never browser-supplied, so it cannot
        become an open redirect; and the identity provider only accepts it
        when it is also registered there, character for character."""
        name = "OIDC_POST_LOGOUT_REDIRECT_URI"
        try:
            parts = urlsplit(value)
            parts.port  # noqa: B018 -- raises ValueError for an invalid port
        except ValueError:
            raise AuthConfigurationError(f"{name} must be an absolute http(s) URL.") from None
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise AuthConfigurationError(f"{name} must be an absolute http(s) URL.")
        if parts.scheme == "http" and self.environment == "production":
            raise AuthConfigurationError(f"{name} must use https in production.")
        if parts.username is not None or parts.password is not None or parts.fragment:
            raise AuthConfigurationError(f"{name} must not carry credentials or a fragment.")
        if "\\" in value or any(ord(ch) < 0x21 for ch in value):
            raise AuthConfigurationError(f"{name} must not contain spaces or control characters.")
        if _origin_of(value) != self._application_origin():
            raise AuthConfigurationError(
                f"{name} must be on the application's own origin (PUBLIC_APP_ORIGIN, or the "
                "origin of OIDC_REDIRECT_URI when PUBLIC_APP_ORIGIN is not set)."
            )

    def _application_origin(self) -> str | None:
        if self.public_app_origin is not None:
            return _origin_of(self.public_app_origin)
        return _origin_of(self.redirect_uri)

    @property
    def post_logout_local_path(self) -> str:
        """ADR-0064: where the browser logout route sends the browser itself
        when no provider redirect is made -- the path and query of the
        configured post-logout URI (same origin by the check above), or `/`.
        Always a same-origin path, never an absolute URL."""
        if self.post_logout_redirect_uri is None:
            return "/"
        parts = urlsplit(self.post_logout_redirect_uri)
        path = parts.path or "/"
        return f"{path}?{parts.query}" if parts.query else path

    @property
    def login_transaction_cookie_name(self) -> str:
        return f"{self.cookie_name}_login"

    @property
    def normalized_public_app_origin(self) -> str | None:
        """The canonicalized `PUBLIC_APP_ORIGIN`, or `None` when this
        deployment has not declared one (ADR-0024). Every browser-facing
        destination this package produces is same-origin by construction --
        this exists for diagnostics and for a consuming project's own
        composition root, never to build a redirect out of a request."""
        if self.public_app_origin is None:
            return None
        return normalize_public_app_origin(self.public_app_origin, environment=self.environment)


def _origin_of(value: str) -> str | None:
    """`scheme://host[:port]`, lower-cased, default port dropped; `None` if
    `value` has no http(s) scheme and host."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    default_port = 443 if parts.scheme == "https" else 80
    host = parts.hostname.lower()
    if port is None or port == default_port:
        return f"{parts.scheme}://{host}"
    return f"{parts.scheme}://{host}:{port}"


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise AuthConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


_FORWARDED_FOR_HEADER = "X-Forwarded-For"


def trust_proxy_headers_from_env() -> bool:
    """`TRUST_PROXY_HEADERS` (default `false`), on its own: a route outside
    the login flow needs it without the rest of the auth configuration."""
    raw = os.environ.get("TRUST_PROXY_HEADERS")
    return _parse_bool("TRUST_PROXY_HEADERS", raw) if raw is not None else False


def resolve_client_address(request: Request, *, trust_proxy_headers: bool) -> str:
    """The address a pre-authentication rate limit is keyed by: the direct
    peer, or -- only when `trust_proxy_headers` -- the last `X-Forwarded-For`
    hop, the one entry the trusted proxy appended and a client cannot
    forge. The trust model is `saas_os/api/auth/routes.py::_resolve_client_address`'s
    docstring."""
    direct_peer = request.client.host if request.client is not None else "unknown"
    if not trust_proxy_headers:
        return direct_peer
    forwarded = request.headers.get(_FORWARDED_FOR_HEADER)
    if not forwarded:
        return direct_peer
    last_hop = forwarded.rsplit(",", 1)[-1].strip()
    return last_hop or direct_peer


def _auth_http_config_from_env() -> AuthHttpConfig:
    environment = os.environ.get("ENVIRONMENT", "development")
    public_app_origin = os.environ.get("PUBLIC_APP_ORIGIN") or None
    try:
        redirect_uri = resolve_callback_url(
            public_app_origin=public_app_origin,
            redirect_uri=os.environ.get("OIDC_REDIRECT_URI"),
            environment=environment,
        )
    except PublicAppOriginError as exc:
        raise AuthConfigurationError(str(exc)) from exc
    if not redirect_uri:
        raise AuthConfigurationError(
            "Neither PUBLIC_APP_ORIGIN nor OIDC_REDIRECT_URI is set. Copy .env.example to "
            ".env and set PUBLIC_APP_ORIGIN to the browser-visible application origin -- the "
            "callback is derived from it (docs/ADR/0024-single-origin-application-runtime.md). "
            "Set OIDC_REDIRECT_URI instead only for a callback that is not on that origin "
            "(see docs/ADR/0005-identity-build-vs-buy.md)."
        )
    secure_raw = os.environ.get("AUTH_COOKIE_SECURE")
    return AuthHttpConfig(
        redirect_uri=redirect_uri,
        cookie_name=os.environ.get("AUTH_COOKIE_NAME", _DEFAULT_COOKIE_NAME),
        cookie_secure=(
            _parse_bool("AUTH_COOKIE_SECURE", secure_raw) if secure_raw is not None else True
        ),
        post_login_path=os.environ.get("AUTH_POST_LOGIN_PATH", _DEFAULT_POST_LOGIN_PATH),
        environment=environment,
        trust_proxy_headers=trust_proxy_headers_from_env(),
        public_app_origin=public_app_origin,
        post_logout_redirect_uri=os.environ.get("OIDC_POST_LOGOUT_REDIRECT_URI") or None,
    )


@lru_cache
def get_auth_http_config() -> AuthHttpConfig:
    """Process-wide cached singleton. Tests call
    `get_auth_http_config.cache_clear()` after `monkeypatch.setenv(...)`."""
    return _auth_http_config_from_env()
