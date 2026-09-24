"""`PUBLIC_APP_ORIGIN` -- the one browser-visible origin a SaaS-OS
application is served on, and the single derivation of the OIDC callback
URL from it (ADR-0024).

Two distinct kinds of address exist in a Compose-composed application and
conflating them is the defect this module prevents:

    browser / public origin   http://localhost:8080  (PUBLIC_APP_ORIGIN)
            !=
    internal service origin   http://backend:8000    (Compose service DNS)

Only the first may ever appear in a redirect URI, a cookie domain, or a
link handed to a browser. `PUBLIC_APP_ORIGIN` is therefore an *origin*
and nothing else: scheme + host + optional port, with no path, no query,
no fragment, and no credentials -- anything else is rejected at
configuration time rather than silently producing a callback URL the
provider will refuse (or, worse, accept against the wrong host).

The derivation is fixed, never configurable:

    OIDC redirect URI = PUBLIC_APP_ORIGIN + "/auth/callback"

`/auth/callback` is `api/auth/routes.py`'s own route, mounted by
`api.platform.build_platform_app()` for every consumer; making the path
configurable would let a deployment register a callback the application
does not actually serve. The browser never supplies any part of it --
there is no `next=`/`redirect_uri` request parameter anywhere in this
repository, and this module does not introduce one.

`OIDC_REDIRECT_URI` (the pre-existing, explicit setting) keeps working
unchanged and stays the escape hatch for a deployment whose callback is
genuinely not on the public application origin. Setting *both* it and
`PUBLIC_APP_ORIGIN` to values that disagree is a fail-closed configuration
error -- never silent precedence either way, the same posture
`core/identity/provider.py::_reject_if_both_set` already takes for the
`OIDC_*`/`ZITADEL_*` name cutover.
"""

from __future__ import annotations

from urllib.parse import urlsplit

AUTH_CALLBACK_PATH = "/auth/callback"
"""`api/auth/routes.py`'s callback route, as mounted by
`api.platform.build_platform_app()`. Fixed, not configurable."""


class PublicAppOriginError(ValueError):
    """Raised for an invalid/inconsistent public-origin configuration.
    Carries only non-secret configuration values (an origin and a callback
    URL); never a token, code, or client secret."""


def _netloc(host: str, port: int | None) -> str:
    """Rebuild `host[:port]` from `urlsplit`'s decomposed parts.

    `urlsplit(...).hostname` strips the brackets an IPv6 literal is written
    with, so `http://[::1]:8080` decomposes to host `::1` -- reassembling
    that unbracketed would produce the malformed `http://::1:8080`. Only an
    IPv6 literal can contain a colon; hostnames and IPv4 addresses are
    reassembled exactly as before.
    """
    literal = f"[{host}]" if ":" in host else host
    return literal if port is None else f"{literal}:{port}"


def normalize_public_app_origin(value: str | None, *, environment: str = "development") -> str:
    """Validate a browser-visible origin and return it canonicalized
    (lowercased scheme/host, port preserved, no trailing slash).

    `environment="production"` additionally refuses a plaintext `http://`
    origin -- the same rule `api/auth/config.py` already enforces for
    `OIDC_REDIRECT_URI` and `AUTH_COOKIE_SECURE`, applied one level up so a
    production deployment cannot derive an `http://` callback at all.
    """
    raw = (value or "").strip()
    if not raw:
        raise PublicAppOriginError(
            "PUBLIC_APP_ORIGIN must not be empty -- set the browser-visible origin, "
            "e.g. https://app.example.com (production) or http://localhost:8080 (local)."
        )
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:  # urlsplit raises on a non-numeric/out-of-range port
        raise PublicAppOriginError(f"PUBLIC_APP_ORIGIN has an invalid port: {raw!r}") from exc
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise PublicAppOriginError(
            f"PUBLIC_APP_ORIGIN must be an absolute http(s) origin, got: {raw!r}"
        )
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise PublicAppOriginError(
            "PUBLIC_APP_ORIGIN must be an origin only -- no path, query string, or fragment "
            f"(got: {raw!r}). The application is always served at the root of this origin."
        )
    if "@" in parts.netloc:
        raise PublicAppOriginError("PUBLIC_APP_ORIGIN must not embed credentials.")
    if parts.scheme.lower() == "http" and environment == "production":
        raise PublicAppOriginError("PUBLIC_APP_ORIGIN must use https in production.")
    return f"{parts.scheme.lower()}://{_netloc(host, port)}"


def callback_url_for(value: str | None, *, environment: str = "development") -> str:
    """`PUBLIC_APP_ORIGIN` -> the deployment's one OIDC redirect URI."""
    return normalize_public_app_origin(value, environment=environment) + AUTH_CALLBACK_PATH


def _canonical_url(value: str) -> str:
    """Scheme/host-case- and trailing-slash-insensitive form, for comparing
    a configured `OIDC_REDIRECT_URI` against the derived one. Deliberately
    not a general URL normalizer -- it exists only for that equality check."""
    try:
        parts = urlsplit(value.strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError as exc:  # non-numeric/out-of-range port, e.g. ":notaport"
        # Only the explicitly configured `OIDC_REDIRECT_URI` reaches here
        # unvalidated; the derived URL this is compared against has already
        # been through `normalize_public_app_origin`.
        raise PublicAppOriginError(f"OIDC_REDIRECT_URI has an invalid port: {value!r}") from exc
    path = parts.path.rstrip("/") or "/"
    return f"{parts.scheme.lower()}://{_netloc(host, port)}{path}"


def resolve_callback_url(
    *,
    public_app_origin: str | None,
    redirect_uri: str | None,
    environment: str = "development",
) -> str | None:
    """Resolve the deployment's OIDC callback URL from the two settings.

    - only `OIDC_REDIRECT_URI`   -> that value, unchanged (pre-ADR-0024 behavior)
    - only `PUBLIC_APP_ORIGIN`   -> derived, `<origin>/auth/callback`
    - both, agreeing             -> the explicit value, unchanged
    - both, disagreeing          -> `PublicAppOriginError` (fail closed)
    - neither                    -> `None`; the caller reports its own
      "not configured" error, since what is required differs per caller
    """
    explicit = (redirect_uri or "").strip() or None
    origin = (public_app_origin or "").strip() or None
    if origin is None:
        return explicit
    derived = callback_url_for(origin, environment=environment)
    if explicit is None:
        return derived
    if _canonical_url(explicit) != _canonical_url(derived):
        raise PublicAppOriginError(
            "OIDC_REDIRECT_URI and PUBLIC_APP_ORIGIN disagree: PUBLIC_APP_ORIGIN implies "
            f"{derived!r} but OIDC_REDIRECT_URI is {explicit!r}. Unset one of them -- a "
            "callback on a different origin than the application is never resolved silently."
        )
    return explicit
