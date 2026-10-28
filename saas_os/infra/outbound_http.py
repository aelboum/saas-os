"""Outbound HTTP clients whose routing and trust come only from explicit
configuration (owner decision on ledger row 965, 2026-10-28; ADR-0054 Q2).

Two library defaults let a process's environment change where a request
goes and which certificates it accepts, without anything in SaaS-OS
configuration saying so:

- httpx's `trust_env=True` reads `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
  `NO_PROXY`, `SSL_CERT_FILE`, `SSL_CERT_DIR` and `.netrc`;
- `urllib.request`'s default opener reads the same proxy variables, follows
  redirects (including `https://` to `http://`), and its default TLS context
  loads OpenSSL's default verify paths, which `SSL_CERT_FILE` and
  `SSL_CERT_DIR` override.

The clients built here ignore all of that. They:

- trust certifi's CA bundle, or exactly the one PEM file a caller names
  (`ca_bundle`), never the environment's; certificate and hostname
  verification are always on;
- connect directly, or through exactly the one `http://<host>:<port>`
  forward proxy a caller names (`proxy_url`); `https://` targets go through
  it as a `CONNECT` tunnel, with TLS verified against the target's name;
- never follow a redirect.

Error messages never repeat a configured value: a proxy URL can carry a
host layout an operator does not want in logs, and the bundle path is
deployment detail.
"""

from __future__ import annotations

import ssl
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import IO, Any
from urllib.error import HTTPError
from urllib.parse import urlsplit

import certifi
import httpx


class OutboundHTTPConfigurationError(ValueError):
    """An explicit proxy or CA setting is unusable. The message names the
    problem, never the value."""


@dataclass(frozen=True)
class OutboundHTTPSettings:
    """`ca_bundle`: path to a PEM file that replaces certifi's bundle (it is
    not added to it). `proxy_url`: `http://<host>:<port>` of a forward proxy.
    `None` means certifi and a direct connection."""

    ca_bundle: str | None = None
    proxy_url: str | None = None


def parse_proxy_url(value: str, *, setting: str) -> str:
    """`http://<host>:<port>` and nothing else: no credentials, path, query
    or fragment (the same shape as `EGRESS_PROXY_URL`,
    `saas_os/infra/egress/proxy.py`). Returns the normalised URL."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        parts, port = None, None
    if (
        parts is None
        or parts.scheme != "http"
        or not parts.hostname
        or port is None
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise OutboundHTTPConfigurationError(f"{setting} must be http://<host>:<port>")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"http://{host}:{port}"


def settings_from_values(
    *, ca_bundle: str | None, proxy_url: str | None, ca_setting: str, proxy_setting: str
) -> OutboundHTTPSettings:
    """Validate raw configuration values (empty means unset). `ca_setting` and
    `proxy_setting` are the names used in error messages."""
    bundle = (ca_bundle or "").strip() or None
    if bundle is not None and not Path(bundle).is_file():
        raise OutboundHTTPConfigurationError(f"{ca_setting} does not name a readable file")
    proxy = (proxy_url or "").strip() or None
    if proxy is not None:
        proxy = parse_proxy_url(proxy, setting=proxy_setting)
    settings = OutboundHTTPSettings(ca_bundle=bundle, proxy_url=proxy)
    # Load the bundle now, so a file that is not PEM certificates fails at
    # configuration rather than at the first request.
    try:
        ssl_context(settings.ca_bundle)
    except (ssl.SSLError, OSError) as exc:
        raise OutboundHTTPConfigurationError(f"{ca_setting} is not a PEM CA bundle") from exc
    return settings


@lru_cache(maxsize=8)
def ssl_context(ca_bundle: str | None) -> ssl.SSLContext:
    """A verifying client context over exactly one trust store. With
    `cafile`, `create_default_context` loads only that file, never OpenSSL's
    default verify paths, so `SSL_CERT_FILE`/`SSL_CERT_DIR` play no part."""
    return ssl.create_default_context(cafile=ca_bundle or certifi.where())


def httpx_client(settings: OutboundHTTPSettings, **kwargs: Any) -> httpx.Client:
    """An `httpx.Client` that reads nothing from the environment and does not
    follow redirects. `kwargs` are passed through (`timeout`, `base_url`,
    `headers`, and `transport` for tests)."""
    return httpx.Client(
        verify=ssl_context(settings.ca_bundle),
        proxy=settings.proxy_url,
        trust_env=False,
        follow_redirects=False,
        **kwargs,
    )


class RedirectRefusedError(HTTPError):
    """A `3xx` answer that `urllib` would otherwise have followed."""


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise RedirectRefusedError(req.full_url, code, "redirect refused", headers, fp)


class _ExplicitProxyHandler(urllib.request.ProxyHandler):
    """`ProxyHandler` without its `NO_PROXY` check: the base class asks
    `urllib.request.proxy_bypass`, which reads the environment, and would
    connect directly to a host listed there."""

    def proxy_open(self, req: urllib.request.Request, proxy: str, type: str) -> None:  # noqa: A002 -- the base class's parameter name
        req.set_proxy(urlsplit(proxy).netloc, "http")


def urllib_opener(settings: OutboundHTTPSettings) -> urllib.request.OpenerDirector:
    """An opener whose proxy table is exactly `settings.proxy_url` (an
    explicit `ProxyHandler` replaces the one `build_opener` would build from
    the environment), whose TLS context is `ssl_context()`, and which raises
    `RedirectRefusedError` instead of following a redirect."""
    proxies = (
        {"http": settings.proxy_url, "https": settings.proxy_url} if settings.proxy_url else {}
    )
    return urllib.request.build_opener(
        _ExplicitProxyHandler(proxies),
        urllib.request.HTTPSHandler(context=ssl_context(settings.ca_bundle)),
        _RefuseRedirects(),
    )
