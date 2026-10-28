"""Routing and trust of every call SaaS-OS makes to the OIDC provider --
discovery, JWKS and the token exchange (owner decision on ledger row 965,
2026-10-28; `saas_os/infra/outbound_http.py`).

Real sockets, all on 127.0.0.1: a local HTTPS provider whose certificate a
throwaway CA signed, a local `CONNECT` proxy, and a listener standing in for
an environment proxy, which records anything that connects to it.

- `HTTPS_PROXY` and friends, `NO_PROXY`, `SSL_CERT_FILE` and `SSL_CERT_DIR`
  alone change neither where a call goes nor which certificate it accepts;
- `OIDC_CA_BUNDLE` and `OIDC_PROXY_URL` do, and verification stays on;
- no call follows a redirect, including `https://` to `http://`.
"""

from __future__ import annotations

import json
import ssl
from collections.abc import Iterator
from pathlib import Path

import pytest
from jwt.exceptions import PyJWKClientError

import saas_os.core.identity.oidc as oidc_module
import saas_os.core.identity.provider as provider_module
from saas_os.core.identity.errors import OIDCExchangeError
from saas_os.core.identity.provider import (
    OIDCConfigurationError,
    OIDCFlowEndpoints,
    OIDCProviderConfig,
    get_oidc_http_settings,
)
from saas_os.infra.outbound_http import ssl_context
from tests.support.outbound_http_support import (
    ENVIRONMENT_PROXY_VARIABLES,
    LocalHTTPServer,
    LocalProxy,
    LocalTLS,
    Route,
    local_tls,
    proxy,
    serve,
)

_DISCOVERY = "/.well-known/openid-configuration"
_CREDENTIALED_PROXY = "http://user:SECRET-PW@proxy.internal:3128"  # pragma: allowlist secret
_JWKS = {
    "keys": [
        {
            "kty": "EC",
            "crv": "P-256",
            "kid": "k1",
            "use": "sig",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",  # pragma: allowlist secret
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",  # pragma: allowlist secret
        }
    ]
}


class _FakeSecretsProvider:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)

    def get_required(self, name: str) -> str:
        value = self.get(name)
        if not value:
            raise LookupError(name)
        return value


@pytest.fixture(autouse=True)
def _fresh() -> Iterator[None]:
    caches = (get_oidc_http_settings, oidc_module._jwk_client, ssl_context)  # pyright: ignore[reportPrivateUsage]
    for cache in caches:
        cache.cache_clear()
    yield
    for cache in caches:
        cache.cache_clear()


@pytest.fixture
def tls(tmp_path: Path) -> LocalTLS:
    return local_tls(tmp_path / "provider")


@pytest.fixture
def environment_proxy(monkeypatch: pytest.MonkeyPatch) -> Iterator[LocalProxy]:
    """Every proxy variable names a listener that records connections."""
    with proxy(LocalProxy(relay=False)) as recorder:
        for name in ENVIRONMENT_PROXY_VARIABLES:
            monkeypatch.setenv(name, recorder.url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        yield recorder


def _configure(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    monkeypatch.setattr(
        provider_module, "get_secrets_provider", lambda: _FakeSecretsProvider(values)
    )
    get_oidc_http_settings.cache_clear()


def _provider(tls: LocalTLS, extra: dict[str, Route] | None = None) -> LocalHTTPServer:
    return LocalHTTPServer(routes=dict(extra or {}), ssl_context=tls.server_context)


def _discovery_route(issuer: str) -> Route:
    return Route(200, json.dumps({"issuer": issuer, "jwks_uri": f"{issuer}/keys"}).encode())


def _discover(issuer: str) -> str:
    return provider_module._discover_jwks_uri(issuer)  # pyright: ignore[reportPrivateUsage]


# --- the environment alone changes nothing --------------------------------------


def test_the_environment_trust_store_is_not_used(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS, environment_proxy: LocalProxy
) -> None:
    """`SSL_CERT_FILE`/`SSL_CERT_DIR` name the provider's CA, which a
    default `urllib` context would load; without `OIDC_CA_BUNDLE` the
    certificate is refused, and the environment proxy is never contacted."""
    monkeypatch.setenv("SSL_CERT_FILE", str(tls.ca_file))
    monkeypatch.setenv("SSL_CERT_DIR", str(tls.ca_file.parent))
    _configure(monkeypatch)
    with serve(_provider(tls)) as server:
        server.routes[_DISCOVERY] = _discovery_route(server.origin)
        with pytest.raises(OIDCConfigurationError, match="Could not fetch"):
            _discover(server.origin)
    assert server.requests == []
    assert environment_proxy.connections == 0


def test_an_explicit_ca_bundle_connects_directly_whatever_the_proxy_variables_say(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS, environment_proxy: LocalProxy
) -> None:
    _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file))
    with serve(_provider(tls)) as server:
        server.routes[_DISCOVERY] = _discovery_route(server.origin)
        jwks_uri = _discover(server.origin)
    assert jwks_uri == f"{server.origin}/keys"
    assert server.requests == [_DISCOVERY]
    assert environment_proxy.connections == 0


def test_the_trust_store_is_verifying() -> None:
    context = ssl_context(None)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


# --- explicit configuration ------------------------------------------------------


def test_an_explicit_proxy_tunnels_and_tls_is_verified_on_the_provider_name(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS, environment_proxy: LocalProxy
) -> None:
    """`NO_PROXY=localhost` would make `urllib`'s own proxy handler connect
    directly; the explicit proxy is used anyway."""
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    monkeypatch.setenv("no_proxy", "localhost,127.0.0.1")
    with serve(_provider(tls)) as server, proxy(LocalProxy()) as explicit:
        server.routes[_DISCOVERY] = _discovery_route(server.origin)
        _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file), OIDC_PROXY_URL=explicit.url)
        _discover(server.origin)
    assert [head.split(b"\r\n")[0] for head in explicit.heads] == [
        f"CONNECT localhost:{server.port} HTTP/1.1".encode()
    ]
    assert server.requests == [_DISCOVERY]
    assert environment_proxy.connections == 0


def test_a_bundle_that_did_not_sign_the_provider_is_refused(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS, tmp_path: Path
) -> None:
    other = local_tls(tmp_path / "other")
    _configure(monkeypatch, OIDC_CA_BUNDLE=str(other.ca_file))
    with serve(_provider(tls)) as server:
        server.routes[_DISCOVERY] = _discovery_route(server.origin)
        with pytest.raises(OIDCConfigurationError, match="Could not fetch"):
            _discover(server.origin)
    assert server.requests == []


@pytest.mark.parametrize(
    ("values", "setting"),
    [
        ({"OIDC_PROXY_URL": "https://proxy.internal:3128"}, "OIDC_PROXY_URL"),
        ({"OIDC_PROXY_URL": _CREDENTIALED_PROXY}, "OIDC_PROXY_URL"),
        ({"OIDC_PROXY_URL": "http://proxy.internal"}, "OIDC_PROXY_URL"),
        ({"OIDC_PROXY_URL": "http://proxy.internal:3128/path"}, "OIDC_PROXY_URL"),
        ({"OIDC_CA_BUNDLE": "/nonexistent/SECRET-PATH.pem"}, "OIDC_CA_BUNDLE"),
    ],
)
def test_an_unusable_setting_fails_closed_without_repeating_the_value(
    monkeypatch: pytest.MonkeyPatch, values: dict[str, str], setting: str
) -> None:
    _configure(monkeypatch, **values)
    with pytest.raises(OIDCConfigurationError, match=setting) as excinfo:
        get_oidc_http_settings()
    assert "SECRET" not in str(excinfo.value)
    assert "proxy.internal" not in str(excinfo.value)


def test_a_bundle_that_is_not_pem_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    garbage = tmp_path / "not-a-bundle.pem"
    garbage.write_text("not a certificate\n", encoding="ascii")
    _configure(monkeypatch, OIDC_CA_BUNDLE=str(garbage))
    with pytest.raises(OIDCConfigurationError, match="OIDC_CA_BUNDLE is not a PEM CA bundle"):
        get_oidc_http_settings()


# --- redirects ---------------------------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_discovery_refuses_a_redirect_even_to_https_on_the_same_host(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS, status: int
) -> None:
    _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file))
    with serve(_provider(tls)) as server:
        server.routes[_DISCOVERY] = Route(status, headers=(("Location", "/elsewhere"),))
        server.routes["/elsewhere"] = _discovery_route(server.origin)
        with pytest.raises(OIDCConfigurationError, match="redirect"):
            _discover(server.origin)
    assert server.requests == [_DISCOVERY]


def test_discovery_refuses_a_downgrade_to_plain_http(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS
) -> None:
    """The attack: an `https://` issuer redirects discovery to `http://`,
    where anyone on the path can serve their own `jwks_uri`."""
    _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file))
    with serve(LocalHTTPServer(routes={})) as plain, serve(_provider(tls)) as server:
        plain.routes[_DISCOVERY] = _discovery_route(server.origin)
        server.routes[_DISCOVERY] = Route(
            302, headers=(("Location", f"{plain.origin}{_DISCOVERY}"),)
        )
        with pytest.raises(OIDCConfigurationError, match="redirect") as excinfo:
            _discover(server.origin)
    assert plain.requests == []
    assert plain.origin not in str(excinfo.value)


def test_discovery_still_requires_the_issuer_and_an_https_jwks_uri(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS
) -> None:
    """End to end through the real client (#135's checks, unchanged)."""
    _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file))
    with serve(_provider(tls)) as server:
        server.routes[_DISCOVERY] = Route(
            200, json.dumps({"issuer": "https://other.test", "jwks_uri": "x"}).encode()
        )
        with pytest.raises(OIDCConfigurationError, match="does not name the configured issuer"):
            _discover(server.origin)
        server.routes[_DISCOVERY] = Route(
            200,
            json.dumps(
                {"issuer": server.origin, "jwks_uri": f"http://localhost:{server.port}/keys"}
            ).encode(),
        )
        with pytest.raises(OIDCConfigurationError, match="no usable 'jwks_uri'"):
            _discover(server.origin)


# --- JWKS ---------------------------------------------------------------------------


def test_jwks_uses_the_explicit_trust_ignores_the_environment_and_caches(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS, environment_proxy: LocalProxy
) -> None:
    _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file))
    with serve(_provider(tls, {"/keys": Route(200, json.dumps(_JWKS).encode())})) as server:
        client = oidc_module._jwk_client(f"{server.origin}/keys")  # pyright: ignore[reportPrivateUsage]
        assert client.get_signing_key("k1").key_id == "k1"
        assert client.get_signing_key("k1").key_id == "k1"
        # An unknown `kid` refreshes once, then the library's cooldown holds.
        for _ in range(3):
            with pytest.raises(PyJWKClientError):
                client.get_signing_key("unknown")
    assert server.requests == ["/keys", "/keys"]
    assert environment_proxy.connections == 0


def test_jwks_without_the_bundle_refuses_the_certificate(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(tls.ca_file))
    _configure(monkeypatch)
    with serve(_provider(tls, {"/keys": Route(200, json.dumps(_JWKS).encode())})) as server:
        client = oidc_module._jwk_client(f"{server.origin}/keys")  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(PyJWKClientError):
            client.get_signing_key("k1")
    assert server.requests == []


def test_jwks_refuses_a_downgrade_redirect(monkeypatch: pytest.MonkeyPatch, tls: LocalTLS) -> None:
    _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file))
    keys = {"/keys": Route(200, json.dumps(_JWKS).encode())}
    with serve(LocalHTTPServer(routes=keys)) as plain, serve(_provider(tls)) as server:
        server.routes["/keys"] = Route(302, headers=(("Location", f"{plain.origin}/keys"),))
        client = oidc_module._jwk_client(f"{server.origin}/keys")  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(PyJWKClientError) as excinfo:
            client.get_signing_key("k1")
    assert plain.requests == []
    assert plain.origin not in str(excinfo.value)


def test_jwks_goes_through_the_explicit_proxy(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS
) -> None:
    keys = {"/keys": Route(200, json.dumps(_JWKS).encode())}
    with serve(_provider(tls, keys)) as server, proxy(LocalProxy()) as explicit:
        _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file), OIDC_PROXY_URL=explicit.url)
        client = oidc_module._jwk_client(f"{server.origin}/keys")  # pyright: ignore[reportPrivateUsage]
        assert client.get_signing_key("k1").key_id == "k1"
    assert len(explicit.heads) == 1
    assert explicit.heads[0].startswith(f"CONNECT localhost:{server.port} ".encode())


# --- token exchange --------------------------------------------------------------


def _exchange(origin: str) -> str:
    return oidc_module.exchange_authorization_code(
        OIDCProviderConfig(issuer=origin, client_id="c", audience="c", jwks_uri=f"{origin}/keys"),
        OIDCFlowEndpoints(
            authorization_endpoint=f"{origin}/authorize", token_endpoint=f"{origin}/token"
        ),
        code="code",
        code_verifier="verifier",
        redirect_uri="https://app.test/callback",
        client_secret=None,
    )


def test_the_token_exchange_ignores_the_environment(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS, environment_proxy: LocalProxy
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(tls.ca_file))
    token = Route(200, json.dumps({"id_token": "signed.id.token"}).encode())
    with serve(_provider(tls, {"/token": token})) as server:
        _configure(monkeypatch)
        with pytest.raises(OIDCExchangeError):
            _exchange(server.origin)
        assert server.requests == []
        _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file))
        assert _exchange(server.origin) == "signed.id.token"
    assert server.requests == ["/token"]
    assert environment_proxy.connections == 0


def test_the_token_exchange_goes_through_the_explicit_proxy(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS
) -> None:
    token = Route(200, json.dumps({"id_token": "signed.id.token"}).encode())
    with serve(_provider(tls, {"/token": token})) as server, proxy(LocalProxy()) as explicit:
        _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file), OIDC_PROXY_URL=explicit.url)
        assert _exchange(server.origin) == "signed.id.token"
    assert explicit.heads[0].startswith(f"CONNECT localhost:{server.port} ".encode())


@pytest.mark.parametrize("status", [302, 307, 308])
def test_the_token_exchange_does_not_follow_a_redirect(
    monkeypatch: pytest.MonkeyPatch, tls: LocalTLS, status: int
) -> None:
    """A followed `307`/`308` would resend the code, the verifier and any
    client secret to the redirect's target."""
    with serve(LocalHTTPServer(routes={})) as plain, serve(_provider(tls)) as server:
        server.routes["/token"] = Route(status, headers=(("Location", f"{plain.origin}/token"),))
        _configure(monkeypatch, OIDC_CA_BUNDLE=str(tls.ca_file))
        with pytest.raises(OIDCExchangeError):
            _exchange(server.origin)
    assert server.requests == ["/token"]
    assert plain.requests == []
