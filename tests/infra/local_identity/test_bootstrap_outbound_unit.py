"""Routing and trust of the ZITADEL bootstrap's Management API client (owner
decision on ledger row 965, 2026-10-28): `OIDC_CA_BUNDLE` and
`OIDC_PROXY_URL` only, never `HTTPS_PROXY` and friends or `SSL_CERT_FILE`.
Real sockets on 127.0.0.1 only (`tests/support/outbound_http_support.py`).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from saas_os.infra.local_identity import zitadel_bootstrap as zb
from saas_os.infra.outbound_http import OutboundHTTPSettings, ssl_context
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

_ORG = "/management/v1/orgs/me"


@pytest.fixture(autouse=True)
def _fast_and_fresh(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(zb, "_RETRIES", 1)
    monkeypatch.setattr(zb, "_RETRY_DELAY_SECONDS", 0.0)
    ssl_context.cache_clear()
    yield
    ssl_context.cache_clear()


@pytest.fixture
def tls(tmp_path: Path) -> LocalTLS:
    return local_tls(tmp_path / "zitadel")


@pytest.fixture
def environment(monkeypatch: pytest.MonkeyPatch, tls: LocalTLS) -> Iterator[LocalProxy]:
    """Proxy variables name a recording listener; `SSL_CERT_FILE` names the
    CA that signed the local ZITADEL's certificate."""
    with proxy(LocalProxy(relay=False)) as recorder:
        for name in ENVIRONMENT_PROXY_VARIABLES:
            monkeypatch.setenv(name, recorder.url)
        monkeypatch.setenv("SSL_CERT_FILE", str(tls.ca_file))
        yield recorder


def _zitadel(tls: LocalTLS) -> LocalHTTPServer:
    org = Route(200, json.dumps({"org": {"id": "org-1"}}).encode())
    return LocalHTTPServer(routes={_ORG: org}, ssl_context=tls.server_context)


def _org_id(origin: str, http: OutboundHTTPSettings) -> str:
    config = zb.BootstrapConfig(zitadel_url=origin, http=http)
    with zb._client(config, "fake-pat") as client:  # pyright: ignore[reportPrivateUsage]
        return zb.get_org_id(client)


def test_the_environment_alone_neither_routes_nor_trusts(
    tls: LocalTLS, environment: LocalProxy
) -> None:
    with serve(_zitadel(tls)) as server:
        with pytest.raises(httpx.ConnectError):
            _org_id(server.origin, OutboundHTTPSettings())
        assert server.requests == []
        assert _org_id(server.origin, OutboundHTTPSettings(ca_bundle=str(tls.ca_file))) == "org-1"
    assert server.requests == [_ORG]
    assert environment.connections == 0


def test_an_explicit_proxy_is_used(tls: LocalTLS, environment: LocalProxy) -> None:
    with serve(_zitadel(tls)) as server, proxy(LocalProxy()) as explicit:
        http = OutboundHTTPSettings(ca_bundle=str(tls.ca_file), proxy_url=explicit.url)
        assert _org_id(server.origin, http) == "org-1"
    assert explicit.heads[0].startswith(f"CONNECT localhost:{server.port} ".encode())
    assert environment.connections == 0


def test_a_redirect_is_not_followed(tls: LocalTLS) -> None:
    """The client carries the bootstrap PAT; a followed redirect would
    present it elsewhere."""
    with serve(LocalHTTPServer(routes={})) as plain, serve(_zitadel(tls)) as server:
        server.routes[_ORG] = Route(307, headers=(("Location", f"{plain.origin}{_ORG}"),))
        with pytest.raises(httpx.HTTPStatusError):
            _org_id(server.origin, OutboundHTTPSettings(ca_bundle=str(tls.ca_file)))
    assert plain.requests == []


def test_configuration_reads_the_explicit_settings(tls: LocalTLS) -> None:
    config = zb.load_config(
        [],
        {
            "ZITADEL_INTERNAL_URL": "https://z.test",
            "OIDC_CA_BUNDLE": str(tls.ca_file),
            "OIDC_PROXY_URL": "http://proxy.internal:3128",
        },
    )
    assert config.http == OutboundHTTPSettings(
        ca_bundle=str(tls.ca_file), proxy_url="http://proxy.internal:3128"
    )
    assert zb.load_config([], {"ZITADEL_INTERNAL_URL": "https://z.test"}).http == (
        OutboundHTTPSettings()
    )


@pytest.mark.parametrize(
    "env",
    [
        {"OIDC_PROXY_URL": "http://user:SECRET-PW@proxy.internal:3128"},  # pragma: allowlist secret
        {"OIDC_CA_BUNDLE": "/nonexistent/SECRET-PATH.pem"},
    ],
)
def test_an_unusable_setting_stops_the_bootstrap_without_repeating_it(
    env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        zb.load_config([], {"ZITADEL_INTERNAL_URL": "https://z.test", **env})
    assert excinfo.value.code != 0
    assert "SECRET" not in capsys.readouterr().err
