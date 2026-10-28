"""Routing and trust of `GitHubPullRequestProvider` (owner decision on ledger
row 965, 2026-10-28): explicit `proxy_url` and `ca_bundle` only, never
`HTTPS_PROXY` and friends or `SSL_CERT_FILE`, and no redirect, which would
present the token elsewhere. Real sockets on 127.0.0.1 only, standing in
for `api.github.com` (`tests/support/outbound_http_support.py`); no request
reaches GitHub.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from saas_os.control_plane.development import github_provider
from saas_os.control_plane.development.errors import PullRequestProviderError
from saas_os.control_plane.development.github_provider import GitHubPullRequestProvider
from saas_os.control_plane.development.provider import FileChange
from saas_os.infra.outbound_http import OutboundHTTPConfigurationError, ssl_context
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

_REPO = "/repos/acme/sandbox"
_FAKE_TOKEN = "fake-token-for-local-tests"  # pragma: allowlist secret
_CREDENTIALED_PROXY = "http://user:SECRET-PW@proxy.internal:3128"  # pragma: allowlist secret


def _json(status: int, body: object) -> Route:
    return Route(status, json.dumps(body).encode())


def _github_routes() -> dict[str, Route]:
    return {
        f"{_REPO}/git/ref/heads/main": _json(200, {"object": {"sha": "base"}}),
        f"{_REPO}/git/commits/base": _json(200, {"tree": {"sha": "tree0"}}),
        f"{_REPO}/git/blobs": _json(201, {"sha": "blob1"}),
        f"{_REPO}/git/trees": _json(201, {"sha": "tree1"}),
        f"{_REPO}/git/commits": _json(201, {"sha": "commit1"}),
        f"{_REPO}/git/refs": _json(201, {}),
        f"{_REPO}/pulls": _json(201, {"html_url": "https://github.example/pr/1"}),
    }


@pytest.fixture(autouse=True)
def _fresh() -> Iterator[None]:
    ssl_context.cache_clear()
    yield
    ssl_context.cache_clear()


@pytest.fixture
def tls(tmp_path: Path) -> LocalTLS:
    return local_tls(tmp_path / "github")


@pytest.fixture
def environment(monkeypatch: pytest.MonkeyPatch, tls: LocalTLS) -> Iterator[LocalProxy]:
    """Proxy variables name a recording listener; `SSL_CERT_FILE` names the
    CA that signed the local server's certificate."""
    with proxy(LocalProxy(relay=False)) as recorder:
        for name in ENVIRONMENT_PROXY_VARIABLES:
            monkeypatch.setenv(name, recorder.url)
        monkeypatch.setenv("SSL_CERT_FILE", str(tls.ca_file))
        yield recorder


@pytest.fixture
def github(monkeypatch: pytest.MonkeyPatch, tls: LocalTLS) -> Iterator[LocalHTTPServer]:
    with serve(LocalHTTPServer(routes=_github_routes(), ssl_context=tls.server_context)) as server:
        monkeypatch.setattr(github_provider, "_API_BASE", server.origin)
        yield server


def _open(provider: GitHubPullRequestProvider) -> str:
    try:
        return provider.open_pull_request(
            repository="acme/sandbox",
            base_branch="main",
            branch_name="proposal",
            title="t",
            body="b",
            file_changes=[FileChange(path="a.txt", content="x")],
        )
    finally:
        provider.close()


def test_the_environment_alone_neither_routes_nor_trusts(
    github: LocalHTTPServer, environment: LocalProxy, tls: LocalTLS
) -> None:
    with pytest.raises(PullRequestProviderError):
        _open(GitHubPullRequestProvider(_FAKE_TOKEN))
    assert github.requests == []
    assert _open(GitHubPullRequestProvider(_FAKE_TOKEN, ca_bundle=str(tls.ca_file))) == (
        "https://github.example/pr/1"
    )
    assert github.requests[0] == f"{_REPO}/git/ref/heads/main"
    assert environment.connections == 0


def test_an_explicit_proxy_is_used(
    github: LocalHTTPServer, environment: LocalProxy, tls: LocalTLS
) -> None:
    with proxy(LocalProxy()) as explicit:
        provider = GitHubPullRequestProvider(
            _FAKE_TOKEN, ca_bundle=str(tls.ca_file), proxy_url=explicit.url
        )
        assert _open(provider) == "https://github.example/pr/1"
    assert explicit.heads
    assert all(
        head.startswith(f"CONNECT localhost:{github.port} ".encode()) for head in explicit.heads
    )
    assert environment.connections == 0


def test_a_redirect_is_not_followed(github: LocalHTTPServer, tls: LocalTLS) -> None:
    with serve(LocalHTTPServer(routes={})) as plain:
        github.routes[f"{_REPO}/git/ref/heads/main"] = Route(
            307, headers=(("Location", f"{plain.origin}/steal"),)
        )
        with pytest.raises(PullRequestProviderError):
            _open(GitHubPullRequestProvider(_FAKE_TOKEN, ca_bundle=str(tls.ca_file)))
    assert plain.requests == []


@pytest.mark.parametrize(
    ("proxy_url", "ca_bundle", "name"),
    [
        (_CREDENTIALED_PROXY, None, "proxy_url"),
        ("socks5://proxy.internal:1080", None, "proxy_url"),
        (None, "/nonexistent/SECRET-PATH.pem", "ca_bundle"),
    ],
)
def test_an_unusable_setting_is_refused_without_repeating_it(
    proxy_url: str | None, ca_bundle: str | None, name: str
) -> None:
    with pytest.raises(OutboundHTTPConfigurationError, match=name) as excinfo:
        GitHubPullRequestProvider(_FAKE_TOKEN, proxy_url=proxy_url, ca_bundle=ca_bundle)
    assert "SECRET" not in str(excinfo.value)
    assert "proxy.internal" not in str(excinfo.value)
