"""P2.2 -- pure unit tests for the Authorization Code Flow additions in
`core/identity`: PKCE derivation, authorization-URL construction, the
server-side token exchange (against an `httpx.MockTransport`), endpoint
discovery parsing, and the client-secret accessor. No database, no
network."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import core.identity.oidc as oidc_module
import core.identity.provider as provider_module
import httpx
import pytest
from core.identity.errors import OIDCExchangeError
from core.identity.login_transactions import (
    PKCE_CODE_CHALLENGE_METHOD,
    StartedLogin,
    derive_code_challenge,
)
from core.identity.oidc import build_authorization_url, exchange_authorization_code
from core.identity.provider import (
    OIDCConfigurationError,
    OIDCFlowEndpoints,
    OIDCProviderConfig,
    get_oidc_client_secret,
)

_CONFIG = OIDCProviderConfig(
    issuer="https://idp.example.test",
    client_id="test-client",
    audience="test-client",
    jwks_uri="https://idp.example.test/keys",
)
_ENDPOINTS = OIDCFlowEndpoints(
    authorization_endpoint="https://idp.example.test/oauth/v2/authorize",
    token_endpoint="https://idp.example.test/oauth/v2/token",
)
_REDIRECT_URI = "https://app.example.com/auth/callback"


# --- PKCE ------------------------------------------------------------------------


def test_code_challenge_matches_the_rfc_7636_appendix_b_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert derive_code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_pkce_method_is_s256_never_plain() -> None:
    assert PKCE_CODE_CHALLENGE_METHOD == "S256"


def test_started_login_carries_no_code_verifier() -> None:
    assert "code_verifier" not in StartedLogin.__dataclass_fields__


# --- Authorization URL -------------------------------------------------------


def test_authorization_url_carries_state_nonce_and_s256_challenge_only() -> None:
    url = build_authorization_url(
        _CONFIG,
        _ENDPOINTS,
        redirect_uri=_REDIRECT_URI,
        state="the-state",
        nonce="the-nonce",
        code_challenge="the-challenge",
    )
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == _ENDPOINTS.authorization_endpoint
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert query == {
        "response_type": "code",
        "client_id": "test-client",
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid",
        "state": "the-state",
        "nonce": "the-nonce",
        "code_challenge": "the-challenge",
        "code_challenge_method": "S256",
    }
    assert "code_verifier" not in url
    assert "client_secret" not in url


def test_authorization_url_always_includes_the_openid_scope() -> None:
    url = build_authorization_url(
        _CONFIG,
        _ENDPOINTS,
        redirect_uri=_REDIRECT_URI,
        state="s",
        nonce="n",
        code_challenge="c",
        scopes=("profile",),
    )
    assert parse_qs(urlsplit(url).query)["scope"] == ["openid profile"]


# --- Token exchange ------------------------------------------------------------


class _TokenEndpoint:
    def __init__(self, status_code: int = 200, body: object = None, *, raise_transport=False):
        self.status_code = status_code
        self.body = body if body is not None else {"id_token": "signed.id.token"}
        self.raise_transport = raise_transport
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raise_transport:
            raise httpx.ConnectError("boom")
        if isinstance(self.body, str):
            return httpx.Response(self.status_code, text=self.body)
        return httpx.Response(self.status_code, json=self.body)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            oidc_module,
            "_token_http_client",
            lambda: httpx.Client(transport=httpx.MockTransport(self.handler)),
        )

    def last_form(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(self.requests[-1].content.decode()).items()}


def _exchange(*, client_secret: str | None = "the-client-secret") -> str:
    return exchange_authorization_code(
        _CONFIG,
        _ENDPOINTS,
        code="auth-code-123",
        code_verifier="verifier-456",
        redirect_uri=_REDIRECT_URI,
        client_secret=client_secret,
    )


def test_exchange_posts_the_expected_form_and_returns_the_id_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = _TokenEndpoint()
    endpoint.install(monkeypatch)

    assert _exchange() == "signed.id.token"
    request = endpoint.requests[-1]
    assert request.method == "POST"
    assert str(request.url) == _ENDPOINTS.token_endpoint
    assert endpoint.last_form() == {
        "grant_type": "authorization_code",
        "code": "auth-code-123",
        "redirect_uri": _REDIRECT_URI,
        "client_id": "test-client",
        "code_verifier": "verifier-456",
        "client_secret": "the-client-secret",
    }


def test_exchange_omits_client_secret_for_a_public_client(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint = _TokenEndpoint()
    endpoint.install(monkeypatch)
    _exchange(client_secret=None)
    assert "client_secret" not in endpoint.last_form()
    assert endpoint.last_form()["code_verifier"] == "verifier-456"


def test_exchange_never_puts_code_or_verifier_in_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint = _TokenEndpoint()
    endpoint.install(monkeypatch)
    _exchange()
    assert "auth-code-123" not in str(endpoint.requests[-1].url)
    assert "verifier-456" not in str(endpoint.requests[-1].url)


@pytest.mark.parametrize(
    ("endpoint", "expected_reason"),
    [
        (
            _TokenEndpoint(400, {"error": "invalid_grant"}),
            "provider rejected the authorization code",
        ),
        (
            _TokenEndpoint(401, {"error": "invalid_client"}),
            "provider rejected the authorization code",
        ),
        (_TokenEndpoint(500, {"error": "boom"}), "provider unavailable"),
        (_TokenEndpoint(503, "down"), "provider unavailable"),
        (_TokenEndpoint(200, "<html>not json</html>"), "provider response was not JSON"),
        (_TokenEndpoint(200, {"access_token": "x"}), "provider response carried no id_token"),
        (_TokenEndpoint(200, {"id_token": ""}), "provider response carried no id_token"),
    ],
)
def test_exchange_failures_are_classified_and_never_echo_the_response(
    monkeypatch: pytest.MonkeyPatch, endpoint: _TokenEndpoint, expected_reason: str
) -> None:
    endpoint.install(monkeypatch)
    with pytest.raises(OIDCExchangeError) as excinfo:
        _exchange()
    assert excinfo.value.reason == expected_reason
    message = str(excinfo.value)
    for forbidden in ("auth-code-123", "verifier-456", "the-client-secret", "invalid_grant"):
        assert forbidden not in message


def test_exchange_transport_error_is_classified(monkeypatch: pytest.MonkeyPatch) -> None:
    _TokenEndpoint(raise_transport=True).install(monkeypatch)
    with pytest.raises(OIDCExchangeError) as excinfo:
        _exchange()
    assert excinfo.value.reason.startswith("transport error")
    assert "boom" not in str(excinfo.value)


# --- Endpoint discovery ----------------------------------------------------


class _FakeHTTPResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _patch_discovery(monkeypatch: pytest.MonkeyPatch, document: dict[str, object]) -> None:
    monkeypatch.setattr(
        provider_module.urllib.request,
        "urlopen",
        lambda url, timeout: _FakeHTTPResponse(json.dumps(document).encode()),
    )


def test_flow_endpoints_are_discovered_from_the_standard_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_discovery(
        monkeypatch,
        {
            "authorization_endpoint": "https://idp.example.test/oauth/v2/authorize",
            "token_endpoint": "https://idp.example.test/oauth/v2/token",
            "jwks_uri": "https://idp.example.test/keys",
        },
    )
    endpoints = provider_module._discover_flow_endpoints("https://idp.example.test")
    assert endpoints == _ENDPOINTS


@pytest.mark.parametrize(
    "document",
    [
        {"token_endpoint": "https://idp.example.test/token"},
        {"authorization_endpoint": "https://idp.example.test/authorize"},
        {
            "authorization_endpoint": "http://idp.example.test/authorize",
            "token_endpoint": "https://idp.example.test/token",
        },
        {
            "authorization_endpoint": "https://idp.example.test/authorize",
            "token_endpoint": "javascript:alert(1)",
        },
    ],
)
def test_flow_endpoint_discovery_fails_closed_on_missing_or_non_https_endpoints(
    monkeypatch: pytest.MonkeyPatch, document: dict[str, object]
) -> None:
    _patch_discovery(monkeypatch, document)
    with pytest.raises(OIDCConfigurationError):
        provider_module._discover_flow_endpoints("https://idp.example.test")


def test_http_endpoints_are_allowed_only_for_an_http_development_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_discovery(
        monkeypatch,
        {
            "authorization_endpoint": "http://localhost:8080/authorize",
            "token_endpoint": "http://localhost:8080/token",
        },
    )
    endpoints = provider_module._discover_flow_endpoints("http://localhost:8080")
    assert endpoints.token_endpoint == "http://localhost:8080/token"


# --- Client secret -------------------------------------------------------------


class _FakeSecrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)

    def get_required(self, name: str) -> str:
        value = self.get(name)
        if not value:
            raise LookupError(name)
        return value


def test_client_secret_comes_through_the_secrets_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provider_module,
        "get_secrets_provider",
        lambda: _FakeSecrets({"ZITADEL_CLIENT_SECRET": "s"}),
    )
    assert get_oidc_client_secret() == "s"


def test_empty_client_secret_means_public_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        provider_module, "get_secrets_provider", lambda: _FakeSecrets({"ZITADEL_CLIENT_SECRET": ""})
    )
    assert get_oidc_client_secret() is None


def test_identity_modules_never_read_secrets_from_the_environment_directly() -> None:
    """AST-level, not text-level: module docstrings legitimately *mention*
    `os.environ` to say it is never used for a secret; the code itself
    must contain no `import os` and no `os.environ`/`os.getenv` access."""
    import ast
    import inspect

    import core.identity.login_transactions as lt_module

    for module in (oidc_module, provider_module, lt_module):
        tree = ast.parse(inspect.getsource(module))
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import | ast.ImportFrom)
            for alias in node.names
        }
        assert "os" not in imported
        attribute_accesses = {
            f"{node.value.id}.{node.attr}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
        }
        assert "os.environ" not in attribute_accesses
        assert "os.getenv" not in attribute_accesses
