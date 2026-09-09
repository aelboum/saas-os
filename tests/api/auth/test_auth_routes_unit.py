"""P2.2 -- HTTP-shape unit tests for `api/auth/routes.py` and the cookie
transport in `api/dependencies.py`, with every `core.identity` primitive
monkeypatched (no database, no Redis, no provider). The real end-to-end
behavior is `tests/api/auth/test_auth_flow_integration.py`'s job; this
file pins response codes, cookie attributes, redirect targets, and what
never appears in a response."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

import api.auth.routes as routes_module
import api.dependencies as deps
import pytest
from api.auth.config import get_auth_http_config
from api.main import app
from core.identity.errors import (
    InvalidSignatureError,
    LoginTransactionInvalidError,
    OIDCExchangeError,
    SessionRevokedError,
)
from core.identity.login_transactions import ConsumedLogin, StartedLogin
from core.identity.oidc import VerifiedIdentity
from core.identity.provider import OIDCFlowEndpoints, OIDCProviderConfig
from fastapi import Request
from fastapi.testclient import TestClient

_PROVIDER = OIDCProviderConfig(
    issuer="https://idp.example.test",
    client_id="test-client",
    audience="test-client",
    jwks_uri="https://idp.example.test/keys",
)
_ENDPOINTS = OIDCFlowEndpoints(
    authorization_endpoint="https://idp.example.test/oauth/v2/authorize",
    token_endpoint="https://idp.example.test/oauth/v2/token",
)
_TX_ID = uuid.uuid4()
_STARTED = StartedLogin(
    transaction_id=_TX_ID,
    state="state-value",
    nonce="nonce-value",
    code_challenge="challenge-value",
    expires_at=datetime.now(UTC) + timedelta(minutes=10),
)
_USER_ID = uuid.uuid4()
_SESSION_ID = uuid.uuid4()
_RAW_SESSION_TOKEN = "raw-session-token-never-in-a-body"


class _FakeUser:
    id = _USER_ID


class _FakeSession:
    id = _SESSION_ID
    user_id = _USER_ID


@pytest.fixture(autouse=True)
def _configure(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://app.example.com/auth/callback")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    monkeypatch.setenv("AUTH_POST_LOGIN_PATH", "/app")
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_auth_http_config.cache_clear()

    async def _no_rate_limit(request: Request) -> None:
        return None

    app.dependency_overrides[routes_module._enforce_auth_rate_limit] = _no_rate_limit
    monkeypatch.setattr(routes_module, "get_oidc_provider_config", lambda: _PROVIDER)
    monkeypatch.setattr(routes_module, "get_oidc_flow_endpoints", lambda: _ENDPOINTS)
    monkeypatch.setattr(routes_module, "get_oidc_client_secret", lambda: "client-secret-value")
    monkeypatch.setattr(routes_module, "begin_login_transaction", lambda: _STARTED)
    yield
    app.dependency_overrides.clear()
    get_auth_http_config.cache_clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, base_url="https://testserver")


def _cookie(response, name: str) -> SimpleCookie | None:
    for header in response.headers.get_list("set-cookie"):
        jar = SimpleCookie()
        jar.load(header)
        if name in jar:
            return jar
    return None


# --- /auth/login -----------------------------------------------------------------


def test_login_redirects_to_the_provider_with_state_nonce_and_pkce(client: TestClient) -> None:
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    parts = urlsplit(location)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == _ENDPOINTS.authorization_endpoint
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert query["state"] == "state-value"
    assert query["nonce"] == "nonce-value"
    assert query["code_challenge"] == "challenge-value"
    assert query["code_challenge_method"] == "S256"
    assert query["redirect_uri"] == "https://app.example.com/auth/callback"
    assert query["response_type"] == "code"
    assert "client_secret" not in location
    assert "code_verifier" not in location


def test_login_sets_a_bound_httponly_transaction_cookie(client: TestClient) -> None:
    response = client.get("/auth/login", follow_redirects=False)
    jar = _cookie(response, "saas_os_session_login")
    assert jar is not None
    morsel = jar["saas_os_session_login"]
    assert morsel.value == str(_TX_ID)
    assert morsel["httponly"]
    assert morsel["secure"]
    assert morsel["samesite"].lower() == "lax"
    assert morsel["path"] == "/auth"
    assert int(morsel["max-age"]) == 600


def test_login_ignores_a_browser_supplied_redirect(client: TestClient) -> None:
    response = client.get(
        "/auth/login", params={"next": "https://attacker.example"}, follow_redirects=False
    )
    location = response.headers["location"]
    assert "attacker.example" not in location
    assert parse_qs(urlsplit(location).query)["redirect_uri"] == [
        "https://app.example.com/auth/callback"
    ]


# --- /auth/callback --------------------------------------------------------------


def _happy_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        routes_module,
        "consume_login_transaction",
        lambda tx, state: ConsumedLogin(
            transaction_id=tx, nonce="nonce-value", code_verifier="verifier-value"
        ),
    )
    monkeypatch.setattr(
        routes_module, "exchange_authorization_code", lambda *a, **k: "id.token.value"
    )
    monkeypatch.setattr(
        routes_module,
        "validate_id_token",
        lambda token, provider, expected_nonce=None: VerifiedIdentity(
            issuer=_PROVIDER.issuer, subject="sub-1", email=None, raw_claims={}
        ),
    )
    monkeypatch.setattr(
        routes_module, "get_or_create_user_for_external_identity", lambda iss, sub: _FakeUser()
    )
    monkeypatch.setattr(
        routes_module, "issue_session", lambda user_id: (_FakeSession(), _RAW_SESSION_TOKEN)
    )


def test_callback_success_sets_a_secure_session_cookie_and_redirects_home(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _happy_callback(monkeypatch)
    client.cookies.set("saas_os_session_login", str(_TX_ID))
    response = client.get(
        "/auth/callback",
        params={"code": "the-code", "state": "state-value"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/app"
    jar = _cookie(response, "saas_os_session")
    assert jar is not None
    morsel = jar["saas_os_session"]
    assert morsel.value == _RAW_SESSION_TOKEN
    assert morsel["httponly"]
    assert morsel["secure"]
    assert morsel["samesite"].lower() == "lax"
    assert morsel["path"] == "/"
    assert int(morsel["max-age"]) == 12 * 3600
    # The transaction cookie is cleared, the token never appears in the body.
    login_jar = _cookie(response, "saas_os_session_login")
    assert login_jar is not None and login_jar["saas_os_session_login"].value == ""
    assert _RAW_SESSION_TOKEN not in response.text
    assert "the-code" not in response.text


@pytest.mark.parametrize(
    ("params", "with_cookie"),
    [
        ({"code": "c"}, True),  # missing state
        ({"state": "state-value"}, True),  # missing code
        ({}, True),
        ({"code": "c", "state": "state-value"}, False),  # missing transaction cookie
        ({"code": "c" * 3000, "state": "state-value"}, True),  # oversized
    ],
)
def test_malformed_callbacks_get_the_same_generic_400(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, params, with_cookie: bool
) -> None:
    called = False

    def _must_not_consume(tx, state):
        nonlocal called
        called = True
        raise AssertionError

    monkeypatch.setattr(routes_module, "consume_login_transaction", _must_not_consume)
    if with_cookie:
        client.cookies.set("saas_os_session_login", str(_TX_ID))
    response = client.get("/auth/callback", params=params, follow_redirects=False)
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid login callback."}
    assert called is False


def test_invalid_transaction_gets_the_identical_400(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _reject(tx, state):
        raise LoginTransactionInvalidError()

    monkeypatch.setattr(routes_module, "consume_login_transaction", _reject)
    client.cookies.set("saas_os_session_login", str(_TX_ID))
    response = client.get(
        "/auth/callback", params={"code": "c", "state": "wrong"}, follow_redirects=False
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid login callback."}


def test_garbage_transaction_cookie_is_a_400_not_a_500(client: TestClient) -> None:
    client.cookies.set("saas_os_session_login", "not-a-uuid")
    response = client.get(
        "/auth/callback", params={"code": "c", "state": "state-value"}, follow_redirects=False
    )
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("reason", "expected_status"),
    [
        ("provider rejected the authorization code", 502),
        ("provider unavailable", 503),
        ("transport error (ConnectError)", 503),
        ("provider response carried no id_token", 502),
    ],
)
def test_exchange_failures_map_to_502_or_503_never_500(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, reason: str, expected_status: int
) -> None:
    _happy_callback(monkeypatch)

    def _fail(*a, **k):
        raise OIDCExchangeError(reason)

    monkeypatch.setattr(routes_module, "exchange_authorization_code", _fail)
    client.cookies.set("saas_os_session_login", str(_TX_ID))
    response = client.get(
        "/auth/callback",
        params={"code": "the-code", "state": "state-value"},
        follow_redirects=False,
    )
    assert response.status_code == expected_status
    assert "the-code" not in response.text
    assert _cookie(response, "saas_os_session") is None


def test_rejected_id_token_is_a_401_with_no_session_cookie(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _happy_callback(monkeypatch)

    def _reject(token, provider, expected_nonce=None):
        raise InvalidSignatureError()

    monkeypatch.setattr(routes_module, "validate_id_token", _reject)
    client.cookies.set("saas_os_session_login", str(_TX_ID))
    response = client.get(
        "/auth/callback",
        params={"code": "the-code", "state": "state-value"},
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert _cookie(response, "saas_os_session") is None
    assert "id.token" not in response.text


def test_callback_passes_the_transaction_nonce_to_the_validator(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _happy_callback(monkeypatch)
    seen: dict[str, object] = {}

    def _capture(token, provider, expected_nonce=None):
        seen["expected_nonce"] = expected_nonce
        return VerifiedIdentity(issuer=_PROVIDER.issuer, subject="s", email=None, raw_claims={})

    monkeypatch.setattr(routes_module, "validate_id_token", _capture)
    client.cookies.set("saas_os_session_login", str(_TX_ID))
    client.get(
        "/auth/callback",
        params={"code": "the-code", "state": "state-value"},
        follow_redirects=False,
    )
    assert seen["expected_nonce"] == "nonce-value"


# --- /auth/me and /auth/logout via the cookie transport -------------------------


def test_me_and_logout_require_a_session(client: TestClient) -> None:
    assert client.get("/auth/me").status_code == 401
    assert client.post("/auth/logout").status_code == 401


def test_me_accepts_the_session_cookie_and_returns_only_the_user_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(deps, "validate_session", lambda raw: _FakeSession())
    client.cookies.set("saas_os_session", _RAW_SESSION_TOKEN)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json() == {"user_id": str(_USER_ID)}
    assert _RAW_SESSION_TOKEN not in response.text


def test_logout_revokes_the_current_session_and_clears_the_cookie(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    revoked: list[uuid.UUID] = []
    monkeypatch.setattr(deps, "validate_session", lambda raw: _FakeSession())
    monkeypatch.setattr(
        routes_module, "revoke_session", lambda session_id: revoked.append(session_id)
    )
    client.cookies.set("saas_os_session", _RAW_SESSION_TOKEN)
    response = client.post("/auth/logout")
    assert response.status_code == 204
    assert revoked == [_SESSION_ID]
    jar = _cookie(response, "saas_os_session")
    assert jar is not None and jar["saas_os_session"].value == ""


def test_logout_with_a_revoked_session_is_a_401_that_leaks_nothing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _revoked(raw):
        raise SessionRevokedError(_SESSION_ID)

    monkeypatch.setattr(deps, "validate_session", _revoked)
    client.cookies.set("saas_os_session", _RAW_SESSION_TOKEN)
    response = client.post("/auth/logout")
    assert response.status_code == 401
    assert str(_SESSION_ID) not in response.text


def test_malformed_authorization_header_is_never_rescued_by_a_valid_cookie(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(deps, "validate_session", lambda raw: _FakeSession())
    client.cookies.set("saas_os_session", _RAW_SESSION_TOKEN)
    response = client.get("/auth/me", headers={"Authorization": "Basic abc"})
    assert response.status_code == 401


def test_bearer_header_takes_precedence_over_the_cookie(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def _validate(raw):
        seen.append(raw)
        return _FakeSession()

    monkeypatch.setattr(deps, "validate_session", _validate)
    client.cookies.set("saas_os_session", "cookie-token")
    client.get("/auth/me", headers={"Authorization": "Bearer header-token"})
    assert seen == ["header-token"]


def test_auth_routes_are_registered_in_openapi(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/auth/login", "/auth/callback", "/auth/logout", "/auth/me"} <= set(paths)
