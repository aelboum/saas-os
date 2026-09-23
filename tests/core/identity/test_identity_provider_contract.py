"""Provider-contract / substitution tests for `IdentityProvider`
(docs/ADR/0023-... Phase 2 -- the provider-neutral identity boundary).

Proves the boundary isn't leaky the same way
`tests/core/billing/test_billing_provider.py` proves `BillingProvider`
isn't: a second, independent, in-memory implementation
(`FakeIdentityProvider`, test-only -- never imported by production code)
satisfies the identical `Protocol` the real `OIDCIdentityProvider` adapter
does, AND the HTTP auth layer (`api/auth/routes.py`) can be driven
end-to-end against that fake with no ZITADEL, no network, and no change
to route code -- i.e. `api/auth/routes.py` depends on the `IdentityProvider`
contract, not on `core.identity.oidc`'s free functions or anything
ZITADEL-shaped.

This file does not re-test OIDC security properties (issuer/audience/
algorithm/nonce/PKCE/state) -- those remain exactly where they already
were: `tests/core/identity/test_oidc.py`, `test_oidc_flow_unit.py`,
`test_login_transactions_integration.py`. Duplicating that coverage here
would violate this phase's own "do not duplicate large amounts of
security test logic merely to satisfy the Protocol" instruction.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlencode, urlsplit

import api.auth.routes as routes_module
import pytest
from api.auth.config import get_auth_http_config
from api.main import app
from core.identity.login_transactions import ConsumedLogin, StartedLogin
from core.identity.oidc import OIDCIdentityProvider, VerifiedIdentity
from core.identity.provider import IdentityProvider, OIDCFlowEndpoints, OIDCProviderConfig
from fastapi import Request
from fastapi.testclient import TestClient

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


class FakeIdentityProvider:
    """A second, independent `IdentityProvider` implementation -- no
    network access, no credentials, in-memory only. Records every call so
    tests can assert against it directly, mirroring
    `core/billing/provider.py::FakeBillingProvider`'s own shape and role
    (the default provider unit tests run against, since it needs no
    external service)."""

    def __init__(
        self,
        config: OIDCProviderConfig = _CONFIG,
        endpoints: OIDCFlowEndpoints = _ENDPOINTS,
        *,
        id_token: str = "fake.id.token",
        identity: VerifiedIdentity | None = None,
    ) -> None:
        self._config = config
        self._endpoints = endpoints
        self._id_token = id_token
        self._identity = identity or VerifiedIdentity(
            issuer=config.issuer, subject="fake-subject", email=None, raw_claims={}
        )
        self.authorization_url_calls: list[dict[str, object]] = []
        self.exchange_calls: list[dict[str, object]] = []
        self.validate_calls: list[dict[str, object]] = []

    def get_config(self) -> OIDCProviderConfig:
        return self._config

    def get_flow_endpoints(self) -> OIDCFlowEndpoints:
        return self._endpoints

    def build_authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
        scopes: tuple[str, ...] = ("openid",),
    ) -> str:
        self.authorization_url_calls.append(
            {
                "redirect_uri": redirect_uri,
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
            }
        )
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._config.client_id,
                "redirect_uri": redirect_uri,
                "scope": " ".join(scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{self._endpoints.authorization_endpoint}?{query}"

    def exchange_authorization_code(
        self, *, code: str, code_verifier: str, redirect_uri: str
    ) -> str:
        self.exchange_calls.append(
            {"code": code, "code_verifier": code_verifier, "redirect_uri": redirect_uri}
        )
        return self._id_token

    def validate_id_token(
        self, token: str, *, expected_nonce: str | None = None
    ) -> VerifiedIdentity:
        self.validate_calls.append({"token": token, "expected_nonce": expected_nonce})
        return self._identity


# --- Structural conformance: two different implementations, one contract --------


def test_fake_identity_provider_satisfies_the_protocol() -> None:
    assert isinstance(FakeIdentityProvider(), IdentityProvider)


def test_real_oidc_identity_provider_satisfies_the_protocol() -> None:
    assert isinstance(OIDCIdentityProvider(_CONFIG, _ENDPOINTS), IdentityProvider)


# --- Fake provider: coverage of each contract operation --------------------------


def test_get_config_returns_the_configured_value() -> None:
    provider = FakeIdentityProvider()
    assert provider.get_config() == _CONFIG


def test_get_flow_endpoints_returns_the_configured_value() -> None:
    provider = FakeIdentityProvider()
    assert provider.get_flow_endpoints() == _ENDPOINTS


def test_build_authorization_url_carries_state_nonce_and_pkce() -> None:
    provider = FakeIdentityProvider()
    url = provider.build_authorization_url(
        redirect_uri="https://app.example.test/auth/callback",
        state="state-value",
        nonce="nonce-value",
        code_challenge="challenge-value",
    )
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == _ENDPOINTS.authorization_endpoint
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert query["state"] == "state-value"
    assert query["nonce"] == "nonce-value"
    assert query["code_challenge"] == "challenge-value"
    assert query["code_challenge_method"] == "S256"
    assert "client_secret" not in url
    assert "code_verifier" not in url
    assert provider.authorization_url_calls == [
        {
            "redirect_uri": "https://app.example.test/auth/callback",
            "state": "state-value",
            "nonce": "nonce-value",
            "code_challenge": "challenge-value",
        }
    ]


def test_exchange_authorization_code_returns_the_configured_id_token() -> None:
    provider = FakeIdentityProvider(id_token="configured-id-token")
    result = provider.exchange_authorization_code(
        code="the-code",
        code_verifier="the-verifier",
        redirect_uri="https://app.example.test/auth/callback",
    )
    assert result == "configured-id-token"
    assert provider.exchange_calls == [
        {
            "code": "the-code",
            "code_verifier": "the-verifier",
            "redirect_uri": "https://app.example.test/auth/callback",
        }
    ]


def test_validate_id_token_returns_the_configured_identity_and_receives_the_nonce() -> None:
    identity = VerifiedIdentity(issuer=_CONFIG.issuer, subject="sub-123", email=None, raw_claims={})
    provider = FakeIdentityProvider(identity=identity)
    result = provider.validate_id_token("some.id.token", expected_nonce="nonce-value")
    assert result is identity
    assert provider.validate_calls == [{"token": "some.id.token", "expected_nonce": "nonce-value"}]


# --- Substitution into the real auth path ----------------------------------------
#
# The point of this section: api/auth/routes.py is driven end-to-end
# (through FastAPI's TestClient, real routing/cookie/status-code
# behavior) against FakeIdentityProvider -- never OIDCIdentityProvider,
# never ZITADEL, never a network call. If the auth path only worked
# against the real adapter, this would fail; it doesn't, because the
# route code depends on the Protocol, not a concrete implementation.

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


@pytest.fixture
def fake_provider() -> FakeIdentityProvider:
    return FakeIdentityProvider(
        identity=VerifiedIdentity(issuer=_CONFIG.issuer, subject="sub-1", email=None, raw_claims={})
    )


@pytest.fixture
def client(
    monkeypatch: pytest.MonkeyPatch, fake_provider: FakeIdentityProvider
) -> Iterator[TestClient]:
    monkeypatch.setenv("OIDC_REDIRECT_URI", "https://app.example.com/auth/callback")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    monkeypatch.setenv("AUTH_POST_LOGIN_PATH", "/app")
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_auth_http_config.cache_clear()

    async def _no_rate_limit(request: Request) -> None:
        return None

    app.dependency_overrides[routes_module._enforce_auth_rate_limit] = _no_rate_limit
    monkeypatch.setattr(routes_module, "get_identity_provider", lambda: fake_provider)
    monkeypatch.setattr(routes_module, "begin_login_transaction", lambda: _STARTED)
    monkeypatch.setattr(
        routes_module,
        "consume_login_transaction",
        lambda tx, state: ConsumedLogin(
            transaction_id=tx, nonce="nonce-value", code_verifier="verifier-value"
        ),
    )
    monkeypatch.setattr(
        routes_module, "get_or_create_user_for_external_identity", lambda iss, sub: _FakeUser()
    )
    monkeypatch.setattr(
        routes_module, "issue_session", lambda user_id: (_FakeSession(), _RAW_SESSION_TOKEN)
    )
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()
    get_auth_http_config.cache_clear()


def test_login_redirects_using_the_fake_providers_authorization_url(
    client: TestClient, fake_provider: FakeIdentityProvider
) -> None:
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    parts = urlsplit(location)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == _ENDPOINTS.authorization_endpoint
    assert fake_provider.authorization_url_calls == [
        {
            "redirect_uri": "https://app.example.com/auth/callback",
            "state": "state-value",
            "nonce": "nonce-value",
            "code_challenge": "challenge-value",
        }
    ]


def test_callback_completes_a_full_login_against_the_fake_provider(
    client: TestClient, fake_provider: FakeIdentityProvider
) -> None:
    client.cookies.set("saas_os_session_login", str(_TX_ID))
    response = client.get(
        "/auth/callback",
        params={"code": "the-code", "state": "state-value"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/app"
    assert fake_provider.exchange_calls == [
        {
            "code": "the-code",
            "code_verifier": "verifier-value",
            "redirect_uri": "https://app.example.com/auth/callback",
        }
    ]
    assert fake_provider.validate_calls == [
        {"token": "fake.id.token", "expected_nonce": "nonce-value"}
    ]
    jar_header = response.headers.get_list("set-cookie")
    assert any(_RAW_SESSION_TOKEN in header for header in jar_header)
