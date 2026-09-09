"""P2.2 -- live OIDC provider validation gate. Runs ONLY when an operator
explicitly opts in with `ZITADEL_LIVE_TEST=1` and real, non-placeholder
provider settings are present in the environment (through the normal
`infra.secrets` path). Without them every test here SKIPS -- it never
fakes a pass, and the P2.2 report must say
"Live ZITADEL validation: NOT RUN -- credentials unavailable" when this
file skipped.

What can be validated non-interactively against a real provider: the
discovery document resolves (issuer, JWKS, authorization/token
endpoints), and `GET /auth/login` redirects to the provider's real
authorization endpoint with a state/nonce/PKCE-S256 envelope. Completing
the code exchange requires a human to authenticate in a browser, which
this test does not automate.
"""

from __future__ import annotations

import os
from urllib.parse import parse_qs, urlsplit

import pytest

pytestmark = pytest.mark.integration

_PLACEHOLDER_HOSTS = ("your-zitadel-instance.example.com", "idp.example.test")


@pytest.fixture(autouse=True)
def _require_live_credentials() -> None:
    if os.environ.get("ZITADEL_LIVE_TEST") != "1":
        pytest.skip("Live ZITADEL validation: NOT RUN -- ZITADEL_LIVE_TEST=1 not set")
    from core.identity import get_oidc_provider_config

    get_oidc_provider_config.cache_clear()
    try:
        config = get_oidc_provider_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Live ZITADEL validation: NOT RUN -- provider not configured: {exc}")
    if any(host in config.issuer for host in _PLACEHOLDER_HOSTS):
        pytest.skip("Live ZITADEL validation: NOT RUN -- placeholder issuer configured")


def test_live_discovery_resolves_flow_endpoints() -> None:
    from core.identity import get_oidc_flow_endpoints, get_oidc_provider_config

    get_oidc_flow_endpoints.cache_clear()
    config = get_oidc_provider_config()
    endpoints = get_oidc_flow_endpoints()
    assert config.jwks_uri.startswith("https://")
    assert endpoints.authorization_endpoint.startswith("https://")
    assert endpoints.token_endpoint.startswith("https://")


def test_live_login_redirects_to_the_real_authorization_endpoint() -> None:
    from api.auth.config import get_auth_http_config
    from api.main import app
    from fastapi.testclient import TestClient

    from core.identity import get_oidc_flow_endpoints

    get_auth_http_config.cache_clear()
    client = TestClient(app, base_url="https://testserver")
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(get_oidc_flow_endpoints().authorization_endpoint)
    query = parse_qs(urlsplit(location).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] and query["nonce"] and query["code_challenge"]
