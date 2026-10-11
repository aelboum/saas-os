"""Cross-site request forgery defense for cookie-authenticated mutations
(docs/ADR/0044-same-origin-check-for-cookie-authenticated-mutations.md;
`saas_os/api/dependencies.py::_enforce_same_origin_for_cookie_mutation`).

No database: the session lookup is stubbed, so what is exercised is the
real dependency chain's decision about the *request* -- which credential
it carries, which method, and what the browser says about where it came
from. The state-changing capability routes against a real database are in
`tests/api/v1/test_capability_routers_integration.py`.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import saas_os.api.auth.routes as routes_module
import saas_os.api.dependencies as deps
import saas_os.api.v1 as v1
from saas_os.api.auth.config import get_auth_http_config
from saas_os.api.platform import build_platform_app
from saas_os.core.billing import FakeBillingProvider

_APP_ORIGIN = "https://app.example.com"
_COOKIE = "saas_os_session"
_TOKEN = "raw-session-token"
_USER_ID = uuid.uuid4()
_SESSION_ID = uuid.uuid4()
_NOT_AUTHORIZED = {"detail": "Not authorized."}


class _FakeSession:
    id = _SESSION_ID
    user_id = _USER_ID


@pytest.fixture
def revoked(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    """Sessions `/auth/logout` actually revoked -- the state change."""
    calls: list[uuid.UUID] = []
    monkeypatch.setattr(
        routes_module, "revoke_session", lambda session_id: calls.append(session_id)
    )
    return calls


@pytest.fixture(autouse=True)
def _configure(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PUBLIC_APP_ORIGIN", raising=False)
    monkeypatch.setenv("OIDC_REDIRECT_URI", f"{_APP_ORIGIN}/auth/callback")
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_auth_http_config.cache_clear()
    monkeypatch.setattr(deps, "validate_session", lambda raw: _FakeSession())
    yield
    get_auth_http_config.cache_clear()


def _app() -> FastAPI:
    app = build_platform_app(title="csrf", version="test")

    @app.post("/probe/actor")
    async def _actor(
        actor_id: uuid.UUID = Depends(deps.get_current_actor),  # noqa: B008 -- FastAPI idiom
    ) -> dict[str, str]:
        return {"actor": str(actor_id)}

    async def _no_rate_limit() -> None:
        return None

    app.dependency_overrides[routes_module._enforce_auth_rate_limit] = _no_rate_limit
    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_app(), base_url="https://testserver")


def _with_cookie(client: TestClient) -> TestClient:
    client.cookies.set(_COOKIE, _TOKEN)
    return client


# --- A legitimate browser request -------------------------------------------------------


def test_same_origin_cookie_mutation_is_accepted(
    client: TestClient, revoked: list[uuid.UUID]
) -> None:
    response = _with_cookie(client).post("/auth/logout", headers={"Origin": _APP_ORIGIN})
    assert response.status_code == 204
    assert revoked == [_SESSION_ID]


@pytest.mark.parametrize(
    "origin",
    ["https://app.example.com", "https://APP.Example.COM", "https://app.example.com:443"],
)
def test_the_trusted_origin_is_compared_as_an_origin_not_as_a_string(
    client: TestClient, revoked: list[uuid.UUID], origin: str
) -> None:
    assert _with_cookie(client).post("/auth/logout", headers={"Origin": origin}).status_code == 204


def test_same_origin_with_the_browsers_own_fetch_metadata_is_accepted(
    client: TestClient, revoked: list[uuid.UUID]
) -> None:
    headers = {"Origin": _APP_ORIGIN, "Sec-Fetch-Site": "same-origin"}
    assert _with_cookie(client).post("/auth/logout", headers=headers).status_code == 204


# --- Forged requests ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        "https://attacker.example.net",  # unrelated site
        "https://evil.example.com",  # sibling subdomain: same site, different origin
        "https://example.com",  # parent domain
        "https://app.example.com.attacker.net",  # look-alike suffix
        "https://app.example.com:8443",  # same host, different port
        "http://app.example.com",  # same host, downgraded scheme
    ],
)
def test_a_cookie_mutation_from_another_origin_is_refused(
    client: TestClient, revoked: list[uuid.UUID], origin: str
) -> None:
    response = _with_cookie(client).post("/auth/logout", headers={"Origin": origin})
    assert response.status_code == 403 and response.json() == _NOT_AUTHORIZED
    assert revoked == []  # nothing changed


def test_a_cookie_mutation_without_an_origin_header_is_refused(
    client: TestClient, revoked: list[uuid.UUID]
) -> None:
    response = _with_cookie(client).post("/auth/logout")
    assert response.status_code == 403 and response.json() == _NOT_AUTHORIZED
    assert revoked == []


@pytest.mark.parametrize(
    "origin",
    [
        "null",  # sandboxed frame, data: URL, some redirects
        "",
        "app.example.com",  # no scheme
        "https://app.example.com/path",  # not an origin
        "https://app.example.com?x=1",
        "https://user:pw@app.example.com",  # pragma: allowlist secret
        "https://app.example.com:notaport",
        "javascript:alert(1)",
        "https://",
    ],
)
def test_a_malformed_origin_header_is_refused(
    client: TestClient, revoked: list[uuid.UUID], origin: str
) -> None:
    response = _with_cookie(client).post("/auth/logout", headers={"Origin": origin})
    assert response.status_code == 403
    assert revoked == []


@pytest.mark.parametrize("fetch_site", ["same-site", "cross-site", "none"])
def test_fetch_metadata_that_is_not_same_origin_is_refused_even_with_a_matching_origin(
    client: TestClient, revoked: list[uuid.UUID], fetch_site: str
) -> None:
    headers = {"Origin": _APP_ORIGIN, "Sec-Fetch-Site": fetch_site}
    assert _with_cookie(client).post("/auth/logout", headers=headers).status_code == 403
    assert revoked == []


def test_the_refusal_is_logged_with_a_reason_and_no_request_value(
    client: TestClient, revoked: list[uuid.UUID], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="saas_os.api.csrf"):
        _with_cookie(client).post("/auth/logout", headers={"Origin": "https://evil.example.com"})
    (record,) = [r for r in caplog.records if r.getMessage() == "csrf_rejected"]
    assert record.csrf_reason == "origin_mismatch"  # type: ignore[attr-defined]
    assert "evil.example.com" not in str(record.__dict__)
    assert _TOKEN not in str(record.__dict__)


# --- What the check must not break --------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},  # a script: no Origin at all
        {"Origin": "https://attacker.example.net"},
        {"Origin": "null", "Sec-Fetch-Site": "cross-site"},
    ],
)
def test_bearer_authenticated_clients_are_unaffected(
    client: TestClient, revoked: list[uuid.UUID], headers: dict[str, str]
) -> None:
    response = client.post("/auth/logout", headers={"Authorization": f"Bearer {_TOKEN}", **headers})
    assert response.status_code == 204
    assert revoked == [_SESSION_ID]


def test_a_bearer_header_wins_even_when_a_cookie_is_also_sent(
    client: TestClient, revoked: list[uuid.UUID]
) -> None:
    response = _with_cookie(client).post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {_TOKEN}", "Origin": "https://attacker.example.net"},
    )
    assert response.status_code == 204


def test_safe_methods_are_not_checked(client: TestClient) -> None:
    response = _with_cookie(client).get(
        "/auth/me", headers={"Origin": "https://attacker.example.net"}
    )
    assert response.status_code == 200 and response.json() == {"user_id": str(_USER_ID)}
    assert _with_cookie(client).get("/auth/me").status_code == 200


def test_a_request_with_no_credential_is_still_a_401_not_a_403(client: TestClient) -> None:
    assert client.post("/auth/logout").status_code == 401
    assert (
        client.post("/probe/actor", headers={"Origin": "https://attacker.example.net"}).status_code
        == 401
    )


def test_a_cookie_with_a_dead_session_from_the_right_origin_is_a_401(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from saas_os.core.identity.errors import SessionRevokedError

    def _dead(raw: str) -> _FakeSession:
        raise SessionRevokedError(_SESSION_ID)

    monkeypatch.setattr(deps, "validate_session", _dead)
    response = _with_cookie(client).post("/auth/logout", headers={"Origin": _APP_ORIGIN})
    assert response.status_code == 401


# --- Both authenticated dependencies, and the configured origin ---------------------------


def test_the_actor_dependency_enforces_it_too(client: TestClient) -> None:
    assert _with_cookie(client).post("/probe/actor").status_code == 403
    ok = _with_cookie(client).post("/probe/actor", headers={"Origin": _APP_ORIGIN})
    assert ok.status_code == 200 and ok.json() == {"actor": str(_USER_ID)}


def test_public_app_origin_is_the_trusted_origin_when_declared(
    monkeypatch: pytest.MonkeyPatch, revoked: list[uuid.UUID]
) -> None:
    monkeypatch.delenv("OIDC_REDIRECT_URI", raising=False)
    monkeypatch.setenv("PUBLIC_APP_ORIGIN", "https://product.example.org")
    get_auth_http_config.cache_clear()
    client = _with_cookie(TestClient(_app(), base_url="https://testserver"))

    assert client.post("/auth/logout", headers={"Origin": _APP_ORIGIN}).status_code == 403
    accepted = client.post("/auth/logout", headers={"Origin": "https://product.example.org"})
    assert accepted.status_code == 204


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://app.example.com", "https://app.example.com"),
        ("HTTPS://App.Example.com:443/", "https://app.example.com"),
        ("http://localhost:8080", "http://localhost:8080"),
        ("http://localhost:80", "http://localhost"),
        ("null", None),
        ("https://app.example.com/x", None),
        ("ftp://app.example.com", None),
        ("https://a@app.example.com", None),
        ("https://app.example.com:99999", None),
    ],
)
def test_origin_normalization(value: str, expected: str | None) -> None:
    assert deps._normalized_origin(value) == expected


# --- Every state-changing capability route -------------------------------------------------

_ID = "00000000-0000-4000-8000-000000000001"
_UNSAFE_ROUTES = [
    ("POST", f"members/{_ID}/suspend"),
    ("POST", f"members/{_ID}/reactivate"),
    ("POST", f"members/{_ID}/revoke"),
    ("POST", "invitations"),
    ("POST", f"invitations/{_ID}/revoke"),
    ("POST", "api-keys"),
    ("POST", f"api-keys/{_ID}/rotate"),
    ("DELETE", f"api-keys/{_ID}"),
    ("POST", "billing/subscriptions"),
    ("POST", f"billing/subscriptions/{_ID}/cancel"),
]


@pytest.fixture
def capability_client() -> TestClient:
    app = build_platform_app(title="csrf capabilities", version="test")
    for router in (
        v1.members_router,
        v1.invitations_router,
        v1.api_keys_router,
        v1.build_billing_router(provider=FakeBillingProvider()),
        v1.usage_router,
    ):
        app.include_router(router)
    return _with_cookie(TestClient(app, base_url="https://testserver"))


def test_the_list_below_is_every_unsafe_capability_route() -> None:
    from saas_os.api.route_policy import assert_route_policies

    app = build_platform_app(title="csrf capabilities", version="test")
    for router in (
        v1.members_router,
        v1.invitations_router,
        v1.api_keys_router,
        v1.build_billing_router(provider=FakeBillingProvider()),
        v1.usage_router,
    ):
        app.include_router(router)
    unsafe = {
        key
        for key in assert_route_policies(app, production=False)
        if " /v1/" in key and not key.startswith("GET ")
    }
    assert len(unsafe) == len(_UNSAFE_ROUTES) == 10


@pytest.mark.parametrize(("method", "path"), _UNSAFE_ROUTES)
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Origin": "https://evil.example.com"},
        {"Origin": "https://attacker.example.net"},
        {"Origin": _APP_ORIGIN, "Sec-Fetch-Site": "same-site"},
    ],
    ids=["no-origin", "sibling-subdomain", "unrelated-site", "same-site-fetch"],
)
def test_every_state_changing_capability_route_refuses_a_forged_cookie_request(
    capability_client: TestClient, method: str, path: str, headers: dict[str, str]
) -> None:
    """Refused by the first dependency in the chain: before tenant
    resolution, rate limiting, authorization, or any database access (there
    is no database in this test)."""
    response = capability_client.request(
        method,
        f"/v1/tenants/{_ID}/{path}",
        json={"name": "x", "email": "a@b.test"},
        headers=headers,
    )
    assert response.status_code == 403 and response.json() == _NOT_AUTHORIZED


# --- Negative control ---------------------------------------------------------------------


def test_without_the_check_the_forged_request_goes_through(
    client: TestClient, revoked: list[uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        deps, "_enforce_same_origin_for_cookie_mutation", lambda request, authorization: None
    )
    response = _with_cookie(client).post(
        "/auth/logout", headers={"Origin": "https://evil.example.com"}
    )
    assert response.status_code == 204
    assert revoked == [_SESSION_ID]
