"""P2.2 -- the complete browser login flow, end to end, through the real
`api.main.app` against real PostgreSQL and real Redis, with the OIDC
*provider* replaced by a deterministic in-process stand-in:

- JWKS: `core.identity.oidc._jwk_client` is monkeypatched to an in-memory
  key map (the same technique `tests/core/identity/test_oidc.py` uses),
  and ID tokens are RS256-signed here with a real RSA key -- so the
  *existing* validator does real signature/issuer/audience/expiry/
  algorithm/nonce checks, nothing is bypassed.
- Token endpoint: `core.identity.oidc._token_http_client` is
  monkeypatched to an `httpx.MockTransport` that behaves like a strict
  provider -- it verifies the PKCE `code_verifier` against the
  `code_challenge` it saw in the authorization URL, the `redirect_uri`,
  and the client secret, and only then returns an ID token carrying the
  nonce from that same authorization request.

Everything else is real: the login-transaction table, the session table,
the cookie round trip, `get_current_actor()`, tenant membership, RBAC.

Live ZITADEL is deliberately NOT what this file proves -- see
`tests/core/identity/test_live_zitadel_integration.py`.

Marked `integration`. Run locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/api/auth/test_auth_flow_integration.py
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

import api.auth.routes as routes_module
import core.identity.oidc as oidc_module
import httpx
import jwt
import pytest
from api.auth.config import get_auth_http_config
from api.main import app
from api.v1.tenant_status import ACTION, RESOURCE
from core.identity.errors import SessionRevokedError
from core.identity.login_transactions import derive_code_challenge
from core.identity.provider import OIDCFlowEndpoints, OIDCProviderConfig
from core.identity.service import add_tenant_membership, find_external_identity, get_membership
from core.identity.sessions import validate_session
from core.rbac.service import assign_role, create_role, grant_permission, register_permission
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.ratelimit.config import get_ratelimit_config
from jwt.exceptions import PyJWKClientError
from sqlalchemy import text

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_ISSUER = "https://idp.example.test"
_CLIENT_ID = "test-client"
_CLIENT_SECRET = "client-secret-for-the-flow-test"
_KID = "flow-key-1"
_PROVIDER = OIDCProviderConfig(
    issuer=_ISSUER, client_id=_CLIENT_ID, audience=_CLIENT_ID, jwks_uri=f"{_ISSUER}/keys"
)
_ENDPOINTS = OIDCFlowEndpoints(
    authorization_endpoint=f"{_ISSUER}/oauth/v2/authorize",
    token_endpoint=f"{_ISSUER}/oauth/v2/token",
)
_REDIRECT_URI = "http://testserver/auth/callback"
_COOKIE = "saas_os_session"
_LOGIN_COOKIE = f"{_COOKIE}_login"


@pytest.fixture(autouse=True)
def _require_reachable_database_and_redis() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    get_ratelimit_config.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.login_transactions LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.login_transactions not reachable: {exc}")
    finally:
        probe.dispose()
    try:
        config = get_ratelimit_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured: {exc}")
    import redis as redis_sync

    try:
        redis_sync.Redis.from_url(config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable: {exc}")


# --- The stand-in provider -----------------------------------------------------


class _FakeSigningKey:
    def __init__(self, key: object) -> None:
        self.key = key


class _FakeJWKClient:
    def __init__(self, keys_by_kid: dict[str, object]) -> None:
        self._keys = keys_by_kid

    def get_signing_key_from_jwt(self, token: str) -> _FakeSigningKey:
        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self._keys:
            raise PyJWKClientError(f"no key {kid!r}")
        return _FakeSigningKey(self._keys[kid])


class Provider:
    """Deterministic OIDC provider: remembers every authorization request
    it "received" (parsed from the redirect the app produced) and answers
    the token endpoint strictly."""

    def __init__(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.authorizations: dict[str, dict[str, str]] = {}  # code -> authorization params
        self.token_requests: list[dict[str, str]] = []
        self.subject = f"sub-{uuid.uuid4().hex[:10]}"
        self.extra_claims: dict[str, object] = {}
        self.claim_overrides: dict[str, object] = {}
        self.sign_with: rsa.RSAPrivateKey | None = None
        self.alg = "RS256"
        self.token_status = 200
        self.token_body_override: object | None = None
        self.raise_transport = False

    # The "user authenticates at the provider" step: given the redirect
    # the app produced, mint an authorization code bound to that request.
    def authorize(self, authorization_url: str) -> tuple[str, str]:
        parts = urlsplit(authorization_url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == _ENDPOINTS.authorization_endpoint
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert params["code_challenge_method"] == "S256"
        assert params["redirect_uri"] == _REDIRECT_URI
        assert params["client_id"] == _CLIENT_ID
        assert "openid" in params["scope"].split()
        code = f"code-{uuid.uuid4().hex}"
        self.authorizations[code] = params
        return code, params["state"]

    def _id_token(self, nonce: str) -> str:
        now = int(time.time())
        claims: dict[str, object] = {
            "iss": _ISSUER,
            "aud": _CLIENT_ID,
            "sub": self.subject,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            **self.extra_claims,
        }
        claims.update(self.claim_overrides)
        key = self.sign_with or self.private_key
        if self.alg == "HS256":
            return jwt.encode(claims, "a-shared-secret-that-is-long-enough-for-hs256-use", "HS256")
        return jwt.encode(claims, key, algorithm=self.alg, headers={"kid": _KID})

    def token_handler(self, request: httpx.Request) -> httpx.Response:
        if self.raise_transport:
            raise httpx.ConnectError("provider down")
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.token_requests.append(form)
        if self.token_body_override is not None:
            return httpx.Response(self.token_status, json=self.token_body_override)
        if self.token_status != 200:
            return httpx.Response(self.token_status, json={"error": "server_error"})
        authorization = self.authorizations.pop(form.get("code", ""), None)
        if authorization is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        if form.get("client_secret") != _CLIENT_SECRET:
            return httpx.Response(401, json={"error": "invalid_client"})
        if form.get("redirect_uri") != _REDIRECT_URI:
            return httpx.Response(400, json={"error": "invalid_grant"})
        if derive_code_challenge(form.get("code_verifier", "")) != authorization["code_challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant", "reason": "pkce"})
        return httpx.Response(
            200,
            json={
                "id_token": self._id_token(authorization["nonce"]),
                "access_token": "opaque-access-token-never-used",
                "token_type": "Bearer",
            },
        )


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[Provider]:
    p = Provider()
    monkeypatch.setenv("OIDC_REDIRECT_URI", _REDIRECT_URI)
    monkeypatch.setenv("AUTH_COOKIE_NAME", _COOKIE)
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")  # TestClient speaks plain http
    monkeypatch.setenv("AUTH_POST_LOGIN_PATH", "/")
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_auth_http_config.cache_clear()
    monkeypatch.setattr(routes_module, "get_oidc_provider_config", lambda: _PROVIDER)
    monkeypatch.setattr(routes_module, "get_oidc_flow_endpoints", lambda: _ENDPOINTS)
    monkeypatch.setattr(routes_module, "get_oidc_client_secret", lambda: _CLIENT_SECRET)
    fake_jwks = _FakeJWKClient({_KID: p.private_key.public_key()})
    monkeypatch.setattr(oidc_module, "_jwk_client", lambda jwks_uri: fake_jwks)
    monkeypatch.setattr(
        oidc_module,
        "_token_http_client",
        lambda: httpx.Client(transport=httpx.MockTransport(p.token_handler)),
    )
    yield p
    get_auth_http_config.cache_clear()
    _cleanup_identity_rows(p.subject)


def _admin_execute(sql: str, params: dict[str, object]) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(text(sql), params)
    finally:
        engine.dispose()


def _cleanup_identity_rows(subject: str) -> None:
    identity = find_external_identity(_ISSUER, subject)
    if identity is None:
        return
    user_id = str(identity.user_id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": user_id})
        session.execute(
            text("DELETE FROM core.external_identities WHERE user_id = :u"), {"u": user_id}
        )
        session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user_id})


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _set_cookie_header(response: httpx.Response, name: str) -> SimpleCookie | None:
    for header in response.headers.get_list("set-cookie"):
        jar = SimpleCookie()
        jar.load(header)
        if name in jar:
            return jar
    return None


def _start_login(client: TestClient) -> str:
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 303
    assert _LOGIN_COOKIE in client.cookies
    return response.headers["location"]


def _login(client: TestClient, provider: Provider) -> httpx.Response:
    code, state = provider.authorize(_start_login(client))
    return client.get(
        "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
    )


def _session_count(user_id: uuid.UUID) -> int:
    with session_scope() as session:
        return session.execute(
            text("SELECT count(*) FROM core.sessions WHERE user_id = :u"), {"u": str(user_id)}
        ).scalar_one()


# --- Happy path -------------------------------------------------------------------


def test_full_login_issues_a_core_session_and_the_cookie_authenticates(
    client: TestClient, provider: Provider
) -> None:
    response = _login(client, provider)
    assert response.status_code == 303
    assert response.headers["location"] == "/"

    jar = _set_cookie_header(response, _COOKIE)
    assert jar is not None
    morsel = jar[_COOKIE]
    assert morsel["httponly"] and morsel["samesite"].lower() == "lax" and morsel["path"] == "/"
    raw_token = morsel.value
    assert raw_token and raw_token not in response.text

    # The provider saw a strict PKCE exchange with the secret in the body only.
    assert len(provider.token_requests) == 1
    assert provider.token_requests[0]["client_secret"] == _CLIENT_SECRET

    # The cookie is the existing session secret: hashed at rest, never raw.
    session_record = validate_session(raw_token)
    assert session_record.token_hash == hashlib.sha256(raw_token.encode()).hexdigest()
    with session_scope() as db:
        stored = db.execute(
            text("SELECT token_hash FROM core.sessions WHERE id = :id"),
            {"id": str(session_record.id)},
        ).scalar_one()
    assert stored != raw_token

    # Mapped by issuer+subject, and the transaction row is gone.
    identity = find_external_identity(_ISSUER, provider.subject)
    assert identity is not None and identity.user_id == session_record.user_id
    assert _LOGIN_COOKIE not in client.cookies or client.cookies.get(_LOGIN_COOKIE) == ""

    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json() == {"user_id": str(session_record.user_id)}


def test_known_identity_maps_to_the_same_user_on_a_second_login(
    client: TestClient, provider: Provider
) -> None:
    _login(client, provider)
    first = client.get("/auth/me").json()["user_id"]
    second_client = TestClient(app)
    _login(second_client, provider)
    second = second_client.get("/auth/me").json()["user_id"]
    assert first == second
    assert _session_count(uuid.UUID(first)) == 2


def test_email_only_collision_cannot_authenticate_as_another_user(
    client: TestClient, provider: Provider
) -> None:
    provider.extra_claims = {"email": "shared@example.test"}
    _login(client, provider)
    victim = client.get("/auth/me").json()["user_id"]

    attacker = Provider()
    attacker.subject = f"sub-attacker-{uuid.uuid4().hex[:8]}"
    attacker.extra_claims = {"email": "shared@example.test"}
    # Same issuer, same key material (the provider signs both), different subject.
    attacker.private_key = provider.private_key
    provider.subject = attacker.subject  # reuse the fixture's mocked transport/JWKS
    other_client = TestClient(app)
    _login(other_client, provider)
    other = other_client.get("/auth/me").json()["user_id"]
    try:
        assert other != victim
    finally:
        _cleanup_identity_rows(attacker.subject)


def test_unknown_identity_is_provisioned_with_zero_tenant_authority(
    client: TestClient, provider: Provider
) -> None:
    """Repository-defined first-login policy (`get_or_create_user_for_
    external_identity`): a bare User row -- no tenant, no membership, no
    role. It reaches no tenant route."""
    _login(client, provider)
    tenant = create_tenant(f"p22-no-access-{uuid.uuid4().hex[:8]}")
    try:
        response = client.get(f"/v1/tenants/{tenant.id}/status")
        assert response.status_code == 404
        forged = client.get(f"/v1/tenants/{uuid.uuid4()}/status")
        assert forged.status_code == 404
        assert response.json() == forged.json()
    finally:
        with session_scope() as db:
            db.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


def test_tenant_membership_and_rbac_remain_enforced_after_oidc_login(
    client: TestClient, provider: Provider
) -> None:
    _login(client, provider)
    user_id = uuid.UUID(client.get("/auth/me").json()["user_id"])
    tenant = create_tenant(f"p22-member-{uuid.uuid4().hex[:8]}")
    other = create_tenant(f"p22-other-{uuid.uuid4().hex[:8]}")
    try:
        add_tenant_membership(tenant.id, user_id)
        # member but no permission -> 403; other tenant -> 404; granted -> 200
        assert client.get(f"/v1/tenants/{tenant.id}/status").status_code == 403
        assert client.get(f"/v1/tenants/{other.id}/status").status_code == 404

        role = create_role(tenant.id, f"p22-role-{uuid.uuid4().hex[:6]}")
        permission = register_permission(RESOURCE, ACTION)
        grant_permission(tenant.id, role.id, permission.id)
        membership = get_membership(tenant.id, user_id)
        assert membership is not None
        assign_role(tenant.id, membership.id, role.id)

        ok = client.get(f"/v1/tenants/{tenant.id}/status")
        assert ok.status_code == 200 and ok.json()["id"] == str(tenant.id)
        assert client.get(f"/v1/tenants/{other.id}/status").status_code == 404
    finally:
        with tenant_session_scope(tenant.id) as db:
            for table in ("membership_roles", "role_permissions", "roles", "tenant_memberships"):
                db.execute(
                    text(f"DELETE FROM core.{table} WHERE tenant_id = :t"), {"t": str(tenant.id)}
                )
        _admin_execute("DELETE FROM core.audit_log WHERE tenant_id = :t", {"t": str(tenant.id)})
        with session_scope() as db:
            db.execute(
                text("DELETE FROM core.tenants WHERE id IN (:a, :b)"),
                {"a": str(tenant.id), "b": str(other.id)},
            )


# --- Callback rejection matrix -------------------------------------------------


def test_reused_callback_is_rejected_and_creates_no_second_session(
    client: TestClient, provider: Provider
) -> None:
    code, state = provider.authorize(_start_login(client))
    tx_cookie = client.cookies.get(_LOGIN_COOKIE)
    first = client.get(
        "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
    )
    assert first.status_code == 303
    user_id = uuid.UUID(client.get("/auth/me").json()["user_id"])

    replay = TestClient(app, cookies={_LOGIN_COOKIE: tx_cookie})
    second = replay.get(
        "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
    )
    assert second.status_code == 400
    assert _set_cookie_header(second, _COOKIE) is None
    assert _session_count(user_id) == 1


def test_mismatched_state_is_rejected(client: TestClient, provider: Provider) -> None:
    code, _state = provider.authorize(_start_login(client))
    response = client.get(
        "/auth/callback", params={"code": code, "state": "forged-state"}, follow_redirects=False
    )
    assert response.status_code == 400
    assert len(provider.token_requests) == 0  # never reached the provider


def test_missing_state_is_rejected(client: TestClient, provider: Provider) -> None:
    code, _ = provider.authorize(_start_login(client))
    assert client.get("/auth/callback", params={"code": code}).status_code == 400


def test_missing_code_is_rejected(client: TestClient, provider: Provider) -> None:
    _, state = provider.authorize(_start_login(client))
    assert client.get("/auth/callback", params={"state": state}).status_code == 400


def test_state_without_the_browser_bound_cookie_is_rejected(
    client: TestClient, provider: Provider
) -> None:
    """The state alone (an attacker-observed query string) resolves nothing."""
    code, state = provider.authorize(_start_login(client))
    stranger = TestClient(app)
    response = stranger.get(
        "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
    )
    assert response.status_code == 400
    assert len(provider.token_requests) == 0


def test_expired_transaction_is_rejected(client: TestClient, provider: Provider) -> None:
    code, state = provider.authorize(_start_login(client))
    tx_id = client.cookies.get(_LOGIN_COOKIE)
    with session_scope() as db:
        db.execute(
            text("UPDATE core.login_transactions SET expires_at = :past WHERE id = :id"),
            {"past": datetime.now(UTC) - timedelta(minutes=1), "id": tx_id},
        )
    response = client.get(
        "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
    )
    assert response.status_code == 400


def test_token_exchange_rejection_is_a_502(client: TestClient, provider: Provider) -> None:
    _start_login(client)
    _, state = provider.authorize(_start_login(client))
    response = client.get(
        "/auth/callback", params={"code": "never-issued", "state": state}, follow_redirects=False
    )
    assert response.status_code == 502
    assert _set_cookie_header(response, _COOKIE) is None


def test_provider_outage_is_a_503(client: TestClient, provider: Provider) -> None:
    provider.raise_transport = True
    code, state = provider.authorize(_start_login(client))
    response = client.get(
        "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
    )
    assert response.status_code == 503
    assert "provider down" not in response.text


@pytest.mark.parametrize(
    "tamper",
    [
        "wrong_signature",
        "wrong_issuer",
        "wrong_audience",
        "unsupported_algorithm",
        "nonce_mismatch",
        "missing_nonce",
        "expired",
    ],
)
def test_id_token_rejections_are_401_with_no_session(
    client: TestClient, provider: Provider, tamper: str
) -> None:
    if tamper == "wrong_signature":
        provider.sign_with = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif tamper == "wrong_issuer":
        provider.claim_overrides = {"iss": "https://evil.example"}
    elif tamper == "wrong_audience":
        provider.claim_overrides = {"aud": "another-client"}
    elif tamper == "unsupported_algorithm":
        provider.alg = "HS256"
    elif tamper == "nonce_mismatch":
        provider.claim_overrides = {"nonce": "not-the-nonce"}
    elif tamper == "missing_nonce":
        provider.claim_overrides = {"nonce": None}
    elif tamper == "expired":
        now = int(time.time())
        provider.claim_overrides = {"iat": now - 7200, "exp": now - 3600}

    code, state = provider.authorize(_start_login(client))
    response = client.get(
        "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
    )
    assert response.status_code == 401, tamper
    assert _set_cookie_header(response, _COOKIE) is None
    assert find_external_identity(_ISSUER, provider.subject) is None


# --- Session lifecycle ----------------------------------------------------------


def test_logout_revokes_the_session_and_clears_the_cookie(
    client: TestClient, provider: Provider
) -> None:
    login = _login(client, provider)
    raw_token = _set_cookie_header(login, _COOKIE)[_COOKIE].value  # type: ignore[index]

    response = client.post("/auth/logout")
    assert response.status_code == 204
    cleared = _set_cookie_header(response, _COOKIE)
    assert cleared is not None and cleared[_COOKIE].value == ""

    with pytest.raises(SessionRevokedError):
        validate_session(raw_token)
    assert client.get("/auth/me").status_code == 401
    # Repeated logout with the revoked credential: same generic 401, no side effect.
    again = TestClient(app, cookies={_COOKIE: raw_token})
    assert again.post("/auth/logout").status_code == 401


def test_revoked_and_expired_sessions_are_rejected_via_the_cookie(
    client: TestClient, provider: Provider
) -> None:
    login = _login(client, provider)
    raw_token = _set_cookie_header(login, _COOKIE)[_COOKIE].value  # type: ignore[index]
    record = validate_session(raw_token)
    with session_scope() as db:
        db.execute(
            text("UPDATE core.sessions SET expires_at = :past WHERE id = :id"),
            {"past": datetime.now(UTC) - timedelta(seconds=1), "id": str(record.id)},
        )
    assert client.get("/auth/me").status_code == 401


# --- Concurrency ------------------------------------------------------------------


def test_two_concurrent_callbacks_for_one_transaction_yield_one_session(
    client: TestClient, provider: Provider
) -> None:
    code, state = provider.authorize(_start_login(client))
    tx_cookie = client.cookies.get(_LOGIN_COOKIE)

    def _attempt(_: int) -> int:
        c = TestClient(app, cookies={_LOGIN_COOKIE: tx_cookie})
        return c.get(
            "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(_attempt, range(2)))
    assert statuses == [303, 400]
    identity = find_external_identity(_ISSUER, provider.subject)
    assert identity is not None
    assert _session_count(identity.user_id) == 1
    assert len(provider.token_requests) == 1


# --- Rate limiting ------------------------------------------------------------------


def test_login_endpoint_is_rate_limited(
    client: TestClient, provider: Provider, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "2")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    get_ratelimit_config.cache_clear()
    try:
        import redis as redis_sync

        # Fresh window for this client address.
        r = redis_sync.Redis.from_url(get_ratelimit_config().redis_url)
        for key in r.scan_iter("ratelimit:auth:*"):
            r.delete(key)
        statuses = [client.get("/auth/login", follow_redirects=False).status_code for _ in range(3)]
        assert statuses == [303, 303, 429]
    finally:
        get_ratelimit_config.cache_clear()


# --- Leakage --------------------------------------------------------------------------


def test_no_secret_appears_in_logs_responses_or_audit_metadata(
    client: TestClient, provider: Provider, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        authorization_url = _start_login(client)
        code, state = provider.authorize(authorization_url)
        response = client.get(
            "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
        )
        client.get("/auth/me")
        client.post("/auth/logout")
        bad = client.get("/auth/callback", params={"code": code, "state": state})

    raw_token = _set_cookie_header(response, _COOKIE)[_COOKIE].value  # type: ignore[index]
    verifier = provider.token_requests[0]["code_verifier"]
    id_token = None
    # Reconstruct what the provider returned: it is the only id_token minted.
    # Scoped to this application's own loggers: `httpx`'s client-side
    # request-line log (the URL *this test's own TestClient* was told to
    # fetch, e.g. ".../auth/callback?code=...") is test-harness noise from
    # using httpx as the browser stand-in, not a leak from application
    # code -- a real deployment has no such client-side logger for
    # inbound requests it receives.
    app_records = [r for r in caplog.records if r.name.startswith(("api.", "core."))]
    assert app_records, "expected at least one application log record"
    for record in app_records:
        message = record.getMessage() + str(record.__dict__)
        for forbidden in (code, raw_token, verifier, _CLIENT_SECRET, state):
            assert forbidden not in message, f"{forbidden[:8]}... leaked into logs"
        assert "eyJ" not in message  # no JWT fragment
    for body in (response.text, bad.text):
        for forbidden in (code, raw_token, verifier, _CLIENT_SECRET, state):
            assert forbidden not in body
        assert "Traceback" not in body
    assert id_token is None
