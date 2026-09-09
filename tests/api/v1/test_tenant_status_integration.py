"""End-to-end integration tests for the ingress middleware chain +
first external route (docs/IMPLEMENTATION-ROADMAP.md Phase 8.1's own
Tests: "an unauthenticated request to a protected route is rejected; an
authenticated-but-unauthorized request is rejected; a valid request
passes through with correct identity context attached"; Phase 8.2's own
Tests: "end-to-end test hitting the real route through the real
middleware chain; OpenAPI spec validated against the actual response
shape").

Uses FastAPI's `TestClient` against the real `api.main.app` ASGI
application -- every request genuinely traverses authentication, tenant
resolution, rate limiting, and RBAC authorization against real
PostgreSQL and real Redis (this checkpoint's own Step 18: "Do not rely
entirely on mocks for security boundaries").

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/api/v1/test_tenant_status_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from api.main import app
from api.v1.tenant_status import ACTION, RESOURCE
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_user
from core.identity.sessions import issue_session
from core.rbac.service import assign_role, create_role, grant_permission, register_permission
from fastapi.testclient import TestClient
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.ratelimit.config import get_ratelimit_config
from sqlalchemy import text

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


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

    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.membership_roles LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.membership_roles not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()

    try:
        config = get_ratelimit_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")

    import redis as redis_sync

    try:
        redis_sync.Redis.from_url(config.redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Redis not reachable at the configured REDIS_URL: {exc}. "
            "Run `docker compose up -d redis` first."
        )


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique("api-tenant"))
        self.user = create_user()  # granted the required permission
        self.unauthorized_user = create_user()  # a member, but no permission grant
        add_tenant_membership(self.tenant.id, self.user.id)
        add_tenant_membership(self.tenant.id, self.unauthorized_user.id)

        role = create_role(self.tenant.id, _unique("tenant-status-role"))
        permission = register_permission(RESOURCE, ACTION)
        grant_permission(self.tenant.id, role.id, permission.id)

        from core.identity.service import get_membership

        membership = get_membership(self.tenant.id, self.user.id)
        assert membership is not None
        assign_role(self.tenant.id, membership.id, role.id)

        _, self.user_token = issue_session(self.user.id)
        _, self.unauthorized_user_token = issue_session(self.unauthorized_user.id)

    def cleanup(self) -> None:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.sessions WHERE user_id IN (:a, :b)"),
                {"a": str(self.user.id), "b": str(self.unauthorized_user.id)},
            )
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.membership_roles WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.role_permissions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(self.tenant.id)}
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id IN (:a, :b)"),
                {"a": str(self.user.id), "b": str(self.unauthorized_user.id)},
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _status_url(tenant_id: uuid.UUID) -> str:
    return f"/v1/tenants/{tenant_id}/status"


# --- Phase 8.1 Tests: unauthenticated / unauthorized / valid ---------------


def test_unauthenticated_request_is_rejected(client: TestClient, fx: _Fixture) -> None:
    response = client.get(_status_url(fx.tenant.id))
    assert response.status_code == 401


def test_malformed_authorization_header_is_rejected(client: TestClient, fx: _Fixture) -> None:
    response = client.get(
        _status_url(fx.tenant.id), headers={"Authorization": "NotBearer sometoken"}
    )
    assert response.status_code == 401


def test_invalid_session_token_is_rejected(client: TestClient, fx: _Fixture) -> None:
    response = client.get(
        _status_url(fx.tenant.id), headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert response.status_code == 401


def test_authenticated_but_unauthorized_request_is_rejected(
    client: TestClient, fx: _Fixture
) -> None:
    response = client.get(
        _status_url(fx.tenant.id),
        headers={"Authorization": f"Bearer {fx.unauthorized_user_token}"},
    )
    assert response.status_code == 403


def test_valid_request_passes_through_with_correct_identity(
    client: TestClient, fx: _Fixture
) -> None:
    response = client.get(
        _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(fx.tenant.id)
    assert body["status"] == "pending"


# --- Phase 8.2 Tests: /v1/, OpenAPI, valid/invalid auth ---------------------


def test_route_is_served_under_v1(client: TestClient, fx: _Fixture) -> None:
    response = client.get(
        _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
    )
    assert response.status_code == 200
    assert response.request.url.path.startswith("/v1/")


def test_route_is_documented_in_the_openapi_spec(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert "/v1/tenants/{tenant_id}/status" in spec["paths"]
    assert "get" in spec["paths"]["/v1/tenants/{tenant_id}/status"]


def test_openapi_response_shape_matches_the_actual_response(
    client: TestClient, fx: _Fixture
) -> None:
    spec = client.get("/openapi.json").json()
    response_schema_ref = spec["paths"]["/v1/tenants/{tenant_id}/status"]["get"]["responses"][
        "200"
    ]["content"]["application/json"]["schema"]
    # Resolve the $ref to the actual component schema.
    schema_name = response_schema_ref["$ref"].split("/")[-1]
    schema = spec["components"]["schemas"][schema_name]
    documented_fields = set(schema["properties"].keys())

    response = client.get(
        _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
    )
    actual_fields = set(response.json().keys())
    assert actual_fields == documented_fields


# --- Tenant resolution: forged/wrong/missing tenant, non-enumeration -------


def test_forged_nonexistent_tenant_returns_404(client: TestClient, fx: _Fixture) -> None:
    response = client.get(
        _status_url(uuid.uuid4()), headers={"Authorization": f"Bearer {fx.user_token}"}
    )
    assert response.status_code == 404


def test_real_tenant_without_membership_returns_the_same_404_as_nonexistent(
    client: TestClient, fx: _Fixture
) -> None:
    """Non-enumeration proof: a caller cannot distinguish "this tenant
    doesn't exist" from "this tenant exists but I'm not a member" --
    both responses are byte-identical."""
    other_tenant = create_tenant(_unique("api-other-tenant"))
    try:
        forged_response = client.get(
            _status_url(uuid.uuid4()), headers={"Authorization": f"Bearer {fx.user_token}"}
        )
        wrong_tenant_response = client.get(
            _status_url(other_tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
        )
        assert forged_response.status_code == wrong_tenant_response.status_code == 404
        assert forged_response.json() == wrong_tenant_response.json()
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(other_tenant.id)}
            )


def test_membership_removed_after_session_issued_loses_access(
    client: TestClient, fx: _Fixture
) -> None:
    """A user's session remains valid, but their tenant membership is
    removed -- the request must be denied (same 404 as never having been
    a member), proving tenant context is re-validated on every request,
    never cached in the session."""
    with tenant_session_scope(fx.tenant.id) as session:
        session.execute(
            text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t AND user_id = :u"),
            {"t": str(fx.tenant.id), "u": str(fx.unauthorized_user.id)},
        )
    response = client.get(
        _status_url(fx.tenant.id),
        headers={"Authorization": f"Bearer {fx.unauthorized_user_token}"},
    )
    assert response.status_code == 404
    # restore for fixture cleanup's own membership-role deletion pass
    add_tenant_membership(fx.tenant.id, fx.unauthorized_user.id)


# --- Audit ---------------------------------------------------------------


def test_authorization_denial_is_audited(client: TestClient, fx: _Fixture) -> None:
    client.get(
        _status_url(fx.tenant.id),
        headers={"Authorization": f"Bearer {fx.unauthorized_user_token}"},
    )
    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "api.access_denied"]
    assert len(matching) == 1
    assert matching[0].actor_user_id == fx.unauthorized_user.id
    assert matching[0].outcome == "denied"
    assert matching[0].resource_id == f"{RESOURCE}:{ACTION}"


def test_successful_read_is_not_audited(client: TestClient, fx: _Fixture) -> None:
    client.get(_status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"})
    entries = list_audit_entries(fx.tenant.id)
    assert entries == []


def test_audit_entries_never_carry_the_session_token(client: TestClient, fx: _Fixture) -> None:
    client.get(
        _status_url(fx.tenant.id),
        headers={"Authorization": f"Bearer {fx.unauthorized_user_token}"},
    )
    entries = list_audit_entries(fx.tenant.id)
    for entry in entries:
        assert fx.unauthorized_user_token not in str(entry.entry_metadata)


# --- Error responses never leak internals -----------------------------


def test_error_responses_never_leak_a_stack_trace_or_sql(client: TestClient, fx: _Fixture) -> None:
    response = client.get(_status_url(fx.tenant.id))
    body = response.text
    assert "Traceback" not in body
    assert "SELECT" not in body
    assert "sqlalchemy" not in body.lower()


# --- Rate limiting ---------------------------------------------------------


def test_rate_limit_exceeded_returns_429_with_retry_after(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "2")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    get_ratelimit_config.cache_clear()
    try:
        headers = {"Authorization": f"Bearer {fx.user_token}"}
        first = client.get(_status_url(fx.tenant.id), headers=headers)
        second = client.get(_status_url(fx.tenant.id), headers=headers)
        third = client.get(_status_url(fx.tenant.id), headers=headers)

        assert first.status_code == 200
        assert second.status_code == 200
        assert third.status_code == 429
        assert "Retry-After" in third.headers
    finally:
        get_ratelimit_config.cache_clear()
