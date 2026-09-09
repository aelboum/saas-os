"""End-to-end correlation-header tests through the real, fully-authenticated
ingress chain (docs/IMPLEMENTATION-ROADMAP.md P1.4).

`tests/api/test_middleware_unit.py` covers the middleware's own contract
in isolation (no DB/Redis needed); this file proves the same header
survives every response the *real* `api.main.app` produces -- including
every step of `api/dependencies.py`'s enforced chain (authentication ->
tenant resolution -> rate limiting -> RBAC) -- and that a caller cannot
use the correlation header to influence any of those steps.

Marked `integration`; excluded from the default `pytest` run. Run locally
the same way as `tests/api/v1/test_tenant_status_integration.py` (same
module docstring's invocation), plus `REDIS_URL` for rate limiting.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from api.main import app
from api.middleware import CORRELATION_ID_HEADER
from api.v1.tenant_status import ACTION, RESOURCE
from core.identity.service import add_tenant_membership, create_user, get_membership
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
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}.")


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
        self.tenant = create_tenant(_unique("corr-tenant"))
        self.user = create_user()
        self.unauthorized_user = create_user()
        add_tenant_membership(self.tenant.id, self.user.id)
        add_tenant_membership(self.tenant.id, self.unauthorized_user.id)

        role = create_role(self.tenant.id, _unique("corr-role"))
        permission = register_permission(RESOURCE, ACTION)
        grant_permission(self.tenant.id, role.id, permission.id)

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


# --- Header present across every real response status ----------------------


def test_header_present_on_successful_authenticated_request(
    client: TestClient, fx: _Fixture
) -> None:
    response = client.get(
        _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
    )
    assert response.status_code == 200
    assert response.headers.get(CORRELATION_ID_HEADER)


def test_header_present_on_401_unauthenticated(client: TestClient, fx: _Fixture) -> None:
    response = client.get(_status_url(fx.tenant.id))
    assert response.status_code == 401
    assert response.headers.get(CORRELATION_ID_HEADER)


def test_header_present_on_403_unauthorized(client: TestClient, fx: _Fixture) -> None:
    response = client.get(
        _status_url(fx.tenant.id),
        headers={"Authorization": f"Bearer {fx.unauthorized_user_token}"},
    )
    assert response.status_code == 403
    assert response.headers.get(CORRELATION_ID_HEADER)


def test_header_present_on_404_forged_tenant(client: TestClient, fx: _Fixture) -> None:
    response = client.get(
        _status_url(uuid.uuid4()), headers={"Authorization": f"Bearer {fx.user_token}"}
    )
    assert response.status_code == 404
    assert response.headers.get(CORRELATION_ID_HEADER)


def test_header_present_on_429_rate_limited(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "1")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    get_ratelimit_config.cache_clear()
    try:
        headers = {"Authorization": f"Bearer {fx.user_token}"}
        first = client.get(_status_url(fx.tenant.id), headers=headers)
        second = client.get(_status_url(fx.tenant.id), headers=headers)
        assert first.status_code == 200
        assert second.status_code == 429
        assert second.headers.get(CORRELATION_ID_HEADER)
    finally:
        get_ratelimit_config.cache_clear()


# --- Incoming header is honored end-to-end ---------------------------------


def test_valid_incoming_request_id_is_echoed_through_the_full_chain(
    client: TestClient, fx: _Fixture
) -> None:
    response = client.get(
        _status_url(fx.tenant.id),
        headers={
            "Authorization": f"Bearer {fx.user_token}",
            CORRELATION_ID_HEADER: "caller-chosen-id-789",
        },
    )
    assert response.status_code == 200
    assert response.headers[CORRELATION_ID_HEADER] == "caller-chosen-id-789"


# --- Adversarial: correlation ID cannot influence identity/tenant/authz ----


def test_forged_request_id_matching_another_users_id_does_not_authenticate(
    client: TestClient, fx: _Fixture
) -> None:
    """A caller sets X-Request-ID to look like the authorized user's own
    UUID -- must have zero effect; the request is still unauthenticated."""
    response = client.get(
        _status_url(fx.tenant.id),
        headers={CORRELATION_ID_HEADER: str(fx.user.id)},
    )
    assert response.status_code == 401


def test_forged_request_id_does_not_grant_rbac_permission(client: TestClient, fx: _Fixture) -> None:
    """The unauthorized (but authenticated, real-member) user sets
    X-Request-ID to the resource:action string -- must have zero effect on
    the RBAC decision."""
    response = client.get(
        _status_url(fx.tenant.id),
        headers={
            "Authorization": f"Bearer {fx.unauthorized_user_token}",
            CORRELATION_ID_HEADER: f"{RESOURCE}-{ACTION}",
        },
    )
    assert response.status_code == 403


def test_forged_request_id_does_not_bypass_tenant_membership_check(
    client: TestClient, fx: _Fixture
) -> None:
    """X-Request-ID set to a real tenant ID the caller is not a member of
    -- must not grant access to that tenant."""
    other_tenant = create_tenant(_unique("corr-other-tenant"))
    try:
        response = client.get(
            _status_url(other_tenant.id),
            headers={
                "Authorization": f"Bearer {fx.user_token}",
                CORRELATION_ID_HEADER: str(other_tenant.id),
            },
        )
        assert response.status_code == 404
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(other_tenant.id)}
            )


def test_varying_request_id_per_call_does_not_bypass_rate_limiting(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rate limiting is keyed by tenant+path (api/dependencies.py), never
    by request_id -- a caller rotating X-Request-ID on every call must
    still be rate-limited exactly as if it never varied."""
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "2")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    get_ratelimit_config.cache_clear()
    try:
        headers_base = {"Authorization": f"Bearer {fx.user_token}"}
        results = []
        for i in range(3):
            headers = {**headers_base, CORRELATION_ID_HEADER: f"distinct-id-{i}"}
            results.append(client.get(_status_url(fx.tenant.id), headers=headers).status_code)
        assert results == [200, 200, 429]
    finally:
        get_ratelimit_config.cache_clear()


# --- Logging: real request never logs the bearer token ---------------------


def test_real_request_log_line_carries_request_id_and_never_the_session_token(
    client: TestClient, fx: _Fixture, caplog: pytest.LogCaptureFixture
) -> None:
    from infra.observability.config import ObservabilityConfig
    from infra.observability.logging import CorrelationFilter

    caplog.set_level(logging.INFO)
    handler_filter = CorrelationFilter(ObservabilityConfig())
    caplog.handler.addFilter(handler_filter)
    try:
        response = client.get(
            _status_url(fx.tenant.id),
            headers={
                "Authorization": f"Bearer {fx.user_token}",
                CORRELATION_ID_HEADER: "log-proof-id",
            },
        )
    finally:
        caplog.handler.removeFilter(handler_filter)

    assert response.status_code == 200
    matching = [r for r in caplog.records if getattr(r, "request_id", None) == "log-proof-id"]
    assert matching

    for record in caplog.records:
        assert fx.user_token not in record.getMessage()
        for value in vars(record).values():
            assert fx.user_token not in str(value)
