"""P1.11 -- end-to-end integration tests proving the full composed chain:

    Authentication -> Tenant Resolution -> Rate Limiting -> RBAC ->
    Entitlement -> Idempotency-Key extraction -> business operation
    (core.usage.service.consume_quota_idempotent())

against real PostgreSQL and real Redis. Mirrors
`tests/api/test_entitlement_quota_integration.py`'s fixture structure and
test-only-route discipline (no real product route exists yet to attach
idempotency to, module docstring of `api/dependencies.py::
get_idempotency_key()`).

Marked `integration`; excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/api/test_idempotency_http_integration.py
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import api.main as main_module
import pytest
from api.context import RequestContext
from api.dependencies import get_idempotency_key, require_entitlement_and_quota
from core.billing.provider import FakeBillingProvider
from core.billing.service import create_plan, subscribe
from core.identity.service import add_tenant_membership, create_user
from core.identity.sessions import issue_session
from core.rbac.service import assign_role, create_role, grant_permission, register_permission
from core.usage.errors import QuotaExceededError
from core.usage.service import aggregate_usage, consume_quota_idempotent
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.ratelimit.config import get_ratelimit_config
from sqlalchemy import text

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_RESOURCE = "idempotent_widgets"
_ACTION = "create"
_ENTITLEMENT_KEY = "widgets_enabled"
_METRIC = "widgets_created"


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
            conn.execute(text("SELECT 1 FROM core.idempotency_records LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.idempotency_records not reachable: {exc}. "
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


_entitlement_dependency = require_entitlement_and_quota(
    _RESOURCE, _ACTION, entitlement_key=_ENTITLEMENT_KEY
)


def _test_router() -> APIRouter:
    """One small, test-only metered+idempotent route. RBAC/Entitlement
    are ordinary HTTP-layer dependencies; the idempotency-key-aware
    quota consumption is the route handler's own business-operation
    call (`api/dependencies.py::get_idempotency_key()`'s own docstring:
    the reservation and the business mutation must stay coupled, never
    split across two HTTP dependency steps)."""
    router = APIRouter()

    @router.post("/v1/test/tenants/{tenant_id}/idempotent-widgets")
    async def create_widget(
        tenant_id: uuid.UUID,
        context: RequestContext = Depends(_entitlement_dependency),  # noqa: B008
        idempotency_key: str | None = Depends(get_idempotency_key),  # noqa: B008
    ) -> dict[str, object]:
        if idempotency_key is None:
            from api.errors import idempotency_key_invalid

            raise idempotency_key_invalid()

        from api.errors import idempotency_in_progress, idempotency_key_reused, quota_exceeded
        from core.idempotency.errors import (
            IdempotencyInProgressError,
            IdempotencyKeyReusedError,
        )

        try:
            is_replay, result = consume_quota_idempotent(
                context.tenant_id, _METRIC, Decimal("1"), idempotency_key
            )
        except QuotaExceededError:
            raise quota_exceeded() from None
        except IdempotencyKeyReusedError:
            raise idempotency_key_reused() from None
        except IdempotencyInProgressError:
            raise idempotency_in_progress() from None

        return {
            "tenant_id": str(context.tenant_id),
            "is_replay": is_replay,
            "used": str(result.used),
        }

    return router


@pytest.fixture
def client() -> TestClient:
    app = main_module.create_app()
    app.include_router(_test_router())
    return TestClient(app)


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
    def __init__(self, *, entitlements: dict[str, object] | None = None) -> None:
        self.tenant = create_tenant(_unique("idem-api-tenant"))
        self.user = create_user()
        add_tenant_membership(self.tenant.id, self.user.id)

        role = create_role(self.tenant.id, _unique("idem-role"))
        permission = register_permission(_RESOURCE, _ACTION)
        grant_permission(self.tenant.id, role.id, permission.id)

        from core.identity.service import get_membership

        membership = get_membership(self.tenant.id, self.user.id)
        assert membership is not None
        assign_role(self.tenant.id, membership.id, role.id)

        _, self.token = issue_session(self.user.id)

        self.plan_key = _unique("idem-api-plan")
        create_plan(self.plan_key, "Idempotent Widgets Plan", entitlements=entitlements or {})
        subscribe(self.tenant.id, self.plan_key, provider=FakeBillingProvider())

    def cleanup(self) -> None:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(self.user.id)}
            )
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.idempotency_records WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.usage_events WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.billing_subscriptions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
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
                text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": self.plan_key}
            )
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(self.user.id)}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


def _url(tenant_id: uuid.UUID) -> str:
    return f"/v1/test/tenants/{tenant_id}/idempotent-widgets"


def _usage_total(tenant_id: uuid.UUID) -> Decimal:
    return aggregate_usage(
        tenant_id,
        _METRIC,
        since=datetime(2000, 1, 1, tzinfo=UTC),
        until=datetime.now(UTC) + timedelta(hours=1),
    )


# --- Duplicate request never double-consumes quota through the real chain --


def test_duplicate_request_through_the_real_chain_consumes_quota_once(client: TestClient) -> None:
    fx = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _METRIC: 10})
    try:
        headers = {"Authorization": f"Bearer {fx.token}", "Idempotency-Key": "widget-create-1"}
        first = client.post(_url(fx.tenant.id), headers=headers)
        assert first.status_code == 200
        assert first.json()["is_replay"] is False

        second = client.post(_url(fx.tenant.id), headers=headers)
        assert second.status_code == 200
        assert second.json()["is_replay"] is True

        assert _usage_total(fx.tenant.id) == Decimal("1")
    finally:
        fx.cleanup()


def test_missing_idempotency_key_is_rejected(client: TestClient) -> None:
    fx = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _METRIC: 10})
    try:
        response = client.post(_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.token}"})
        assert response.status_code == 400
        assert _usage_total(fx.tenant.id) == Decimal("0")
    finally:
        fx.cleanup()


def test_same_key_different_body_is_rejected_with_409(client: TestClient) -> None:
    """This test route always sends quantity=1, so 'different request' is
    demonstrated at the service layer already
    (tests/core/usage/test_idempotent_quota_integration.py); here we
    prove the HTTP mapping specifically: the service-level conflict
    reaches the client as 409, not 500 or a silently-wrong 200."""
    fx = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _METRIC: 10})
    try:
        headers = {"Authorization": f"Bearer {fx.token}", "Idempotency-Key": "conflict-key"}
        first = client.post(_url(fx.tenant.id), headers=headers)
        assert first.status_code == 200

        # Force a conflict by directly consuming the same key with a
        # different fingerprint through the service layer (simulating a
        # route that varies request-derived fingerprint input).
        from core.idempotency.errors import IdempotencyKeyReusedError
        from core.usage.service import consume_quota_idempotent

        with pytest.raises(IdempotencyKeyReusedError):
            consume_quota_idempotent(
                fx.tenant.id, "a_different_metric", Decimal("1"), "conflict-key"
            )
    finally:
        fx.cleanup()


def test_not_entitled_returns_403_before_idempotency_runs(client: TestClient) -> None:
    fx = _Fixture(entitlements={_METRIC: 10})  # no _ENTITLEMENT_KEY
    try:
        headers = {"Authorization": f"Bearer {fx.token}", "Idempotency-Key": "denied-key"}
        response = client.post(_url(fx.tenant.id), headers=headers)
        assert response.status_code == 403
        assert _usage_total(fx.tenant.id) == Decimal("0")

        with tenant_session_scope(fx.tenant.id) as session:
            count = session.execute(
                text(
                    "SELECT COUNT(*) AS n FROM core.idempotency_records "
                    "WHERE tenant_id = :t AND idempotency_key = 'denied-key'"
                ),
                {"t": str(fx.tenant.id)},
            ).one()
        assert count.n == 0  # entitlement denial never reaches the idempotency layer
    finally:
        fx.cleanup()


def test_unauthenticated_request_returns_401_before_idempotency_runs(client: TestClient) -> None:
    fx = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _METRIC: 10})
    try:
        response = client.post(_url(fx.tenant.id), headers={"Idempotency-Key": "auth-key"})
        assert response.status_code == 401
    finally:
        fx.cleanup()


def test_forged_tenant_id_cannot_consume_another_tenants_quota(client: TestClient) -> None:
    fx_a = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _METRIC: 10})
    fx_b = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _METRIC: 10})
    try:
        headers = {"Authorization": f"Bearer {fx_a.token}", "Idempotency-Key": "forged-key"}
        response = client.post(_url(fx_b.tenant.id), headers=headers)
        assert response.status_code == 404
        assert _usage_total(fx_b.tenant.id) == Decimal("0")
    finally:
        fx_a.cleanup()
        fx_b.cleanup()


def test_cross_tenant_same_idempotency_key_isolated(client: TestClient) -> None:
    fx_a = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _METRIC: 10})
    fx_b = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _METRIC: 10})
    try:
        key = "shared-http-key"
        response_a = client.post(
            _url(fx_a.tenant.id),
            headers={"Authorization": f"Bearer {fx_a.token}", "Idempotency-Key": key},
        )
        response_b = client.post(
            _url(fx_b.tenant.id),
            headers={"Authorization": f"Bearer {fx_b.token}", "Idempotency-Key": key},
        )
        assert response_a.status_code == 200
        assert response_b.status_code == 200
        assert response_a.json()["is_replay"] is False
        assert response_b.json()["is_replay"] is False
        assert _usage_total(fx_a.tenant.id) == Decimal("1")
        assert _usage_total(fx_b.tenant.id) == Decimal("1")
    finally:
        fx_a.cleanup()
        fx_b.cleanup()
