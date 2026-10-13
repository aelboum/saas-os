"""P1.9 -- end-to-end integration tests for
`saas_os.api.dependencies.require_entitlement_and_quota()` through the real
ingress chain (Authentication -> Tenant Resolution -> Rate Limiting ->
RBAC -> Entitlement -> Quota) against real PostgreSQL and real Redis.
Mirrors `tests/api/v1/test_tenant_status_integration.py`'s fixture
structure and discipline (real role/permission/session, no mocks for
security boundaries).

`saas_os/api/v1/tenant_status.py` is the repository's one shipped route and is
deliberately unmetered (docs/API-ARCHITECTURE.md: read-only status
check) -- this file mounts one small, test-only route on top of the real
`saas_os.api.main.app` FastAPI instance (via `create_app()`, not the shared
module-level singleton, so no other test session sees it) that uses
`require_entitlement_and_quota()` exactly the way a future product route
would, proving the dependency is genuinely reusable rather than
special-cased for one route.

Marked `integration`; excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/api/test_entitlement_quota_integration.py
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from sqlalchemy import text

import saas_os.api.main as main_module
from lifecycle_callers import PROVISIONING
from saas_os.api.context import RequestContext
from saas_os.api.dependencies import require_entitlement_and_quota
from saas_os.core.audit_log.service import list as list_audit_entries
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import create_plan, subscribe
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.identity.sessions import issue_session
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import create_tenant
from saas_os.core.usage.service import aggregate_usage
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope
from saas_os.infra.ratelimit.config import get_ratelimit_config


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from sqlalchemy import text

    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine
    from saas_os.infra.db.session import build_session_factory, session_scope

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
            # ADR-0045 Phase C: lifecycle changes also write platform audit
            # rows, which reference the tenant or the acting user and which
            # the runtime role can never delete.
            platform_where = (
                "target_tenant_id::text = ANY(:v)"
                if table == "tenants"
                else "actor_user_id::text = ANY(:v)"
            )
            # A migration test may be cleaning up below the revision that
            # creates the table.
            if session.execute(text("SELECT to_regclass('core.platform_audit_log')")).scalar():
                session.execute(
                    text(f"DELETE FROM core.platform_audit_log WHERE {platform_where}"),  # noqa: S608
                    {"v": values},
                )
    finally:
        engine.dispose()


_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

pytestmark = pytest.mark.integration

_RESOURCE = "widgets"
_ACTION = "consume"
_ENTITLEMENT_KEY = "widgets_enabled"
_QUOTA_METRIC = "widgets_created"


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
            conn.execute(text("SELECT 1 FROM core.billing_subscriptions LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.billing_subscriptions not reachable: {exc}. "
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


_widget_dependency = require_entitlement_and_quota(
    _RESOURCE, _ACTION, entitlement_key=_ENTITLEMENT_KEY, quota_metric=_QUOTA_METRIC
)


def _test_router() -> APIRouter:
    """One small, test-only metered route -- exercises
    `require_entitlement_and_quota()` exactly the way a future real
    product route would. `_widget_dependency` is built once at module
    scope (not inline in the signature below) purely to avoid a
    `Depends(...)` call in an argument default outside `saas_os/api/**` --
    `pyproject.toml`'s per-file B008 ignore is scoped to `saas_os/api/**/*.py`
    only, since that is the one place this FastAPI-idiomatic pattern is
    actually exercised in production code."""
    router = APIRouter()

    @router.post("/v1/test/tenants/{tenant_id}/widgets")
    async def create_widget(
        tenant_id: uuid.UUID,
        context: RequestContext = Depends(_widget_dependency),  # noqa: B008
    ) -> dict[str, str]:
        return {"tenant_id": str(context.tenant_id)}

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
        self.tenant = create_tenant(_unique("quota-api-tenant"), caller=PROVISIONING)
        self.user = create_user()
        add_tenant_membership(self.tenant.id, self.user.id, caller=_PROVISIONING)

        role = create_role(self.tenant.id, _unique("quota-role"), caller=_PROVISIONING)
        permission = register_permission(_RESOURCE, _ACTION)
        grant_permission(self.tenant.id, role.id, permission.id, caller=_PROVISIONING)

        from saas_os.core.identity.service import get_membership

        membership = get_membership(self.tenant.id, self.user.id)
        assert membership is not None
        assign_first_role_for_new_tenant(
            self.tenant.id, membership.id, role.id, caller=_PROVISIONING
        )

        _, self.token = issue_session(self.user.id)

        self.plan_key = _unique("quota-api-plan")
        create_plan(self.plan_key, "Widgets Plan", entitlements=entitlements or {})
        subscribe(self.tenant.id, self.plan_key, provider=FakeBillingProvider())

    def cleanup(self) -> None:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(self.user.id)}
            )
        with tenant_session_scope(self.tenant.id) as session:
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
            _admin_clear_audit_references({"id": str(self.user.id)}, table="users")
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(self.user.id)}
            )
            _admin_clear_audit_references({"id": str(self.tenant.id)}, table="tenants")
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


def _url(tenant_id: uuid.UUID) -> str:
    return f"/v1/test/tenants/{tenant_id}/widgets"


def _usage_total(tenant_id: uuid.UUID, metric: str) -> Decimal:
    """A window wide enough to catch anything this file could plausibly
    record, regardless of when the test actually runs."""
    return aggregate_usage(
        tenant_id,
        metric,
        since=datetime(2000, 1, 1, tzinfo=UTC),
        until=datetime.now(UTC) + timedelta(hours=1),
    )


# --- Happy path: entitled, within quota -------------------------------


def test_entitled_and_within_quota_succeeds_and_records_usage(client: TestClient) -> None:
    fx = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _QUOTA_METRIC: 10})
    try:
        response = client.post(_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.token}"})
        assert response.status_code == 200
        assert _usage_total(fx.tenant.id, _QUOTA_METRIC) == Decimal("1")
    finally:
        fx.cleanup()


# --- Not entitled -> 403 ------------------------------------------------


def test_not_entitled_returns_403_and_does_not_run_the_operation(client: TestClient) -> None:
    fx = _Fixture(entitlements={_QUOTA_METRIC: 10})  # no _ENTITLEMENT_KEY
    try:
        response = client.post(_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.token}"})
        assert response.status_code == 403
        assert _usage_total(fx.tenant.id, _QUOTA_METRIC) == Decimal("0")  # denial ran nothing

        entries = list_audit_entries(fx.tenant.id, resource_type="entitlement")
        assert any(e.resource_id == _ENTITLEMENT_KEY and e.outcome == "denied" for e in entries)
    finally:
        fx.cleanup()


# --- Quota exhausted -> 429 ----------------------------------------------


def test_quota_exhausted_returns_429_and_does_not_double_record(client: TestClient) -> None:
    fx = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _QUOTA_METRIC: 1})
    try:
        first = client.post(_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.token}"})
        assert first.status_code == 200

        second = client.post(_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.token}"})
        assert second.status_code == 429
        assert second.json()["detail"] == "Quota exceeded."
        assert _usage_total(fx.tenant.id, _QUOTA_METRIC) == Decimal("1")
    finally:
        fx.cleanup()


# --- Authentication/RBAC interaction unchanged -----------------------------


def test_unauthenticated_request_returns_401_before_entitlement_or_quota(
    client: TestClient,
) -> None:
    fx = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _QUOTA_METRIC: 10})
    try:
        response = client.post(_url(fx.tenant.id))
        assert response.status_code == 401
    finally:
        fx.cleanup()


def test_rbac_denial_still_returns_403_before_entitlement_or_quota_run(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user with no granted permission at all must still be rejected by
    RBAC -- P1.9 must not weaken or bypass the existing RBAC step."""
    fx = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _QUOTA_METRIC: 10})
    try:
        other_user = create_user()
        add_tenant_membership(fx.tenant.id, other_user.id, caller=_PROVISIONING)
        _, other_token = issue_session(other_user.id)
        try:
            response = client.post(
                _url(fx.tenant.id), headers={"Authorization": f"Bearer {other_token}"}
            )
            assert response.status_code == 403
            assert _usage_total(fx.tenant.id, _QUOTA_METRIC) == Decimal("0")
        finally:
            with session_scope() as session:
                session.execute(
                    text("DELETE FROM core.sessions WHERE user_id = :u"),
                    {"u": str(other_user.id)},
                )
            with tenant_session_scope(fx.tenant.id) as session:
                session.execute(
                    text(
                        "DELETE FROM core.tenant_memberships WHERE tenant_id = :t AND user_id = :u"
                    ),
                    {"t": str(fx.tenant.id), "u": str(other_user.id)},
                )
            # The RBAC-denial path (require_permission's own dependency)
            # audits this attempt with actor_user_id=other_user.id --
            # that row must go before the user row it references.
            _admin_delete_audit_log_for_tenant(fx.tenant.id)
            with session_scope() as session:
                _admin_clear_audit_references({"id": str(other_user.id)}, table="users")
                session.execute(
                    text("DELETE FROM core.users WHERE id = :id"), {"id": str(other_user.id)}
                )
    finally:
        fx.cleanup()


# --- Tenant isolation at the HTTP layer -------------------------------


def test_forged_tenant_id_in_url_cannot_consume_another_tenants_quota(
    client: TestClient,
) -> None:
    """The `tenant_id` path parameter is validated against a real
    membership before being trusted (saas_os/api/dependencies.py's own
    docstring) -- a caller cannot name a tenant they don't belong to and
    have this route consume that tenant's quota."""
    fx_a = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _QUOTA_METRIC: 10})
    fx_b = _Fixture(entitlements={_ENTITLEMENT_KEY: True, _QUOTA_METRIC: 10})
    try:
        response = client.post(
            _url(fx_b.tenant.id), headers={"Authorization": f"Bearer {fx_a.token}"}
        )
        assert response.status_code == 404  # non-enumerating: not-found, not "forbidden"
        assert _usage_total(fx_b.tenant.id, _QUOTA_METRIC) == Decimal("0")
    finally:
        fx_a.cleanup()
        fx_b.cleanup()
