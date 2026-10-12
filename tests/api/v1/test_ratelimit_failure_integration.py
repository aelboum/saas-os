"""P1.5 -- end-to-end rate-limit backend-failure tests through the real,
fully-authenticated ingress chain (docs/IMPLEMENTATION-ROADMAP.md P1.5).

`tests/infra/ratelimit/test_ratelimit_backend_failure_*.py` cover the
limiter's own contract in isolation; this file proves the same 503
behavior holds through the *real* `saas_os.api.main.app` -- authentication,
tenant resolution, and RBAC never bypassed by a Redis outage -- and adds
the tenant-isolation proofs docs/IMPLEMENTATION-ROADMAP.md P1.5 section 9
calls for, against a *healthy* Redis.

Marked `integration`; excluded from the default `pytest` run. Run the
same way as `tests/api/v1/test_correlation_integration.py`
(same module docstring's invocation), plus a reachable `REDIS_URL`.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from saas_os.api.main import app
from saas_os.api.middleware import CORRELATION_ID_HEADER
from saas_os.api.v1.tenant_status import ACTION, RESOURCE
from saas_os.core.audit_log.service import list as list_audit_entries
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.identity.service import add_tenant_membership, create_user, get_membership
from saas_os.core.identity.sessions import issue_session
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import create_tenant
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
    finally:
        engine.dispose()


_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

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
        pytest.skip(f"PostgreSQL/core.membership_roles not reachable: {exc}.")
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
        self.tenant = create_tenant(_unique("rl-tenant"))
        self.user = create_user()
        add_tenant_membership(self.tenant.id, self.user.id, caller=_PROVISIONING)

        role = create_role(self.tenant.id, _unique("rl-role"), caller=_PROVISIONING)
        permission = register_permission(RESOURCE, ACTION)
        grant_permission(self.tenant.id, role.id, permission.id, caller=_PROVISIONING)

        membership = get_membership(self.tenant.id, self.user.id)
        assert membership is not None
        assign_first_role_for_new_tenant(
            self.tenant.id, membership.id, role.id, caller=_PROVISIONING
        )

        _, self.user_token = issue_session(self.user.id)

    def cleanup(self) -> None:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(self.user.id)}
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
            _admin_clear_audit_references({"u": str(self.user.id)}, table="users")
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(self.user.id)})
            _admin_clear_audit_references({"id": str(self.tenant.id)}, table="tenants")
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


def _point_redis_at_an_unreachable_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulates a Redis outage for the duration of one test -- points
    `REDIS_URL` at a real, immediately-refusing local port (module
    docstring: no unrelated container is touched, no shared Redis
    instance is stopped)."""
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    get_ratelimit_config.cache_clear()


# --- Redis outage: fail closed, through the real chain ---------------------


def test_redis_outage_produces_503_not_500_not_429(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        response = client.get(
            _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
        )
        assert response.status_code == 503
        assert response.status_code != 500
        assert response.status_code != 429
        assert response.json()["detail"] == "Service temporarily unavailable."
        assert "Retry-After" in response.headers
    finally:
        get_ratelimit_config.cache_clear()


def test_503_response_carries_the_correlation_header(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P1.4's correlation header must survive this new failure path too."""
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        response = client.get(
            _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
        )
        assert response.status_code == 503
        assert response.headers.get(CORRELATION_ID_HEADER)
    finally:
        get_ratelimit_config.cache_clear()


def test_error_response_never_leaks_redis_connection_details(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        response = client.get(
            _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
        )
        body = response.text
        assert "127.0.0.1" not in body
        assert "redis" not in body.lower()
        assert "Traceback" not in body
        assert "ConnectionError" not in body
    finally:
        get_ratelimit_config.cache_clear()


# --- Security: no bypass of anything downstream of rate limiting -----------


def test_redis_outage_never_reaches_rbac_or_the_handler(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-closed means the request is rejected *before* RBAC ever runs
    -- proven directly by making the RBAC decision function itself raise
    if invoked, not merely by inspecting the response."""
    import saas_os.api.dependencies as deps

    def _must_not_be_called(**kwargs: object) -> bool:
        raise AssertionError("core.rbac.can must never be invoked during a rate-limit outage")

    monkeypatch.setattr(deps, "rbac_can", _must_not_be_called)
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        response = client.get(
            _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
        )
        assert response.status_code == 503
    finally:
        get_ratelimit_config.cache_clear()


def test_redis_outage_does_not_authenticate_an_unauthenticated_caller(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Redis outage must never turn into an authorization success --
    an unauthenticated request during the same outage still gets 401,
    never 503-before-401 and never a bypass straight to 200."""
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        response = client.get(_status_url(fx.tenant.id))
        assert response.status_code == 401
    finally:
        get_ratelimit_config.cache_clear()


def test_redis_outage_does_not_bypass_tenant_membership_check(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller who is not a member of the tenant still gets 404 during
    the outage -- tenant resolution runs *before* rate limiting and is
    unaffected by it."""
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        response = client.get(
            _status_url(uuid.uuid4()), headers={"Authorization": f"Bearer {fx.user_token}"}
        )
        assert response.status_code == 404
    finally:
        get_ratelimit_config.cache_clear()


def test_redis_outage_is_not_audited_as_a_security_event(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backend outage is operational, not an audit-worthy actor
    decision (module docstring / saas_os/api/dependencies.py's own P1.5 note) --
    no `core.audit_log` entry is created for it. (The fixture's own
    provisioning is audited -- ADR-0031 -- so only new entries count.)"""
    before = {entry.id for entry in list_audit_entries(fx.tenant.id)}
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        response = client.get(
            _status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"}
        )
        assert response.status_code == 503
    finally:
        get_ratelimit_config.cache_clear()
    entries = [entry for entry in list_audit_entries(fx.tenant.id) if entry.id not in before]
    assert entries == []


# --- Observability: correlated, safe logging --------------------------------


def test_backend_failure_is_correlated_and_distinguishable_in_logs(
    client: TestClient,
    fx: _Fixture,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from saas_os.infra.observability.config import ObservabilityConfig
    from saas_os.infra.observability.logging import CorrelationFilter

    caplog.set_level(logging.INFO)
    handler_filter = CorrelationFilter(ObservabilityConfig())
    caplog.handler.addFilter(handler_filter)
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        response = client.get(
            _status_url(fx.tenant.id),
            headers={
                "Authorization": f"Bearer {fx.user_token}",
                CORRELATION_ID_HEADER: "rl-outage-proof-id",
            },
        )
        assert response.status_code == 503
    finally:
        caplog.handler.removeFilter(handler_filter)
        get_ratelimit_config.cache_clear()

    backend_failure_logs = [
        r for r in caplog.records if r.getMessage() == "rate_limit_backend_unavailable"
    ]
    assert backend_failure_logs
    assert getattr(backend_failure_logs[0], "request_id", None) == "rl-outage-proof-id"

    # distinguishable from a normal request_completed access-log line --
    # never emitted under the message a genuine 429 would carry.
    for record in caplog.records:
        assert "rate_limit_exceeded" not in record.getMessage()


def test_no_redis_credentials_or_connection_string_appear_in_logs(
    client: TestClient,
    fx: _Fixture,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING)
    _point_redis_at_an_unreachable_port(monkeypatch)
    try:
        client.get(_status_url(fx.tenant.id), headers={"Authorization": f"Bearer {fx.user_token}"})
    finally:
        get_ratelimit_config.cache_clear()

    for record in caplog.records:
        message = record.getMessage()
        assert "redis://" not in message
        for value in vars(record).values():
            assert "redis://" not in str(value)


# --- Tenant isolation (healthy Redis) --------------------------------------


def test_tenant_a_rate_limit_state_does_not_affect_tenant_b(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    other_tenant = create_tenant(_unique("rl-tenant-b"))
    other_user = create_user()
    add_tenant_membership(other_tenant.id, other_user.id, caller=_PROVISIONING)
    role = create_role(other_tenant.id, _unique("rl-role-b"), caller=_PROVISIONING)
    permission = register_permission(RESOURCE, ACTION)
    grant_permission(other_tenant.id, role.id, permission.id, caller=_PROVISIONING)
    membership = get_membership(other_tenant.id, other_user.id)
    assert membership is not None
    assign_first_role_for_new_tenant(other_tenant.id, membership.id, role.id, caller=_PROVISIONING)
    _, other_token = issue_session(other_user.id)

    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "1")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    get_ratelimit_config.cache_clear()
    try:
        a_headers = {"Authorization": f"Bearer {fx.user_token}"}
        b_headers = {"Authorization": f"Bearer {other_token}"}

        a_first = client.get(_status_url(fx.tenant.id), headers=a_headers)
        a_second = client.get(_status_url(fx.tenant.id), headers=a_headers)
        assert a_first.status_code == 200
        assert a_second.status_code == 429  # tenant A is now rate-limited

        # tenant B's own limit is untouched by tenant A's usage.
        b_first = client.get(_status_url(other_tenant.id), headers=b_headers)
        assert b_first.status_code == 200
    finally:
        get_ratelimit_config.cache_clear()
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(other_user.id)}
            )
        with tenant_session_scope(other_tenant.id) as session:
            session.execute(
                text("DELETE FROM core.membership_roles WHERE tenant_id = :t"),
                {"t": str(other_tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.role_permissions WHERE tenant_id = :t"),
                {"t": str(other_tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(other_tenant.id)}
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(other_tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(other_tenant.id)
        with session_scope() as session:
            _admin_clear_audit_references({"u": str(other_user.id)}, table="users")
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(other_user.id)})
            _admin_clear_audit_references({"id": str(other_tenant.id)}, table="tenants")
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(other_tenant.id)}
            )


def test_forged_tenant_id_cannot_manipulate_the_real_tenants_limiter(
    client: TestClient, fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller who is authenticated but not a member of a forged tenant
    ID is rejected (404) *before* rate limiting -- their requests never
    increment that tenant's real counter. Proven by exhausting a
    forged/non-member tenant's supposed limit, then confirming the real
    tenant's own limit is still fully available."""
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "1")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    get_ratelimit_config.cache_clear()
    try:
        forged_tenant_id = uuid.uuid4()
        headers = {"Authorization": f"Bearer {fx.user_token}"}

        for _ in range(3):
            response = client.get(_status_url(forged_tenant_id), headers=headers)
            assert response.status_code == 404  # never a member; never rate-limited either

        # the real, member tenant's own (separately-keyed) limit is
        # untouched by those forged-tenant attempts.
        real_response = client.get(_status_url(fx.tenant.id), headers=headers)
        assert real_response.status_code == 200
    finally:
        get_ratelimit_config.cache_clear()
