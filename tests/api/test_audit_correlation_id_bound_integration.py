"""PRIV-03 Phase P11 (privacy re-audit RA-07, finding 1) -- a client-controlled
`X-Request-ID` can never make an audited authorization denial fail its
own audit write, through the real ingress chain against real PostgreSQL
and Redis.

Before the fix, `api/middleware.py` accepted up to 128 characters while
`core.audit_log.correlation_id` is `VARCHAR(100)` and `record()` did not
check it: a 101- to 128-character header on an RBAC (or entitlement)
denial raised `psycopg.errors.StringDataRightTruncation` inside the audit
write, the request became HTTP 500, and the denial record was lost. Now
the middleware bound equals the column width (an over-long header is
treated as absent and a uuid4 is generated) and `record()` enforces the
same bound itself. Both audited denial paths `api/dependencies.py` has --
`require_permission()` (RBAC, `resource_type="http_route"`) on the real
tenant-status route, and `require_entitlement_and_quota()`'s entitlement
check (`resource_type="entitlement"`) on a test-only mounted route, the
same pattern `tests/api/test_entitlement_quota_integration.py` uses --
are exercised at 100, 101 and 128 characters.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/api/test_audit_correlation_id_bound_integration.py
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import api.main as main_module
import pytest
from api.dependencies import RequestContext, require_entitlement_and_quota
from api.middleware import CORRELATION_ID_HEADER
from api.v1.tenant_status import ACTION, RESOURCE
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_user
from core.identity.sessions import issue_session
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from infra.ratelimit.config import get_ratelimit_config
from sqlalchemy import text

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_LIMIT = 100
_LENGTHS = [_LIMIT, _LIMIT + 1, 128]

_GATE_RESOURCE = "ra07.gate"
_GATE_ACTION = "invoke"
_ENTITLEMENT_KEY = "ra07.entitlement"


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
        pytest.skip(f"PostgreSQL/core.membership_roles not reachable: {exc}")
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
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}")


# The entitlement-gated test route: built once at module scope so no
# `Depends(...)` default sits in a signature outside `api/**` (the B008
# ignore is scoped there), exactly like test_entitlement_quota_integration.
_gate_dependency = require_entitlement_and_quota(
    _GATE_RESOURCE, _GATE_ACTION, entitlement_key=_ENTITLEMENT_KEY
)


def _gate_router() -> APIRouter:
    router = APIRouter()

    @router.post("/v1/test/ra07/tenants/{tenant_id}/gate")
    async def gate(
        tenant_id: uuid.UUID,
        context: RequestContext = Depends(_gate_dependency),  # noqa: B008
    ) -> dict[str, str]:
        return {"tenant_id": str(context.tenant_id)}

    return router


@pytest.fixture
def client() -> TestClient:
    app = main_module.create_app()
    app.include_router(_gate_router())
    return TestClient(app)


@dataclass
class Rig:
    tenant_id: uuid.UUID
    member_token: str  # a member with no role: RBAC denial on the status route
    gated_token: str  # holds the gate permission; the tenant has no plan: entitlement denial
    user_ids: list[uuid.UUID]


def _build_rig() -> Rig:
    tenant = create_tenant(f"priv03-p11-{uuid.uuid4().hex[:8]}")
    member, gated = create_user(), create_user()
    add_tenant_membership(tenant.id, member.id)
    gated_membership = add_tenant_membership(tenant.id, gated.id)
    role = create_role(tenant.id, "ra07-gate-role")
    permission = register_permission(_GATE_RESOURCE, _GATE_ACTION)
    register_permission(RESOURCE, ACTION)  # exists globally; deliberately not granted
    grant_permission(tenant.id, role.id, permission.id)
    assign_first_role_for_new_tenant(tenant.id, gated_membership.id, role.id)
    _, member_token = issue_session(member.id)
    _, gated_token = issue_session(gated.id)
    return Rig(
        tenant_id=tenant.id,
        member_token=member_token,
        gated_token=gated_token,
        user_ids=[member.id, gated.id],
    )


def _teardown(rig: Rig) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            for table in (
                "core.audit_log",
                "core.membership_roles",
                "core.role_permissions",
                "core.roles",
                "core.tenant_memberships",
                "core.tenant_ancestry",
            ):
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
                    {"t": str(rig.tenant_id)},
                )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)}
            )
            for user_id in rig.user_ids:
                session.execute(
                    text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(user_id)}
                )
                session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(user_id)})
    finally:
        engine.dispose()


@pytest.fixture
def rig() -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(built)


def _denial_rows(rig: Rig, resource_type: str):
    return list_audit_entries(rig.tenant_id, resource_type=resource_type, limit=50)


def _assert_denied_and_audited_once(
    response, rig: Rig, *, resource_type: str, supplied: str, before: int
) -> None:
    assert response.status_code == 403, response.text  # the denial, never a 500
    rows = _denial_rows(rig, resource_type)
    assert len(rows) == before + 1  # exactly one new denial record
    stored = rows[0].correlation_id
    echoed = response.headers[CORRELATION_ID_HEADER]
    assert stored is not None
    assert len(stored) <= _LIMIT  # never wider than the column
    assert stored == echoed  # the audit row correlates to the id the caller was told
    if len(supplied) <= _LIMIT:
        assert stored == supplied  # accepted verbatim at the boundary
    else:
        assert stored != supplied and uuid.UUID(stored).version == 4  # replaced, not truncated
        assert not supplied.startswith(stored)


@pytest.mark.parametrize("length", _LENGTHS)
def test_rbac_denial_survives_any_accepted_or_over_long_request_id(
    length: int, client: TestClient, rig: Rig
) -> None:
    supplied = "r" * length
    before = len(_denial_rows(rig, "http_route"))
    response = client.get(
        f"/v1/tenants/{rig.tenant_id}/status",
        headers={"Authorization": f"Bearer {rig.member_token}", CORRELATION_ID_HEADER: supplied},
    )
    _assert_denied_and_audited_once(
        response, rig, resource_type="http_route", supplied=supplied, before=before
    )


@pytest.mark.parametrize("length", _LENGTHS)
def test_entitlement_denial_survives_any_accepted_or_over_long_request_id(
    length: int, client: TestClient, rig: Rig
) -> None:
    supplied = "e" * length
    before = len(_denial_rows(rig, "entitlement"))
    response = client.post(
        f"/v1/test/ra07/tenants/{rig.tenant_id}/gate",
        headers={"Authorization": f"Bearer {rig.gated_token}", CORRELATION_ID_HEADER: supplied},
    )
    _assert_denied_and_audited_once(
        response, rig, resource_type="entitlement", supplied=supplied, before=before
    )
    assert len(_denial_rows(rig, "http_route")) == 0  # RBAC passed; only the entitlement denied
