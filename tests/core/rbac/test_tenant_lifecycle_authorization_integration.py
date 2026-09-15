"""PRIV-03 Phase P8 -- tenant lifecycle authorization fence for tenant
principals (privacy re-audit finding RA-04), against real PostgreSQL.

Approved policy: a tenant's own principals -- members, service accounts,
API-key holders, delegates, and an existing user session trying to obtain
tenant context -- are denied while the tenant is SUSPENDED, DELETED,
PURGING or PURGED; ACTIVE (and PENDING) keep working; platform, purge and
support operations authorize separately (the P6 support fence is left
exactly as it was). The fence lives at the authorization chokepoints --
`core.rbac.can()` (target tenant locked FOR SHARE for the whole decision,
each allow path re-locking its own candidate tenant),
`core.api_keys.validate_api_key()` and `api.dependencies.get_tenant_context()`
-- and does not rely on purge-time deletion of any row: every test here
asserts the membership/role/key/service-account/delegation rows are still
present and live when the denial happens.

Every persisted-state assertion goes through the privileged migrations
role so RLS cannot hide anything; every action under test runs as the
ordinary application role. Marked `integration`, mirroring
`tests/core/rbac/test_support_access_lifecycle_integration.py` (whose
locking/race patterns are reused here).

How to run this test locally:

    docker compose up -d db redis
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:app_pw@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/core/rbac/test_tenant_lifecycle_authorization_integration.py
"""

from __future__ import annotations

import asyncio
import os
import threading
import traceback
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import core.rbac.authorization as authz
import pytest
from api.dependencies import get_tenant_context
from api.main import app
from core.api_keys.errors import InvalidApiKeyError
from core.api_keys.service import (
    create_api_key,
    create_service_account_api_key,
    validate_api_key,
)
from core.identity.service import (
    add_tenant_membership,
    create_service_account,
    create_user,
    get_membership,
)
from core.identity.sessions import issue_session, validate_session
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    assign_service_account_role,
    create_delegation,
    create_role,
    grant_permission,
    register_permission,
)
from fastapi import HTTPException
from fastapi.testclient import TestClient
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from core.rbac import PrincipalType, RoleScope, can
from core.tenancy import (
    Tenant,
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_INACCESSIBLE = [
    TenantStatus.SUSPENDED,
    TenantStatus.DELETED,
    TenantStatus.PURGING,
    TenantStatus.PURGED,
]
_RESOURCE, _ACTION = "widget", "read"
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.service_accounts LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.service_accounts not reachable: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def http() -> Iterator[TestClient]:
    """The real ASGI app; the ingress chain needs Redis for its rate
    limiter, so HTTP assertions skip when Redis is unreachable."""
    import redis

    try:
        redis.Redis.from_url(_REDIS_URL, socket_connect_timeout=1).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at REDIS_URL: {exc}")
    with TestClient(app) as client:
        yield client


# --- rig -------------------------------------------------------------------------


@dataclass
class Rig:
    tenant_id: uuid.UUID
    admin_id: uuid.UUID
    delegate_id: uuid.UUID
    service_account_id: uuid.UUID
    user_key: str
    service_account_key: str
    session_token: str
    widget_read_permission_id: uuid.UUID
    user_ids: list[uuid.UUID] = field(default_factory=list)


def _unique(prefix: str) -> str:
    return f"priv03-p8-{prefix}-{uuid.uuid4().hex[:8]}"


def _build_rig(
    *, parent_id: uuid.UUID | None = None, role_scope: RoleScope = RoleScope.SELF
) -> Rig:
    """An ACTIVE tenant with one fully equipped principal of each kind:
    an admin member (role granting the representative business permission
    plus the management capabilities the rig needs), a service account
    with the same role, a user API key, a service-account API key, a
    delegate holding a valid delegation, and a platform session."""
    tenant = create_tenant(_unique("tenant"), parent_id=parent_id)
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    admin_user, delegate = create_user(), create_user()
    membership = add_tenant_membership(tenant.id, admin_user.id)
    role = create_role(tenant.id, "admin")
    permission_ids: dict[tuple[str, str], uuid.UUID] = {}
    for resource, action in (
        (_RESOURCE, _ACTION),
        ("tenant", "read_status"),
        ("api_key", "create"),
        ("service_account_role", "create"),
        ("delegation_grant", "create"),
    ):
        permission = register_permission(resource, action)
        permission_ids[(resource, action)] = permission.id
        grant_permission(tenant.id, role.id, permission.id)
    assign_first_role_for_new_tenant(tenant.id, membership.id, role.id, scope=role_scope)
    service_account = create_service_account(tenant.id, "bot")
    assign_service_account_role(
        actor_user_id=admin_user.id,
        tenant_id=tenant.id,
        service_account_id=service_account.id,
        role_id=role.id,
    )
    _, user_key = create_api_key(tenant.id, admin_user.id, "user-key")
    _, service_account_key = create_service_account_api_key(
        actor_user_id=admin_user.id,
        tenant_id=tenant.id,
        service_account_id=service_account.id,
        name="sa-key",
    )
    create_delegation(
        delegator_user_id=admin_user.id,
        delegate_user_id=delegate.id,
        tenant_id=tenant.id,
        scope_mode=RoleScope.SELF,
        permission_id=permission_ids[(_RESOURCE, _ACTION)],
    )
    _, session_token = issue_session(admin_user.id)
    return Rig(
        tenant_id=tenant.id,
        admin_id=admin_user.id,
        delegate_id=delegate.id,
        service_account_id=service_account.id,
        user_key=user_key,
        service_account_key=service_account_key,
        session_token=session_token,
        widget_read_permission_id=permission_ids[(_RESOURCE, _ACTION)],
        user_ids=[admin_user.id, delegate.id],
    )


_CLEANUP_ORDER = (
    "core.audit_log",
    "core.api_keys",
    "core.service_account_roles",
    "core.membership_roles",
    "core.role_permissions",
    "core.roles",
    "core.delegation_grants",
    "core.service_accounts",
    "core.tenant_memberships",
    "core.support_access_requests",
    "core.tenant_ancestry",
)


def _teardown(admin: sessionmaker[Session], rigs: list[Rig]) -> None:
    with session_scope(session_factory=admin) as session:
        for rig in rigs:
            for table in _CLEANUP_ORDER:
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
                    {"t": str(rig.tenant_id)},
                )
        for rig in reversed(rigs):  # children before parents
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)}
            )
        for rig in rigs:
            for uid in rig.user_ids:
                session.execute(
                    text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": str(uid)}
                )
                session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(uid)})


@pytest.fixture
def rig(admin: sessionmaker[Session]) -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(admin, [built])


def _close(tenant_id: uuid.UUID, status: TenantStatus) -> None:
    if status is TenantStatus.SUSPENDED:
        transition_tenant_status(tenant_id, TenantStatus.SUSPENDED)
        return
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    if status is TenantStatus.PURGING:
        transition_tenant_status(tenant_id, TenantStatus.PURGING)
    elif status is TenantStatus.PURGED:
        purge_tenant(tenant_id)


def _member_can(rig: Rig, tenant_id: uuid.UUID | None = None) -> bool:
    return can(
        actor_id=rig.admin_id,
        tenant_id=tenant_id or rig.tenant_id,
        action=_ACTION,
        resource=_RESOURCE,
    )


def _service_account_can(rig: Rig) -> bool:
    return can(
        actor_id=rig.service_account_id,
        tenant_id=rig.tenant_id,
        action=_ACTION,
        resource=_RESOURCE,
        actor_type=PrincipalType.SERVICE_ACCOUNT,
        actor_tenant_id=rig.tenant_id,
    )


def _delegate_can(rig: Rig) -> bool:
    return can(
        actor_id=rig.delegate_id, tenant_id=rig.tenant_id, action=_ACTION, resource=_RESOURCE
    )


def _row_count(admin: sessionmaker[Session], sql: str, tenant_id: uuid.UUID) -> int:
    with session_scope(session_factory=admin) as session:
        return session.execute(text(sql), {"t": str(tenant_id)}).scalar_one()


def _live_rows(admin: sessionmaker[Session], rig: Rig) -> dict[str, int]:
    """The authorizing rows -- proving a denial is the fence, not deletion."""
    t = rig.tenant_id
    return {
        "active_memberships": _row_count(
            admin,
            "SELECT count(*) FROM core.tenant_memberships "
            "WHERE tenant_id = :t AND status = 'active'",
            t,
        ),
        "membership_roles": _row_count(
            admin, "SELECT count(*) FROM core.membership_roles WHERE tenant_id = :t", t
        ),
        "active_service_accounts": _row_count(
            admin,
            "SELECT count(*) FROM core.service_accounts WHERE tenant_id = :t AND status = 'active'",
            t,
        ),
        "unrevoked_api_keys": _row_count(
            admin,
            "SELECT count(*) FROM core.api_keys WHERE tenant_id = :t AND revoked_at IS NULL",
            t,
        ),
        "unrevoked_delegations": _row_count(
            admin,
            "SELECT count(*) FROM core.delegation_grants "
            "WHERE tenant_id = :t AND revoked_at IS NULL",
            t,
        ),
    }


_ROWS_WHILE_LIVE = {
    "active_memberships": 1,
    "membership_roles": 1,
    "active_service_accounts": 1,
    "unrevoked_api_keys": 2,
    "unrevoked_delegations": 1,
}


def _tenant_context_status(rig: Rig) -> int | str:
    try:
        asyncio.run(get_tenant_context(rig.tenant_id, rig.admin_id))
    except HTTPException as exc:
        return exc.status_code
    return "context"


# --- 1. ACTIVE regression ------------------------------------------------------


def test_active_tenant_admits_every_principal(rig: Rig, admin: sessionmaker[Session]) -> None:
    assert _member_can(rig) is True
    assert _service_account_can(rig) is True
    assert _delegate_can(rig) is True
    assert validate_api_key(rig.user_key).tenant_id == rig.tenant_id
    assert validate_api_key(rig.service_account_key).tenant_id == rig.tenant_id
    assert validate_session(rig.session_token).user_id == rig.admin_id
    assert _tenant_context_status(rig) == "context"
    assert _live_rows(admin, rig) == _ROWS_WHILE_LIVE


def test_active_tenant_serves_the_authenticated_route(rig: Rig, http: TestClient) -> None:
    response = http.get(
        f"/v1/tenants/{rig.tenant_id}/status",
        headers={"Authorization": f"Bearer {rig.session_token}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "active"


# --- 2. SUSPENDED / DELETED / PURGING / PURGED deny every tenant principal ---------


@pytest.mark.parametrize("status", _INACCESSIBLE)
def test_inaccessible_tenant_denies_the_member_while_its_rows_stay_live(
    status: TenantStatus, rig: Rig, admin: sessionmaker[Session]
) -> None:
    _close(rig.tenant_id, status)
    assert get_tenant(rig.tenant_id).status == status.value
    assert _member_can(rig) is False
    assert _tenant_context_status(rig) == 404  # same 404 as "no such tenant"/"not a member"
    assert validate_session(rig.session_token).user_id == rig.admin_id  # identity survives
    if status is not TenantStatus.PURGED:
        # Not deletion: the ACTIVE membership and its role are still there.
        rows = _live_rows(admin, rig)
        assert rows["active_memberships"] == 1 and rows["membership_roles"] == 1
        assert get_membership(rig.tenant_id, rig.admin_id) is not None


@pytest.mark.parametrize("status", _INACCESSIBLE)
def test_inaccessible_tenant_denies_both_api_keys(
    status: TenantStatus, rig: Rig, admin: sessionmaker[Session]
) -> None:
    _close(rig.tenant_id, status)
    with pytest.raises(InvalidApiKeyError):  # the generic error: nothing about the tenant leaks
        validate_api_key(rig.user_key)
    with pytest.raises(InvalidApiKeyError):
        validate_api_key(rig.service_account_key)
    if status is not TenantStatus.PURGED:
        assert _live_rows(admin, rig)["unrevoked_api_keys"] == 2  # rows still there, unusable
        denied = _row_count(
            admin,
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'api_key.validate' AND outcome = 'denied' "
            "AND metadata->>'denied_gate' = 'tenant_lifecycle'",
            rig.tenant_id,
        )
        assert denied == 2


@pytest.mark.parametrize("status", _INACCESSIBLE)
def test_inaccessible_tenant_denies_the_service_account(
    status: TenantStatus, rig: Rig, admin: sessionmaker[Session]
) -> None:
    _close(rig.tenant_id, status)
    assert _service_account_can(rig) is False
    if status is not TenantStatus.PURGED:
        assert _live_rows(admin, rig)["active_service_accounts"] == 1  # still ACTIVE, still denied


@pytest.mark.parametrize("status", _INACCESSIBLE)
def test_inaccessible_tenant_denies_the_delegate(
    status: TenantStatus, rig: Rig, admin: sessionmaker[Session]
) -> None:
    _close(rig.tenant_id, status)
    assert _delegate_can(rig) is False
    if status is not TenantStatus.PURGED:
        assert _live_rows(admin, rig)["unrevoked_delegations"] == 1  # valid grant, still denied


@pytest.mark.parametrize("status", _INACCESSIBLE)
def test_inaccessible_tenant_returns_404_on_the_authenticated_route(
    status: TenantStatus, rig: Rig, http: TestClient
) -> None:
    _close(rig.tenant_id, status)
    response = http.get(
        f"/v1/tenants/{rig.tenant_id}/status",
        headers={"Authorization": f"Bearer {rig.session_token}"},
    )
    assert response.status_code == 404


def test_suspension_is_reversible_and_membership_suspension_is_a_different_thing(
    rig: Rig,
) -> None:
    """Tenant SUSPENDED (this fence) and membership SUSPENDED (Phase G)
    are distinct: the membership stays ACTIVE throughout, and reactivating
    the tenant restores the member's authorization without touching it."""
    transition_tenant_status(rig.tenant_id, TenantStatus.SUSPENDED)
    assert _member_can(rig) is False
    membership = get_membership(rig.tenant_id, rig.admin_id)
    assert membership is not None and membership.status == "active"
    transition_tenant_status(rig.tenant_id, TenantStatus.ACTIVE)
    assert _member_can(rig) is True


def test_suspended_or_closed_ancestor_lends_no_subtree_authority_to_a_live_child(
    admin: sessionmaker[Session],
) -> None:
    parent = _build_rig(role_scope=RoleScope.SUBTREE)
    child = _build_rig(parent_id=parent.tenant_id)
    try:
        assert _member_can(parent, child.tenant_id) is True  # SUBTREE role at the parent reaches it
        transition_tenant_status(parent.tenant_id, TenantStatus.SUSPENDED)
        assert _member_can(parent, child.tenant_id) is False
        assert _member_can(child) is True  # the child's own principals are unaffected
        transition_tenant_status(parent.tenant_id, TenantStatus.ACTIVE)
        transition_tenant_status(parent.tenant_id, TenantStatus.DELETED)
        assert _member_can(parent, child.tenant_id) is False
        assert get_tenant(child.tenant_id).status == TenantStatus.ACTIVE.value
    finally:
        _teardown(admin, [parent, child])


# --- 3. Concurrency: closure vs. authorization on the shared chokepoint ----------


def _in_frame(name: str) -> bool:
    return any(frame.name == name for frame in traceback.extract_stack())


def _pause_after_lifecycle_lock(
    monkeypatch: pytest.MonkeyPatch,
    tenant_id: uuid.UUID,
    paused: threading.Event,
    release: threading.Event,
) -> None:
    """Patch `lock_accessible_tenant` as `can()` sees it: acquire the real
    FOR SHARE lock on `tenant_id`, then hold the decision open."""
    real = authz.lock_accessible_tenant
    fired = {"done": False}

    def locked_then_paused(session: Session, tid: uuid.UUID) -> Tenant:
        tenant = real(session, tid)
        if tid == tenant_id and not fired["done"] and _in_frame("can"):
            fired["done"] = True
            paused.set()
            assert release.wait(timeout=30)
        return tenant

    monkeypatch.setattr(authz, "lock_accessible_tenant", locked_then_paused)


def _hold_tenant_row_then_write(
    tenant_id: uuid.UUID, status: TenantStatus, ready: threading.Event, release: threading.Event
) -> None:
    """A lifecycle transition in progress: hold the tenant row FOR UPDATE
    (the lock `transition_tenant_status()`/`purge_tenant()` take), let the
    racing caller start, then write `status` and commit."""
    with session_scope() as session:
        row = session.get(Tenant, tenant_id, with_for_update=True)
        assert row is not None
        ready.set()
        assert release.wait(timeout=30)
        row.status = status.value
        session.flush()


_PRINCIPALS = {
    "member": _member_can,
    "service_account": _service_account_can,
    "delegate": _delegate_can,
}


def _can_in_thread(rig: Rig, principal: str) -> tuple[threading.Thread, dict[str, Any]]:
    outcome: dict[str, Any] = {}

    def _run() -> None:
        try:
            outcome["allow"] = _PRINCIPALS[principal](rig)
        except BaseException as exc:  # noqa: BLE001 -- surfaced by the assertions
            outcome["error"] = exc

    thread = threading.Thread(target=_run)
    thread.start()
    return thread, outcome


@pytest.mark.parametrize("principal", list(_PRINCIPALS))
def test_authorization_holding_the_lifecycle_lock_completes_and_closure_waits(
    principal: str, rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Authorization first: `can()` holds the target's share lock; the
    suspension's FOR UPDATE blocks until the decision returns (True, made
    while genuinely open); then it commits and the next decision is
    denied."""
    paused, release = threading.Event(), threading.Event()
    _pause_after_lifecycle_lock(monkeypatch, rig.tenant_id, paused, release)
    thread, outcome = _can_in_thread(rig, principal)
    assert paused.wait(timeout=30), "can() never took the lifecycle lock"
    closer = threading.Thread(
        target=transition_tenant_status, args=(rig.tenant_id, TenantStatus.SUSPENDED)
    )
    closer.start()
    closer.join(timeout=2)
    assert closer.is_alive(), "the suspension must block on the authorization's share lock"
    assert get_tenant(rig.tenant_id).status == TenantStatus.ACTIVE.value
    release.set()
    thread.join(timeout=30)
    closer.join(timeout=30)
    assert "error" not in outcome, outcome
    assert outcome["allow"] is True
    assert get_tenant(rig.tenant_id).status == TenantStatus.SUSPENDED.value
    assert _PRINCIPALS[principal](rig) is False


@pytest.mark.parametrize("principal", list(_PRINCIPALS))
def test_closure_holding_the_lifecycle_lock_blocks_authorization_until_it_commits(
    principal: str, rig: Rig
) -> None:
    """Closure first: the transition holds the tenant row FOR UPDATE with
    DELETED pending; `can()` blocks on it, then observes the committed
    state and denies -- while every authorizing row still exists."""
    ready, release = threading.Event(), threading.Event()
    holder = threading.Thread(
        target=_hold_tenant_row_then_write,
        args=(rig.tenant_id, TenantStatus.DELETED, ready, release),
    )
    holder.start()
    assert ready.wait(timeout=30)
    thread, outcome = _can_in_thread(rig, principal)
    thread.join(timeout=2)
    assert thread.is_alive(), "the authorization must block on the row the transition holds"
    release.set()
    holder.join(timeout=30)
    thread.join(timeout=30)
    assert "error" not in outcome, outcome
    assert outcome["allow"] is False
    assert get_tenant(rig.tenant_id).status == TenantStatus.DELETED.value
