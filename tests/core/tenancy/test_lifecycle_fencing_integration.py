"""PRIV-03 Phase P2 -- lifecycle mutation fencing, against a real
PostgreSQL instance.

Proves, for every Core mutation entry point that gained a
`require_open_tenant()` guard, that a tenant in any *closed* lifecycle
state (`DELETED`, `PURGING`, `PURGED` -- `core.tenancy.lifecycle.
CLOSED_STATUSES`) rejects the mutation with `TenantClosedError` *before*
any row is written, and that an open tenant still accepts a
representative mutation exactly as before. Also proves the `PURGED`
tombstone: the `core.tenants` row is still present with a stable UUID.

Every fenced call below is made with placeholder ids for everything
except `tenant_id`: the guard is the *first* thing each function does
after pure argument validation, so it must fire before any of those
placeholder ids could ever reach the database. That is the property under
test -- "fails closed before touching data", not "fails eventually".

Marked `integration` and excluded from the default `pytest` run,
mirroring `tests/core/tenancy/test_tenancy_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/tenancy/test_lifecycle_fencing_integration.py
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from core.api_keys.service import (
    create_api_key,
    create_service_account_api_key,
    rotate_api_key,
)
from core.billing.service import subscribe as billing_subscribe
from core.billing.service import subscribe_idempotent, upgrade_subscription
from core.feature_flags.service import set_tenant_override
from core.idempotency.service import begin_idempotent_operation, run_idempotent
from core.identity.service import (
    add_tenant_membership,
    create_invitation,
    create_service_account,
    create_user,
    enable_service_account,
    reactivate_membership,
)
from core.notifications.service import dispatch_notification
from core.rbac.scope import RoleScope
from core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
    assign_role,
    assign_service_account_role,
    create_delegation,
    create_delegation_to_service_account,
    create_deny,
    create_deny_for_service_account,
    create_role,
    create_support_access_request,
    grant_permission,
)
from core.usage.service import consume_quota, consume_quota_idempotent, ingest_event
from core.webhooks.service import subscribe as webhook_subscribe
from core.webhooks.service import trigger_event
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from core.tenancy import (
    CLOSED_STATUSES,
    TenantClosedError,
    TenantStatus,
    create_tenant,
    get_tenant,
    require_open_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

_CLOSED: list[TenantStatus] = sorted(CLOSED_STATUSES, key=lambda s: s.value)


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.tenants LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


@pytest.fixture
def admin_session_factory() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def _unique_name(prefix: str) -> str:
    return f"priv03-p2-{prefix}-{uuid.uuid4().hex[:8]}"


def _tenant_in_status(status: TenantStatus) -> uuid.UUID:
    """Create a tenant and walk it to `status` through the real graph."""
    tenant = create_tenant(_unique_name(status.value))
    path: dict[TenantStatus, list[TenantStatus]] = {
        TenantStatus.PENDING: [],
        TenantStatus.ACTIVE: [TenantStatus.ACTIVE],
        TenantStatus.SUSPENDED: [TenantStatus.ACTIVE, TenantStatus.SUSPENDED],
        TenantStatus.DELETED: [TenantStatus.DELETED],
        TenantStatus.PURGING: [TenantStatus.DELETED, TenantStatus.PURGING],
        TenantStatus.PURGED: [TenantStatus.DELETED, TenantStatus.PURGING, TenantStatus.PURGED],
    }
    for step in path[status]:
        transition_tenant_status(tenant.id, step)
    return tenant.id


def _delete_tenant_rows(
    admin_session_factory: sessionmaker[Session], *tenant_ids: uuid.UUID
) -> None:
    """Teardown for tenants that only ever received fenced (rejected)
    mutations -- nothing but the tenant row (and its self-ancestry row,
    which cascades) exists. Audit rows are cleared defensively through the
    privileged role, since the application role cannot delete them."""
    with session_scope(session_factory=admin_session_factory) as session:
        for tenant_id in tenant_ids:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    with session_scope() as session:
        for tenant_id in tenant_ids:
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


# --- The fenced mutation entry points --------------------------------------
#
# One entry per guarded Core function. Each callable takes only the
# tenant id; every other argument is a placeholder that would be invalid
# if it were ever reached -- which is exactly why the guard must fire
# first. Async entry points are driven with `asyncio.run` and raise before
# they would ever touch Redis, so no job queue is needed.

_U = uuid.uuid4
_EXPIRES = datetime.now(UTC) + timedelta(hours=1)


def _run(coro_factory: Callable[[uuid.UUID], object]) -> Callable[[uuid.UUID], object]:
    def _call(tenant_id: uuid.UUID) -> object:
        return asyncio.run(coro_factory(tenant_id))  # type: ignore[arg-type]

    return _call


_FENCED: dict[str, Callable[[uuid.UUID], object]] = {
    # core/identity
    "identity.add_tenant_membership": lambda t: add_tenant_membership(t, _U()),
    "identity.create_service_account": lambda t: create_service_account(t, "sa"),
    "identity.enable_service_account": lambda t: enable_service_account(t, _U()),
    "identity.reactivate_membership": lambda t: reactivate_membership(t, _U(), actor_user_id=_U()),
    "identity.create_invitation": lambda t: create_invitation(t, _U(), "x@example.com"),
    # core/rbac
    "rbac.create_role": lambda t: create_role(t, "r"),
    "rbac.grant_permission": lambda t: grant_permission(t, _U(), _U()),
    "rbac.assign_role": lambda t: assign_role(t, _U(), _U(), actor_user_id=_U()),
    "rbac.assign_first_role_for_new_tenant": lambda t: assign_first_role_for_new_tenant(
        t, _U(), _U()
    ),
    "rbac.assign_service_account_role": lambda t: assign_service_account_role(
        actor_user_id=_U(), tenant_id=t, service_account_id=_U(), role_id=_U()
    ),
    "rbac.create_delegation": lambda t: create_delegation(
        delegator_user_id=_U(),
        delegate_user_id=_U(),
        tenant_id=t,
        scope_mode=RoleScope.SELF,
        permission_id=_U(),
    ),
    "rbac.create_delegation_to_service_account": lambda t: create_delegation_to_service_account(
        delegator_user_id=_U(),
        service_account_id=_U(),
        service_account_tenant_id=t,
        tenant_id=t,
        scope_mode=RoleScope.SELF,
        permission_id=_U(),
    ),
    "rbac.create_deny": lambda t: create_deny(
        grantor_user_id=_U(),
        principal_user_id=_U(),
        tenant_id=t,
        scope_mode=RoleScope.SELF,
        permission_id=_U(),
    ),
    "rbac.create_deny_for_service_account": lambda t: create_deny_for_service_account(
        grantor_user_id=_U(),
        service_account_id=_U(),
        service_account_tenant_id=t,
        tenant_id=t,
        scope_mode=RoleScope.SELF,
        permission_id=_U(),
    ),
    "rbac.create_support_access_request": lambda t: create_support_access_request(
        requester_user_id=_U(), tenant_id=t, reason="r", requested_expires_at=_EXPIRES
    ),
    "rbac.approve_support_access": lambda t: approve_support_access(
        approver_user_id=_U(), tenant_id=t, request_id=_U()
    ),
    # core/api_keys
    "api_keys.create_api_key": lambda t: create_api_key(t, _U(), "k"),
    "api_keys.create_service_account_api_key": lambda t: create_service_account_api_key(
        actor_user_id=_U(), tenant_id=t, service_account_id=_U(), name="k"
    ),
    "api_keys.rotate_api_key": lambda t: rotate_api_key(t, _U()),
    # core/billing
    "billing.subscribe": lambda t: billing_subscribe(t, "plan"),
    "billing.subscribe_idempotent": lambda t: subscribe_idempotent(t, "plan", "key-1"),
    "billing.upgrade_subscription": lambda t: upgrade_subscription(t, _U(), "plan"),
    # core/usage
    "usage.ingest_event": _run(lambda t: ingest_event(t, "m", Decimal("1"))),
    "usage.consume_quota": lambda t: consume_quota(t, "m"),
    "usage.consume_quota_idempotent": lambda t: consume_quota_idempotent(
        t, "m", Decimal("1"), "key-1"
    ),
    # core/webhooks
    "webhooks.subscribe": lambda t: webhook_subscribe(t, "https://example.com/hook"),
    "webhooks.trigger_event": _run(lambda t: trigger_event(t, "evt", {})),
    # core/notifications
    "notifications.dispatch_notification": _run(
        lambda t: dispatch_notification(t, _U(), "in_app", "body")
    ),
    # core/feature_flags -- needs a real flag key to get past `get_flag()`;
    # covered separately below with a real flag.
    # core/idempotency
    "idempotency.run_idempotent": lambda t: run_idempotent(
        t, "op", "key-1", {}, lambda session: {}
    ),
    "idempotency.begin_idempotent_operation": lambda t: begin_idempotent_operation(
        t, "op", "key-1", {}
    ),
    # core/tenancy -- a new child beneath a closed parent
    "tenancy.create_tenant_under_closed_parent": lambda t: create_tenant(
        _unique_name("child"), parent_id=t
    ),
}


@pytest.fixture(scope="module")
def closed_tenants() -> Iterator[dict[TenantStatus, uuid.UUID]]:
    """One tenant per closed status, shared by every fencing case in this
    module -- fenced calls never write, so sharing is safe."""
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        tenants = {status: _tenant_in_status(status) for status in sorted(CLOSED_STATUSES)}
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"could not provision closed tenants: {exc}")
    try:
        yield tenants
    finally:
        engine = build_engine(get_migrations_database_config())
        try:
            _delete_tenant_rows(build_session_factory(engine), *tenants.values())
        finally:
            engine.dispose()


@pytest.mark.parametrize("status", _CLOSED)
@pytest.mark.parametrize("entry_point", sorted(_FENCED))
def test_closed_tenant_rejects_new_mutation_before_writing(
    entry_point: str, status: TenantStatus, closed_tenants: dict[TenantStatus, uuid.UUID]
) -> None:
    tenant_id = closed_tenants[status]
    with pytest.raises(TenantClosedError) as excinfo:
        _FENCED[entry_point](tenant_id)
    assert excinfo.value.tenant_id == tenant_id
    assert excinfo.value.status is status
    # Nothing was written: the tenant is still exactly in `status`.
    assert get_tenant(tenant_id).status == status.value


@pytest.mark.parametrize("status", _CLOSED)
def test_closed_tenant_rejects_feature_flag_override_before_writing(
    status: TenantStatus,
    closed_tenants: dict[TenantStatus, uuid.UUID],
    admin_session_factory: sessionmaker[Session],
) -> None:
    """`set_tenant_override()` resolves the (global) flag before the
    tenant guard, so it needs a real flag to reach the fence."""
    from core.feature_flags.service import create_flag

    key = f"priv03_p2_{uuid.uuid4().hex[:8]}"
    create_flag(key)
    try:
        with pytest.raises(TenantClosedError):
            set_tenant_override(closed_tenants[status], key, True)
        with session_scope(session_factory=admin_session_factory) as session:
            count = session.execute(
                text(
                    "SELECT count(*) FROM core.feature_flag_tenant_overrides WHERE tenant_id = :t"
                ),
                {"t": str(closed_tenants[status])},
            ).scalar_one()
        assert count == 0
    finally:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(text("DELETE FROM core.feature_flags WHERE key = :k"), {"k": key})


@pytest.mark.parametrize("status", _CLOSED)
def test_require_open_tenant_itself(
    status: TenantStatus, closed_tenants: dict[TenantStatus, uuid.UUID]
) -> None:
    with pytest.raises(TenantClosedError):
        require_open_tenant(closed_tenants[status])


# --- Open tenants still accept mutations (existing semantics unchanged) ----


@pytest.mark.parametrize(
    "status", [TenantStatus.PENDING, TenantStatus.ACTIVE, TenantStatus.SUSPENDED]
)
def test_open_tenant_still_accepts_a_representative_mutation(
    status: TenantStatus, admin_session_factory: sessionmaker[Session]
) -> None:
    """PENDING/ACTIVE/SUSPENDED are open: `require_open_tenant()` returns
    the tenant, a membership + role + API key can be created, exactly as
    before P2 (the wider per-module suites cover every other entry point
    on open tenants already)."""
    tenant_id = _tenant_in_status(status)
    user = create_user()
    try:
        assert require_open_tenant(tenant_id).status == status.value
        membership = add_tenant_membership(tenant_id, user.id)
        assert membership.tenant_id == tenant_id
        role = create_role(tenant_id, "member")
        assert role.tenant_id == tenant_id
        key, _raw = create_api_key(tenant_id, user.id, "k")
        assert key.tenant_id == tenant_id
    finally:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})
            session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(user.id)})


# --- The mutation fence is authority-reducing-safe --------------------------


def test_closing_a_tenant_does_not_fence_the_transition_itself(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """The lifecycle transition is the one mutation a closed tenant must
    still accept: DELETED -> PURGING -> PURGED all succeed on a tenant
    that rejects every other new mutation."""
    tenant_id = _tenant_in_status(TenantStatus.DELETED)
    try:
        with pytest.raises(TenantClosedError):
            create_role(tenant_id, "r")
        assert transition_tenant_status(tenant_id, TenantStatus.PURGING).status == "purging"
        with pytest.raises(TenantClosedError):
            create_role(tenant_id, "r")
        assert transition_tenant_status(tenant_id, TenantStatus.PURGED).status == "purged"
        with pytest.raises(TenantClosedError):
            create_role(tenant_id, "r")
    finally:
        _delete_tenant_rows(admin_session_factory, tenant_id)


# --- Tombstone ---------------------------------------------------------------


def test_purged_tenant_row_persists_as_a_tombstone_with_a_stable_uuid(
    admin_session_factory: sessionmaker[Session],
) -> None:
    tenant_id = _tenant_in_status(TenantStatus.PURGED)
    try:
        tombstone = get_tenant(tenant_id)
        assert tombstone.id == tenant_id
        assert tombstone.status == TenantStatus.PURGED.value
        with session_scope() as session:
            row_count = session.execute(
                text("SELECT count(*) FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)}
            ).scalar_one()
        assert row_count == 1
        # Terminal: nothing moves it out of PURGED.
        for target in TenantStatus:
            with pytest.raises(Exception):  # noqa: B017, PT011 -- InvalidTenantTransitionError
                transition_tenant_status(tenant_id, target)
        assert get_tenant(tenant_id).status == TenantStatus.PURGED.value
    finally:
        _delete_tenant_rows(admin_session_factory, tenant_id)


def test_child_cannot_be_created_under_a_closed_parent_and_no_row_is_left(
    admin_session_factory: sessionmaker[Session],
) -> None:
    parent_id = _tenant_in_status(TenantStatus.PURGING)
    try:
        with pytest.raises(TenantClosedError):
            create_tenant(_unique_name("child"), parent_id=parent_id)
        with session_scope() as session:
            children = session.execute(
                text("SELECT count(*) FROM core.tenants WHERE parent_id = :p"),
                {"p": str(parent_id)},
            ).scalar_one()
        assert children == 0
    finally:
        _delete_tenant_rows(admin_session_factory, parent_id)
