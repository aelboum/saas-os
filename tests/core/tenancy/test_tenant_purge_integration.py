"""PRIV-03 Phase P3 -- Core purge orchestration, against a real PostgreSQL
instance: `core.tenancy.purge_tenant()` empties one tenant's operational
data in the fixed `PURGE_STEPS` order, keeps every retained record, and
leaves the tenant row behind as a minimized `PURGED` tombstone.

Every scenario builds a *rich* tenant (memberships, roles, grants, service
accounts, API keys, invitations, webhooks, notifications, flags,
idempotency, usage, billing, support access, an AI approval request, and
the audit rows those writes produce) next to an untouched sibling and
parent, then purges exactly one of them and checks -- through the
privileged migrations role, so RLS cannot hide anything -- what is gone,
what remains, and that nothing outside the target moved.

Marked `integration`, excluded from the default `pytest` run, mirroring
`tests/core/tenancy/test_lifecycle_fencing_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/tenancy/test_tenant_purge_integration.py
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from core.api_keys.errors import InvalidApiKeyError
from core.api_keys.service import (
    create_api_key,
    create_service_account_api_key,
    revoke_api_key,
    validate_api_key,
)
from core.billing.provider import FakeBillingProvider
from core.billing.service import create_plan
from core.billing.service import subscribe as billing_subscribe
from core.feature_flags.service import create_flag, set_tenant_override
from core.idempotency.service import begin_idempotent_operation
from core.identity.models import ServiceAccountStatus
from core.identity.service import (
    add_tenant_membership,
    create_invitation,
    create_service_account,
    create_user,
    enable_service_account,
    get_service_account,
)
from core.notifications.models import Notification
from core.rbac.scope import RoleScope
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    assign_service_account_role,
    create_delegation,
    create_deny,
    create_role,
    create_support_access_request,
    grant_permission,
    purge_tenant_authorization,
    register_permission,
)
from core.usage.models import UsageEvent
from core.webhooks.service import record_webhook_delivery
from core.webhooks.service import subscribe as webhook_subscribe
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from control_plane.approvals.models import ApprovalRequest
from core.tenancy import (
    PURGE_STEPS,
    InvalidTenantTransitionError,
    TenantClosedError,
    TenantHasDescendantsError,
    TenantNotPurgingError,
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    require_purging_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

# Tables emptied by the purge (tenant_id column on every one of them).
_PURGED_TABLES = (
    "core.api_keys",
    "core.notifications",
    "core.webhook_replay_records",
    "core.webhook_subscriptions",
    "core.membership_roles",
    "core.role_permissions",
    "core.service_account_roles",
    "core.deny_grants",
    "core.roles",
    "core.invitations",
    "core.tenant_memberships",
    "core.feature_flag_tenant_overrides",
    "core.idempotency_records",
)
# Tables the purge must leave exactly as it found them.
_RETAINED_TABLES = (
    "core.audit_log",
    "core.billing_subscriptions",
    "core.support_access_requests",
    "core.usage_events",  # deferred -- no rollup/retention decision exists yet
    "control_plane.approval_requests",  # deferred -- P5 owns AI disposition
    "core.tenant_ancestry",
)


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
        pytest.skip(f"PostgreSQL not reachable at DATABASE_URL: {exc}")
    finally:
        probe_engine.dispose()
    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    """The privileged migrations role -- used ONLY to observe true row
    counts regardless of RLS and to tear fixtures down. Every purge
    under test runs through the ordinary application role."""
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def _uniq(prefix: str) -> str:
    return f"priv03-p3-{prefix}-{uuid.uuid4().hex[:8]}"


@dataclass
class Rig:
    """One populated tenant and the ids needed to inspect it afterward."""

    tenant_id: uuid.UUID
    admin_user_id: uuid.UUID
    member_user_id: uuid.UUID
    support_user_id: uuid.UUID
    role_id: uuid.UUID
    audited_service_account_id: uuid.UUID
    plain_service_account_id: uuid.UUID
    user_raw_key: str
    service_account_raw_key: str
    user_ids: list[uuid.UUID] = field(default_factory=list)
    permission_names: list[tuple[str, str]] = field(default_factory=list)
    plan_key: str = ""
    flag_key: str = ""


_CAPABILITIES = (
    ("membership_role", "create"),
    ("service_account_role", "create"),
    ("api_key", "create"),
    ("invitation", "create"),
    ("delegation_grant", "create"),
    ("deny_grant", "create"),
    ("widget", "read"),  # an ordinary business permission to delegate / deny
)


def _build_rig(*, parent_id: uuid.UUID | None = None, rich: bool = True) -> Rig:
    """Create an ACTIVE tenant populated with one row (at least) in every
    purged table, every retained table, and the audit rows those writes
    produce. `rich=False` builds the minimal neighbour rig (membership +
    role + API key + webhook) used for sibling/parent untouched checks."""
    tenant = create_tenant(_uniq("tenant"), parent_id=parent_id)
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    t = tenant.id

    admin_user = create_user()
    member_user = create_user()
    support_user = create_user()
    admin_membership = add_tenant_membership(t, admin_user.id)
    add_tenant_membership(t, member_user.id)

    role = create_role(t, "admin")
    permission_ids: dict[tuple[str, str], uuid.UUID] = {}
    for resource, action in _CAPABILITIES:
        permission = register_permission(resource, action)
        permission_ids[(resource, action)] = permission.id
        grant_permission(t, role.id, permission.id)
    assign_first_role_for_new_tenant(t, admin_membership.id, role.id)

    _, user_raw_key = create_api_key(t, admin_user.id, "user-key")
    rig = Rig(
        tenant_id=t,
        admin_user_id=admin_user.id,
        member_user_id=member_user.id,
        support_user_id=support_user.id,
        role_id=role.id,
        audited_service_account_id=uuid.uuid4(),
        plain_service_account_id=uuid.uuid4(),
        user_raw_key=user_raw_key,
        service_account_raw_key="",
        user_ids=[admin_user.id, member_user.id, support_user.id],
        permission_names=list(_CAPABILITIES),
    )
    webhook, _secret = webhook_subscribe(t, "https://example.com/hook", actor_user_id=admin_user.id)
    if not rich:
        return rig

    # Service accounts: one whose *own* audit trail names it as an actor
    # (a revoked service-account key writes a SERVICE_ACCOUNT-actor audit
    # row), which must therefore be retained disabled; one with no audit
    # reference, which is deleted outright.
    audited_sa = create_service_account(t, "audited-sa")
    plain_sa = create_service_account(t, "plain-sa")
    rig.audited_service_account_id = audited_sa.id
    rig.plain_service_account_id = plain_sa.id
    assign_service_account_role(
        actor_user_id=admin_user.id, tenant_id=t, service_account_id=audited_sa.id, role_id=role.id
    )
    revoked_key, _ = create_service_account_api_key(
        actor_user_id=admin_user.id, tenant_id=t, service_account_id=audited_sa.id, name="sa-old"
    )
    revoke_api_key(t, revoked_key.id)  # -> audit row with actor_service_account_id
    _, sa_raw_key = create_service_account_api_key(
        actor_user_id=admin_user.id, tenant_id=t, service_account_id=audited_sa.id, name="sa-live"
    )
    rig.service_account_raw_key = sa_raw_key

    create_delegation(
        delegator_user_id=admin_user.id,
        delegate_user_id=member_user.id,
        tenant_id=t,
        scope_mode=RoleScope.SELF,
        permission_id=permission_ids[("widget", "read")],
    )
    create_deny(
        grantor_user_id=admin_user.id,
        principal_user_id=member_user.id,
        tenant_id=t,
        scope_mode=RoleScope.SELF,
        permission_id=permission_ids[("widget", "read")],
    )
    create_invitation(t, admin_user.id, f"{uuid.uuid4().hex[:8]}@example.com")
    record_webhook_delivery(t, webhook.id, uuid.uuid4())
    with tenant_session_scope(t) as session:
        session.add(
            Notification(
                tenant_id=t,
                recipient_user_id=admin_user.id,
                channel="in_app",
                body="hi",
                status="sent",
            )
        )
        session.add(
            UsageEvent(
                tenant_id=t,
                metric="api_calls",
                quantity=Decimal("1"),
                occurred_at=datetime.now(UTC),
            )
        )
        session.add(
            ApprovalRequest(
                tenant_id=t,
                proposer_user_id=admin_user.id,
                tool_key="tool.example",
                payload={},
                status="pending",
            )
        )
    rig.flag_key = _uniq("flag").replace("-", "_")
    create_flag(rig.flag_key)
    set_tenant_override(t, rig.flag_key, True, actor_user_id=admin_user.id)
    begin_idempotent_operation(t, "op", "key-1", {})
    rig.plan_key = _uniq("plan").replace("-", "_")
    create_plan(rig.plan_key, "Plan")
    billing_subscribe(t, rig.plan_key, provider=FakeBillingProvider(), actor_user_id=admin_user.id)
    create_support_access_request(
        requester_user_id=support_user.id,
        tenant_id=t,
        reason="forensics",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    return rig


def _counts(admin: sessionmaker[Session], tenant_id: uuid.UUID, tables: tuple[str, ...]) -> dict:
    with session_scope(session_factory=admin) as session:
        return {
            table: session.execute(
                text(f"SELECT count(*) FROM {table} WHERE tenant_id = :t"),
                {"t": str(tenant_id)},  # noqa: S608 -- fixed table names from a module constant
            ).scalar_one()
            for table in tables
        }


def _teardown(admin: sessionmaker[Session], rigs: list[Rig]) -> None:
    tenant_ids = [str(r.tenant_id) for r in rigs]
    order = (
        "core.audit_log",
        "core.api_keys",
        "core.notifications",
        "core.webhook_replay_records",
        "core.webhook_subscriptions",
        "core.membership_roles",
        "core.role_permissions",
        "core.service_account_roles",
        "core.deny_grants",
        "core.delegation_grants",
        "core.roles",
        "core.invitations",
        "core.service_accounts",
        "core.tenant_memberships",
        "core.feature_flag_tenant_overrides",
        "core.idempotency_records",
        "core.usage_events",
        "core.billing_subscriptions",
        "core.support_access_requests",
        "control_plane.approval_requests",
    )
    with session_scope(session_factory=admin) as session:
        for table in order:
            for tid in tenant_ids:
                session.execute(text(f"DELETE FROM {table} WHERE tenant_id = :t"), {"t": tid})  # noqa: S608
        # children before parents
        for rig in sorted(rigs, key=lambda r: get_tenant(r.tenant_id).parent_id is None):
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)}
            )
        for rig in rigs:
            for uid in rig.user_ids:
                session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(uid)})
            if rig.plan_key:
                session.execute(
                    text("DELETE FROM core.billing_plans WHERE key = :k"), {"k": rig.plan_key}
                )
            if rig.flag_key:
                session.execute(
                    text("DELETE FROM core.feature_flags WHERE key = :k"), {"k": rig.flag_key}
                )


@pytest.fixture
def world(admin: sessionmaker[Session]) -> Iterator[tuple[Rig, Rig, Rig]]:
    """parent -> (target, sibling): the target is purged; parent and
    sibling must come out byte-for-byte untouched."""
    parent = _build_rig(rich=False)
    target = _build_rig(parent_id=parent.tenant_id)
    sibling = _build_rig(parent_id=parent.tenant_id, rich=False)
    try:
        yield target, sibling, parent
    finally:
        _teardown(admin, [target, sibling, parent])


def _delete_then_purge(tenant_id: uuid.UUID):
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    return purge_tenant(tenant_id)


# --- Lifecycle entry ---------------------------------------------------------


@pytest.mark.parametrize(
    "status", [TenantStatus.PENDING, TenantStatus.ACTIVE, TenantStatus.SUSPENDED]
)
def test_open_tenant_cannot_be_purged(status: TenantStatus, admin: sessionmaker[Session]) -> None:
    tenant = create_tenant(_uniq("open"))
    for step in {
        TenantStatus.PENDING: [],
        TenantStatus.ACTIVE: [TenantStatus.ACTIVE],
        TenantStatus.SUSPENDED: [TenantStatus.ACTIVE, TenantStatus.SUSPENDED],
    }[status]:
        transition_tenant_status(tenant.id, step)
    try:
        with pytest.raises(InvalidTenantTransitionError):
            purge_tenant(tenant.id)
        assert get_tenant(tenant.id).status == status.value
    finally:
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant.id)})


def test_deleted_tenant_enters_purging_then_ends_purged_as_a_tombstone(
    world: tuple[Rig, Rig, Rig],
) -> None:
    target, _, parent = world
    transition_tenant_status(target.tenant_id, TenantStatus.DELETED)
    result = purge_tenant(target.tenant_id)
    tombstone = get_tenant(target.tenant_id)
    assert tombstone.id == target.tenant_id
    assert tombstone.status == TenantStatus.PURGED.value
    assert tombstone.name == f"purged-{target.tenant_id}"
    assert tombstone.parent_id == parent.tenant_id  # hierarchy never rewritten
    assert result.passes == 2  # one purging pass + one clean verification pass
    assert result.already_purged is False


def test_purge_sequence_is_the_fixed_contract(world: tuple[Rig, Rig, Rig]) -> None:
    target, _, _ = world
    result = _delete_then_purge(target.tenant_id)
    assert tuple(result.deleted) == PURGE_STEPS
    assert all(result.deleted[step] > 0 for step in PURGE_STEPS), result.deleted


# --- What is gone, what remains -----------------------------------------------


def test_operational_rows_are_removed_and_retained_evidence_remains(
    world: tuple[Rig, Rig, Rig], admin: sessionmaker[Session]
) -> None:
    target, _, _ = world
    before_retained = _counts(admin, target.tenant_id, _RETAINED_TABLES)
    assert all(count > 0 for count in before_retained.values()), before_retained
    before_purged = _counts(admin, target.tenant_id, _PURGED_TABLES)
    assert all(count > 0 for count in before_purged.values()), before_purged

    _delete_then_purge(target.tenant_id)

    assert _counts(admin, target.tenant_id, _PURGED_TABLES) == dict.fromkeys(_PURGED_TABLES, 0)
    after_retained = _counts(admin, target.tenant_id, _RETAINED_TABLES)
    # PRIV-03 P4: the purge itself appends exactly three lifecycle audit
    # rows (delete_requested, purge_started, purge_completed); every other
    # retained table is untouched.
    assert after_retained.pop("core.audit_log") == before_retained.pop("core.audit_log") + 3
    assert after_retained == before_retained


def test_audit_referenced_service_account_and_grants_are_retained_revoked(
    world: tuple[Rig, Rig, Rig], admin: sessionmaker[Session]
) -> None:
    target, _, _ = world
    result = _delete_then_purge(target.tenant_id)
    # The service account a SERVICE_ACCOUNT-actor audit row names survives,
    # disabled; the one with no audit reference is gone.
    assert result.retained_service_account_ids == {target.audited_service_account_id}
    with session_scope(session_factory=admin) as session:
        rows = session.execute(
            text("SELECT id, status FROM core.service_accounts WHERE tenant_id = :t"),
            {"t": str(target.tenant_id)},
        ).all()
    assert {(r[0], r[1]) for r in rows} == {
        (target.audited_service_account_id, ServiceAccountStatus.DISABLED.value)
    }
    # No audit row names a delegation grant today, so every grant is deleted
    # -- and any that had to be kept would be revoked.
    assert result.retained_delegation_grant_ids == frozenset()
    with session_scope(session_factory=admin) as session:
        live_grants = session.execute(
            text(
                "SELECT count(*) FROM core.delegation_grants "
                "WHERE tenant_id = :t AND revoked_at IS NULL"
            ),
            {"t": str(target.tenant_id)},
        ).scalar_one()
    assert live_grants == 0


def test_global_users_survive(world: tuple[Rig, Rig, Rig], admin: sessionmaker[Session]) -> None:
    target, _, _ = world
    _delete_then_purge(target.tenant_id)
    with session_scope(session_factory=admin) as session:
        for uid in target.user_ids:
            assert (
                session.execute(
                    text("SELECT count(*) FROM core.users WHERE id = :u"), {"u": str(uid)}
                ).scalar_one()
                == 1
            )


def test_sibling_and_parent_are_untouched(
    world: tuple[Rig, Rig, Rig], admin: sessionmaker[Session]
) -> None:
    target, sibling, parent = world
    tables = _PURGED_TABLES + _RETAINED_TABLES
    sibling_before = _counts(admin, sibling.tenant_id, tables)
    parent_before = _counts(admin, parent.tenant_id, tables)
    _delete_then_purge(target.tenant_id)
    assert _counts(admin, sibling.tenant_id, tables) == sibling_before
    assert _counts(admin, parent.tenant_id, tables) == parent_before
    assert get_tenant(sibling.tenant_id).status == TenantStatus.ACTIVE.value
    assert get_tenant(parent.tenant_id).status == TenantStatus.ACTIVE.value
    # The sibling's credentials still work; the target's do not.
    assert validate_api_key(sibling.user_raw_key).tenant_id == sibling.tenant_id


# --- Credentials -------------------------------------------------------------


def test_no_credential_remains_usable(world: tuple[Rig, Rig, Rig]) -> None:
    target, _, _ = world
    assert validate_api_key(target.user_raw_key).tenant_id == target.tenant_id
    assert validate_api_key(target.service_account_raw_key).tenant_id == target.tenant_id
    _delete_then_purge(target.tenant_id)
    with pytest.raises(InvalidApiKeyError):
        validate_api_key(target.user_raw_key)
    with pytest.raises(InvalidApiKeyError):
        validate_api_key(target.service_account_raw_key)


def test_credentials_cannot_be_resurrected_on_the_tombstone(world: tuple[Rig, Rig, Rig]) -> None:
    target, _, _ = world
    _delete_then_purge(target.tenant_id)
    with pytest.raises(TenantClosedError):
        create_api_key(target.tenant_id, target.admin_user_id, "resurrected")
    with pytest.raises(TenantClosedError):
        enable_service_account(target.tenant_id, target.audited_service_account_id)
    retained = get_service_account(target.tenant_id, target.audited_service_account_id)
    assert retained is not None and retained.status == ServiceAccountStatus.DISABLED.value


# --- Idempotency, retry, crash ------------------------------------------------


def test_purged_tenant_purges_again_as_a_no_op(world: tuple[Rig, Rig, Rig]) -> None:
    target, _, _ = world
    first = _delete_then_purge(target.tenant_id)
    second = purge_tenant(target.tenant_id)
    assert first.already_purged is False
    assert second.already_purged is True
    assert second.total_deleted == 0
    assert get_tenant(target.tenant_id).status == TenantStatus.PURGED.value


def test_purging_tenant_can_be_retried(world: tuple[Rig, Rig, Rig]) -> None:
    target, _, _ = world
    transition_tenant_status(target.tenant_id, TenantStatus.DELETED)
    transition_tenant_status(target.tenant_id, TenantStatus.PURGING)
    result = purge_tenant(target.tenant_id)  # entered already in PURGING
    assert result.already_purged is False
    assert get_tenant(target.tenant_id).status == TenantStatus.PURGED.value


def test_crash_after_a_partial_pass_leaves_purging_and_the_retry_completes(
    world: tuple[Rig, Rig, Rig], admin: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulate a crash in the last step of the first pass: every earlier
    step's rows are already gone, the last step's are not, and the tenant
    is left PURGING -- never PURGED over live data. The retry finishes."""
    import core.idempotency.service as idempotency_service

    target, _, _ = world
    transition_tenant_status(target.tenant_id, TenantStatus.DELETED)

    def _crash(tenant_id: uuid.UUID) -> int:
        raise RuntimeError("simulated crash before idempotency purge")

    monkeypatch.setattr(idempotency_service, "purge_tenant_idempotency_records", _crash)
    with pytest.raises(RuntimeError, match="simulated crash"):
        purge_tenant(target.tenant_id)

    assert get_tenant(target.tenant_id).status == TenantStatus.PURGING.value
    partial = _counts(admin, target.tenant_id, _PURGED_TABLES)
    assert partial["core.idempotency_records"] == 1  # the step that "crashed"
    assert partial["core.tenant_memberships"] == 0  # an earlier step already ran

    monkeypatch.undo()
    result = purge_tenant(target.tenant_id)
    assert get_tenant(target.tenant_id).status == TenantStatus.PURGED.value
    assert _counts(admin, target.tenant_id, _PURGED_TABLES) == dict.fromkeys(_PURGED_TABLES, 0)
    assert result.deleted["idempotency_records"] == 1


def test_final_transition_never_happens_when_a_required_step_fails(
    world: tuple[Rig, Rig, Rig], monkeypatch: pytest.MonkeyPatch
) -> None:
    import core.rbac.service as rbac_service

    target, _, _ = world
    transition_tenant_status(target.tenant_id, TenantStatus.DELETED)
    monkeypatch.setattr(
        rbac_service,
        "purge_tenant_authorization",
        lambda tenant_id: (_ for _ in ()).throw(RuntimeError("authorization step failed")),
    )
    with pytest.raises(RuntimeError, match="authorization step failed"):
        purge_tenant(target.tenant_id)
    assert get_tenant(target.tenant_id).status == TenantStatus.PURGING.value
    assert get_tenant(target.tenant_id).name != f"purged-{target.tenant_id}"


def test_concurrent_purge_attempts_are_safe(
    world: tuple[Rig, Rig, Rig], admin: sessionmaker[Session]
) -> None:
    target, _, _ = world
    transition_tenant_status(target.tenant_id, TenantStatus.DELETED)
    errors: list[BaseException] = []
    results: list[object] = []

    def _run() -> None:
        try:
            results.append(purge_tenant(target.tenant_id))
        except BaseException as exc:  # noqa: BLE001 -- collected and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=_run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == [], errors
    assert len(results) == 2
    assert get_tenant(target.tenant_id).status == TenantStatus.PURGED.value
    assert _counts(admin, target.tenant_id, _PURGED_TABLES) == dict.fromkeys(_PURGED_TABLES, 0)


# --- Hierarchy ---------------------------------------------------------------


def test_parent_with_a_live_child_cannot_be_purged_and_nothing_moves(
    world: tuple[Rig, Rig, Rig], admin: sessionmaker[Session]
) -> None:
    target, sibling, parent = world
    tables = _PURGED_TABLES + _RETAINED_TABLES
    child_before = _counts(admin, target.tenant_id, tables)
    transition_tenant_status(parent.tenant_id, TenantStatus.DELETED)
    with pytest.raises(TenantHasDescendantsError) as excinfo:
        purge_tenant(parent.tenant_id)
    assert excinfo.value.descendant_ids == {target.tenant_id, sibling.tenant_id}
    assert (
        get_tenant(parent.tenant_id).status == TenantStatus.DELETED.value
    )  # never entered PURGING
    assert get_tenant(target.tenant_id).status == TenantStatus.ACTIVE.value
    assert _counts(admin, target.tenant_id, tables) == child_before


def test_purged_child_tombstones_do_not_block_the_parent(
    world: tuple[Rig, Rig, Rig],
) -> None:
    target, sibling, parent = world
    _delete_then_purge(target.tenant_id)
    _delete_then_purge(sibling.tenant_id)
    transition_tenant_status(parent.tenant_id, TenantStatus.DELETED)
    purge_tenant(parent.tenant_id)
    assert get_tenant(parent.tenant_id).status == TenantStatus.PURGED.value
    # Children keep their parent link -- tombstones point at a tombstone.
    assert get_tenant(target.tenant_id).parent_id == parent.tenant_id


# --- Security: a malicious caller cannot turn purge into something else ------


def test_module_purge_steps_refuse_an_open_tenant(world: tuple[Rig, Rig, Rig]) -> None:
    _, sibling, _ = world
    with pytest.raises(TenantNotPurgingError):
        purge_tenant_authorization(sibling.tenant_id)
    with pytest.raises(TenantNotPurgingError):
        require_purging_tenant(sibling.tenant_id)


def test_rls_hides_the_sibling_from_a_purge_scoped_session(
    world: tuple[Rig, Rig, Rig], admin: sessionmaker[Session]
) -> None:
    """Even a buggy or malicious step running inside the target's own
    tenant session cannot see, let alone delete, the sibling's rows --
    `FORCE ROW LEVEL SECURITY` decides, not the WHERE clause."""
    target, sibling, _ = world
    sibling_roles_before = _counts(admin, sibling.tenant_id, ("core.roles",))
    assert sibling_roles_before["core.roles"] > 0
    with tenant_session_scope(target.tenant_id) as session:
        visible = session.execute(
            text("SELECT count(*) FROM core.roles WHERE tenant_id = :s"),
            {"s": str(sibling.tenant_id)},
        ).scalar_one()
        assert visible == 0
        session.execute(
            text("DELETE FROM core.roles WHERE tenant_id = :s"), {"s": str(sibling.tenant_id)}
        )
    assert _counts(admin, sibling.tenant_id, ("core.roles",)) == sibling_roles_before


def test_purge_needs_no_privileged_bypass(admin: sessionmaker[Session]) -> None:
    """Every purge step runs as the ordinary application role behind
    DATABASE_URL: no SECURITY DEFINER function exists anywhere, and that
    role has neither BYPASSRLS nor SUPERUSER."""
    from sqlalchemy.engine import make_url

    app_role_name = make_url(get_database_config().url).username
    with session_scope(session_factory=admin) as session:
        secdef = session.execute(
            text("SELECT count(*) FROM pg_proc WHERE prosecdef = true")
        ).scalar_one()
        app_role = session.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = :r"),
            {"r": app_role_name},
        ).one()
    assert secdef == 0
    assert (app_role[0], app_role[1]) == (False, False)
