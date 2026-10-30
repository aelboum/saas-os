"""Tenant lifecycle authority against a real PostgreSQL (ADR-0045 Phase C,
sections 5a, 8 and 12): `create_tenant`, `transition_tenant_status` and
`move_tenant` take a required caller, authorize it through the platform
chokepoint on the state actually read, and write their evidence in the
same transaction.

Negative controls for the denials here are in
`test_phase_c_negative_controls_integration.py`.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, REASON, TENANT_PURGE, P, Scene
from platform_helpers import BOOTSTRAP, PlatformWorld

import saas_os.core.tenancy.authority as lifecycle_authority
from saas_os.core.authority import CallerTypeError, ServiceAccountCaller, UserCaller
from saas_os.core.identity.errors import LastTenantAdministratorError
from saas_os.core.platform_authority import (
    InvalidPlatformRequestError,
    MoveIntoCallerHierarchyError,
    PlatformNotAuthorizedError,
    TenantParentRuleError,
)
from saas_os.core.rbac import (
    approve_support_access,
    can,
    create_delegation,
    create_support_access_request,
    register_permission,
)
from saas_os.core.rbac.scope import RoleScope
from saas_os.core.tenancy import (
    InvalidTenantTransitionError,
    TenantClosedError,
    TenantNotFoundError,
    TenantStatus,
    create_tenant,
    get_tenancy_config,
    move_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

SELF_SUSPEND = ("tenant", "suspend")
ALL_SYSTEM = (PROVISIONING, TENANT_PURGE, BILLING, BOOTSTRAP)


def _name() -> str:
    return f"pc-{uuid.uuid4().hex[:10]}"


def _service_account() -> ServiceAccountCaller:
    return ServiceAccountCaller(service_account_id=uuid.uuid4(), tenant_id=uuid.uuid4())


# --- callers ------------------------------------------------------------------


@pytest.mark.parametrize("caller", [None, "admin", object(), uuid.uuid4()])
def test_every_lifecycle_function_refuses_a_missing_or_wrongly_typed_caller(
    scene: Scene, caller: Any
) -> None:
    tenant = scene.tenant()
    with pytest.raises(CallerTypeError):
        create_tenant(_name(), caller=caller)
    with pytest.raises(CallerTypeError):
        transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=caller)
    with pytest.raises(CallerTypeError):
        move_tenant(tenant, None, caller=caller)
    assert scene.status(tenant) == "pending"


def test_every_lifecycle_function_refuses_a_service_account(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant()
    for call in (
        lambda c: create_tenant(_name(), caller=c),
        lambda c: transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=c),
        lambda c: move_tenant(tenant, None, caller=c),
    ):
        with pytest.raises(PlatformNotAuthorizedError):
            call(_service_account())
    assert scene.status(tenant) == "pending"
    assert platform.audit(outcome="success", action="platform.tenant.activate") == []


def test_a_user_without_the_permission_and_a_tenant_administrator_are_refused(
    scene: Scene, platform: PlatformWorld
) -> None:
    parent = scene.tenant(active=True)
    administrator, _ = scene.admin(parent, scope=RoleScope.SUBTREE)
    stranger = UserCaller(platform.user())
    wrong_permission, _ = platform.operator([P.TENANT_READ, P.TENANT_SUSPEND])
    for caller in (stranger, administrator, wrong_permission):
        with pytest.raises(PlatformNotAuthorizedError):
            create_tenant(_name(), caller=caller)
        with pytest.raises(PlatformNotAuthorizedError):
            create_tenant(_name(), parent_id=parent, caller=caller)
        with pytest.raises(PlatformNotAuthorizedError):
            transition_tenant_status(parent, TenantStatus.DELETED, caller=caller)
        with pytest.raises(PlatformNotAuthorizedError):
            move_tenant(parent, None, caller=caller)
    assert scene.status(parent) == "active"
    denied = platform.audit(action="platform.tenant.create", outcome="denied")
    assert {row["reason"] for row in denied} == {"not_authorized"}
    assert len(denied) == 6


def test_an_operator_holding_only_the_permission_of_one_edge_may_take_only_that_edge(
    scene: Scene, platform: PlatformWorld
) -> None:
    creator, _ = platform.operator([P.TENANT_CREATE])
    suspender, _ = platform.operator([P.TENANT_SUSPEND])
    reactivator, _ = platform.operator([P.TENANT_REACTIVATE])
    deleter, _ = platform.operator([P.TENANT_DELETE])
    mover, _ = platform.operator([P.TENANT_MOVE])

    tenant = create_tenant(_name(), caller=creator).id
    scene.tenants.append(tenant)
    for other in (suspender, reactivator, deleter, mover):
        with pytest.raises(PlatformNotAuthorizedError):
            transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=other)
    transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=creator)

    for other in (creator, reactivator, deleter, mover):
        with pytest.raises(PlatformNotAuthorizedError):
            transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=other)
    transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=suspender)

    for other in (creator, suspender, deleter, mover):
        with pytest.raises(PlatformNotAuthorizedError):
            transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=other)
    transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=reactivator)

    for other in (creator, suspender, reactivator, mover):
        with pytest.raises(PlatformNotAuthorizedError):
            transition_tenant_status(tenant, TenantStatus.DELETED, caller=other)
    transition_tenant_status(tenant, TenantStatus.DELETED, caller=deleter)
    assert scene.status(tenant) == "deleted"

    # No person takes a purge edge, whatever they hold.
    owner, _ = platform.owner()
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(tenant, TenantStatus.PURGING, caller=owner)
    assert scene.status(tenant) == "deleted"


def test_system_purposes_against_every_transition_cell_by_cell(scene: Scene) -> None:
    """Section 5a: PROVISIONING takes `PENDING -> ACTIVE` only; TENANT_PURGE
    takes `DELETED -> PURGING` and `PURGING -> PURGED` only; the other two
    purposes take nothing."""
    edges: list[tuple[TenantStatus, TenantStatus, Any]] = [
        (TenantStatus.PENDING, TenantStatus.ACTIVE, PROVISIONING),
        (TenantStatus.PENDING, TenantStatus.DELETED, None),
        (TenantStatus.ACTIVE, TenantStatus.SUSPENDED, None),
        (TenantStatus.ACTIVE, TenantStatus.DELETED, None),
        (TenantStatus.SUSPENDED, TenantStatus.ACTIVE, None),
        (TenantStatus.SUSPENDED, TenantStatus.DELETED, None),
        (TenantStatus.DELETED, TenantStatus.PURGING, TENANT_PURGE),
        (TenantStatus.PURGING, TenantStatus.PURGED, TENANT_PURGE),
    ]
    for current, target, accepted in edges:
        for purpose in ALL_SYSTEM:
            tenant = scene.tenant()
            scene.set_status(tenant, current)
            if purpose is accepted:
                transition_tenant_status(tenant, target, caller=purpose)
                assert scene.status(tenant) == target.value, (current, target, purpose)
            else:
                with pytest.raises(PlatformNotAuthorizedError):
                    transition_tenant_status(tenant, target, caller=purpose)
                assert scene.status(tenant) == current.value, (current, target, purpose)


def test_the_edge_is_selected_from_the_status_read_under_lock(scene: Scene) -> None:
    """A provisioning caller presenting `-> ACTIVE` against a tenant that is
    in fact SUSPENDED is judged as a reactivation, and refused."""
    tenant = scene.tenant(active=True)
    scene.set_status(tenant, TenantStatus.SUSPENDED)
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=PROVISIONING)
    assert scene.status(tenant) == "suspended"


def test_a_provisioning_caller_can_do_no_operator_work(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    other = scene.tenant()
    for target in (TenantStatus.SUSPENDED, TenantStatus.DELETED):
        with pytest.raises(PlatformNotAuthorizedError):
            transition_tenant_status(tenant, target, caller=PROVISIONING)
    with pytest.raises(PlatformNotAuthorizedError):
        move_tenant(tenant, other, caller=PROVISIONING)
    assert scene.status(tenant) == "active"
    denied = platform.audit(outcome="denied")
    assert {row["actor_type"] for row in denied} == {"system"}
    assert {row["system_authority"] for row in denied} == {"provisioning"}


def test_an_invalid_transition_and_an_unknown_tenant_are_reported_as_before(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Reported to a caller who holds the authority the transition needs.
    A caller who does not is refused before the tenant is read
    (`test_transition_disclosure_integration.py`): provisioning may not
    suspend, so it is no longer told that a pending tenant cannot be."""
    tenant = scene.tenant()
    suspender, _ = platform.operator([P.TENANT_SUSPEND])
    with pytest.raises(InvalidTenantTransitionError):
        transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=suspender)
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=PROVISIONING)
    with pytest.raises(TenantNotFoundError):
        transition_tenant_status(uuid.uuid4(), TenantStatus.ACTIVE, caller=PROVISIONING)
    with pytest.raises(TenantNotFoundError):
        create_tenant(_name(), parent_id=uuid.uuid4(), caller=PROVISIONING)


# --- the parent rule ------------------------------------------------------------

_PARENT_RULE: list[tuple[TenantStatus, str, type[Exception] | None, str | None]] = [
    (TenantStatus.PENDING, "provisioning", None, None),
    (TenantStatus.PENDING, "operator", None, None),
    (TenantStatus.ACTIVE, "provisioning", TenantParentRuleError, "parent_active_requires_operator"),
    (TenantStatus.ACTIVE, "operator", None, None),
    (TenantStatus.SUSPENDED, "provisioning", TenantParentRuleError, "parent_suspended"),
    (TenantStatus.SUSPENDED, "operator", TenantParentRuleError, "parent_suspended"),
    (TenantStatus.DELETED, "provisioning", TenantClosedError, "parent_closed"),
    (TenantStatus.DELETED, "operator", TenantClosedError, "parent_closed"),
    (TenantStatus.PURGING, "operator", TenantClosedError, "parent_closed"),
    (TenantStatus.PURGED, "provisioning", TenantClosedError, "parent_closed"),
]


@pytest.mark.parametrize(("status", "who", "error", "code"), _PARENT_RULE)
def test_the_parent_rule_cell_by_cell(
    scene: Scene,
    platform: PlatformWorld,
    status: TenantStatus,
    who: str,
    error: type[Exception] | None,
    code: str | None,
) -> None:
    parent = scene.tenant()
    scene.set_status(parent, status)
    caller: Any = PROVISIONING if who == "provisioning" else platform.operator([P.TENANT_CREATE])[0]
    before = platform.scalar(
        "SELECT count(*) FROM core.tenants WHERE parent_id = :p", {"p": parent}
    )
    if error is None:
        child = create_tenant(_name(), parent_id=parent, caller=caller)
        scene.tenants.append(child.id)
        assert child.parent_id == parent
        return
    with pytest.raises(error):
        create_tenant(_name(), parent_id=parent, caller=caller)
    after = platform.scalar("SELECT count(*) FROM core.tenants WHERE parent_id = :p", {"p": parent})
    assert after == before  # refused before the tenant row was inserted
    denied = platform.audit(action="platform.tenant.create", outcome="denied")
    assert [row["reason"] for row in denied] == [code]
    assert denied[0]["target_id"] == str(parent)


def test_root_creation_is_allowed_for_provisioning_and_for_an_operator(
    scene: Scene, platform: PlatformWorld
) -> None:
    operator, _ = platform.operator([P.TENANT_CREATE])
    for caller in (PROVISIONING, operator):
        tenant = create_tenant(_name(), caller=caller)
        scene.tenants.append(tenant.id)
        assert tenant.parent_id is None and tenant.status == "pending"
    for purpose in (TENANT_PURGE, BILLING, BOOTSTRAP):
        with pytest.raises(PlatformNotAuthorizedError):
            create_tenant(_name(), caller=purpose)


def test_no_tenant_authority_creates_a_child_beneath_an_active_parent(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Ruling R3: a tenant administrator with every tenant permission and
    SUBTREE scope, a delegate and a support grantee all have no path."""
    parent = scene.tenant(active=True)
    administrator, _ = scene.admin(
        parent, extra=[("delegation_grant", "create")], scope=RoleScope.SUBTREE
    )
    delegate = UserCaller(platform.user())
    permission = register_permission("membership_role", "create")
    create_delegation(
        caller=administrator,
        delegate_user_id=delegate.user_id,
        tenant_id=parent,
        scope_mode=RoleScope.SUBTREE,
        permission_id=permission.id,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    for caller in (administrator, delegate):
        with pytest.raises(PlatformNotAuthorizedError):
            create_tenant(_name(), parent_id=parent, caller=caller)
    children = platform.scalar(
        "SELECT count(*) FROM core.tenants WHERE parent_id = :p", {"p": parent}
    )
    assert children == 0


def test_a_parent_activated_after_the_callers_decision_is_judged_as_active(scene: Scene) -> None:
    """The status used is the one read under the row lock at creation time,
    not the one the caller saw when it decided to ask."""
    parent = scene.tenant()
    child = create_tenant(_name(), parent_id=parent, caller=PROVISIONING)
    scene.tenants.append(child.id)
    transition_tenant_status(parent, TenantStatus.ACTIVE, caller=PROVISIONING)
    with pytest.raises(TenantParentRuleError) as refused:
        create_tenant(_name(), parent_id=parent, caller=PROVISIONING)
    assert refused.value.code == "parent_active_requires_operator"


# --- evidence -------------------------------------------------------------------


def test_creation_writes_platform_and_tenant_evidence_in_one_transaction(
    scene: Scene, platform: PlatformWorld
) -> None:
    parent = scene.tenant()
    platform.clear_audit()
    child = create_tenant(_name(), parent_id=parent, caller=PROVISIONING).id
    scene.tenants.append(child)

    rows = platform.audit(action="platform.tenant.create")
    assert len(rows) == 1
    assert rows[0]["actor_type"] == "system" and rows[0]["system_authority"] == "provisioning"
    assert rows[0]["target_tenant_id"] == child and rows[0]["outcome"] == "success"
    assert rows[0]["metadata"] == {"parent_id": str(parent), "parent_status": "pending"}

    own = scene.tenant_audit(child, "tenant.create")
    assert len(own) == 1 and own[0]["actor_type"] == "system"
    attached = scene.tenant_audit(parent, "tenant.child_attach")
    assert len(attached) == 1 and attached[0]["resource_id"] == str(child)


def test_an_operator_is_recorded_as_a_person_in_both_trails(
    scene: Scene, platform: PlatformWorld
) -> None:
    operator, _ = platform.operator([P.TENANT_CREATE, P.TENANT_SUSPEND, P.TENANT_REACTIVATE])
    tenant = create_tenant(_name(), caller=operator).id
    scene.tenants.append(tenant)
    transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=operator)
    transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=operator, reason=REASON)
    transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=operator)

    for action in ("create", "activate", "suspend", "reactivate"):
        rows = platform.audit(action=f"platform.tenant.{action}", outcome="success")
        assert len(rows) == 1, action
        assert rows[0]["actor_type"] == "user" and rows[0]["actor_user_id"] == operator.user_id
        assert rows[0]["target_tenant_id"] == tenant
        own = scene.tenant_audit(tenant, f"tenant.{action}")
        assert len(own) == 1, action
        assert own[0]["actor_type"] == "user" and own[0]["actor_user_id"] == operator.user_id
    assert platform.audit(action="platform.tenant.suspend")[0]["reason"] == REASON


@pytest.mark.parametrize("failing", ["record_platform", "record_tenant"])
def test_a_failure_in_either_evidence_write_rolls_the_change_back(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    tenant = scene.tenant(active=True)
    operator, _ = platform.operator([P.TENANT_SUSPEND])
    platform.clear_audit()
    before = len(scene.tenant_audit(tenant))

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("forced evidence failure")

    monkeypatch.setattr(lifecycle_authority, failing, boom)
    with pytest.raises(RuntimeError):
        transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=operator)
    assert scene.status(tenant) == "active"
    assert platform.audit(outcome="success") == []
    assert len(scene.tenant_audit(tenant)) == before


def test_deletion_evidence_is_written_inside_the_transition(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    operator, _ = platform.operator([P.TENANT_DELETE])
    transition_tenant_status(tenant, TenantStatus.DELETED, caller=operator)
    own = scene.tenant_audit(tenant, "tenant.delete_requested")
    assert len(own) == 1 and own[0]["actor_user_id"] == operator.user_id
    assert own[0]["metadata"] == {"from_status": "active", "to_status": "deleted"}
    assert len(platform.audit(action="platform.tenant.delete", outcome="success")) == 1
    # A row for a closed tenant is accepted by `core.audit_log` (one of the
    # open questions for Phase C): the purge transition's platform row too.
    transition_tenant_status(tenant, TenantStatus.PURGING, caller=TENANT_PURGE)
    assert len(platform.audit(action="platform.tenant.purge_transition")) == 1


# --- move -----------------------------------------------------------------------


def test_move_requires_the_permission_and_writes_evidence_in_three_trails(
    scene: Scene, platform: PlatformWorld
) -> None:
    old_parent = scene.tenant()
    new_parent = scene.tenant()
    tenant = scene.tenant(parent=old_parent)
    mover, _ = platform.operator([P.TENANT_MOVE])
    platform.clear_audit()
    moved = move_tenant(tenant, new_parent, caller=mover, reason=REASON)
    assert moved.parent_id == new_parent
    rows = platform.audit(action="platform.tenant.move", outcome="success")
    assert len(rows) == 1 and rows[0]["actor_user_id"] == mover.user_id
    assert rows[0]["metadata"] == {
        "old_parent_id": str(old_parent),
        "new_parent_id": str(new_parent),
    }
    for audited in (tenant, old_parent, new_parent):
        own = scene.tenant_audit(audited, "tenant.move")
        assert len(own) == 1 and own[0]["resource_id"] == str(tenant)
        assert own[0]["actor_user_id"] == mover.user_id


def test_move_refuses_a_caller_who_is_a_member_of_the_new_parents_chain(
    scene: Scene, platform: PlatformWorld
) -> None:
    grandparent = scene.tenant()
    new_parent = scene.tenant(parent=grandparent)
    tenant = scene.tenant()
    mover, _ = platform.operator([P.TENANT_MOVE])
    membership = scene.join(grandparent, mover.user_id)
    with pytest.raises(MoveIntoCallerHierarchyError):
        move_tenant(tenant, new_parent, caller=mover)
    assert (
        platform.scalar("SELECT parent_id FROM core.tenants WHERE id = :t", {"t": tenant}) is None
    )
    denied = platform.audit(action="platform.tenant.move", outcome="denied")
    assert [row["reason"] for row in denied] == ["caller_in_new_parent_chain"]
    # A suspended membership still counts: it can be reactivated.
    platform.execute(
        "UPDATE core.tenant_memberships SET status = 'suspended' WHERE id = :m", {"m": membership}
    )
    with pytest.raises(MoveIntoCallerHierarchyError):
        move_tenant(tenant, new_parent, caller=mover)
    platform.execute(
        "UPDATE core.tenant_memberships SET status = 'revoked' WHERE id = :m", {"m": membership}
    )
    assert move_tenant(tenant, new_parent, caller=mover).parent_id == new_parent


def test_move_refuses_a_suspended_new_parent(scene: Scene, platform: PlatformWorld) -> None:
    """ADR-0045 section 12a, amendment of 2026-10-31: nobody attaches a
    child to a suspended tenant, by a move as by a creation. A suspended
    tenant may itself be moved, and a no-op move stays a no-op."""
    old_parent = scene.tenant()
    suspended = scene.tenant()
    scene.set_status(suspended, TenantStatus.SUSPENDED)
    tenant = scene.tenant(parent=old_parent)
    mover, _ = platform.operator([P.TENANT_MOVE])
    platform.clear_audit()
    before = len(scene.tenant_audit(suspended))

    with pytest.raises(TenantParentRuleError) as refused:
        move_tenant(tenant, suspended, caller=mover, reason=REASON)
    assert refused.value.code == "parent_suspended"
    assert refused.value.parent_id == suspended
    parent_now = platform.scalar("SELECT parent_id FROM core.tenants WHERE id = :t", {"t": tenant})
    assert parent_now == old_parent
    ancestors = platform.scalar(
        "SELECT count(*) FROM core.tenant_ancestry WHERE tenant_id = :t AND ancestor_id = :a",
        {"t": tenant, "a": suspended},
    )
    assert ancestors == 0
    denied = platform.audit(action="platform.tenant.move", outcome="denied")
    assert [row["reason"] for row in denied] == ["parent_suspended"]
    assert platform.audit(action="platform.tenant.move", outcome="success") == []
    assert len(scene.tenant_audit(suspended)) == before

    # The suspended tenant itself may still be moved, to a root position.
    scene.set_status(tenant, TenantStatus.SUSPENDED)
    assert move_tenant(tenant, None, caller=mover).parent_id is None
    # A tenant already beneath a parent that is later suspended: a no-op.
    child = scene.tenant(parent=old_parent)
    scene.set_status(old_parent, TenantStatus.SUSPENDED)
    assert move_tenant(child, old_parent, caller=mover).parent_id == old_parent
    # Reactivated, the parent admits the move again.
    scene.set_status(suspended, TenantStatus.ACTIVE)
    assert move_tenant(child, suspended, caller=mover).parent_id == suspended


# --- tenant self-service suspension ------------------------------------------------


def _self_suspender(scene: Scene, tenant: uuid.UUID) -> UserCaller:
    user_id, membership_id = scene.member(tenant)
    scene.role(tenant, membership_id, [SELF_SUSPEND])
    return UserCaller(user_id)


def test_a_member_holding_tenant_suspend_may_suspend_their_own_tenant(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    scene.admin(tenant)
    member = _self_suspender(scene, tenant)
    platform.clear_audit()
    with pytest.raises(InvalidPlatformRequestError):  # a reason is required
        transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=member)
    assert scene.status(tenant) == "active"
    transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=member, reason=REASON)
    assert scene.status(tenant) == "suspended"
    own = scene.tenant_audit(tenant, "tenant.suspend")
    assert len(own) == 1 and own[0]["actor_user_id"] == member.user_id
    assert own[0]["metadata"]["self_service"] is True
    # A tenant operation: no platform success row.
    assert platform.audit(action="platform.tenant.suspend", outcome="success") == []
    # Nobody inside a suspended tenant can reactivate it.
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=member)
    assert scene.status(tenant) == "suspended"


def test_self_suspension_is_refused_for_everyone_but_the_tenants_own_role_holder(
    scene: Scene, platform: PlatformWorld
) -> None:
    parent = scene.tenant()
    tenant = scene.tenant(parent=parent)
    scene.activate(parent, tenant)
    register_permission(*SELF_SUSPEND)

    plain_member = UserCaller(scene.member(tenant)[0])
    # An ancestor's administrator holding the permission with SUBTREE scope.
    ancestor_admin, _ = scene.admin(parent, extra=[SELF_SUSPEND], scope=RoleScope.SUBTREE)
    assert can(
        actor_id=ancestor_admin.user_id, tenant_id=tenant, action="suspend", resource="tenant"
    )
    # A delegate of the tenant's own administrator.
    delegator, _ = scene.admin(tenant, extra=[SELF_SUSPEND, ("delegation_grant", "create")])
    delegate = UserCaller(platform.user())
    create_delegation(
        caller=delegator,
        delegate_user_id=delegate.user_id,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=register_permission(*SELF_SUSPEND).id,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    assert can(actor_id=delegate.user_id, tenant_id=tenant, action="suspend", resource="tenant")
    # A support grantee.
    support = UserCaller(platform.user())
    approver, _ = scene.admin(tenant, extra=[("support_access_request", "approve")])
    request = create_support_access_request(
        caller=support,
        tenant_id=tenant,
        reason="incident",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    approve_support_access(tenant_id=tenant, request_id=request.id, caller=approver)
    assert not can(actor_id=support.user_id, tenant_id=tenant, action="suspend", resource="tenant")

    for caller in (plain_member, ancestor_admin, delegate, support):
        with pytest.raises(PlatformNotAuthorizedError):
            transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=caller, reason=REASON)
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(
            tenant,
            TenantStatus.SUSPENDED,
            caller=ServiceAccountCaller(service_account_id=uuid.uuid4(), tenant_id=tenant),
            reason=REASON,
        )
    assert scene.status(tenant) == "active"
    # The role holder may not suspend a descendant, only their own tenant.
    parent_suspender = _self_suspender(scene, parent)
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(
            tenant, TenantStatus.SUSPENDED, caller=parent_suspender, reason=REASON
        )
    assert scene.status(tenant) == "active"


def test_the_platform_tenant_cannot_be_self_suspended(
    scene: Scene, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = scene.tenant(active=True)
    scene.admin(tenant)
    member = _self_suspender(scene, tenant)
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(tenant))
    get_tenancy_config.cache_clear()
    try:
        with pytest.raises(PlatformNotAuthorizedError):
            transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=member, reason=REASON)
        assert scene.status(tenant) == "active"
    finally:
        monkeypatch.delenv("PLATFORM_TENANT_ID")
        get_tenancy_config.cache_clear()


def test_self_suspension_keeps_the_descendant_administrator_guard(scene: Scene) -> None:
    """ADR-0043, unchanged: suspending a tenant whose SUBTREE administrator
    is the only administrator of a child is refused."""
    tenant = scene.tenant()
    child = scene.tenant(parent=tenant)
    scene.activate(tenant, child)
    subtree_admin, _ = scene.admin(tenant, scope=RoleScope.SUBTREE)
    # An administrator is an ACTIVE member of the tenant itself (ADR-0043):
    # this one is a member of the child, and owes the authority there to
    # the SUBTREE role in the parent.
    scene.join(child, subtree_admin.user_id)
    assert scene.has_administrator(child)
    member = _self_suspender(scene, tenant)
    with pytest.raises(LastTenantAdministratorError):
        transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=member, reason=REASON)
    assert scene.status(tenant) == "active"
