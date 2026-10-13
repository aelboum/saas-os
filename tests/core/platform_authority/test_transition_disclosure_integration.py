"""`transition_tenant_status` discloses nothing to a caller without
authority, against a real PostgreSQL (ADR-0045 section 12).

A preliminary gate refuses such a caller before the tenant is read or
locked, with the same error and the same evidence whether the tenant
exists or not and whatever its status. The gate is not the decision: the
caller is authorized again inside the transaction, under its locks.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, REASON, TENANT_PURGE, P, Scene
from platform_helpers import PlatformWorld, join, start, wait_until_blocked_by
from sqlalchemy import text

import saas_os.core.tenancy.authority as lifecycle_authority
from saas_os.core.authority import UserCaller
from saas_os.core.platform_authority import (
    InvalidPlatformRequestError,
    PlatformNotAuthorizedError,
    revoke_platform_permission,
)
from saas_os.core.rbac import register_permission
from saas_os.core.tenancy import (
    InvalidTenantTransitionError,
    TenantNotFoundError,
    TenantStatus,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

SELF_SUSPEND = ("tenant", "suspend")

# target status -> the operations it can select, first one first. No edge
# leads to PENDING: it has none, and is refused as a request (below).
_CANDIDATES: dict[TenantStatus, list[str]] = {
    TenantStatus.ACTIVE: ["tenant.activate", "tenant.reactivate"],
    TenantStatus.SUSPENDED: ["tenant.suspend"],
    TenantStatus.DELETED: ["tenant.delete"],
    TenantStatus.PURGING: ["tenant.purge_transition"],
    TenantStatus.PURGED: ["tenant.purge_transition"],
}
_STATES = list(TenantStatus)


def _tenant_in(scene: Scene, status: TenantStatus | None) -> uuid.UUID:
    """A tenant put directly in `status`; `None` is an id that names no
    tenant at all."""
    if status is None:
        return uuid.uuid4()
    tenant = scene.tenant()
    scene.set_status(tenant, status)
    return tenant


def _refusal(caller: Any, tenant: uuid.UUID, target: TenantStatus) -> PlatformNotAuthorizedError:
    with pytest.raises(PlatformNotAuthorizedError) as raised:
        transition_tenant_status(tenant, target, caller=caller, reason=REASON)
    return raised.value


# --- the same refusal, whatever is true of the tenant --------------------------------


@pytest.mark.parametrize("target", list(_CANDIDATES))
def test_a_caller_without_authority_gets_one_answer_for_every_tenant_state(
    scene: Scene, platform: PlatformWorld, target: TenantStatus
) -> None:
    stranger = UserCaller(platform.user())
    candidates = _CANDIDATES[target]
    answers = set()
    for status in (None, *_STATES):
        tenant = _tenant_in(scene, status)
        platform.clear_audit()

        refusal = _refusal(stranger, tenant, target)

        answers.add((type(refusal), refusal.operation, refusal.code, str(refusal)))
        if status is not None:
            assert scene.status(tenant) == status.value  # nothing changed
        # Exactly one row, and it says nothing about the tenant.
        (row,) = platform.audit()
        assert row["action"] == f"platform.{candidates[0]}"
        assert row["outcome"] == "denied" and row["reason"] == "not_authorized"
        assert row["actor_user_id"] == stranger.user_id
        assert row["target_id"] == str(tenant) and row["target_tenant_id"] is None
        assert row["metadata"] == {
            "to_status": target.value,
            "candidate_operations": candidates,
            "stage": "preliminary",
        }
    # Missing, and in each of the six statuses: indistinguishable.
    assert len(answers) == 1


def test_an_activation_refusal_is_recorded_as_activate_and_names_both_candidates(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = _tenant_in(scene, TenantStatus.SUSPENDED)  # it would be a reactivation
    platform.clear_audit()
    refusal = _refusal(UserCaller(platform.user()), tenant, TenantStatus.ACTIVE)
    assert refusal.operation == "tenant.activate"
    (row,) = platform.audit()
    assert row["action"] == "platform.tenant.activate"
    assert row["metadata"]["candidate_operations"] == ["tenant.activate", "tenant.reactivate"]


@pytest.mark.parametrize(
    ("caller", "target"),
    [
        (PROVISIONING, TenantStatus.SUSPENDED),
        (PROVISIONING, TenantStatus.DELETED),
        (PROVISIONING, TenantStatus.PURGING),
        (BILLING, TenantStatus.ACTIVE),
        (TENANT_PURGE, TenantStatus.ACTIVE),
        (TENANT_PURGE, TenantStatus.SUSPENDED),
    ],
)
def test_a_system_purpose_the_target_does_not_accept_gets_the_same_answer(
    scene: Scene, platform: PlatformWorld, caller: Any, target: TenantStatus
) -> None:
    answers = set()
    for status in (None, TenantStatus.PENDING, TenantStatus.ACTIVE, TenantStatus.DELETED):
        refusal = _refusal(caller, _tenant_in(scene, status), target)
        answers.add((refusal.operation, refusal.code))
    assert len(answers) == 1
    denied = platform.audit(outcome="denied")
    assert len(denied) == 4
    assert all(row["metadata"]["stage"] == "preliminary" for row in denied)


# --- the gate reads and locks nothing ------------------------------------------------


def test_the_refusal_does_not_wait_for_the_tenant_row(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Another transaction holds the tenant's row `FOR UPDATE`. A caller
    without authority is refused at once: the gate neither reads the row
    under lock nor waits for it."""
    tenant = scene.tenant(active=True)
    stranger = UserCaller(platform.user())
    connection = platform.admin.connect()
    transaction = connection.begin()
    try:
        connection.execute(
            text("SELECT id FROM core.tenants WHERE id = :t FOR UPDATE"), {"t": tenant}
        )
        thread, outcome = start(
            lambda: transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=stranger),
            "stranger",
        )
        thread.join(timeout=20)
        finished_while_locked = not thread.is_alive()
    finally:
        transaction.rollback()
        connection.close()
    join(thread)
    assert finished_while_locked
    assert isinstance(outcome["error"], PlatformNotAuthorizedError)


# --- the gate is not the decision ---------------------------------------------------


def test_authority_revoked_after_the_gate_does_not_carry_the_transition(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = scene.tenant(active=True)
    owner, _ = platform.owner()
    operator, operator_id = platform.operator([P.TENANT_SUSPEND])
    real = lifecycle_authority.passes_transition_gate

    def gate_then_revoke(*args: Any, **kwargs: Any) -> bool:
        passed = real(*args, **kwargs)
        assert passed  # the caller held the permission when the gate looked
        revoke_platform_permission(operator_id, P.TENANT_SUSPEND, caller=owner, reason=REASON)
        return passed

    monkeypatch.setattr(lifecycle_authority, "passes_transition_gate", gate_then_revoke)
    platform.clear_audit()

    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=operator)

    assert scene.status(tenant) == "active"
    (denied,) = platform.audit(action="platform.tenant.suspend", outcome="denied")
    assert denied["metadata"] is None  # refused by the decision, not by the gate


def test_a_member_without_the_permission_passes_the_gate_and_is_refused_by_the_decision(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Suspension admits the tenant's own members to the gate, because the
    self-service rule can only ever admit one of them. A member the rule
    does not admit is refused by the decision -- before the tenant's status
    is reported, so the answer does not depend on it."""
    register_permission(*SELF_SUSPEND)
    answers = set()
    for status in (TenantStatus.ACTIVE, TenantStatus.SUSPENDED, TenantStatus.DELETED):
        tenant = scene.tenant(active=True)
        member = UserCaller(scene.member(tenant)[0])
        scene.set_status(tenant, status)
        platform.clear_audit()
        refusal = _refusal(member, tenant, TenantStatus.SUSPENDED)
        answers.add((refusal.operation, refusal.code))
        assert scene.status(tenant) == status.value
        (row,) = platform.audit()
        assert row["action"] == "platform.tenant.suspend" and row["metadata"] is None
    assert answers == {("tenant.suspend", "not_authorized")}


# --- what is unchanged ---------------------------------------------------------------


def test_self_service_suspension_still_works_and_only_for_the_callers_own_tenant(
    scene: Scene, platform: PlatformWorld
) -> None:
    register_permission(*SELF_SUSPEND)
    tenant, other = scene.tenant(active=True), scene.tenant(active=True)
    scene.admin(tenant)  # the tenant keeps an administrator
    user_id, membership_id = scene.member(tenant)
    scene.role(tenant, membership_id, [SELF_SUSPEND])
    member = UserCaller(user_id)

    platform.clear_audit()
    refusal = _refusal(member, other, TenantStatus.SUSPENDED)
    assert refusal.code == "not_authorized"
    assert platform.audit()[0]["metadata"]["stage"] == "preliminary"  # not a member there
    assert scene.status(other) == "active"

    transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=member, reason=REASON)
    assert scene.status(tenant) == "suspended"
    (own,) = scene.tenant_audit(tenant, "tenant.suspend")
    assert own["metadata"]["self_service"] is True


def test_a_caller_with_the_authority_is_still_told_what_is_wrong_with_the_request(
    scene: Scene, platform: PlatformWorld
) -> None:
    """The two state errors are unchanged for a caller who holds the
    authority the transition needs."""
    suspender, _ = platform.operator([P.TENANT_SUSPEND])
    with pytest.raises(TenantNotFoundError):
        transition_tenant_status(uuid.uuid4(), TenantStatus.SUSPENDED, caller=suspender)
    with pytest.raises(InvalidTenantTransitionError):
        transition_tenant_status(scene.tenant(), TenantStatus.SUSPENDED, caller=suspender)


def test_a_target_no_edge_leads_to_is_refused_as_a_request_before_anything_is_read(
    scene: Scene, platform: PlatformWorld
) -> None:
    """`PENDING` can be reached from nowhere. Every caller is told so in
    the same words for every tenant, with no audit row and no read: the
    answer depends on the request alone, so it cannot be used to learn
    whether a tenant exists or what state it is in."""
    register_permission(*SELF_SUSPEND)
    own = scene.tenant(active=True)
    member = UserCaller(scene.member(own)[0])
    operator, _ = platform.operator([P.TENANT_SUSPEND, P.TENANT_CREATE, P.TENANT_DELETE])
    callers: list[Any] = [UserCaller(platform.user()), member, operator, PROVISIONING, TENANT_PURGE]
    platform.clear_audit()
    answers = set()
    for caller in callers:
        for status in (None, *_STATES):
            tenant = own if (caller is member and status is TenantStatus.ACTIVE) else None
            tenant = tenant or _tenant_in(scene, status)
            with pytest.raises(InvalidPlatformRequestError) as raised:
                transition_tenant_status(tenant, TenantStatus.PENDING, caller=caller, reason=REASON)
            answers.add(str(raised.value))
    assert answers == {"No tenant transition leads to 'pending'."}
    assert platform.audit(outcome="denied") == []
    assert scene.status(own) == "active"


def test_a_self_service_holder_repeating_a_suspension_is_refused_not_told_the_status(
    scene: Scene, platform: PlatformWorld
) -> None:
    """A consequence of deciding before the edge is validated (ADR-0045
    section 12). The self-service rule admits a member only of a tenant
    that admits its principals; once the tenant is suspended the same
    member is refused, where `InvalidTenantTransitionError` used to be
    reported."""
    register_permission(*SELF_SUSPEND)
    tenant = scene.tenant(active=True)
    scene.admin(tenant)
    user_id, membership_id = scene.member(tenant)
    scene.role(tenant, membership_id, [SELF_SUSPEND])
    member = UserCaller(user_id)
    transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=member, reason=REASON)
    platform.clear_audit()

    refusal = _refusal(member, tenant, TenantStatus.SUSPENDED)

    assert (refusal.operation, refusal.code) == ("tenant.suspend", "not_authorized")
    assert scene.status(tenant) == "suspended"
    (row,) = platform.audit()
    assert row["action"] == "platform.tenant.suspend" and row["outcome"] == "denied"
    assert row["actor_user_id"] == user_id and row["metadata"] is None


def test_the_state_errors_of_an_activation_need_the_authority_under_lock(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """For `ACTIVE` the operation is not known before the status is read.
    A missing tenant or an invalid edge is still reported only to a caller
    who holds, inside the transaction, the authority for one of the two
    candidates -- not to one who merely held it when the gate looked."""
    owner, _ = platform.owner()
    creator, operator_id = platform.operator([P.TENANT_CREATE])
    deleted = _tenant_in(scene, TenantStatus.DELETED)
    real = lifecycle_authority.passes_transition_gate
    revoked = {"done": False}

    def gate_then_revoke(*args: Any, **kwargs: Any) -> bool:
        passed = real(*args, **kwargs)
        if not revoked["done"]:
            assert passed
            revoke_platform_permission(operator_id, P.TENANT_CREATE, caller=owner, reason=REASON)
            revoked["done"] = True
        return passed

    # While the authority is held: the two state errors, as documented.
    with pytest.raises(TenantNotFoundError):
        transition_tenant_status(uuid.uuid4(), TenantStatus.ACTIVE, caller=creator)
    with pytest.raises(InvalidTenantTransitionError):
        transition_tenant_status(deleted, TenantStatus.ACTIVE, caller=creator)

    monkeypatch.setattr(lifecycle_authority, "passes_transition_gate", gate_then_revoke)
    with pytest.raises(PlatformNotAuthorizedError):  # revoked after the gate: told nothing
        transition_tenant_status(uuid.uuid4(), TenantStatus.ACTIVE, caller=creator)
    monkeypatch.setattr(lifecycle_authority, "passes_transition_gate", lambda *a, **k: True)
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(deleted, TenantStatus.ACTIVE, caller=creator)
    assert scene.status(deleted) == "deleted"


def test_the_residual_for_an_activation_is_limited_to_holders_of_one_of_its_operations(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Documented residual (ADR-0045 section 12). For `ACTIVE` the
    operation depends on the status read, so a caller who holds the
    authority for one of the two candidates passes the gate and can learn
    that a tenant does not exist, or that it needs the other one."""
    creator, _ = platform.operator([P.TENANT_CREATE])  # may activate, not reactivate
    with pytest.raises(TenantNotFoundError):
        transition_tenant_status(uuid.uuid4(), TenantStatus.ACTIVE, caller=creator)
    suspended = _tenant_in(scene, TenantStatus.SUSPENDED)
    platform.clear_audit()
    refusal = _refusal(creator, suspended, TenantStatus.ACTIVE)
    assert refusal.operation == "tenant.reactivate"  # the operation the status selected
    assert scene.status(suspended) == "suspended"
    (row,) = platform.audit()
    assert row["action"] == "platform.tenant.reactivate" and row["metadata"] is None


# --- negative control ----------------------------------------------------------------


def test_without_the_gate_a_caller_without_authority_makes_the_transition_lock_the_tenant(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    stranger = UserCaller(platform.user())
    missing, pending, deleted = uuid.uuid4(), scene.tenant(), scene.tenant()
    scene.set_status(deleted, TenantStatus.DELETED)
    for tenant in (missing, pending, deleted):
        _refusal(stranger, tenant, TenantStatus.ACTIVE)  # the gate: one answer

    monkeypatch.setattr(lifecycle_authority, "passes_transition_gate", lambda *a, **k: True)

    # The decision under lock still refuses every one of them: with the
    # gate gone the answer is the same, and nothing is changed...
    for tenant in (missing, pending, deleted):
        _refusal(stranger, tenant, TenantStatus.ACTIVE)
    assert scene.status(pending) == "pending" and scene.status(deleted) == "deleted"
    # ...but the tenant's row is now read and locked for a caller with no
    # authority: the call waits behind another transaction holding it.
    connection = platform.admin.connect()
    transaction = connection.begin()
    try:
        connection.execute(
            text("SELECT id FROM core.tenants WHERE id = :t FOR UPDATE"), {"t": pending}
        )
        blocker = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        thread, outcome = start(
            lambda: transition_tenant_status(pending, TenantStatus.ACTIVE, caller=stranger),
            "stranger",
        )
        wait_until_blocked_by(platform.admin, blocker)  # what the gate prevents
    finally:
        transaction.rollback()
        connection.close()
    join(thread)
    assert isinstance(outcome["error"], PlatformNotAuthorizedError)
