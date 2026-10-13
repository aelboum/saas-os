"""Platform authority against a real PostgreSQL (ADR-0045 Phase B):
`platform_can()`, `authorize_platform_caller()`, the operator and grant
lifecycle, the rules for a person changing authority, platform audit, and
the separation from tenant RBAC.

Each denial test has a matching negative control in
`test_platform_authority_negative_controls_integration.py`, which removes
the protection and shows the same scenario succeeding.

Marked `integration`, excluded from the default `pytest` run. Disposable
databases only: every test starts from empty platform tables.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from platform_helpers import ALL_PERMISSIONS, BOOTSTRAP, REASON, PlatformWorld
from sqlalchemy import text

import saas_os.core.platform_authority.audit as audit_module
import saas_os.core.platform_authority.service as service_module
from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)
from saas_os.core.identity import add_tenant_membership
from saas_os.core.platform_authority import (
    PLATFORM_OPERATIONS,
    DuplicatePlatformGrantError,
    InactivePlatformSubjectError,
    InvalidPlatformOperatorStateError,
    InvalidPlatformRequestError,
    PlatformAmplificationError,
    PlatformAuditOutcome,
    PlatformGrantNotFoundError,
    PlatformNotAuthorizedError,
    PlatformOperatorAlreadyEnrolledError,
    PlatformOperatorNotFoundError,
    PlatformPermission,
    PlatformSubjectNotFoundError,
    SelfAuthorityChangeError,
    UnknownPlatformOperationError,
    authorize_platform_caller,
    enroll_operator,
    grant_platform_permission,
    platform_can,
    platform_owner_exists,
    reactivate_operator,
    record_platform_event_in_transaction,
    revoke_operator,
    revoke_platform_permission,
    suspend_operator,
)
from saas_os.core.rbac import (
    assign_first_role_for_new_tenant,
    can,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
MANAGE = P.AUTHORITY_MANAGE


# --- platform_can ------------------------------------------------------------


def test_platform_can_requires_user_operator_and_grant(platform: PlatformWorld) -> None:
    assert platform_can(user_id=uuid.uuid4(), permission=P.TENANT_READ) is False  # no such user
    plain_user = platform.user()
    assert platform_can(user_id=plain_user, permission=P.TENANT_READ) is False  # not an operator

    caller, operator_id = platform.operator([P.TENANT_READ])
    assert platform_can(user_id=caller.user_id, permission=P.TENANT_READ) is True
    # Holding one permission implies no other.
    for other in P:
        if other is not P.TENANT_READ:
            assert platform_can(user_id=caller.user_id, permission=other) is False, other
    assert platform.live_permissions(operator_id) == {"platform.tenant:read"}


def test_platform_can_denies_a_suspended_or_revoked_operator_and_an_inactive_user(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    subject, operator_id = platform.operator([P.TENANT_READ])
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is True

    suspend_operator(operator_id, caller=owner, reason=REASON)
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is False
    reactivate_operator(operator_id, caller=owner, reason=REASON)
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is True

    platform.set_user_active(subject.user_id, False)
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is False
    platform.set_user_active(subject.user_id, True)
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is True

    revoke_operator(operator_id, caller=owner, reason=REASON)
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is False


def test_platform_can_fails_closed_on_wrong_argument_types(platform: PlatformWorld) -> None:
    owner, _ = platform.owner()
    assert platform_can(user_id=owner.user_id, permission=MANAGE) is True
    assert platform_can(user_id=str(owner.user_id), permission=MANAGE) is False  # type: ignore[arg-type]
    assert platform_can(user_id=owner.user_id, permission=MANAGE.value) is False  # type: ignore[arg-type]
    assert platform_can(user_id=owner.user_id, permission="*") is False  # type: ignore[arg-type]
    assert platform_can(user_id=None, permission=MANAGE) is False  # type: ignore[arg-type]


def test_platform_can_inside_a_tenant_scope_is_false_fail_closed(platform: PlatformWorld) -> None:
    """Defence in depth: bound to a tenant, the platform tables are hidden,
    so even a real owner is not seen. Authorization never relies on this;
    it is what happens if code gets the ordering wrong."""
    owner, _ = platform.owner()
    with tenant_session_scope(uuid.uuid4()) as session:
        assert platform_can(user_id=owner.user_id, permission=MANAGE, session=session) is False
        assert platform_owner_exists(session) is False
    with session_scope() as session:
        assert platform_can(user_id=owner.user_id, permission=MANAGE, session=session) is True


def test_visibility_of_platform_rows_is_not_authorization(platform: PlatformWorld) -> None:
    """An untenanted session of the runtime role can *see* every platform
    row -- the row-level-security policy does not stop it -- and a user
    with no grant is still refused. The decision is Core's, not the
    policy's."""
    owner, operator_id = platform.owner()
    stranger = UserCaller(platform.user())
    with session_scope() as session:
        visible = session.execute(text("SELECT count(*) FROM core.platform_grants")).scalar_one()
        assert visible == len(ALL_PERMISSIONS)
        with pytest.raises(PlatformNotAuthorizedError):
            authorize_platform_caller(stranger, session=session, operation="grant.create")
    with pytest.raises(PlatformNotAuthorizedError):
        suspend_operator(operator_id, caller=stranger, reason=REASON)
    assert platform.operator_status(operator_id) == "active"
    assert platform_can(user_id=owner.user_id, permission=MANAGE) is True


# --- separation from tenant RBAC --------------------------------------------


@pytest.fixture
def tenant_admin(platform: PlatformWorld) -> Iterator[tuple[uuid.UUID, UserCaller]]:
    """A tenant with one administrator holding `membership_role:create`."""
    tenant_id = create_tenant(f"pa-{uuid.uuid4().hex[:10]}", caller=PROVISIONING).id
    user_id = platform.user()
    membership = add_tenant_membership(tenant_id, user_id, caller=PROVISIONING)
    role = create_role(tenant_id, "admin", caller=PROVISIONING)
    permission = register_permission("membership_role", "create")
    grant_permission(tenant_id, role.id, permission.id, caller=PROVISIONING)
    assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=PROVISIONING)
    try:
        yield tenant_id, UserCaller(user_id)
    finally:
        for table in (
            "audit_log",
            "membership_roles",
            "role_permissions",
            "roles",
            "tenant_memberships",
            "tenant_ancestry",
        ):
            platform.execute(
                f"DELETE FROM core.{table} WHERE tenant_id = :t",  # noqa: S608 -- fixed names
                {"t": tenant_id},
            )
        platform.execute(
            "DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", {"t": tenant_id}
        )
        platform.execute("DELETE FROM core.tenants WHERE id = :t", {"t": tenant_id})


def test_a_tenant_administrator_holds_no_platform_authority(
    platform: PlatformWorld,
    tenant_admin: tuple[uuid.UUID, UserCaller],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not even an administrator of the designated platform tenant:
    `PLATFORM_TENANT_ID` grants nothing."""
    from saas_os.core.tenancy.config import get_tenancy_config

    tenant_id, admin_caller = tenant_admin
    owner, operator_id = platform.owner()
    assert can(
        actor_id=admin_caller.user_id,
        tenant_id=tenant_id,
        action="create",
        resource="membership_role",
    )
    monkeypatch.setenv("PLATFORM_TENANT_ID", str(tenant_id))
    get_tenancy_config.cache_clear()
    try:
        for permission in P:
            assert platform_can(user_id=admin_caller.user_id, permission=permission) is False
        with pytest.raises(PlatformNotAuthorizedError):
            enroll_operator(platform.user(), caller=admin_caller, reason=REASON)
        with pytest.raises(PlatformNotAuthorizedError):
            grant_platform_permission(
                operator_id, P.TENANT_READ, caller=admin_caller, reason=REASON
            )
        with pytest.raises(PlatformNotAuthorizedError):
            revoke_operator(operator_id, caller=admin_caller, reason=REASON)
    finally:
        monkeypatch.delenv("PLATFORM_TENANT_ID")
        get_tenancy_config.cache_clear()
    assert platform_can(user_id=owner.user_id, permission=MANAGE) is True


def test_a_platform_owner_holds_no_tenant_authority(
    platform: PlatformWorld, tenant_admin: tuple[uuid.UUID, UserCaller]
) -> None:
    """Every platform permission confers nothing in a tenant: `can()` never
    reads a platform grant."""
    tenant_id, _ = tenant_admin
    owner, _ = platform.owner()
    for resource, action in (
        ("membership_role", "create"),
        ("role", "create"),
        ("tenant", "read_status"),
    ):
        assert not can(
            actor_id=owner.user_id, tenant_id=tenant_id, action=action, resource=resource
        )


def test_no_platform_permission_is_a_row_in_the_tenant_permission_catalog(
    platform: PlatformWorld,
) -> None:
    platform.owner()
    assert (
        platform.scalar(
            "SELECT count(*) FROM core.permissions WHERE resource LIKE 'platform.%' "
            "OR resource || ':' || action = ANY(:values)",
            {"values": [p.value for p in P]},
        )
        == 0
    )


def test_platform_operations_write_nothing_to_the_tenant_audit_log(
    platform: PlatformWorld,
) -> None:
    """Platform evidence has its own table; `core.audit_log` is untouched."""
    before = platform.scalar("SELECT count(*) FROM core.audit_log")
    owner, _ = platform.owner()
    subject, operator_id = platform.operator([])
    grant_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    suspend_operator(operator_id, caller=owner, reason=REASON)
    with pytest.raises(PlatformNotAuthorizedError):
        suspend_operator(operator_id, caller=subject, reason=REASON)
    assert platform.scalar("SELECT count(*) FROM core.audit_log") == before
    assert platform.audit_count() > 0


# --- authorize_platform_caller -------------------------------------------------


def test_authorize_refuses_a_service_account_for_every_operation(platform: PlatformWorld) -> None:
    caller = ServiceAccountCaller(uuid.uuid4(), uuid.uuid4())
    with session_scope() as session:
        for operation in PLATFORM_OPERATIONS:
            with pytest.raises(PlatformNotAuthorizedError):
                authorize_platform_caller(caller, session=session, operation=operation)


@pytest.mark.parametrize("bad", [None, "user", uuid.uuid4(), {"user_id": "x"}, object()])
def test_authorize_rejects_a_missing_or_malformed_caller(
    platform: PlatformWorld, bad: object
) -> None:
    with session_scope() as session, pytest.raises(CallerTypeError):
        authorize_platform_caller(bad, session=session, operation="grant.create")


def test_authorize_rejects_an_unknown_operation_as_a_programming_error(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    with session_scope() as session, pytest.raises(UnknownPlatformOperationError):
        authorize_platform_caller(owner, session=session, operation="tenant.purge")


def test_authorize_system_purposes_against_every_operation(platform: PlatformWorld) -> None:
    """The run-time check, cell by cell: a purpose is accepted exactly
    where the declared table lists it. A `SystemCaller` is never looked up
    as an operator."""
    with session_scope() as session:
        for operation, row in PLATFORM_OPERATIONS.items():
            for purpose in SystemAuthority:
                caller = SystemCaller(purpose)
                if purpose in row.system_authorities:
                    assert (
                        authorize_platform_caller(caller, session=session, operation=operation)
                        is row
                    )
                else:
                    with pytest.raises(PlatformNotAuthorizedError):
                        authorize_platform_caller(caller, session=session, operation=operation)


def test_a_person_cannot_perform_an_operation_that_has_no_permission(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    with session_scope() as session, pytest.raises(PlatformNotAuthorizedError):
        authorize_platform_caller(owner, session=session, operation="tenant.purge_transition")


def test_an_owner_is_authorized_for_every_operation_that_has_a_permission(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    with session_scope() as session:
        for operation, row in PLATFORM_OPERATIONS.items():
            if row.permission is not None:
                assert authorize_platform_caller(owner, session=session, operation=operation) is row


# --- enrollment -----------------------------------------------------------------


def test_enroll_creates_an_active_operator_with_no_grants_and_audits_it(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    platform.clear_audit()
    subject = platform.user()
    operator = enroll_operator(subject, caller=owner, reason="  onboarding  ")
    assert operator.status == "active" and operator.user_id == subject
    assert operator.enrolled_by_user_id == owner.user_id
    assert platform.live_permissions(operator.id) == set()
    assert platform_can(user_id=subject, permission=P.TENANT_READ) is False
    (row,) = platform.audit()
    assert row["action"] == "platform.operator.enroll" and row["outcome"] == "success"
    assert row["actor_type"] == "user" and row["actor_user_id"] == owner.user_id
    assert row["system_authority"] is None
    assert row["target_type"] == "platform_operator" and row["target_id"] == str(operator.id)
    assert row["reason"] == "onboarding"
    assert row["metadata"] == {"user_id": str(subject)}


def test_enroll_refuses_unknown_inactive_and_already_enrolled_subjects(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    with pytest.raises(PlatformSubjectNotFoundError):
        enroll_operator(uuid.uuid4(), caller=owner, reason=REASON)
    inactive = platform.user()
    platform.set_user_active(inactive, False)
    with pytest.raises(InactivePlatformSubjectError):
        enroll_operator(inactive, caller=owner, reason=REASON)
    subject = platform.user()
    enroll_operator(subject, caller=owner, reason=REASON)
    with pytest.raises(PlatformOperatorAlreadyEnrolledError):
        enroll_operator(subject, caller=owner, reason=REASON)
    assert platform.scalar("SELECT count(*) FROM core.platform_operators") == 2


def test_a_revoked_operator_can_be_reenrolled_as_a_new_row_with_no_grants(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    subject, old_operator_id = platform.operator([P.TENANT_READ, P.AUDIT_READ])
    revoke_operator(old_operator_id, caller=owner, reason=REASON)
    platform.clear_audit()

    new_operator = enroll_operator(subject.user_id, caller=owner, reason=REASON)
    assert new_operator.id != old_operator_id
    assert platform.operator_status(old_operator_id) == "revoked"  # history kept
    assert platform.live_permissions(new_operator.id) == set()  # nothing inherited
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is False
    (row,) = platform.audit("platform.operator.enroll")
    assert row["metadata"] == {
        "user_id": str(subject.user_id),
        "previous_operator_id": str(old_operator_id),
    }


# --- grants -----------------------------------------------------------------------


def test_grant_and_revoke_one_permission_with_history(platform: PlatformWorld) -> None:
    owner, _ = platform.owner()
    subject, operator_id = platform.operator([])
    platform.clear_audit()

    grant = grant_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    assert grant.granted_by_user_id == owner.user_id and grant.revoked_at is None
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is True
    with pytest.raises(DuplicatePlatformGrantError):
        grant_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)

    revoked = revoke_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    assert revoked.id == grant.id and revoked.revoked_by_user_id == owner.user_id
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is False
    with pytest.raises(PlatformGrantNotFoundError):
        revoke_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)

    regrant = grant_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    assert regrant.id != grant.id
    rows = platform.execute(
        "SELECT id, revoked_at IS NOT NULL FROM core.platform_grants "
        "WHERE operator_id = :o AND permission = 'platform.tenant:read' ORDER BY granted_at",
        {"o": operator_id},
    )
    assert rows == [(grant.id, True), (regrant.id, False)]  # the rows are the history
    assert [r["action"] for r in platform.audit(outcome="success")] == [
        "platform.grant.create",
        "platform.grant.revoke",
        "platform.grant.create",
    ]


def test_anti_amplification_a_caller_may_grant_only_what_they_hold(
    platform: PlatformWorld,
) -> None:
    platform.owner()
    manager, _ = platform.operator([MANAGE])  # may manage authority, holds nothing else
    subject, operator_id = platform.operator([])
    grant_platform_permission(operator_id, MANAGE, caller=manager, reason=REASON)
    with pytest.raises(PlatformAmplificationError):
        grant_platform_permission(operator_id, P.TENANT_SUSPEND, caller=manager, reason=REASON)
    assert platform.live_permissions(operator_id) == {MANAGE.value}
    (denied,) = platform.audit("platform.grant.create", "denied")
    assert denied["reason"] == "amplification" and denied["actor_user_id"] == manager.user_id


def test_grant_refuses_a_revoked_operator_and_an_inactive_subject(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    subject, operator_id = platform.operator([])
    platform.set_user_active(subject.user_id, False)
    with pytest.raises(InactivePlatformSubjectError):
        grant_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    platform.set_user_active(subject.user_id, True)
    revoke_operator(operator_id, caller=owner, reason=REASON)
    with pytest.raises(InvalidPlatformOperatorStateError):
        grant_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    with pytest.raises(PlatformOperatorNotFoundError):
        grant_platform_permission(uuid.uuid4(), P.TENANT_READ, caller=owner, reason=REASON)


def test_a_grant_to_a_suspended_operator_confers_nothing_until_reactivation(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    subject, operator_id = platform.operator([])
    suspend_operator(operator_id, caller=owner, reason=REASON)
    grant_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is False
    reactivate_operator(operator_id, caller=owner, reason=REASON)
    assert platform_can(user_id=subject.user_id, permission=P.TENANT_READ) is True


# --- operator status ------------------------------------------------------------------


def test_operator_status_transitions_and_their_refusals(platform: PlatformWorld) -> None:
    owner, _ = platform.owner()
    _, operator_id = platform.operator([P.TENANT_READ, P.AUDIT_READ])
    with pytest.raises(InvalidPlatformOperatorStateError):
        reactivate_operator(operator_id, caller=owner, reason=REASON)  # not suspended
    suspend_operator(operator_id, caller=owner, reason=REASON)
    with pytest.raises(InvalidPlatformOperatorStateError):
        suspend_operator(operator_id, caller=owner, reason=REASON)  # already suspended
    assert platform.live_permissions(operator_id) == {"platform.tenant:read", "platform.audit:read"}
    reactivate_operator(operator_id, caller=owner, reason=REASON)

    platform.clear_audit()
    revoked = revoke_operator(operator_id, caller=owner, reason=REASON)
    assert revoked.status == "revoked"
    assert platform.live_permissions(operator_id) == set()  # every live grant revoked with it
    assert (
        platform.scalar(
            "SELECT count(*) FROM core.platform_grants WHERE operator_id = :o", {"o": operator_id}
        )
        == 2
    )  # ...and kept as history
    (row,) = platform.audit("platform.operator.revoke")
    assert row["metadata"]["revoked_permissions"] == ["platform.audit:read", "platform.tenant:read"]
    for operation in (suspend_operator, reactivate_operator, revoke_operator):  # terminal
        with pytest.raises(InvalidPlatformOperatorStateError):
            operation(operator_id, caller=owner, reason=REASON)
    with pytest.raises(PlatformOperatorNotFoundError):
        suspend_operator(uuid.uuid4(), caller=owner, reason=REASON)


# --- no self-service -------------------------------------------------------------------


def test_an_operator_cannot_change_their_own_authority(platform: PlatformWorld) -> None:
    """Not grant to, revoke from, suspend, reactivate, revoke or enroll
    their own operator -- and the rule is in Core, not at a route."""
    platform.owner()
    owner, operator_id = platform.owner()
    before = platform.live_permissions(operator_id)
    attempts = {
        "platform.operator.enroll": lambda: enroll_operator(
            owner.user_id, caller=owner, reason=REASON
        ),
        "platform.operator.suspend": lambda: suspend_operator(
            operator_id, caller=owner, reason=REASON
        ),
        "platform.operator.reactivate": lambda: reactivate_operator(
            operator_id, caller=owner, reason=REASON
        ),
        "platform.operator.revoke": lambda: revoke_operator(
            operator_id, caller=owner, reason=REASON
        ),
        "platform.grant.revoke": lambda: revoke_platform_permission(
            operator_id, MANAGE, caller=owner, reason=REASON
        ),
        "platform.grant.create": lambda: grant_platform_permission(
            operator_id, MANAGE, caller=owner, reason=REASON
        ),
    }
    platform.clear_audit()
    for action, attempt in attempts.items():
        with pytest.raises(SelfAuthorityChangeError):
            attempt()
        (denied,) = platform.audit(action, "denied")
        assert denied["reason"] == "self_authority_change"
        assert denied["actor_user_id"] == owner.user_id
    assert platform.operator_status(operator_id) == "active"
    assert platform.live_permissions(operator_id) == before
    assert platform.audit(outcome="success") == []


# --- who may change authority --------------------------------------------------------


def _all_six(operator_id: uuid.UUID, subject_user: uuid.UUID, caller: object) -> dict[str, object]:
    return {
        "platform.operator.enroll": lambda: enroll_operator(
            subject_user, caller=caller, reason=REASON
        ),
        "platform.operator.suspend": lambda: suspend_operator(
            operator_id, caller=caller, reason=REASON
        ),
        "platform.operator.reactivate": lambda: reactivate_operator(
            operator_id, caller=caller, reason=REASON
        ),
        "platform.operator.revoke": lambda: revoke_operator(
            operator_id, caller=caller, reason=REASON
        ),
        "platform.grant.create": lambda: grant_platform_permission(
            operator_id, P.TENANT_READ, caller=caller, reason=REASON
        ),
        "platform.grant.revoke": lambda: revoke_platform_permission(
            operator_id, P.AUDIT_READ, caller=caller, reason=REASON
        ),
    }


def test_only_a_holder_of_authority_manage_may_change_authority(platform: PlatformWorld) -> None:
    """Refused: an ordinary user; an operator with every permission except
    `platform.authority:manage`; a suspended owner; an owner whose user is
    deactivated. Each refusal leaves one `denied` row and changes nothing."""
    platform.owner()
    _, target_id = platform.operator([P.AUDIT_READ])
    everything_but_manage = [p for p in P if p is not MANAGE]
    stranger = UserCaller(platform.user())
    near_owner, _ = platform.operator(everything_but_manage)
    suspended_owner, suspended_id = platform.owner()
    inactive_owner, _ = platform.owner()
    real_owner, _ = platform.owner()
    suspend_operator(suspended_id, caller=real_owner, reason=REASON)
    platform.set_user_active(inactive_owner.user_id, False)

    for caller in (stranger, near_owner, suspended_owner, inactive_owner):
        platform.clear_audit()
        for action, attempt in _all_six(target_id, platform.user(), caller).items():
            with pytest.raises(PlatformNotAuthorizedError):
                attempt()  # type: ignore[operator]
            (denied,) = platform.audit(action, "denied")
            assert denied["reason"] == "not_authorized"
            assert denied["actor_type"] == "user" and denied["actor_user_id"] == caller.user_id
        assert platform.audit(outcome="success") == []
    assert platform.operator_status(target_id) == "active"
    assert platform.live_permissions(target_id) == {"platform.audit:read"}


def test_a_service_account_and_a_malformed_caller_are_refused_before_any_write(
    platform: PlatformWorld,
) -> None:
    platform.owner()
    _, target_id = platform.operator([P.AUDIT_READ])
    platform.clear_audit()
    service_account = ServiceAccountCaller(uuid.uuid4(), uuid.uuid4())
    for attempt in _all_six(target_id, platform.user(), service_account).values():
        with pytest.raises(PlatformNotAuthorizedError):
            attempt()  # type: ignore[operator]
    for attempt in _all_six(target_id, platform.user(), None).values():
        with pytest.raises(CallerTypeError):
            attempt()  # type: ignore[operator]
    # A service account is never a platform actor: nothing can be recorded for it.
    assert platform.audit_count() == 0
    assert platform.operator_status(target_id) == "active"


def test_system_purposes_reach_exactly_their_operations(platform: PlatformWorld) -> None:
    """`PLATFORM_BOOTSTRAP` may enroll, grant and suspend, and nothing else.
    `PROVISIONING`, `TENANT_PURGE` and `BILLING_OPERATIONS` reach no
    authority operation at all."""
    platform.owner()
    _, target_id = platform.operator([P.AUDIT_READ])
    for purpose in (
        SystemAuthority.PROVISIONING,
        SystemAuthority.TENANT_PURGE,
        SystemAuthority.BILLING_OPERATIONS,
    ):
        for attempt in _all_six(target_id, platform.user(), SystemCaller(purpose)).values():
            with pytest.raises(PlatformNotAuthorizedError):
                attempt()  # type: ignore[operator]
    assert platform.operator_status(target_id) == "active"
    assert platform.live_permissions(target_id) == {"platform.audit:read"}

    refused = ("platform.operator.reactivate", "platform.operator.revoke", "platform.grant.revoke")
    attempts = _all_six(target_id, platform.user(), BOOTSTRAP)
    for action in refused:
        with pytest.raises(PlatformNotAuthorizedError):
            attempts[action]()  # type: ignore[operator]
    platform.clear_audit()
    attempts["platform.operator.enroll"]()  # type: ignore[operator]
    attempts["platform.grant.create"]()  # type: ignore[operator]
    attempts["platform.operator.suspend"]()  # type: ignore[operator]
    rows = platform.audit(outcome="success")
    assert [r["action"] for r in rows] == [
        "platform.operator.enroll",
        "platform.grant.create",
        "platform.operator.suspend",
    ]
    for row in rows:  # a system purpose is recorded as system, never as a person
        assert row["actor_type"] == "system" and row["actor_user_id"] is None
        assert row["system_authority"] == "platform_bootstrap"


# --- reason and argument validation ------------------------------------------------


@pytest.mark.parametrize("reason", ["", "   ", None, 7, "x" * 501, "line\nbreak"])
def test_a_valid_reason_is_required_before_any_read(
    platform: PlatformWorld, reason: object
) -> None:
    owner, _ = platform.owner()
    _, target_id = platform.operator([])
    platform.clear_audit()
    with pytest.raises(InvalidPlatformRequestError):
        suspend_operator(target_id, caller=owner, reason=reason)  # type: ignore[arg-type]
    with pytest.raises(InvalidPlatformRequestError):
        grant_platform_permission(target_id, P.TENANT_READ, caller=owner, reason=reason)  # type: ignore[arg-type]
    assert platform.audit_count() == 0 and platform.operator_status(target_id) == "active"


def test_a_permission_must_be_a_member_of_the_closed_vocabulary(platform: PlatformWorld) -> None:
    owner, _ = platform.owner()
    _, target_id = platform.operator([])
    for bad in ("platform.tenant:read", "*", "platform.*", None, "membership_role:create"):
        with pytest.raises(InvalidPlatformRequestError):
            grant_platform_permission(target_id, bad, caller=owner, reason=REASON)  # type: ignore[arg-type]
    assert platform.live_permissions(target_id) == set()


# --- platform audit --------------------------------------------------------------------


def test_change_and_evidence_are_atomic_a_failed_audit_write_undoes_the_change(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, _ = platform.owner()
    _, target_id = platform.operator([P.TENANT_READ])
    platform.clear_audit()

    def failing(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(service_module, "record_platform_event_in_transaction", failing)
    with pytest.raises(RuntimeError, match="audit write failed"):
        suspend_operator(target_id, caller=owner, reason=REASON)
    with pytest.raises(RuntimeError, match="audit write failed"):
        revoke_platform_permission(target_id, P.TENANT_READ, caller=owner, reason=REASON)
    with pytest.raises(RuntimeError, match="audit write failed"):
        grant_platform_permission(target_id, P.AUDIT_READ, caller=owner, reason=REASON)
    assert platform.operator_status(target_id) == "active"
    assert platform.live_permissions(target_id) == {"platform.tenant:read"}
    assert platform.audit_count() == 0


def test_a_failure_after_the_audit_write_leaves_neither_change_nor_row(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, _ = platform.owner()
    _, target_id = platform.operator([])
    platform.clear_audit()
    real = service_module.record_platform_event_in_transaction

    def then_fail(*args: object, **kwargs: object) -> object:
        real(*args, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("failure after both were written")

    monkeypatch.setattr(service_module, "record_platform_event_in_transaction", then_fail)
    with pytest.raises(RuntimeError, match="after both were written"):
        suspend_operator(target_id, caller=owner, reason=REASON)
    assert platform.operator_status(target_id) == "active"
    assert platform.audit_count() == 0


def test_a_refusal_survives_a_failing_refusal_audit_write(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `denied` row is best effort: if it cannot be written, the caller
    still receives the refusal and nothing changed."""
    platform.owner()
    _, target_id = platform.operator([])
    stranger = UserCaller(platform.user())
    platform.clear_audit()

    def broken_scope(*args: object, **kwargs: object) -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(audit_module, "session_scope", broken_scope)
    with pytest.raises(PlatformNotAuthorizedError):
        suspend_operator(target_id, caller=stranger, reason=REASON)
    monkeypatch.undo()
    assert platform.operator_status(target_id) == "active"
    assert platform.audit_count() == 0


def test_a_refusal_for_a_nonexistent_user_is_refused_and_not_recorded(
    platform: PlatformWorld,
) -> None:
    """The `denied` row needs an existing user (foreign key). A caller
    naming no real user is refused all the same."""
    platform.owner()
    _, target_id = platform.operator([])
    platform.clear_audit()
    with pytest.raises(PlatformNotAuthorizedError):
        suspend_operator(target_id, caller=UserCaller(uuid.uuid4()), reason=REASON)
    assert platform.audit_count() == 0 and platform.operator_status(target_id) == "active"


def test_the_runtime_role_cannot_alter_or_remove_a_platform_audit_row(
    platform: PlatformWorld,
) -> None:
    from sqlalchemy.exc import ProgrammingError

    platform.owner()
    for statement in (
        "UPDATE core.platform_audit_log SET outcome = 'denied'",
        "DELETE FROM core.platform_audit_log",
        "DELETE FROM core.platform_grants",
        "DELETE FROM core.platform_operators",
    ):
        with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as session:
            session.execute(text(statement))
    assert platform.audit_count() > 0


def test_platform_audit_cannot_be_written_inside_a_tenant_scope(platform: PlatformWorld) -> None:
    """ADR-0045 section 9c, enforced by the database: platform rows are
    written only while no tenant is bound."""
    from sqlalchemy.exc import ProgrammingError

    owner, _ = platform.owner()
    platform.clear_audit()
    with pytest.raises(ProgrammingError, match="row-level security"):
        with tenant_session_scope(uuid.uuid4()) as session:
            record_platform_event_in_transaction(
                session,
                caller=owner,
                action="platform.operator.suspend",
                target_type="platform_operator",
            )
    assert platform.audit_count() == 0


def test_platform_audit_validates_actor_action_and_metadata(platform: PlatformWorld) -> None:
    from saas_os.core.audit_log import ForbiddenMetadataKeyError

    owner, _ = platform.owner()
    platform.clear_audit()
    with session_scope() as session:
        with pytest.raises(CallerTypeError):
            record_platform_event_in_transaction(
                session,
                caller=ServiceAccountCaller(uuid.uuid4(), uuid.uuid4()),
                action="platform.operator.suspend",
                target_type="platform_operator",
            )
        with pytest.raises(InvalidPlatformRequestError):
            record_platform_event_in_transaction(
                session, caller=owner, action="membership.suspend", target_type="x"
            )
        with pytest.raises(ForbiddenMetadataKeyError):
            record_platform_event_in_transaction(
                session,
                caller=owner,
                action="platform.operator.suspend",
                target_type="platform_operator",
                metadata={"token": "x"},
            )
        entry = record_platform_event_in_transaction(
            session,
            caller=owner,
            action="platform.operator.suspend",
            target_type="platform_operator",
            outcome=PlatformAuditOutcome.FAILURE,
        )
        assert entry.actor_type == "user" and entry.outcome == "failure"
    assert platform.audit_count() == 1
