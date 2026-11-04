"""The authenticated approval of ledger deletions and the approver
eligibility register (owner decisions of 2026-11-02 and 2026-11-03;
`docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`). PostgreSQL.

Every act runs through Core with a real session as its evidence, exactly as
the platform-admin route calls it; the database's triggers, grants and
policies are the real ones of migration `c3f9e1a7b5d2`. Deletion stays
disabled: the tests that exercise the deletion switch
`expiry._DELETION_ENABLED` on in-process only (the `deletion_enabled`
fixture), the way the existing expiry tests do.

Cleanup: `Approvals.cleanup` removes every approval-table row (the
downgrade refuses while any exists), then `Ledger`, `Scene` and
`PlatformWorld` remove the rest.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from phase_c_helpers import Scene
from platform_helpers import (
    BOOTSTRAP,
    Gate,
    PlatformWorld,
    join,
    run_first_then_second,
    start,
    wait_until_blocked_by,
)
from retention_approval_helpers import APPROVAL_TABLES, REASON, Approvals
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from test_permission_grant_ledger_retention_integration import Ledger

from saas_os.core.authority import UserCaller
from saas_os.core.identity import revoke_session
from saas_os.core.permission_grants import (
    EnrolmentState,
    InvalidLedgerRetentionRequestError,
    LedgerApprovalRecordNotFoundError,
    LedgerApprovalRefusedError,
    LedgerDeletionDisabledError,
    LedgerExpiryConfirmationMismatchError,
    LedgerHoldAlreadyReleasedError,
    enrol_approver,
    read_approver_eligibility,
    read_approver_register,
    read_permission_grant_ledger_deletion_requests,
    release_permission_grant_ledger_hold,
    revoke_register_entry,
)
from saas_os.core.permission_grants import expiry as expiry_gate
from saas_os.core.permission_grants.expiry import (
    execute_authorized_permission_grant_ledger_deletion,
    expire_permission_grant_ledger_rows,
)
from saas_os.core.platform_authority import (
    PlatformNotAuthorizedError,
    PlatformPermission,
    PlatformSessionEvidence,
)
from saas_os.core.platform_authority.retention_evidence import provenance_linked
from saas_os.infra.db import session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
EXPIRE = "platform.permission_grant_ledger.expired_delete"
REQUEST = "platform.permission_grant_ledger.deletion_request"
APPROVE = "platform.permission_grant_ledger.deletion_approve"
AUTHORIZE = "platform.permission_grant_ledger.deletion_execution_authorize"
REGISTER = "core.permission_grant_ledger_approver_register"
APPROVALS = "core.permission_grant_ledger_deletion_approvals"
AUTHORIZATIONS = "core.permission_grant_ledger_deletion_execution_authorizations"
REQUESTS = "core.permission_grant_ledger_deletion_requests"


@pytest.fixture
def ledger(scene: Scene, platform: PlatformWorld) -> Iterator[Ledger]:
    built = Ledger(scene, platform)
    try:
        yield built
    finally:
        built.cleanup()


@pytest.fixture
def world(ledger: Ledger, platform: PlatformWorld) -> Iterator[Approvals]:
    built = Approvals(ledger, platform)
    try:
        yield built
    finally:
        built.cleanup()


@pytest.fixture
def deletion_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process only: the shipped constant stays `False`."""
    monkeypatch.setattr(expiry_gate, "_DELETION_ENABLED", True)


def _refused(code: str) -> Any:
    return pytest.raises(LedgerApprovalRefusedError, match=f"Refused: {code}\\.")


def _execute(authorization: Any, *, apply: bool = False) -> Any:
    return execute_authorized_permission_grant_ledger_deletion(
        authorization.id, reason="TICKET-9: retention expiry", apply=apply
    )


def _chain(world: Approvals, *tenants: uuid.UUID) -> tuple[Any, Any, Any]:
    request = world.request(*tenants)
    approved = world.approve(request)
    authorization = world.authorize(request)
    return request, approved, authorization


# --- the full path -------------------------------------------------------------------------


def test_the_full_path_binds_verifies_refuses_apply_and_with_the_gate_on_deletes_once(
    world: Approvals, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.register_both()
    first, second = world.expired(migrations=2), world.expired()
    untouched = world.expired()  # eligible but not in scope
    request, approved, authorization = _chain(world, second, first)

    assert request.tenant_ids == tuple(sorted((first, second)))
    assert (request.eligible_ledger_rows, request.state) == (3, "pending")
    assert approved.state == "approved" and approved.approval is not None
    assert approved.approval.approved_by_user_id == world.approver.user_id
    assert authorization.authorized_by_user_id == world.authorizer.user_id
    window = (authorization.expires_at - authorization.authorized_at).total_seconds()
    assert window == 3600
    approval_window = approved.approval.expires_at - approved.approval.approved_at
    assert approval_window.total_seconds() == 72 * 3600

    # The verification: everything under the locks, one `verify` row, no deletion.
    verified = _execute(authorization)
    assert verified.applied is False and verified.eligible_ledger_rows == 3
    assert {t.tenant_id for t in verified.tenants} == {first, second}
    (verify_row,) = [
        r for r in platform.audit(EXPIRE, "success") if r["metadata"]["phase"] == "verify"
    ]
    assert verify_row["actor_user_id"] == world.authorizer.user_id
    assert verify_row["metadata"]["runner"] == "migrations_role_unauthenticated"
    assert verify_row["metadata"]["execution_authorization_id"] == str(authorization.id)
    assert [world.ledger.rows(t) for t in (first, second, untouched)] == [2, 1, 1]

    # `apply` is refused while the gate is off: one denied row, attributed.
    assert expiry_gate._DELETION_ENABLED is False  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(LedgerDeletionDisabledError):
        _execute(authorization, apply=True)
    denied = platform.audit(EXPIRE, "denied")
    assert [(r["reason"], r["actor_user_id"]) for r in denied] == [
        ("deletion_disabled", world.authorizer.user_id)
    ]
    assert [world.ledger.rows(t) for t in (first, second, untouched)] == [2, 1, 1]

    # With the gate switched on in-process: exactly the bound rows go, both
    # records are consumed in the deletion's transaction, once.
    monkeypatch.setattr(expiry_gate, "_DELETION_ENABLED", True)
    done = _execute(authorization, apply=True)
    assert done.applied is True and done.run_id is not None
    assert [world.ledger.rows(t) for t in (first, second, untouched)] == [0, 0, 1]
    consumed = platform.execute(
        f"SELECT consumed_at, consumed_by_platform_audit_id FROM {APPROVALS} "  # noqa: S608
        f"UNION ALL SELECT consumed_at, consumed_by_platform_audit_id FROM {AUTHORIZATIONS}"  # noqa: S608
    )
    assert len(consumed) == 2 and {row[1] for row in consumed} == {done.audit_id}
    # Stamped by the trigger from the database clock, after the locks.
    assert all(row[0] >= done.as_of for row in consumed)
    phases = sorted(r["metadata"]["phase"] for r in platform.audit(EXPIRE, "success"))
    assert phases == ["consume", "run", "tenant", "tenant", "verify"]
    with pytest.raises(LedgerApprovalRefusedError, match="execution_authorization_consumed"):
        _execute(authorization, apply=True)
    with _refused("approval_consumed"):
        world.authorize(request, reason="a second authorisation after the consumption")
    (state,) = read_permission_grant_ledger_deletion_requests(
        caller=world.requester, request_id=request.id
    ).requests
    assert state.state == "consumed"


def test_the_declared_operator_form_can_never_apply_even_with_the_gate_on(
    world: Approvals, deletion_enabled: None
) -> None:
    tenant = world.expired()
    report = world.ledger.report(tenant)
    with pytest.raises(InvalidLedgerRetentionRequestError, match="execution authorisation"):
        expire_permission_grant_ledger_rows(
            caller=world.ledger.reporter,
            reason="TICKET-9",
            tenant_ids=[tenant],
            apply=True,
            confirm_rows=report.eligible_ledger_rows,
            confirm_digest=report.eligible_digest,
        )
    assert world.ledger.rows(tenant) == 1


# --- the person rules ------------------------------------------------------------------------


def test_the_requester_cannot_approve(world: Approvals) -> None:
    world.register_both()
    tenant = world.expired()
    request = world.request(tenant, caller=world.approver)
    with _refused("approver_is_requester"):
        world.approve(request, caller=world.approver)
    assert world.denied(APPROVE) == ["approver_is_requester"]
    assert world.count(APPROVALS) == 0


def test_the_approver_cannot_authorise_execution(world: Approvals) -> None:
    world.register_both()
    tenant = world.expired()
    request = world.request(tenant)
    world.approve(request)
    with _refused("authorizer_is_approver"):
        world.authorize(request, caller=world.approver)
    assert world.count(AUTHORIZATIONS) == 0


def test_the_requester_may_authorise_when_registered(world: Approvals) -> None:
    """Decision 5: two accounts suffice when they are two verified persons."""
    world.designate()
    world.enrol(world.approver, "PERSON-A")
    world.enrol(world.requester, "PERSON-C")
    tenant = world.expired()
    request = world.request(tenant)
    world.approve(request)
    authorization = world.authorize(request, caller=world.requester)
    assert authorization.authorized_by_user_id == world.requester.user_id


def test_an_unregistered_report_holder_cannot_approve_until_enrolled_and_past_the_delay(
    world: Approvals, platform: PlatformWorld
) -> None:
    """Bootstrap and break-glass accounts (NULL provenance) hold report but
    no register entry: ineligible until independently enrolled, and then
    only after 120 days."""
    world.designate()
    tenant = world.expired()
    request = world.request(tenant)
    assert platform.scalar(
        "SELECT enrolled_by_user_id IS NULL FROM core.platform_operators WHERE user_id = :u",
        {"u": world.approver.user_id},
    )
    with _refused("approver_not_eligible"):
        world.approve(request)
    entry = world.enrol(world.approver, "PERSON-A", eligible=False)
    delay = entry.eligible_from - entry.recorded_at  # type: ignore[operator]
    assert delay.days == 120
    with _refused("approver_not_eligible"):
        world.approve(request, reason="still waiting")
    world.make_eligible(entry.id)
    assert world.approve(request).state == "approved"


def test_two_accounts_of_one_verified_person_cannot_approve_and_authorise(
    world: Approvals,
) -> None:
    world.designate()
    world.enrol(world.approver, "PERSON-A")
    # The register refuses a second active enrolment of the same person...
    with _refused("natural_person_already_enrolled"):
        world.enrol(world.authorizer, "PERSON-A", eligible=False)
    # ...so only a forged entry (direct SQL; threat T6) can name it twice;
    # the use-time check still refuses the pair.
    forged = uuid.uuid4()
    world.privileged(
        (
            f"INSERT INTO {REGISTER} (id, entry_type, subject_user_id, recorded_by_user_id, "  # noqa: S608
            "natural_person_ref, verification_ref, authorisation_ref, ticket_ref, "
            "authorised_by_entry_id, valid_until, eligible_from, recorded_at, "
            "recorded_by_platform_audit_id) VALUES (:i, 'approver_enrolment', :s, :r, "
            "'PERSON-A', 'V-X', 'A-X', 'TICKET-X', :d, now() + interval '200 days', "
            "now() - interval '1 day', now(), :a)",
            {
                "i": forged,
                "s": world.authorizer.user_id,
                "r": world.representative.user_id,
                "d": world.designation.id,  # type: ignore[union-attr]
                "a": uuid.uuid4(),
            },
        )
    )
    tenant = world.expired()
    request = world.request(tenant)
    world.approve(request)
    with _refused("same_natural_person"):
        world.authorize(request)


def test_an_authenticated_releaser_cannot_approve_or_authorise_in_scope(
    world: Approvals,
) -> None:
    world.register_both()
    tenant = world.expired()
    # The approver later receives hold management out of band and releases
    # a hold on the tenant through the authenticated route.
    world.grant(world.operator_id(world.approver), P.SECURITY_RETENTION_HOLD_MANAGE)
    hold = world.hold(tenant)
    world.release(hold.hold_id, caller=world.approver)
    request = world.request(tenant)
    with _refused("approver_released_hold"):
        world.approve(request)
    # The other way round: the authoriser released one. (The approver's hold
    # management is withdrawn first: a hold manager never approves.)
    world.platform.execute(
        "UPDATE core.platform_grants SET revoked_at = now() WHERE operator_id = :o "
        "AND permission = 'platform.security_retention_hold:manage'",
        {"o": world.operator_id(world.approver)},
    )
    other = world.expired()
    world.grant(world.operator_id(world.authorizer), P.SECURITY_RETENTION_HOLD_MANAGE)
    second_hold = world.hold(other, "LEGAL-78")
    world.release(second_hold.hold_id, caller=world.authorizer)
    request = world.request(other)
    world.approve(request)
    with _refused("authorizer_released_hold"):
        world.authorize(request)


def test_a_release_after_approval_blocks_execution_by_that_person(
    world: Approvals, deletion_enabled: None
) -> None:
    world.register_both()
    tenant = world.expired()
    request, _approved, authorization = _chain(world, tenant)
    world.grant(world.operator_id(world.authorizer), P.SECURITY_RETENTION_HOLD_MANAGE)
    hold = world.hold(tenant)
    world.release(hold.hold_id, caller=world.authorizer)
    with _refused("authorizer_released_hold"):
        _execute(authorization, apply=True)
    assert world.ledger.rows(tenant) == 1
    assert world.denied(EXPIRE) == ["authorizer_released_hold"]


def _declared_release(world: Approvals, tenant: uuid.UUID) -> None:
    """A release as the removed command made it: a declared actor, no
    channel, no session evidence (written with the privileged role)."""
    hold = world.hold(tenant)
    audit_id = uuid.uuid4()
    world.privileged(
        (
            "INSERT INTO core.platform_audit_log (id, actor_type, actor_user_id, action, "
            "target_type, target_id, target_tenant_id, outcome, reason, metadata) VALUES "
            "(:a, 'user', :u, 'platform.permission_grant_ledger.hold_release', "
            "'permission_grant_ledger_hold', :h, :t, 'success', 'old command', "
            "CAST(:m AS json))",
            {
                "a": audit_id,
                "u": world.ledger.holder.user_id,
                "h": str(hold.hold_id),
                "t": tenant,
                "m": '{"hold_id": "x", "reference": "LEGAL-77"}',
            },
        ),
        (
            "UPDATE core.permission_grant_ledger_holds SET released_at = now(), "
            "released_by_platform_audit_id = :a WHERE id = :h",
            {"a": audit_id, "h": hold.hold_id},
        ),
    )


def test_a_declared_release_blocks_the_tenant(world: Approvals) -> None:
    """A release the removed command made has no authenticated evidence: its
    tenant is blocked for request, approval, authorisation and execution."""
    world.register_both()
    tenant = world.expired()
    request = world.request(tenant)
    world.approve(request)
    _declared_release(world, tenant)
    with _refused("unauthenticated_release_in_scope"):
        world.authorize(request)
    other = world.expired()
    _declared_release(world, other)
    with _refused("unauthenticated_release_in_scope"):
        world.request(other)
    third = world.expired()
    request3, _approved, authorization = _chain(world, third)
    _declared_release(world, third)
    with _refused("unauthenticated_release_in_scope"):
        _execute(authorization)
    assert request3.id != request.id


def test_authority_granted_after_enrolment_blocks_every_step(world: Approvals) -> None:
    world.register_both()
    tenant = world.expired()
    request = world.request(tenant)
    world.grant(world.operator_id(world.approver), P.AUTHORITY_MANAGE)
    with _refused("party_holds_authority_manage"):
        world.approve(request)
    with _refused("party_holds_authority_manage"):
        world.request(world.expired(), caller=world.owner)


def test_provenance_links_are_refused_when_present(world: Approvals) -> None:
    world.register_both()
    # The approver granted the requester its report permission (a link).
    requester, operator_id = world.platform.operator([])
    world.platform.execute(
        "INSERT INTO core.platform_grants (id, operator_id, permission, granted_by_user_id) "
        "VALUES (:i, :o, 'platform.security_retention:report', :g)",
        {"i": uuid.uuid4(), "o": operator_id, "g": world.approver.user_id},
    )
    tenant = world.expired()
    request = world.request(tenant, caller=requester)
    with _refused("approver_linked_to_requester"):
        world.approve(request)


# --- binding, expiry, scope --------------------------------------------------------------------


def test_a_request_binds_an_eligible_scope_with_its_count_and_digest(world: Approvals) -> None:
    tenant = world.expired(migrations=2)
    running = world.ledger.tenant()
    world.ledger.purge(running)  # purged now: two years still running
    with _refused("scope_not_eligible"):
        world.request(tenant, running)
    with pytest.raises(LedgerExpiryConfirmationMismatchError):
        world.request(tenant, rows=1)
    with pytest.raises(LedgerExpiryConfirmationMismatchError):
        world.request(tenant, digest="0" * 64)
    request = world.request(tenant)
    with _refused("overlapping_request"):
        world.request(tenant, caller=world.approver)
    # The same caller retrying with identical content gets the same request.
    again = world.request(tenant)
    assert again.id == request.id and again.replay is True
    with _refused("overlapping_request"):
        world.request(tenant, reason="a different reason")
    assert world.count(REQUESTS) == 1


def test_execution_refuses_a_changed_scope(world: Approvals, deletion_enabled: None) -> None:
    world.register_both()
    tenant = world.expired(migrations=2)
    _request, _approved, authorization = _chain(world, tenant)
    hold = world.hold(tenant)  # placed after the approval: not eligible now
    with _refused("scope_not_eligible"):
        _execute(authorization, apply=True)
    world.release(hold.hold_id)  # an authenticated release by a third person
    # The holder's release is authenticated and the holder is neither party.
    assert _execute(authorization, apply=True).applied is True
    assert world.ledger.rows(tenant) == 0


def test_an_expired_approval_or_authorisation_is_refused_by_the_database_clock(
    world: Approvals,
) -> None:
    world.register_both()
    tenant = world.expired()
    request, approved, authorization = _chain(world, tenant)
    world.privileged(
        (
            f"UPDATE {AUTHORIZATIONS} SET expires_at = now() - interval '1 second', "  # noqa: S608
            "authorized_at = now() - interval '2 hours' WHERE id = :i",
            {"i": authorization.id},
        )
    )
    with _refused("execution_authorization_expired"):
        _execute(authorization)
    world.privileged(
        (
            f"UPDATE {APPROVALS} SET expires_at = now() - interval '1 second', "  # noqa: S608
            "approved_at = now() - interval '73 hours' WHERE id = :i",
            {"i": approved.approval.id},
        )
    )
    with _refused("approval_expired"):
        world.authorize(request, reason="after the approval expired")
    # An expired request cannot be approved.
    other = world.request(world.expired())
    world.privileged(
        (
            f"UPDATE {REQUESTS} SET expires_at = now() - interval '1 second', "  # noqa: S608
            "requested_at = now() - interval '73 hours' WHERE id = :i",
            {"i": other.id},
        )
    )
    with _refused("request_expired"):
        world.approve(other)


def test_two_approvals_of_one_request_and_idempotent_replays(world: Approvals) -> None:
    world.register_both()
    world.enrol(world.requester, "PERSON-C")
    tenant = world.expired()
    request = world.request(tenant)
    approved = world.approve(request)
    replay = world.approve(request)
    assert replay.replay is True and replay.approval.id == approved.approval.id
    with _refused("request_already_approved"):
        world.approve(request, reason="a different reason")
    with _refused("request_already_approved"):
        world.approve(request, caller=world.authorizer)
    first = world.authorize(request)
    again = world.authorize(request)
    assert again.replay is True and again.id == first.id
    assert world.count(APPROVALS) == 1 and world.count(AUTHORIZATIONS) == 1


# --- revocation and invalidation ------------------------------------------------------------


def test_revoking_an_approver_invalidates_its_outstanding_records_at_once(
    world: Approvals, platform: PlatformWorld
) -> None:
    world.register_both()
    tenant = world.expired()
    request, approved, authorization = _chain(world, tenant)
    result = revoke_register_entry(
        world.approver.user_id,
        world.enrolments[world.approver.user_id].id,
        operation="permission_grant_ledger.approver_revoke_by_representative",
        caller=world.representative,
        session_evidence=world.evidence(world.representative),
        ticket_ref="TICKET-31",
        reason=REASON,
    )
    assert (result.invalidated_approvals, result.invalidated_execution_authorizations) == (1, 0)
    rows = platform.execute(
        f"SELECT invalidated_at IS NOT NULL, invalidated_by_platform_audit_id FROM {APPROVALS}"  # noqa: S608
    )
    assert rows == [(True, result.entry.recorded_by_platform_audit_id)]
    with _refused("approval_invalidated"):
        _execute(authorization)
    with _refused("approval_invalidated"):
        world.authorize(request, reason="after the revocation")
    (state,) = read_permission_grant_ledger_deletion_requests(
        caller=world.requester, request_id=request.id
    ).requests
    assert state.state == "invalidated"
    # Revoking the authoriser invalidates its authorisation too.
    second = world.expired()
    world.enrol(world.requester, "PERSON-C")
    req2 = world.request(second, caller=world.authorizer)
    world.approve(req2, caller=world.requester)
    auth2 = world.authorize(req2, caller=world.authorizer)
    security = revoke_register_entry(
        world.authorizer.user_id,
        world.enrolments[world.authorizer.user_id].id,
        operation="permission_grant_ledger.approver_revoke_by_security",
        caller=world.security,
        session_evidence=world.evidence(world.security),
        ticket_ref="TICKET-32",
        reason=REASON,
    )
    # Its authorisation of the first chain and of this one.
    assert security.invalidated_execution_authorizations == 2
    with _refused("execution_authorization_invalidated"):
        _execute(auth2)
    with _refused("entry_already_revoked"):
        revoke_register_entry(
            world.authorizer.user_id,
            world.enrolments[world.authorizer.user_id].id,
            operation="permission_grant_ledger.approver_revoke_by_security",
            caller=world.security,
            session_evidence=world.evidence(world.security),
            ticket_ref="TICKET-33",
            reason=REASON,
        )


def test_revoking_a_designation_suspends_its_enrolments_and_invalidates(
    world: Approvals,
) -> None:
    world.register_both()
    tenant = world.expired()
    request, _approved, _authorization = _chain(world, tenant)
    result = revoke_register_entry(
        world.representative.user_id,
        world.designation.id,  # type: ignore[union-attr]
        operation="permission_grant_ledger.representative_revoke_by_owner",
        caller=world.owner,
        session_evidence=world.evidence(world.owner),
        ticket_ref="TICKET-34",
        reason=REASON,
    )
    assert result.suspended_enrolments == 2
    assert (result.invalidated_approvals, result.invalidated_execution_authorizations) == (1, 1)
    page = read_approver_eligibility(caller=world.auditor)
    assert {a.state for a in page.approvers} == {EnrolmentState.SUSPENDED}
    other = world.expired()
    request = world.request(other)
    with _refused("approver_not_eligible"):
        world.approve(request)


# --- the register's two-party designation and enrolment rules ------------------------------


def test_designation_needs_an_owner_and_an_independent_security_operator(
    world: Approvals,
) -> None:
    from saas_os.core.permission_grants import (
        confirm_representative_designation,
        propose_representative_designation,
    )

    subject = world.representative
    propose = {
        "designation_ref": "BOARD-RES-1",
        "ticket_ref": "TICKET-40",
        "valid_until": world.in_months(11),
        "reason": REASON,
    }
    # Only an authority holder proposes; a report holder cannot.
    with pytest.raises(PlatformNotAuthorizedError):
        propose_representative_designation(
            subject.user_id,
            caller=world.requester,
            session_evidence=world.evidence(world.requester),
            **propose,
        )
    with pytest.raises(InvalidLedgerRetentionRequestError):
        propose_representative_designation(
            subject.user_id,
            caller=world.owner,
            session_evidence=world.evidence(world.owner),
            **{**propose, "valid_until": world.in_months(13)},
        )
    with _refused("register_subject_is_caller"):
        propose_representative_designation(
            world.owner.user_id,
            caller=world.owner,
            session_evidence=world.evidence(world.owner),
            **propose,
        )
    proposal = propose_representative_designation(
        subject.user_id,
        caller=world.owner,
        session_evidence=world.evidence(world.owner),
        **propose,
    )
    # The owner alone cannot confirm (no hold management).
    with pytest.raises(PlatformNotAuthorizedError):
        confirm_representative_designation(
            subject.user_id,
            proposal.id,
            caller=world.owner,
            session_evidence=world.evidence(world.owner),
            ticket_ref="TICKET-41",
            reason=REASON,
        )
    # A hold manager who also holds authority is not independent.
    dual, dual_operator = world.platform.operator([P.SECURITY_RETENTION_HOLD_MANAGE])
    world.grant(dual_operator, P.AUTHORITY_MANAGE)
    with _refused("party_holds_authority_manage"):
        confirm_representative_designation(
            subject.user_id,
            proposal.id,
            caller=dual,
            session_evidence=world.evidence(dual),
            ticket_ref="TICKET-41",
            reason=REASON,
        )
    # The wrong subject in the path: not found.
    with pytest.raises(LedgerApprovalRecordNotFoundError):
        confirm_representative_designation(
            world.approver.user_id,
            proposal.id,
            caller=world.security,
            session_evidence=world.evidence(world.security),
            ticket_ref="TICKET-41",
            reason=REASON,
        )
    designation = confirm_representative_designation(
        subject.user_id,
        proposal.id,
        caller=world.security,
        session_evidence=world.evidence(world.security),
        ticket_ref="TICKET-41",
        reason=REASON,
    )
    assert designation.valid_until == proposal.valid_until
    assert designation.recorded_by_user_id == world.security.user_id
    with _refused("proposal_already_confirmed"):
        confirm_representative_designation(
            subject.user_id,
            proposal.id,
            caller=world.security,
            session_evidence=world.evidence(world.security),
            ticket_ref="TICKET-42",
            reason=REASON,
        )
    # A proposal expires unconfirmed after 72 hours.
    late = propose_representative_designation(
        world.authorizer.user_id,
        caller=world.owner,
        session_evidence=world.evidence(world.owner),
        **propose,
    )
    world.privileged(
        (
            f"UPDATE {REGISTER} SET proposal_expires_at = now() - interval '1 second' "  # noqa: S608
            "WHERE id = :i",
            {"i": late.id},
        )
    )
    with _refused("proposal_expired"):
        confirm_representative_designation(
            world.authorizer.user_id,
            late.id,
            caller=world.security,
            session_evidence=world.evidence(world.security),
            ticket_ref="TICKET-43",
            reason=REASON,
        )


def test_enrolment_rules_self_disjointness_holders_and_one_renewal(world: Approvals) -> None:
    world.designate()
    with _refused("register_subject_is_caller"):
        world.enrol(world.representative, "PERSON-R", eligible=False)
    with _refused("not_a_representative"):
        world.enrol(world.authorizer, "PERSON-B", representative=world.approver, eligible=False)
    with _refused("subject_holds_authority_manage"):
        world.enrol(world.owner, "PERSON-O", eligible=False)
    with _refused("subject_holds_hold_manage"):
        world.enrol(world.ledger.holder, "PERSON-H", eligible=False)
    second_representative, _ = world.platform.operator([P.SECURITY_RETENTION_REPORT])
    world.designate(second_representative)
    with _refused("subject_is_representative"):
        world.enrol(second_representative, "PERSON-S", eligible=False)
    with pytest.raises(InvalidLedgerRetentionRequestError):
        world.enrol(world.approver, "PERSON-A", eligible=False, valid_until=world.in_months(3))
    current = world.enrol(world.approver, "PERSON-A")
    with _refused("subject_is_approver"):
        world.designate(world.approver)
    with _refused("approver_already_enrolled"):
        world.enrol(world.approver, "PERSON-A2", eligible=False)
    renewal = world.enrol(
        world.approver, "PERSON-A", eligible=False, renews_entry_id=current.id, reason="renewal"
    )
    assert renewal.renews_entry_id == current.id
    with _refused("approver_already_enrolled"):
        world.enrol(
            world.approver, "PERSON-A", eligible=False, renews_entry_id=current.id, reason="again"
        )
    # During the overlap the current entry still makes the approver eligible.
    page = read_approver_eligibility(caller=world.auditor)
    states = {a.entry_id: a.state for a in page.approvers}
    assert states == {current.id: EnrolmentState.ELIGIBLE, renewal.id: EnrolmentState.WAITING}
    # The register read is the reviewer's export; refs only.
    entries = read_approver_register(caller=world.auditor, entry_type="approver_enrolment")
    assert {e.id for e in entries.entries} == {current.id, renewal.id}


def test_register_writes_need_a_live_session_of_the_caller_with_multi_factor(
    world: Approvals,
) -> None:
    world.designate()
    tenant = world.expired()
    other_session = world.evidence(world.requester)
    with _refused("session_evidence_invalid"):
        world.request(tenant, session_evidence=other_session, caller=world.approver)
    revoked = world.evidence(world.representative)
    revoke_session(revoked.session_id)
    from saas_os.core.permission_grants import enrol_approver

    with _refused("session_evidence_invalid"):
        enrol_approver(
            world.approver.user_id,
            caller=world.representative,
            session_evidence=revoked,
            natural_person_ref="PERSON-A",
            verification_ref="V",
            authorisation_ref="A",
            ticket_ref="T",
            valid_until=world.in_months(11),
            reason=REASON,
        )
    for evidence in (
        world.evidence(world.representative, multi_factor=False),
        world.evidence(world.representative, required=False),
    ):
        with _refused("multi_factor_not_enforced"):
            enrol_approver(
                world.approver.user_id,
                caller=world.representative,
                session_evidence=evidence,
                natural_person_ref="PERSON-A",
                verification_ref="V",
                authorisation_ref="A",
                ticket_ref="T",
                valid_until=world.in_months(11),
                reason=REASON,
            )
    assert world.count(REGISTER) == 2  # the proposal and the designation


# --- the database: triggers, grants, RLS -------------------------------------------------------


def test_register_rows_cannot_be_updated_or_deleted_by_any_role(
    world: Approvals, admin: Engine
) -> None:
    designation = world.designate()
    for statement in (
        f"UPDATE {REGISTER} SET ticket_ref = 'X' WHERE id = :i",  # noqa: S608
        f"DELETE FROM {REGISTER} WHERE id = :i",  # noqa: S608
    ):
        with pytest.raises(DBAPIError, match="append-only"), admin.begin() as conn:
            conn.execute(text(statement), {"i": designation.id})
        with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as s:
            s.execute(text(statement), {"i": designation.id})
    with pytest.raises(DBAPIError, match="append-only"), admin.begin() as conn:
        conn.execute(text(f"TRUNCATE {REGISTER}"))  # noqa: S608
    assert world.count(REGISTER) == 2


def test_the_trigger_refuses_a_forged_self_enrolment_and_forces_the_clock(
    world: Approvals,
) -> None:
    designation = world.designate()

    def insert(**overrides: Any) -> None:
        params = {
            "i": uuid.uuid4(),
            "s": world.approver.user_id,
            "r": world.representative.user_id,
            "d": designation.id,
            "a": uuid.uuid4(),
            "e": None,
            **overrides,
        }
        with session_scope() as s:
            s.execute(
                text(
                    f"INSERT INTO {REGISTER} (id, entry_type, subject_user_id, "  # noqa: S608
                    "recorded_by_user_id, natural_person_ref, verification_ref, "
                    "authorisation_ref, ticket_ref, authorised_by_entry_id, valid_until, "
                    "eligible_from, recorded_at, recorded_by_platform_audit_id) VALUES "
                    "(:i, 'approver_enrolment', :s, :r, 'P-F', 'V', 'A', 'T', :d, "
                    "now() + interval '200 days', :e, now() - interval '5 years', :a)"
                ),
                params,
            )

    with pytest.raises(DBAPIError, match="nobody enrols themselves"):
        insert(s=world.representative.user_id)
    with pytest.raises(DBAPIError, match="written by the designated representative"):
        insert(r=world.approver.user_id)
    # A shaped insert without its audit row fails at the commit.
    with pytest.raises(DBAPIError, match="no audit row"):
        insert(e=None)
    assert world.count(REGISTER) == 2


def test_approval_records_consume_and_invalidate_one_way_for_every_role(
    world: Approvals, admin: Engine
) -> None:
    world.register_both()
    _request, approved, _authorization = _chain(world, world.expired())
    approval_id = approved.approval.id
    with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as s:
        s.execute(
            text(f"UPDATE {APPROVALS} SET consumed_at = now() WHERE id = :i"),  # noqa: S608
            {"i": approval_id},
        )
    with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as s:
        s.execute(text(f"DELETE FROM {APPROVALS} WHERE id = :i"), {"i": approval_id})  # noqa: S608
    for statement in (
        f"UPDATE {APPROVALS} SET eligible_ledger_rows = 99 WHERE id = :i",  # noqa: S608
        f"UPDATE {APPROVALS} SET consumed_at = now(), "  # noqa: S608
        "invalidated_at = now(), consumed_by_platform_audit_id = :a, "
        "invalidated_by_platform_audit_id = :a WHERE id = :i",
        f"DELETE FROM {APPROVALS} WHERE id = :i",  # noqa: S608
    ):
        with pytest.raises(DBAPIError), admin.begin() as conn:
            conn.execute(text(statement), {"i": approval_id, "a": uuid.uuid4()})
    rows = world.platform.execute(
        f"SELECT eligible_ledger_rows, consumed_at, invalidated_at FROM {APPROVALS}"  # noqa: S608
    )
    assert rows == [(1, None, None)]


def test_the_four_tables_are_invisible_to_a_tenant_scope(world: Approvals) -> None:
    world.register_both()
    tenant = world.expired()
    _chain(world, tenant)
    with tenant_session_scope(tenant) as s:
        for table in APPROVAL_TABLES:
            assert s.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0  # noqa: S608
    for table in APPROVAL_TABLES:
        assert world.count(table) > 0


# --- concurrency, with real locks -----------------------------------------------------------


def _gate_at(monkeypatch: pytest.MonkeyPatch, module: object, name: str) -> Gate:
    gate = Gate("first")
    real = getattr(module, name)

    def wrapped(session: object, *args: object, **kwargs: object) -> object:
        gate.checkpoint(session)
        return real(session, *args, **kwargs)

    monkeypatch.setattr(module, name, wrapped)
    return gate


def test_a_release_committed_before_the_execution_is_seen_by_it(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch, deletion_enabled: None
) -> None:
    """The release holds the tenant row first (design 5.4): the execution
    waits, then sees the authoriser as a releaser in scope."""
    import saas_os.core.permission_grants.retention as retention_module

    world.register_both()
    tenant = world.expired()
    _request, _approved, authorization = _chain(world, tenant)
    world.grant(world.operator_id(world.authorizer), P.SECURITY_RETENTION_HOLD_MANAGE)
    hold = world.hold(tenant, "LEGAL-RACE")
    evidence = world.evidence(world.authorizer)
    pause = _gate_at(monkeypatch, retention_module, "record_platform_event_in_transaction")

    def release() -> object:
        return retention_module.release_permission_grant_ledger_hold(
            hold.hold_id, caller=world.authorizer, reason=REASON, session_evidence=evidence
        )

    first, second = run_first_then_second(
        admin, pause, release, lambda: _execute(authorization, apply=True)
    )
    assert "error" not in first, first
    assert isinstance(second.get("error"), LedgerApprovalRefusedError), second
    assert second["error"].code == "authorizer_released_hold"
    assert world.ledger.rows(tenant) == 1


def test_a_release_started_while_the_execution_holds_the_tenant_waits_for_it(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch, deletion_enabled: None
) -> None:
    """Design 5.4: the release waits for the execution's tenant lock; the
    execution, still seeing the hold active, deletes nothing. The release
    takes the tenant row first by an explicit lock (the lock order of
    placement and deletion); its audit row's foreign key onto the tenant
    would also make it wait (FOR KEY SHARE against FOR UPDATE), so this
    test shows the serialisation, not which of the two locks causes it."""
    import saas_os.core.permission_grants.approvals as approvals_module
    import saas_os.core.permission_grants.retention as retention_module

    world.register_both()
    tenant = world.expired()
    _request, _approved, authorization = _chain(world, tenant)
    hold = world.hold(tenant, "LEGAL-RACE")
    evidence = world.evidence(world.ledger.holder)
    pause = _gate_at(monkeypatch, approvals_module, "scope_state")  # tenant lock held

    def release() -> object:
        return retention_module.release_permission_grant_ledger_hold(
            hold.hold_id, caller=world.ledger.holder, reason=REASON, session_evidence=evidence
        )

    first, second = run_first_then_second(
        admin, pause, lambda: _execute(authorization, apply=True), release
    )
    assert isinstance(first.get("error"), LedgerApprovalRefusedError), first
    assert first["error"].code == "scope_not_eligible"
    assert "error" not in second, second
    assert world.ledger.rows(tenant) == 1


def test_a_hold_placed_while_the_execution_holds_the_tenant_waits_for_its_commit(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch, deletion_enabled: None
) -> None:
    import saas_os.core.permission_grants.approvals as approvals_module

    world.register_both()
    tenant = world.expired(migrations=2)
    _request, _approved, authorization = _chain(world, tenant)
    pause = _gate_at(monkeypatch, approvals_module, "scope_state")  # tenant lock held

    first, second = run_first_then_second(
        admin,
        pause,
        lambda: _execute(authorization, apply=True),
        lambda: world.hold(tenant, "LEGAL-AFTER"),
    )
    assert "error" not in first and "error" not in second, (first, second)
    assert first["result"].applied is True and world.ledger.rows(tenant) == 0
    deleted_at = world.platform.scalar(
        "SELECT created_at FROM core.platform_audit_log WHERE id = :i",
        {"i": first["result"].run_id},
    )
    assert second["result"].placed_at > deleted_at


def test_a_hold_placed_before_the_execution_takes_the_tenant_is_seen(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch, deletion_enabled: None
) -> None:
    import saas_os.core.permission_grants.retention as retention_module

    world.register_both()
    tenant = world.expired()
    _request, _approved, authorization = _chain(world, tenant)
    pause = _gate_at(monkeypatch, retention_module, "record_platform_event_in_transaction")

    first, second = run_first_then_second(
        admin,
        pause,
        lambda: world.hold(tenant, "LEGAL-FIRST"),
        lambda: _execute(authorization, apply=True),
    )
    assert "error" not in first, first
    assert isinstance(second.get("error"), LedgerApprovalRefusedError), second
    assert second["error"].code == "scope_not_eligible"
    assert world.ledger.rows(tenant) == 1


def test_a_revocation_racing_an_approval_waits_and_then_invalidates_it(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.permission_grants.approvals as approvals_module

    world.register_both()
    tenant = world.expired()
    request = world.request(tenant)
    pause = _gate_at(monkeypatch, approvals_module, "record_platform_event_in_transaction")
    evidence = world.evidence(world.approver)
    revoke_evidence = world.evidence(world.representative)

    def approve() -> object:
        return world.approve(request, session_evidence=evidence)

    def revoke() -> object:
        return revoke_register_entry(
            world.approver.user_id,
            world.enrolments[world.approver.user_id].id,
            operation="permission_grant_ledger.approver_revoke_by_representative",
            caller=world.representative,
            session_evidence=revoke_evidence,
            ticket_ref="TICKET-50",
            reason=REASON,
        )

    first, second = run_first_then_second(admin, pause, approve, revoke)
    assert "error" not in first and "error" not in second, (first, second)
    assert second["result"].invalidated_approvals == 1
    with _refused("approval_invalidated"):
        world.authorize(request)


def test_two_approvals_racing_on_one_request_leave_one(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.permission_grants.approvals as approvals_module

    world.register_both()
    tenant = world.expired()
    request = world.request(tenant)
    pause = _gate_at(monkeypatch, approvals_module, "record_platform_event_in_transaction")
    a = world.evidence(world.approver)
    b = world.evidence(world.authorizer)
    first, second = run_first_then_second(
        admin,
        pause,
        lambda: world.approve(request, session_evidence=a),
        lambda: world.approve(request, caller=world.authorizer, session_evidence=b),
    )
    assert "error" not in first, first
    assert isinstance(second.get("error"), LedgerApprovalRefusedError), second
    assert second["error"].code == "request_already_approved"
    assert world.count(APPROVALS) == 1


# --- reads and evidence ----------------------------------------------------------------------


def test_every_act_names_the_session_user_and_its_session(
    world: Approvals, platform: PlatformWorld
) -> None:
    world.register_both()
    _request, _approved, authorization = _chain(world, world.expired())
    for action, actor in (
        (REQUEST, world.requester),
        (APPROVE, world.approver),
        (AUTHORIZE, world.authorizer),
    ):
        (row,) = platform.audit(action, "success")
        assert row["actor_user_id"] == actor.user_id
        assert row["metadata"]["channel"] == "platform_http"
        assert row["metadata"]["session_verified"] is True
        session = platform.scalar(
            "SELECT user_id FROM core.sessions WHERE id = :s",
            {"s": uuid.UUID(row["metadata"]["session_id"])},
        )
        assert session == actor.user_id
    assert authorization.id is not None


def test_the_register_and_eligibility_reads_need_audit_read(world: Approvals) -> None:
    world.register_both()
    with pytest.raises(PlatformNotAuthorizedError):
        read_approver_register(caller=world.requester)
    with pytest.raises(PlatformNotAuthorizedError):
        read_approver_eligibility(caller=world.owner)
    page = read_approver_register(caller=world.auditor)
    kinds = sorted(e.entry_type for e in page.entries)
    assert kinds == [
        "approver_enrolment",
        "approver_enrolment",
        "representative_designation",
        "representative_designation_proposal",
    ]


def test_a_released_hold_replays_for_its_releaser_and_refuses_anyone_else(
    world: Approvals,
) -> None:
    tenant = world.expired()
    hold = world.hold(tenant)
    released = world.release(hold.hold_id)
    again = world.release(hold.hold_id)
    assert again.replay is True and again.platform_audit_id == released.platform_audit_id
    other, _ = world.platform.operator([P.SECURITY_RETENTION_HOLD_MANAGE])
    with pytest.raises(LedgerHoldAlreadyReleasedError):
        world.release(hold.hold_id, caller=other)
    with pytest.raises(LedgerApprovalRefusedError, match="session_evidence_invalid"):
        from saas_os.core.permission_grants import release_permission_grant_ledger_hold

        release_permission_grant_ledger_hold(
            world.hold(tenant, "LEGAL-79").hold_id,
            caller=world.ledger.holder,
            reason=REASON,
            session_evidence=PlatformSessionEvidence(uuid.uuid4(), True),
        )


def test_bootstrap_purpose_and_service_callers_reach_nothing(world: Approvals) -> None:
    world.register_both()
    tenant = world.expired()
    request = world.request(tenant)
    with pytest.raises(PlatformNotAuthorizedError):
        world.approve(
            request,
            caller=BOOTSTRAP,  # type: ignore[arg-type]
            session_evidence=PlatformSessionEvidence(uuid.uuid4(), True),
        )
    with pytest.raises(PlatformNotAuthorizedError):
        world.approve(request, caller=UserCaller(world.platform.user()))


# --- review of 20d9b43 ---------------------------------------------------------------------


@pytest.mark.parametrize("record", ["approval", "authorisation"])
def test_a_revocation_begun_before_the_record_commits_still_invalidates_it(
    world: Approvals, monkeypatch: pytest.MonkeyPatch, record: str
) -> None:
    """The revocation's transaction starts (its `now()` is fixed) before the
    approval or authorisation exists; it then waits at the register lock
    while that record commits. Its invalidation must still apply: the
    trigger stamps `invalidated_at` from the wall clock after the lock, so
    it is never earlier than the record's own time (the transaction start
    would be, and the order CHECK would roll the revocation back)."""
    import saas_os.core.permission_grants.register as register_module

    world.register_both()
    request = world.request(world.expired())
    if record == "authorisation":
        world.approve(request)
    target = world.approver if record == "approval" else world.authorizer
    gate = Gate("first")
    real = register_module.lock_register

    def gated(session: object, **kwargs: object) -> None:
        gate.checkpoint(session)
        real(session, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(register_module, "lock_register", gated)
    evidence = world.evidence(world.security)

    def revoke() -> object:
        return revoke_register_entry(
            target.user_id,
            world.enrolments[target.user_id].id,
            operation="permission_grant_ledger.approver_revoke_by_security",
            caller=world.security,
            session_evidence=evidence,
            ticket_ref="TICKET-70",
            reason=REASON,
        )

    thread, outcome = start(revoke, "first")
    assert gate.paused.wait(timeout=30)
    # The revocation's transaction is open; the record is created now.
    made = world.approve(request) if record == "approval" else world.authorize(request)
    assert made is not None
    gate.release.set()
    join(thread)
    assert "error" not in outcome, outcome
    result = outcome["result"]
    if record == "approval":
        assert result.invalidated_approvals == 1
        stamps = world.platform.execute(
            f"SELECT approved_at, invalidated_at FROM {APPROVALS}"  # noqa: S608
        )
    else:
        assert result.invalidated_execution_authorizations == 1
        stamps = world.platform.execute(
            f"SELECT authorized_at, invalidated_at FROM {AUTHORIZATIONS}"  # noqa: S608
        )
    ((made_at, invalidated_at),) = stamps
    assert invalidated_at is not None and invalidated_at >= made_at


def test_replays_are_refused_once_the_chain_no_longer_holds(world: Approvals) -> None:
    world.register_both()
    request = world.request(world.expired())
    world.approve(request)
    world.authorize(request)
    # The approver gains authority: the identical approval retry is refused,
    # not replayed.
    world.grant(world.operator_id(world.approver), P.AUTHORITY_MANAGE)
    with _refused("party_holds_authority_manage"):
        world.approve(request)
    world.platform.execute(
        "UPDATE core.platform_grants SET revoked_at = now() WHERE permission = "
        "'platform.authority:manage' AND operator_id = :o",
        {"o": world.operator_id(world.approver)},
    )
    # The approval is invalidated: the identical authorisation retry is refused.
    revoke_register_entry(
        world.approver.user_id,
        world.enrolments[world.approver.user_id].id,
        operation="permission_grant_ledger.approver_revoke_by_security",
        caller=world.security,
        session_evidence=world.evidence(world.security),
        ticket_ref="TICKET-71",
        reason=REASON,
    )
    with _refused("approval_invalidated"):
        world.authorize(request)


def test_a_hold_manager_never_approves_or_authorises(world: Approvals) -> None:
    world.register_both()
    request = world.request(world.expired())
    world.approve(request)
    world.grant(world.operator_id(world.authorizer), P.SECURITY_RETENTION_HOLD_MANAGE)
    with _refused("party_holds_hold_manage"):
        world.authorize(request)
    other = world.request(world.expired())
    world.grant(world.operator_id(world.approver), P.SECURITY_RETENTION_HOLD_MANAGE)
    with _refused("party_holds_hold_manage"):
        world.approve(other)


def test_a_representative_never_enrols_someone_linked_to_them(world: Approvals) -> None:
    world.designate()
    world.platform.execute(
        "UPDATE core.platform_grants SET granted_by_user_id = :g WHERE operator_id = :o "
        "AND permission = 'platform.security_retention:report'",
        {"g": world.representative.user_id, "o": world.operator_id(world.approver)},
    )
    with _refused("subject_linked_to_representative"):
        world.enrol(world.approver, "PERSON-A", eligible=False)


def test_an_audit_row_of_another_retention_action_does_not_satisfy_the_check(
    world: Approvals,
) -> None:
    """The deferred check pins the act's own action: a register entry whose
    audit row is a deletion request's is refused at commit."""
    designation = world.designate()
    audit_id = uuid.uuid4()
    with pytest.raises(DBAPIError, match="no audit row"), session_scope() as s:
        s.execute(
            text(
                "INSERT INTO core.platform_audit_log (id, actor_type, actor_user_id, action, "
                "target_type, outcome) VALUES (:a, 'user', :r, "
                "'platform.permission_grant_ledger.deletion_request', 'x', 'success')"
            ),
            {"a": audit_id, "r": world.representative.user_id},
        )
        s.execute(
            text(
                f"INSERT INTO {REGISTER} (id, entry_type, subject_user_id, "  # noqa: S608
                "recorded_by_user_id, natural_person_ref, verification_ref, "
                "authorisation_ref, ticket_ref, authorised_by_entry_id, valid_until, "
                "recorded_by_platform_audit_id) VALUES (:i, 'approver_enrolment', :s, :r, "
                "'P-Z', 'V', 'A', 'T', :d, now() + interval '200 days', :a)"
            ),
            {
                "i": uuid.uuid4(),
                "s": world.approver.user_id,
                "r": world.representative.user_id,
                "d": designation.id,
                "a": audit_id,
            },
        )


def test_a_register_entry_needs_the_audit_action_of_its_own_type(world: Approvals) -> None:
    """An enrolment backed by a revocation's audit row is refused at commit."""
    designation = world.designate()
    audit_id = uuid.uuid4()
    with pytest.raises(DBAPIError, match="no audit row"), session_scope() as s:
        s.execute(
            text(
                "INSERT INTO core.platform_audit_log (id, actor_type, actor_user_id, action, "
                "target_type, outcome) VALUES (:a, 'user', :r, "
                "'platform.permission_grant_ledger.approver_revoke_by_security', 'x', 'success')"
            ),
            {"a": audit_id, "r": world.representative.user_id},
        )
        s.execute(
            text(
                f"INSERT INTO {REGISTER} (id, entry_type, subject_user_id, "  # noqa: S608
                "recorded_by_user_id, natural_person_ref, verification_ref, "
                "authorisation_ref, ticket_ref, authorised_by_entry_id, valid_until, "
                "recorded_by_platform_audit_id) VALUES (:i, 'approver_enrolment', :s, :r, "
                "'P-Y', 'V', 'A', 'T', :d, now() + interval '200 days', :a)"
            ),
            {
                "i": uuid.uuid4(),
                "s": world.approver.user_id,
                "r": world.representative.user_id,
                "d": designation.id,
                "a": audit_id,
            },
        )


def test_the_trigger_refuses_an_enrolment_linked_to_the_representative(
    world: Approvals,
) -> None:
    """The database refuses what Core refuses (`subject_linked_to_representative`),
    for a direct insert too."""
    designation = world.designate()
    world.platform.execute(
        "UPDATE core.platform_grants SET granted_by_user_id = :g WHERE operator_id = :o "
        "AND permission = 'platform.security_retention:report'",
        {"g": world.representative.user_id, "o": world.operator_id(world.approver)},
    )
    with pytest.raises(DBAPIError, match="linked to them"), session_scope() as s:
        s.execute(
            text(
                f"INSERT INTO {REGISTER} (id, entry_type, subject_user_id, "  # noqa: S608
                "recorded_by_user_id, natural_person_ref, verification_ref, "
                "authorisation_ref, ticket_ref, authorised_by_entry_id, valid_until, "
                "recorded_by_platform_audit_id) VALUES (:i, 'approver_enrolment', :s, :r, "
                "'P-X', 'V', 'A', 'T', :d, now() + interval '200 days', :a)"
            ),
            {
                "i": uuid.uuid4(),
                "s": world.approver.user_id,
                "r": world.representative.user_id,
                "d": designation.id,
                "a": uuid.uuid4(),
            },
        )


# --- final closure (owner decisions of 2026-11-03) ------------------------------------------


def _expire_designation(world: Approvals, designation_id: uuid.UUID) -> None:
    """The designation's `valid_until` passes (test setup: the DB clock is
    not advanced, the stored time is moved into the past)."""
    world.privileged(
        (
            f"UPDATE {REGISTER} SET valid_until = now() - interval '1 second' "  # noqa: S608
            "WHERE id = :i",
            {"i": designation_id},
        )
    )


def _enrol_fresh(
    world: Approvals, subject: UserCaller, person: str, verification: str, **kwargs: Any
) -> Any:
    return enrol_approver(
        subject.user_id,
        caller=world.representative,
        session_evidence=world.evidence(world.representative),
        natural_person_ref=person,
        verification_ref=verification,
        authorisation_ref=f"AUTH-{verification}",
        ticket_ref="TICKET-90",
        valid_until=world.in_months(11),
        reason=kwargs.pop("reason", REASON),
        **kwargs,
    )


def test_an_expired_designation_suspends_approval_authorisation_and_execution(
    world: Approvals, deletion_enabled: None
) -> None:
    """F-2: the instant its designation expires (DB clock), an approver
    enrolled under it can no longer approve or authorise, and what it
    approved or authorised before fails at its next use."""
    world.register_both()
    assert world.designation is not None
    authorised = _chain(world, world.expired())  # fully authorised before expiry
    approved_only = world.request(world.expired())
    world.approve(approved_only)  # approved before expiry, not yet authorised
    pending = world.request(world.expired())  # requested before expiry
    _expire_designation(world, world.designation.id)
    page = read_approver_eligibility(caller=world.auditor)
    assert {a.state for a in page.approvers} == {EnrolmentState.SUSPENDED}
    with _refused("approver_not_eligible"):
        world.approve(pending)
    with _refused("approver_not_eligible"):
        world.authorize(approved_only)
    with _refused("approver_not_eligible"):
        _execute(authorised[2])
    with _refused("approver_not_eligible"):
        _execute(authorised[2], apply=True)
    # Nothing was rewritten: expiry is not an event.
    rows = world.platform.execute(
        f"SELECT count(*) FROM {APPROVALS} WHERE invalidated_at IS NOT NULL "  # noqa: S608
        "OR consumed_at IS NOT NULL"
    )
    assert rows == [(0,)]
    assert world.ledger.rows(authorised[0].tenant_ids[0]) == 1


def test_a_new_designation_alone_restores_nothing_and_fresh_enrolment_waits_its_delay(
    world: Approvals,
) -> None:
    """F-2: a new designation does not revive the suspended enrolments; a
    re-enrolment needs a fresh `verification_ref` (`verification_not_fresh`
    otherwise), cannot renew a suspended entry, and makes its subject
    eligible only after its own 120 days."""
    world.register_both()
    assert world.designation is not None
    old_approver = world.enrolments[world.approver.user_id]
    _expire_designation(world, world.designation.id)
    world.designate()  # the same representative, designated again
    request = world.request(world.expired())
    with _refused("approver_not_eligible"):
        world.approve(request)
    states = {
        a.entry_id: a.state for a in read_approver_eligibility(caller=world.auditor).approvers
    }
    assert set(states.values()) == {EnrolmentState.SUSPENDED}
    # The old verification reference is not fresh verification.
    with _refused("verification_not_fresh"):
        _enrol_fresh(world, world.approver, "PERSON-A", "VERIFY-PERSON-A")
    # A suspended enrolment cannot be renewed.
    with _refused("invalid_renewal"):
        _enrol_fresh(
            world, world.approver, "PERSON-A", "VERIFY-PERSON-A-2", renews_entry_id=old_approver.id
        )
    fresh = _enrol_fresh(world, world.approver, "PERSON-A", "VERIFY-PERSON-A-2")
    assert fresh.authorised_by_entry_id == world.designation.id
    assert fresh.renews_entry_id is None
    with _refused("approver_not_eligible"):  # its own 120-day delay
        world.approve(request)
    states = {
        a.entry_id: a.state for a in read_approver_eligibility(caller=world.auditor).approvers
    }
    assert states[fresh.id] is EnrolmentState.WAITING
    assert states[old_approver.id] is EnrolmentState.SUSPENDED
    world.make_eligible(fresh.id)
    world.approve(request)
    # The authoriser, not re-enrolled, is still suspended.
    with _refused("authorizer_not_eligible"):
        world.authorize(request)
    again = _enrol_fresh(world, world.authorizer, "PERSON-B", "VERIFY-PERSON-B-2")
    world.make_eligible(again.id)
    assert world.authorize(request).authorized_by_user_id == world.authorizer.user_id


def test_the_trigger_suspends_enrolments_of_an_expired_designation(world: Approvals) -> None:
    """The database enforces F-2 for a direct insert too: a suspended
    enrolment is neither renewed nor its verification reused; only a fresh
    one passes the trigger (and then still needs its audit row)."""
    world.register_both()
    assert world.designation is not None
    old = world.enrolments[world.approver.user_id]
    _expire_designation(world, world.designation.id)
    designation = world.designate()

    def insert(verification: str, renews: uuid.UUID | None = None) -> None:
        with session_scope() as s:
            s.execute(
                text(
                    f"INSERT INTO {REGISTER} (id, entry_type, subject_user_id, "  # noqa: S608
                    "recorded_by_user_id, natural_person_ref, verification_ref, "
                    "authorisation_ref, ticket_ref, authorised_by_entry_id, renews_entry_id, "
                    "valid_until, recorded_by_platform_audit_id) VALUES (:i, "
                    "'approver_enrolment', :s, :r, 'PERSON-A', :v, 'A', 'T', :d, :n, "
                    "now() + interval '200 days', :a)"
                ),
                {
                    "i": uuid.uuid4(),
                    "s": world.approver.user_id,
                    "r": world.representative.user_id,
                    "v": verification,
                    "d": designation.id,
                    "n": renews,
                    "a": uuid.uuid4(),
                },
            )

    with pytest.raises(DBAPIError, match="verify afresh"):
        insert("VERIFY-PERSON-A")
    with pytest.raises(DBAPIError, match="renews the current enrolment"):
        insert("VERIFY-NEW", renews=old.id)
    # A fresh verification passes the trigger; only the audit check stops it.
    with pytest.raises(DBAPIError, match="no audit row"):
        insert("VERIFY-NEW")


def test_an_expired_enrolment_is_refused_by_the_database_clock(
    world: Approvals, deletion_enabled: None
) -> None:
    world.register_both()
    _request, _approved, authorization = _chain(world, world.expired())
    world.privileged(
        (
            f"UPDATE {REGISTER} SET valid_until = now() - interval '1 second' "  # noqa: S608
            "WHERE id = :i",
            {"i": world.enrolments[world.authorizer.user_id].id},
        )
    )
    with _refused("authorizer_not_eligible"):
        _execute(authorization)
    other = world.request(world.expired())
    world.approve(other)
    with _refused("authorizer_not_eligible"):
        world.authorize(other)


# The four provenance links the register trigger and Core's
# `provenance_linked` refuse between a representative and the subject.
_LINKS = {
    "representative_enrolled_subject": (
        "UPDATE core.platform_operators SET enrolled_by_user_id = :rep{revoke} "
        "WHERE user_id = :subject"
    ),
    "subject_enrolled_representative": (
        "UPDATE core.platform_operators SET enrolled_by_user_id = :subject{revoke} "
        "WHERE user_id = :rep"
    ),
    "representative_granted_subject_report": (
        "UPDATE core.platform_grants g SET granted_by_user_id = :rep{revoke} "
        "FROM core.platform_operators o WHERE o.id = g.operator_id AND o.user_id = :subject "
        "AND g.permission = 'platform.security_retention:report'"
    ),
    "subject_granted_representative_report": (
        "UPDATE core.platform_grants g SET granted_by_user_id = :subject{revoke} "
        "FROM core.platform_operators o WHERE o.id = g.operator_id AND o.user_id = :rep "
        "AND g.permission = 'platform.security_retention:report'"
    ),
}


def _insert_enrolment(world: Approvals, designation_id: uuid.UUID, person: str) -> None:
    with session_scope() as s:
        s.execute(
            text(
                f"INSERT INTO {REGISTER} (id, entry_type, subject_user_id, "  # noqa: S608
                "recorded_by_user_id, natural_person_ref, verification_ref, "
                "authorisation_ref, ticket_ref, authorised_by_entry_id, valid_until, "
                "recorded_by_platform_audit_id) VALUES (:i, 'approver_enrolment', :s, :r, "
                ":p, 'V', 'A', 'T', :d, now() + interval '200 days', :a)"
            ),
            {
                "i": uuid.uuid4(),
                "s": world.approver.user_id,
                "r": world.representative.user_id,
                "p": person,
                "d": designation_id,
                "a": uuid.uuid4(),
            },
        )


def _core_linked(world: Approvals) -> bool:
    with session_scope() as s:
        return provenance_linked(s, world.representative.user_id, world.approver.user_id)


@pytest.mark.parametrize("revoked", [False, True], ids=["live", "revoked"])
@pytest.mark.parametrize("branch", sorted(_LINKS))
def test_the_trigger_refuses_each_provenance_link_like_core(
    world: Approvals, branch: str, revoked: bool
) -> None:
    """Each of the four links, on its own, makes the register trigger refuse
    a direct enrolment, and Core's `provenance_linked` agrees. A revoked
    operator or grant row still links (the history counts)."""
    designation = world.designate()
    operator_revoke = ", status = 'revoked'" if revoked and "enrolled" in branch else ""
    grant_revoke = ", revoked_at = now()" if revoked and "granted" in branch else ""
    world.platform.execute(
        _LINKS[branch].format(revoke=operator_revoke or grant_revoke),
        {"rep": world.representative.user_id, "subject": world.approver.user_id},
    )
    assert _core_linked(world) is True
    with pytest.raises(DBAPIError, match="linked to them"):
        _insert_enrolment(world, designation.id, f"P-{branch[:20]}")


def test_null_or_unrelated_provenance_links_nobody(world: Approvals) -> None:
    """Negative case of the four branches: NULL provenance (bootstrap,
    break-glass) and a grant of another permission link nobody, in the
    trigger and in Core; the direct insert then passes the trigger and only
    the deferred audit check stops it."""
    designation = world.designate()
    world.grant(world.operator_id(world.approver), P.AUDIT_READ)
    world.platform.execute(
        "UPDATE core.platform_grants SET granted_by_user_id = :rep WHERE operator_id = :o "
        "AND permission = 'platform.audit:read'",
        {"rep": world.representative.user_id, "o": world.operator_id(world.approver)},
    )
    assert _core_linked(world) is False
    with pytest.raises(DBAPIError, match="no audit row"):
        _insert_enrolment(world, designation.id, "P-UNLINKED")


def _blocked_by(admin: Engine, pid: int) -> tuple[int, str]:
    wait_until_blocked_by(admin, pid)
    with admin.connect() as conn:
        rows = conn.execute(
            text("SELECT pid, query FROM pg_stat_activity WHERE :p = ANY(pg_blocking_pids(pid))"),
            {"p": pid},
        ).all()
    assert len(rows) == 1, rows
    return rows[0][0], rows[0][1]


def test_the_hold_release_locks_the_tenant_row_before_the_hold_row_in_postgresql(
    world: Approvals, admin: Engine
) -> None:
    """Design 5.4, observed in PostgreSQL: while another transaction holds
    the tenant row `FOR UPDATE`, the release waits on that row in its
    explicit `SELECT ... FROM core.tenants ... FOR UPDATE`, holding no row
    lock on the hold (a third session locks the hold row `NOWAIT`), and
    completes once the tenant row is free. Without the explicit lock the
    release would lock the hold row first and wait only at its audit row's
    foreign-key check on the tenant (an `INSERT INTO core.platform_audit_log`),
    which this test tells apart."""
    tenant = world.expired()
    hold = world.hold(tenant, "LEGAL-LOCK")
    evidence = world.evidence(world.ledger.holder)
    holder = admin.connect()
    transaction = holder.begin()
    thread = None
    try:
        holder.execute(text("SELECT id FROM core.tenants WHERE id = :t FOR UPDATE"), {"t": tenant})
        blocker = holder.execute(text("SELECT pg_backend_pid()")).scalar_one()
        thread, outcome = start(
            lambda: release_permission_grant_ledger_hold(
                hold.hold_id, caller=world.ledger.holder, reason=REASON, session_evidence=evidence
            ),
            "release",
        )
        waiter, query = _blocked_by(admin, blocker)
        # It waits in the explicit tenant lock, not in the audit insert.
        assert "core.tenants" in query and "FOR UPDATE" in query.upper(), query
        assert "platform_audit_log" not in query, query
        with admin.connect() as conn:
            hold_locks = conn.execute(
                text(
                    "SELECT mode FROM pg_locks WHERE pid = :w AND locktype = 'relation' "
                    "AND relation = 'core.permission_grant_ledger_holds'::regclass "
                    "AND mode IN ('RowShareLock', 'RowExclusiveLock')"
                ),
                {"w": waiter},
            ).all()
        assert hold_locks == [], hold_locks
        # The hold row is not locked by the waiting release.
        with admin.begin() as third:
            locked = third.execute(
                text(
                    "SELECT id FROM core.permission_grant_ledger_holds "
                    "WHERE id = :h FOR UPDATE NOWAIT"
                ),
                {"h": hold.hold_id},
            ).scalar_one()
        assert locked == hold.hold_id
    finally:
        transaction.rollback()
        holder.close()
        if thread is not None:
            join(thread)
    assert "error" not in outcome, outcome
    assert outcome["result"].released_at is not None


def test_each_act_rolls_back_its_state_row_with_a_failed_audit_row(
    world: Approvals, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Transaction boundary: when an act's success audit row cannot be
    written, its state row (and a revocation's invalidations) roll back
    with it; nothing is left half done."""
    import saas_os.core.permission_grants.approvals as approvals_module
    import saas_os.core.permission_grants.register as register_module

    world.register_both()
    tenant = world.expired()

    def failing(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("audit write failed")

    def counts() -> tuple[int, ...]:
        return tuple(world.count(t) for t in (REQUESTS, APPROVALS, AUTHORIZATIONS, REGISTER))

    def fails(module: object, act: Any) -> None:
        before = counts()
        with monkeypatch.context() as patch:
            patch.setattr(module, "record_platform_event_in_transaction", failing)
            with pytest.raises(RuntimeError, match="audit write failed"):
                act()
        assert counts() == before

    fails(approvals_module, lambda: world.request(tenant))
    request = world.request(tenant)
    fails(approvals_module, lambda: world.approve(request))
    world.approve(request)
    fails(approvals_module, lambda: world.authorize(request))
    world.authorize(request)
    newcomer, _ = world.platform.operator([P.SECURITY_RETENTION_REPORT])
    fails(register_module, lambda: world.enrol(newcomer, "PERSON-N", eligible=False))
    # The revocation would invalidate the approval: that rolls back too.
    fails(
        register_module,
        lambda: _revoke(world, world.approver, world.evidence(world.security), "TICKET-91"),
    )
    invalidated = world.platform.scalar(
        f"SELECT count(*) FROM {APPROVALS} WHERE invalidated_at IS NOT NULL"  # noqa: S608
    )
    assert invalidated == 0
    # No success row was left by any failed act: one per act that committed.
    for action, expected in (
        (REQUEST, 1),
        (APPROVE, 1),
        (AUTHORIZE, 1),
        ("platform.permission_grant_ledger.approver_enrol", 2),
        ("platform.permission_grant_ledger.approver_revoke_by_security", 0),
    ):
        assert len(world.platform.audit(action, "success")) == expected, action


# --- concurrency, with real locks (final closure re-test) -----------------------------------


def test_two_overlapping_requests_racing_leave_one(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.permission_grants.approvals as approvals_module

    tenant = world.expired()
    pause = _gate_at(monkeypatch, approvals_module, "record_platform_event_in_transaction")
    a = world.evidence(world.requester)
    b = world.evidence(world.approver)
    first, second = run_first_then_second(
        admin,
        pause,
        lambda: world.request(tenant, session_evidence=a),
        lambda: world.request(tenant, caller=world.approver, session_evidence=b),
    )
    assert "error" not in first, first
    assert isinstance(second.get("error"), LedgerApprovalRefusedError), second
    assert second["error"].code == "overlapping_request"
    assert world.count(REQUESTS) == 1


def _revoke(world: Approvals, target: UserCaller, evidence: Any, ticket: str) -> Any:
    return revoke_register_entry(
        target.user_id,
        world.enrolments[target.user_id].id,
        operation="permission_grant_ledger.approver_revoke_by_security",
        caller=world.security,
        session_evidence=evidence,
        ticket_ref=ticket,
        reason=REASON,
    )


def test_a_revocation_committed_first_refuses_the_racing_approval(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other ordering of `test_a_revocation_racing_an_approval_waits_and_
    then_invalidates_it`: the revocation holds the register lock; the
    approval waits on it, then finds the approver no longer eligible."""
    import saas_os.core.permission_grants.register as register_module

    world.register_both()
    request = world.request(world.expired())
    pause = _gate_at(monkeypatch, register_module, "record_platform_event_in_transaction")
    revoke_evidence = world.evidence(world.security)
    approve_evidence = world.evidence(world.approver)
    first, second = run_first_then_second(
        admin,
        pause,
        lambda: _revoke(world, world.approver, revoke_evidence, "TICKET-92"),
        lambda: world.approve(request, session_evidence=approve_evidence),
    )
    assert "error" not in first, first
    assert isinstance(second.get("error"), LedgerApprovalRefusedError), second
    assert second["error"].code == "approver_not_eligible"
    assert world.count(APPROVALS) == 0


@pytest.mark.parametrize("order", ["authorisation_first", "revocation_first"])
def test_a_revocation_racing_an_authorisation_in_both_orders(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch, order: str
) -> None:
    import saas_os.core.permission_grants.approvals as approvals_module
    import saas_os.core.permission_grants.register as register_module

    world.register_both()
    request = world.request(world.expired())
    world.approve(request)
    revoke_evidence = world.evidence(world.security)
    authorize_evidence = world.evidence(world.authorizer)

    def revoke() -> Any:
        return _revoke(world, world.authorizer, revoke_evidence, "TICKET-93")

    def authorize() -> Any:
        return world.authorize(request, session_evidence=authorize_evidence)

    if order == "authorisation_first":
        pause = _gate_at(monkeypatch, approvals_module, "record_platform_event_in_transaction")
        first, second = run_first_then_second(admin, pause, authorize, revoke)
        assert "error" not in first and "error" not in second, (first, second)
        assert second["result"].invalidated_execution_authorizations == 1
        with _refused("execution_authorization_invalidated"):
            _execute(first["result"])
    else:
        pause = _gate_at(monkeypatch, register_module, "record_platform_event_in_transaction")
        first, second = run_first_then_second(admin, pause, revoke, authorize)
        assert "error" not in first, first
        assert isinstance(second.get("error"), LedgerApprovalRefusedError), second
        assert second["error"].code == "authorizer_not_eligible"
        assert world.count(AUTHORIZATIONS) == 0


@pytest.mark.parametrize("same", [True, False], ids=["identical", "different"])
def test_two_renewals_racing_leave_one(
    world: Approvals, admin: Engine, monkeypatch: pytest.MonkeyPatch, same: bool
) -> None:
    """Two renewals of one enrolment at once: the second waits for the
    register lock; an identical retry by the same representative is then a
    replay, a different one is refused. Never two renewals."""
    import saas_os.core.permission_grants.register as register_module

    world.designate()
    current = world.enrol(world.approver, "PERSON-A")
    pause = _gate_at(monkeypatch, register_module, "record_platform_event_in_transaction")
    a = world.evidence(world.representative)
    b = world.evidence(world.representative)
    until = world.in_months(11)

    def renew(evidence: Any, reason: str) -> Any:
        return enrol_approver(
            world.approver.user_id,
            caller=world.representative,
            session_evidence=evidence,
            natural_person_ref="PERSON-A",
            verification_ref="VERIFY-PERSON-A",
            authorisation_ref="AUTH-PERSON-A",
            ticket_ref="TICKET-23",
            valid_until=until,
            reason=reason,
            renews_entry_id=current.id,
        )

    first, second = run_first_then_second(
        admin,
        pause,
        lambda: renew(a, "renewal"),
        lambda: renew(b, "renewal" if same else "another renewal"),
    )
    assert "error" not in first, first
    if same:
        assert "error" not in second, second
        assert second["result"].replay is True and second["result"].id == first["result"].id
    else:
        assert isinstance(second.get("error"), LedgerApprovalRefusedError), second
        assert second["error"].code == "approver_already_enrolled"
    renewals = world.platform.scalar(
        f"SELECT count(*) FROM {REGISTER} WHERE renews_entry_id = :c",  # noqa: S608
        {"c": current.id},
    )
    assert renewals == 1


# --- idempotent recovery (final closure re-test) --------------------------------------------


def test_an_authorisation_retry_with_other_content_or_by_another_person_is_refused(
    world: Approvals,
) -> None:
    """Design 3.1: only the identical retry by the same caller is a replay;
    while an authorisation is live, a different reason or another eligible
    person gets `execution_already_authorized`, never the record."""
    world.register_both()
    world.enrol(world.requester, "PERSON-C")
    request = world.request(world.expired())
    world.approve(request)
    first = world.authorize(request)
    assert world.authorize(request).replay is True
    with _refused("execution_already_authorized"):
        world.authorize(request, reason="another reason")
    with _refused("execution_already_authorized"):
        world.authorize(request, caller=world.requester)
    assert world.count(AUTHORIZATIONS) == 1
    # After the live one expires, a new authorisation may be given (design 7).
    world.privileged(
        (
            f"UPDATE {AUTHORIZATIONS} SET expires_at = now() - interval '1 second', "  # noqa: S608
            "authorized_at = now() - interval '2 hours' WHERE id = :i",
            {"i": first.id},
        )
    )
    renewed = world.authorize(request, reason="after the first one expired")
    assert renewed.id != first.id and renewed.replay is False


def test_register_writes_replay_only_for_the_same_caller_and_content(world: Approvals) -> None:
    from saas_os.core.permission_grants import (
        confirm_representative_designation,
        propose_representative_designation,
    )

    subject = world.representative
    propose = {
        "designation_ref": "BOARD-RES-9",
        "ticket_ref": "TICKET-94",
        "valid_until": world.in_months(11),
        "reason": REASON,
    }
    proposal = propose_representative_designation(
        subject.user_id, caller=world.owner, session_evidence=world.evidence(world.owner), **propose
    )
    again = propose_representative_designation(
        subject.user_id, caller=world.owner, session_evidence=world.evidence(world.owner), **propose
    )
    assert again.replay is True and again.id == proposal.id
    with _refused("proposal_already_pending"):
        propose_representative_designation(
            subject.user_id,
            caller=world.owner,
            session_evidence=world.evidence(world.owner),
            **{**propose, "reason": "another reason"},
        )
    other_owner, _ = world.platform.operator([P.AUTHORITY_MANAGE])
    with _refused("proposal_already_pending"):
        propose_representative_designation(
            subject.user_id,
            caller=other_owner,
            session_evidence=world.evidence(other_owner),
            **propose,
        )
    confirm = {"ticket_ref": "TICKET-95", "reason": REASON}
    designation = confirm_representative_designation(
        subject.user_id,
        proposal.id,
        caller=world.security,
        session_evidence=world.evidence(world.security),
        **confirm,
    )
    replayed = confirm_representative_designation(
        subject.user_id,
        proposal.id,
        caller=world.security,
        session_evidence=world.evidence(world.security),
        **confirm,
    )
    assert replayed.replay is True and replayed.id == designation.id
    other_security, _ = world.platform.operator([P.SECURITY_RETENTION_HOLD_MANAGE])
    with _refused("proposal_already_confirmed"):
        confirm_representative_designation(
            subject.user_id,
            proposal.id,
            caller=other_security,
            session_evidence=world.evidence(other_security),
            **confirm,
        )
    world.designation = designation
    until = world.in_months(11)
    enrolment = world.enrol(world.approver, "PERSON-A", eligible=False, valid_until=until)
    replay = world.enrol(world.approver, "PERSON-A", eligible=False, valid_until=until)
    assert replay.replay is True and replay.id == enrolment.id
    with _refused("approver_already_enrolled"):
        world.enrol(world.approver, "PERSON-A", eligible=False, reason="another reason")
    revoked = _revoke(world, world.approver, world.evidence(world.security), "TICKET-96")
    replay_revocation = _revoke(world, world.approver, world.evidence(world.security), "TICKET-96")
    assert replay_revocation.entry.replay is True
    assert replay_revocation.entry.id == revoked.entry.id
    with _refused("entry_already_revoked"):
        _revoke(world, world.approver, world.evidence(world.security), "TICKET-97")
    with _refused("entry_already_revoked"):
        revoke_register_entry(
            world.approver.user_id,
            enrolment.id,
            operation="permission_grant_ledger.approver_revoke_by_representative",
            caller=world.representative,
            session_evidence=world.evidence(world.representative),
            ticket_ref="TICKET-96",
            reason=REASON,
        )
