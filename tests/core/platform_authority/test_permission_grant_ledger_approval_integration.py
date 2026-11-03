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
    read_approver_eligibility,
    read_approver_register,
    read_permission_grant_ledger_deletion_requests,
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
