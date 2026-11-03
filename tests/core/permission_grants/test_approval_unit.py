"""Pure parts of the permission grant ledger's approval mechanism (owner
decisions of 2026-11-02 and 2026-11-03): the request scope and its digest,
the enrolment state and approver eligibility over register entries, the
12-month arithmetic, and the closed set of refusal codes."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from saas_os.core.permission_grants import (
    APPROVAL_NOT_FOUND_CODES,
    APPROVAL_REFUSAL_CODES,
    EnrolmentState,
    InvalidLedgerRetentionRequestError,
    LedgerApprovalRecordNotFoundError,
    LedgerApprovalRefusedError,
    RegisterEntryView,
    approver_eligibility,
    enrolment_state,
    scope_digest,
)
from saas_os.core.permission_grants.approval_support import twelve_months_after
from saas_os.core.permission_grants.approvals import canonical_scope

NOW = datetime(2026, 11, 3, 12, tzinfo=UTC)
A, B, C = (uuid.UUID(int=n) for n in (3, 1, 2))


def _enrolment(
    subject: uuid.UUID,
    *,
    person: str = "P-1",
    eligible_from: datetime = NOW - timedelta(days=1),
    valid_until: datetime = NOW + timedelta(days=30),
    designation: uuid.UUID | None = None,
    entry_id: uuid.UUID | None = None,
) -> RegisterEntryView:
    return RegisterEntryView(
        id=entry_id or uuid.uuid4(),
        entry_type="approver_enrolment",
        subject_user_id=subject,
        recorded_by_user_id=uuid.uuid4(),
        designation_ref=None,
        natural_person_ref=person,
        verification_ref="V",
        authorisation_ref="A",
        ticket_ref="T",
        proposal_entry_id=None,
        authorised_by_entry_id=designation or uuid.uuid4(),
        revokes_entry_id=None,
        renews_entry_id=None,
        valid_until=valid_until,
        eligible_from=eligible_from,
        proposal_expires_at=None,
        recorded_at=eligible_from - timedelta(days=120),
        recorded_by_platform_audit_id=uuid.uuid4(),
    )


def _revocation(of: uuid.UUID) -> RegisterEntryView:
    entry = _enrolment(uuid.uuid4())
    return RegisterEntryView(
        **{**entry.__dict__, "entry_type": "approver_revocation", "revokes_entry_id": of}
    )


# --- scope -------------------------------------------------------------------------------


def test_the_scope_is_sorted_distinct_and_bounded() -> None:
    assert canonical_scope([A, B, C, A]) == (B, C, A)
    for bad in ([], "x", [str(A)], [A] * 1 + [uuid.uuid4() for _ in range(1000)]):
        with pytest.raises(InvalidLedgerRetentionRequestError):
            canonical_scope(bad)


def test_the_scope_digest_ignores_order_and_duplicates_and_sees_one_id_more() -> None:
    digest = scope_digest([A, B, C])
    assert digest == scope_digest([C, B, A, B])
    assert digest != scope_digest([A, B])
    expected = json.dumps([str(B), str(C), str(A)], separators=(",", ":"))
    assert digest == hashlib.sha256(expected.encode("ascii")).hexdigest()


# --- eligibility -------------------------------------------------------------------------


def test_an_enrolment_is_eligible_only_between_its_delay_and_its_end_unrevoked() -> None:
    entry = _enrolment(A)
    assert enrolment_state(entry, revoked_entry_ids=(), now=NOW) is EnrolmentState.ELIGIBLE
    waiting = _enrolment(A, eligible_from=NOW + timedelta(seconds=1))
    assert enrolment_state(waiting, revoked_entry_ids=(), now=NOW) is EnrolmentState.WAITING
    ended = _enrolment(A, valid_until=NOW)
    assert enrolment_state(ended, revoked_entry_ids=(), now=NOW) is EnrolmentState.EXPIRED
    assert enrolment_state(entry, revoked_entry_ids=[entry.id], now=NOW) is EnrolmentState.REVOKED
    assert entry.authorised_by_entry_id is not None
    assert (
        enrolment_state(entry, revoked_entry_ids=[entry.authorised_by_entry_id], now=NOW)
        is EnrolmentState.SUSPENDED
    )
    with pytest.raises(InvalidLedgerRetentionRequestError):
        enrolment_state(entry, revoked_entry_ids=(), now=datetime(2026, 11, 3))  # noqa: DTZ001


def test_approver_eligibility_reads_only_the_users_eligible_entries() -> None:
    mine = _enrolment(A)
    other = _enrolment(B)
    assert approver_eligibility([mine, other], A, NOW) == mine
    assert approver_eligibility([other], A, NOW) is None
    assert approver_eligibility([mine, _revocation(mine.id)], A, NOW) is None
    # Bootstrap or break-glass accounts have no entry: never eligible.
    assert approver_eligibility([], A, NOW) is None


def test_during_a_renewal_overlap_the_longer_eligible_entry_is_used() -> None:
    current = _enrolment(A, valid_until=NOW + timedelta(days=10))
    renewal_waiting = _enrolment(A, eligible_from=NOW + timedelta(days=50))
    assert approver_eligibility([current, renewal_waiting], A, NOW) == current
    renewal_ready = _enrolment(A, valid_until=NOW + timedelta(days=300))
    assert approver_eligibility([current, renewal_ready], A, NOW) == renewal_ready


def test_twelve_months_follow_postgresql_month_arithmetic() -> None:
    assert twelve_months_after(NOW) == NOW.replace(year=2027)
    leap = datetime(2028, 2, 29, 8, tzinfo=UTC)
    assert twelve_months_after(leap) == datetime(2029, 2, 28, 8, tzinfo=UTC)


# --- refusal codes -------------------------------------------------------------------------


def test_the_refusal_codes_are_a_closed_set() -> None:
    assert not APPROVAL_REFUSAL_CODES & APPROVAL_NOT_FOUND_CODES
    for code in APPROVAL_REFUSAL_CODES:
        assert LedgerApprovalRefusedError(code).code == code
    for code in APPROVAL_NOT_FOUND_CODES:
        assert LedgerApprovalRecordNotFoundError(code).code == code
    with pytest.raises(ValueError):
        LedgerApprovalRefusedError("deletion_enabled")
    with pytest.raises(ValueError):
        LedgerApprovalRecordNotFoundError("ledger_not_found")
