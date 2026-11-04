"""The approver eligibility register of the permission grant ledger (owner
decision 13: option A, 2026-11-02; detailed and made authenticated on
2026-11-03; `docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`, section
4.5).

**What it is for.** Separate accounts never prove separate people: a
platform owner can enrol a second OIDC account and grant it any permission
they hold. Eligibility to approve a deletion of expired ledger rows, or to
authorise its execution, therefore comes only from this append-only
register, in which a representative records that an independent,
out-of-band verification established a distinct natural person
(`natural_person_ref`, `verification_ref`, `authorisation_ref`: opaque
references to records kept outside SaaS OS, never personal data). They
are compared exactly, case included: one external record has one
spelling, and the register keeps it as given. Its
strength is procedural; it does not make separate accounts separate
people.

**Who writes what** (each an authenticated platform-admin act, a fresh
session with a multi-factor login, the subject named by the route's path,
one audit row in the same transaction; decision 6 of 2026-11-03):

- a platform owner (`platform.authority:manage`) **proposes** a
  representative whom the organisation's governing body designated
  (`designation_ref`); the proposal expires after 72 hours;
- an independent security operator (`platform.security_retention_hold:
  manage`, not `platform.authority:manage`; the one in-product identity
  the owner cannot create) **confirms** it, never the proposer or the
  subject. Neither alone can designate;
- a representative (an active designation, the report permission, not an
  authority holder) **enrols** an approver: never themselves, never an
  authority holder, hold manager or representative; eligible 120 days
  after it is recorded and for at most 12 months; one active enrolment per
  account and per natural person, except exactly one renewal;
- a representative or an independent security operator **revokes** an
  enrolment; a platform owner or an independent security operator
  **revokes** a designation, which suspends every enrolment it
  authorised. Revocation is immediate: in the same transaction it
  invalidates every outstanding approval and execution authorisation made
  by the affected approvers.

The database enforces the same rules in its insert trigger (migration
`c3f9e1a7b5d2`), refuses every `UPDATE` and `DELETE`, and requires each
entry's audit row. The runtime role can insert entries, so a holder of the
application credential can forge one (threat T6): detected, not prevented.

**Eligibility** (`approver_eligibility`, pure): an `approver_enrolment` of
the user, not revoked, whose designation is neither revoked nor expired
at `t`, with `eligible_from <= t < valid_until`. The callers add the live
permission checks (report held, `platform.authority:manage` not held).

**A designation's expiry suspends its enrolments at once** (owner
decision F-2, final closure of 2026-11-03, reversing the earlier choice
under which an enrolment outlived an expired designation). A new
designation revives none of them: the approver is enrolled again under it,
with fresh verification (a `verification_ref` that no suspended enrolment
of the same account or natural person carries) and its own 120-day delay.
Expiry is not an event, so nothing is invalidated when it passes:
approval, execution authorisation and execution each re-check eligibility
at their own time, so an approval or authorisation given earlier by such
an approver fails at its next use.
"""

from __future__ import annotations

import enum
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

from saas_os.core.authority import UserCaller
from saas_os.core.identity import User
from saas_os.core.permission_grants.approval_support import (
    ELIGIBILITY_DELAY,
    database_time,
    lock_register,
    refusals_recorded,
    refuse,
    same_act,
    twelve_months_after,
    validated_reference,
    validated_time,
    validated_uuid,
    verify_session,
)
from saas_os.core.permission_grants.errors import (
    InvalidLedgerRetentionRequestError,
    LedgerApprovalRecordNotFoundError,
)
from saas_os.core.permission_grants.models import (
    REGISTER_DESIGNATION,
    REGISTER_DESIGNATION_REVOCATION,
    REGISTER_ENROLMENT,
    REGISTER_ENROLMENT_REVOCATION,
    REGISTER_PROPOSAL,
    ApproverRegisterEntry,
    LedgerDeletionApproval,
    LedgerExecutionAuthorization,
)
from saas_os.core.platform_authority import (
    DEFAULT_OVERSIGHT_PAGE_SIZE,
    MAX_OVERSIGHT_PAGE_SIZE,
    OversightOutcome,
    PlatformPermission,
    authorize_platform_caller,
    platform_change_session,
    platform_operation,
    record_platform_event_in_transaction,
    run_oversight_read,
    validate_page_request,
    validate_reason,
)
from saas_os.core.platform_authority.operations import (
    PERMISSION_GRANT_LEDGER_APPROVER_ELIGIBILITY_READ,
    PERMISSION_GRANT_LEDGER_APPROVER_ENROL,
    PERMISSION_GRANT_LEDGER_APPROVER_REGISTER_READ,
    PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_REPRESENTATIVE,
    PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_SECURITY,
    PERMISSION_GRANT_LEDGER_REPRESENTATIVE_CONFIRM,
    PERMISSION_GRANT_LEDGER_REPRESENTATIVE_PROPOSE,
    PERMISSION_GRANT_LEDGER_REPRESENTATIVE_REVOKE_BY_OWNER,
    PERMISSION_GRANT_LEDGER_REPRESENTATIVE_REVOKE_BY_SECURITY,
)
from saas_os.core.platform_authority.retention_evidence import (
    holds_platform_permission,
    provenance_linked,
)
from saas_os.infra.db import Session, select, update
from saas_os.infra.db import now as db_now

_TARGET = "permission_grant_ledger_approver_register"
P = PlatformPermission

# Which kind of entry each revocation revokes, by operation.
_REVOCATIONS: dict[str, tuple[str, str]] = {
    PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_REPRESENTATIVE: (
        REGISTER_ENROLMENT,
        REGISTER_ENROLMENT_REVOCATION,
    ),
    PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_SECURITY: (
        REGISTER_ENROLMENT,
        REGISTER_ENROLMENT_REVOCATION,
    ),
    PERMISSION_GRANT_LEDGER_REPRESENTATIVE_REVOKE_BY_OWNER: (
        REGISTER_DESIGNATION,
        REGISTER_DESIGNATION_REVOCATION,
    ),
    PERMISSION_GRANT_LEDGER_REPRESENTATIVE_REVOKE_BY_SECURITY: (
        REGISTER_DESIGNATION,
        REGISTER_DESIGNATION_REVOCATION,
    ),
}


# --- views ----------------------------------------------------------------------------


@dataclass(frozen=True)
class RegisterEntryView:
    """One register entry: ids, opaque references and times only."""

    id: uuid.UUID
    entry_type: str
    subject_user_id: uuid.UUID
    recorded_by_user_id: uuid.UUID
    designation_ref: str | None
    natural_person_ref: str | None
    verification_ref: str | None
    authorisation_ref: str | None
    ticket_ref: str
    proposal_entry_id: uuid.UUID | None
    authorised_by_entry_id: uuid.UUID | None
    revokes_entry_id: uuid.UUID | None
    renews_entry_id: uuid.UUID | None
    valid_until: datetime | None
    eligible_from: datetime | None
    proposal_expires_at: datetime | None
    recorded_at: datetime
    recorded_by_platform_audit_id: uuid.UUID
    replay: bool = False


def _view(entry: ApproverRegisterEntry, *, replay: bool = False) -> RegisterEntryView:
    return RegisterEntryView(
        id=entry.id,
        entry_type=entry.entry_type,
        subject_user_id=entry.subject_user_id,
        recorded_by_user_id=entry.recorded_by_user_id,
        designation_ref=entry.designation_ref,
        natural_person_ref=entry.natural_person_ref,
        verification_ref=entry.verification_ref,
        authorisation_ref=entry.authorisation_ref,
        ticket_ref=entry.ticket_ref,
        proposal_entry_id=entry.proposal_entry_id,
        authorised_by_entry_id=entry.authorised_by_entry_id,
        revokes_entry_id=entry.revokes_entry_id,
        renews_entry_id=entry.renews_entry_id,
        valid_until=entry.valid_until,
        eligible_from=entry.eligible_from,
        proposal_expires_at=entry.proposal_expires_at,
        recorded_at=entry.recorded_at,
        recorded_by_platform_audit_id=entry.recorded_by_platform_audit_id,
        replay=replay,
    )


@dataclass(frozen=True)
class RegisterPage:
    entries: tuple[RegisterEntryView, ...]
    next_cursor: uuid.UUID | None


class EnrolmentState(enum.StrEnum):
    """The state of one approver enrolment at a time `t`, from the register
    alone. Only `ELIGIBLE` lets its subject approve or authorise."""

    ELIGIBLE = "eligible"
    WAITING = "waiting"  # before `eligible_from` (the 120-day delay)
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"  # its designation was revoked or has expired


@dataclass(frozen=True)
class EnrolmentEligibility:
    entry_id: uuid.UUID
    subject_user_id: uuid.UUID
    natural_person_ref: str
    state: EnrolmentState
    eligible_from: datetime
    valid_until: datetime
    authorised_by_entry_id: uuid.UUID


@dataclass(frozen=True)
class EligibilityPage:
    as_of: datetime
    approvers: tuple[EnrolmentEligibility, ...]
    next_cursor: uuid.UUID | None


# --- the pure decision -----------------------------------------------------------------


def enrolment_state(
    enrolment: RegisterEntryView,
    *,
    revoked_entry_ids: Iterable[uuid.UUID],
    designation_valid_until: datetime | None,
    now: datetime,
) -> EnrolmentState:
    """The state of `enrolment` at `now`, given the ids of every revoked
    register entry and the `valid_until` of the designation that authorised
    it (`None` when that designation is unknown, which suspends: fail
    closed). A revoked or expired designation suspends the enrolment
    (decision F-2). Pure."""
    validated_time(now, "now")
    if enrolment.entry_type != REGISTER_ENROLMENT:
        raise InvalidLedgerRetentionRequestError("an enrolment state is that of an enrolment.")
    assert enrolment.eligible_from is not None and enrolment.valid_until is not None
    revoked = set(revoked_entry_ids)
    if enrolment.id in revoked:
        return EnrolmentState.REVOKED
    if (
        enrolment.authorised_by_entry_id in revoked
        or designation_valid_until is None
        or now >= validated_time(designation_valid_until, "designation_valid_until")
    ):
        return EnrolmentState.SUSPENDED
    if now >= enrolment.valid_until:
        return EnrolmentState.EXPIRED
    if now < enrolment.eligible_from:
        return EnrolmentState.WAITING
    return EnrolmentState.ELIGIBLE


def approver_eligibility(
    entries: Sequence[RegisterEntryView], user_id: uuid.UUID, now: datetime
) -> RegisterEntryView | None:
    """The enrolment that makes `user_id` eligible at `now`, or `None`.
    `entries` must hold every enrolment of the user, the designations that
    authorised them, and every revocation that names one of them or their
    designations; an enrolment whose designation is missing is suspended
    (fail closed). With an overlapping renewal, the eligible entry that
    lasts longer. Pure."""
    revoked = {e.revokes_entry_id for e in entries if e.revokes_entry_id is not None}
    designations = {e.id: e.valid_until for e in entries if e.entry_type == REGISTER_DESIGNATION}
    eligible = [
        e
        for e in entries
        if e.entry_type == REGISTER_ENROLMENT
        and e.subject_user_id == user_id
        and enrolment_state(
            e,
            revoked_entry_ids=revoked,
            designation_valid_until=(
                designations.get(e.authorised_by_entry_id)
                if e.authorised_by_entry_id is not None
                else None
            ),
            now=now,
        )
        is EnrolmentState.ELIGIBLE
    ]
    if not eligible:
        return None
    return max(eligible, key=lambda e: (e.valid_until, str(e.id)))


# --- database reads (no tenant bound) --------------------------------------------------


def _revoked_ids(session: Session, entry_ids: Iterable[uuid.UUID | None]) -> set[uuid.UUID]:
    ids = sorted({i for i in entry_ids if i is not None})
    if not ids:
        return set()
    return {
        row
        for row in session.execute(
            select(ApproverRegisterEntry.revokes_entry_id).where(
                ApproverRegisterEntry.revokes_entry_id.in_(ids)
            )
        ).scalars()
        if row is not None
    }


def _designation_validity(
    session: Session, designation_ids: Iterable[uuid.UUID | None]
) -> dict[uuid.UUID, datetime]:
    """The `valid_until` of each named designation that exists."""
    ids = sorted({i for i in designation_ids if i is not None})
    if not ids:
        return {}
    rows = session.execute(
        select(ApproverRegisterEntry.id, ApproverRegisterEntry.valid_until).where(
            ApproverRegisterEntry.id.in_(ids),
            ApproverRegisterEntry.entry_type == REGISTER_DESIGNATION,
        )
    ).all()
    return {key: until for key, until in rows if until is not None}


def _designation_live(
    designation_id: uuid.UUID | None,
    validity: dict[uuid.UUID, datetime],
    revoked: set[uuid.UUID],
    at: datetime,
) -> bool:
    """Whether the designation exists, is unrevoked and is unexpired at
    `at` (an enrolment under any other designation is suspended, F-2)."""
    if designation_id is None or designation_id in revoked:
        return False
    until = validity.get(designation_id)
    return until is not None and at < until


def _entries_for_eligibility(session: Session, user_id: uuid.UUID) -> list[RegisterEntryView]:
    enrolments = list(
        session.execute(
            select(ApproverRegisterEntry).where(
                ApproverRegisterEntry.entry_type == REGISTER_ENROLMENT,
                ApproverRegisterEntry.subject_user_id == user_id,
            )
        ).scalars()
    )
    designation_ids = sorted(
        {e.authorised_by_entry_id for e in enrolments if e.authorised_by_entry_id is not None}
    )
    designations = (
        list(
            session.execute(
                select(ApproverRegisterEntry).where(
                    ApproverRegisterEntry.id.in_(designation_ids),
                    ApproverRegisterEntry.entry_type == REGISTER_DESIGNATION,
                )
            ).scalars()
        )
        if designation_ids
        else []
    )
    linked = {e.id for e in enrolments} | set(designation_ids)
    revocations = (
        list(
            session.execute(
                select(ApproverRegisterEntry).where(
                    ApproverRegisterEntry.revokes_entry_id.in_(sorted(linked))
                )
            ).scalars()
        )
        if linked
        else []
    )
    return [_view(e) for e in [*enrolments, *designations, *revocations]]


def eligible_enrolment(
    session: Session, user_id: uuid.UUID, at: datetime
) -> RegisterEntryView | None:
    """The register entry that makes `user_id` eligible at `at` (decided by
    `approver_eligibility`), or `None`."""
    return approver_eligibility(_entries_for_eligibility(session, user_id), user_id, at)


def _active_enrolments(
    session: Session,
    *,
    subject: uuid.UUID | None = None,
    person: str | None = None,
    at: datetime,
) -> list[ApproverRegisterEntry]:
    """Enrolments that are eligible or still waiting at `at`: unexpired,
    unrevoked, their designation unrevoked and unexpired (F-2: an
    enrolment under an expired designation is suspended, not active)."""
    query = select(ApproverRegisterEntry).where(
        ApproverRegisterEntry.entry_type == REGISTER_ENROLMENT,
        ApproverRegisterEntry.valid_until > at,
    )
    if subject is not None:
        query = query.where(ApproverRegisterEntry.subject_user_id == subject)
    if person is not None:
        query = query.where(ApproverRegisterEntry.natural_person_ref == person)
    found = list(session.execute(query).scalars())
    revoked = _revoked_ids(
        session, [e.id for e in found] + [e.authorised_by_entry_id for e in found]
    )
    validity = _designation_validity(session, [e.authorised_by_entry_id for e in found])
    return [
        e
        for e in found
        if e.id not in revoked
        and _designation_live(e.authorised_by_entry_id, validity, revoked, at)
    ]


def _suspended_verification_reused(
    session: Session, *, subject: uuid.UUID, person: str, verification: str, at: datetime
) -> bool:
    """Whether an enrolment of `subject` or of `person` whose designation
    expired or was revoked carries `verification`: a new designation needs
    fresh verification (F-2), never the reference of a suspended
    enrolment."""
    found = list(
        session.execute(
            select(ApproverRegisterEntry).where(
                ApproverRegisterEntry.entry_type == REGISTER_ENROLMENT,
                ApproverRegisterEntry.verification_ref == verification,
                (ApproverRegisterEntry.subject_user_id == subject)
                | (ApproverRegisterEntry.natural_person_ref == person),
            )
        ).scalars()
    )
    if not found:
        return False
    designations = [e.authorised_by_entry_id for e in found]
    revoked = _revoked_ids(session, designations)
    validity = _designation_validity(session, designations)
    return any(
        not _designation_live(e.authorised_by_entry_id, validity, revoked, at) for e in found
    )


def active_designation(
    session: Session, user_id: uuid.UUID, at: datetime
) -> ApproverRegisterEntry | None:
    """The user's unrevoked designation valid at `at` (the one lasting
    longest when there are several), or `None`."""
    found = list(
        session.execute(
            select(ApproverRegisterEntry).where(
                ApproverRegisterEntry.entry_type == REGISTER_DESIGNATION,
                ApproverRegisterEntry.subject_user_id == user_id,
                ApproverRegisterEntry.valid_until > at,
            )
        ).scalars()
    )
    revoked = _revoked_ids(session, [e.id for e in found])
    live = [e for e in found if e.id not in revoked]
    if not live:
        return None
    return max(live, key=lambda e: (e.valid_until, str(e.id)))


def _user_exists(session: Session, user_id: uuid.UUID) -> bool:
    return session.execute(select(User.id).where(User.id == user_id)).first() is not None


def _entry(
    session: Session, entry_id: uuid.UUID, entry_type: str, subject: uuid.UUID
) -> ApproverRegisterEntry:
    entry = session.get(ApproverRegisterEntry, entry_id)
    if entry is None or entry.entry_type != entry_type or entry.subject_user_id != subject:
        raise LedgerApprovalRecordNotFoundError("register_entry_not_found")
    return entry


def _holds(session: Session, user_id: uuid.UUID, permission: PlatformPermission) -> bool:
    return holds_platform_permission(session, user_id, permission)


def _write(
    session: Session,
    *,
    caller: UserCaller,
    operation: str,
    reason: str,
    entry: ApproverRegisterEntry,
    extra: dict[str, object],
) -> ApproverRegisterEntry:
    """Insert `entry` and its audit row (pre-chosen id) in this transaction."""
    session.add(entry)
    session.flush()
    session.refresh(entry)
    metadata: dict[str, object] = {
        "entry_id": str(entry.id),
        "entry_type": entry.entry_type,
        "subject_user_id": str(entry.subject_user_id),
        "ticket_ref": entry.ticket_ref,
    }
    for name in (
        "designation_ref",
        "natural_person_ref",
        "verification_ref",
        "authorisation_ref",
    ):
        value = getattr(entry, name)
        if value is not None:
            metadata[name] = value
    for name in (
        "proposal_entry_id",
        "authorised_by_entry_id",
        "revokes_entry_id",
        "renews_entry_id",
    ):
        value = getattr(entry, name)
        if value is not None:
            metadata[name] = str(value)
    for name in ("valid_until", "eligible_from", "proposal_expires_at"):
        value = getattr(entry, name)
        if value is not None:
            metadata[name] = value.isoformat()
    metadata.update(extra)
    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(operation).audit_action,
        target_type=_TARGET,
        target_id=str(entry.id),
        reason=reason,
        metadata=metadata,
        entry_id=entry.recorded_by_platform_audit_id,
    )
    return entry


def _replay(
    session: Session,
    *,
    caller: UserCaller,
    operation: str,
    reason: str,
    entry: ApproverRegisterEntry,
    extra: dict[str, object],
) -> RegisterEntryView:
    """The same caller retried the same write: the existing entry, and an
    audit row saying so."""
    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(operation).audit_action,
        target_type=_TARGET,
        target_id=str(entry.id),
        reason=reason,
        metadata={"entry_id": str(entry.id), "replay": True, **extra},
    )
    return _view(entry, replay=True)


def _check_reason_and_ticket(reason: object, ticket_ref: object) -> tuple[str, str]:
    return validate_reason(reason), validated_reference(ticket_ref, "ticket_ref")


def _validity(valid_until: object, at: datetime, *, after: datetime) -> datetime:
    value = validated_time(valid_until, "valid_until")
    if value <= after or value > twelve_months_after(at):
        raise InvalidLedgerRetentionRequestError(
            "valid_until must be after the start of eligibility and at most 12 months away."
        )
    return value


# --- writes -----------------------------------------------------------------------------


def propose_representative_designation(
    subject_user_id: uuid.UUID,
    *,
    caller: object,
    session_evidence: object,
    designation_ref: str,
    ticket_ref: str,
    valid_until: datetime,
    reason: str,
) -> RegisterEntryView:
    """A platform owner proposes `subject_user_id` as the representative the
    governing body designated (`designation_ref`). Unconfirmed, it expires
    after 72 hours. It designates nobody on its own."""
    operation = PERMISSION_GRANT_LEDGER_REPRESENTATIVE_PROPOSE
    with refusals_recorded(caller, operation, _TARGET):
        subject = validated_uuid(subject_user_id, "subject_user_id")
        reason, ticket = _check_reason_and_ticket(reason, ticket_ref)
        designation = validated_reference(designation_ref, "designation_ref")
        validated_time(valid_until, "valid_until")
        with platform_change_session(caller, operation) as session:
            authorize_platform_caller(caller, session=session, operation=operation)
            assert isinstance(caller, UserCaller)
            verified = verify_session(session, caller, session_evidence, require_multi_factor=True)
            lock_register(session, shared=False)
            at = database_time(session)
            until = _validity(valid_until, at, after=at)
            if not _user_exists(session, subject):
                raise LedgerApprovalRecordNotFoundError("subject_not_found")
            if subject == caller.user_id:
                raise refuse("register_subject_is_caller")
            pending = session.execute(
                select(ApproverRegisterEntry).where(
                    ApproverRegisterEntry.entry_type == REGISTER_PROPOSAL,
                    ApproverRegisterEntry.subject_user_id == subject,
                    ApproverRegisterEntry.recorded_by_user_id == caller.user_id,
                    ApproverRegisterEntry.proposal_expires_at > at,
                    ApproverRegisterEntry.designation_ref == designation,
                    ApproverRegisterEntry.ticket_ref == ticket,
                    ApproverRegisterEntry.valid_until == until,
                )
            ).scalars()
            for existing in pending:
                confirmed = session.execute(
                    select(ApproverRegisterEntry.id).where(
                        ApproverRegisterEntry.proposal_entry_id == existing.id
                    )
                ).first()
                if confirmed is None and same_act(
                    session,
                    existing.recorded_by_platform_audit_id,
                    caller,
                    reason,
                    platform_operation(operation).audit_action,
                ):
                    return _replay(
                        session,
                        caller=caller,
                        operation=operation,
                        reason=reason,
                        entry=existing,
                        extra=verified.metadata(),
                    )
            # Idempotent recovery (design 3.1): while a proposal for this
            # subject is pending, anything but its identical retry is refused.
            confirmed = select(ApproverRegisterEntry.proposal_entry_id).where(
                ApproverRegisterEntry.proposal_entry_id.is_not(None)
            )
            outstanding = session.execute(
                select(ApproverRegisterEntry.id)
                .where(
                    ApproverRegisterEntry.entry_type == REGISTER_PROPOSAL,
                    ApproverRegisterEntry.subject_user_id == subject,
                    ApproverRegisterEntry.proposal_expires_at > at,
                    ApproverRegisterEntry.id.not_in(confirmed),
                )
                .limit(1)
            ).first()
            if outstanding is not None:
                raise refuse("proposal_already_pending")
            if _holds(session, subject, P.AUTHORITY_MANAGE):
                raise refuse("subject_holds_authority_manage")
            if _active_enrolments(session, subject=subject, at=at):
                raise refuse("subject_is_approver")
            entry = ApproverRegisterEntry(
                id=uuid.uuid4(),
                entry_type=REGISTER_PROPOSAL,
                subject_user_id=subject,
                recorded_by_user_id=caller.user_id,
                designation_ref=designation,
                ticket_ref=ticket,
                valid_until=until,
                recorded_by_platform_audit_id=uuid.uuid4(),
            )
            written = _write(
                session,
                caller=caller,
                operation=operation,
                reason=reason,
                entry=entry,
                extra=verified.metadata(),
            )
            return _view(written)
    raise AssertionError("unreachable")  # pragma: no cover


def confirm_representative_designation(
    subject_user_id: uuid.UUID,
    proposal_id: uuid.UUID,
    *,
    caller: object,
    session_evidence: object,
    ticket_ref: str,
    reason: str,
) -> RegisterEntryView:
    """An independent security operator confirms a proposal: the
    designation, with the proposal's `designation_ref` and `valid_until`.
    Never the proposer, never the subject, never a holder of
    `platform.authority:manage`."""
    operation = PERMISSION_GRANT_LEDGER_REPRESENTATIVE_CONFIRM
    with refusals_recorded(caller, operation, _TARGET):
        subject = validated_uuid(subject_user_id, "subject_user_id")
        proposal_key = validated_uuid(proposal_id, "proposal_id")
        reason, ticket = _check_reason_and_ticket(reason, ticket_ref)
        with platform_change_session(caller, operation) as session:
            authorize_platform_caller(caller, session=session, operation=operation)
            assert isinstance(caller, UserCaller)
            verified = verify_session(session, caller, session_evidence, require_multi_factor=True)
            lock_register(session, shared=False)
            at = database_time(session)
            proposal = _entry(session, proposal_key, REGISTER_PROPOSAL, subject)
            if _holds(session, caller.user_id, P.AUTHORITY_MANAGE):
                raise refuse("party_holds_authority_manage")
            existing = session.execute(
                select(ApproverRegisterEntry).where(
                    ApproverRegisterEntry.proposal_entry_id == proposal.id
                )
            ).scalar_one_or_none()
            if existing is not None:
                if (
                    existing.recorded_by_user_id == caller.user_id
                    and existing.ticket_ref == ticket
                    and same_act(
                        session,
                        existing.recorded_by_platform_audit_id,
                        caller,
                        reason,
                        platform_operation(operation).audit_action,
                    )
                ):
                    return _replay(
                        session,
                        caller=caller,
                        operation=operation,
                        reason=reason,
                        entry=existing,
                        extra=verified.metadata(),
                    )
                raise refuse("proposal_already_confirmed")
            assert proposal.proposal_expires_at is not None and proposal.valid_until is not None
            if at >= proposal.proposal_expires_at or proposal.valid_until <= at:
                raise refuse("proposal_expired")
            if caller.user_id == subject:
                raise refuse("register_subject_is_caller")
            if caller.user_id == proposal.recorded_by_user_id:
                raise refuse("confirmer_is_proposer")
            if _holds(session, subject, P.AUTHORITY_MANAGE):
                raise refuse("subject_holds_authority_manage")
            if _active_enrolments(session, subject=subject, at=at):
                raise refuse("subject_is_approver")
            entry = ApproverRegisterEntry(
                id=uuid.uuid4(),
                entry_type=REGISTER_DESIGNATION,
                subject_user_id=subject,
                recorded_by_user_id=caller.user_id,
                designation_ref=proposal.designation_ref,
                ticket_ref=ticket,
                proposal_entry_id=proposal.id,
                valid_until=proposal.valid_until,
                recorded_by_platform_audit_id=uuid.uuid4(),
            )
            written = _write(
                session,
                caller=caller,
                operation=operation,
                reason=reason,
                entry=entry,
                extra=verified.metadata(),
            )
            return _view(written)
    raise AssertionError("unreachable")  # pragma: no cover


def enrol_approver(
    subject_user_id: uuid.UUID,
    *,
    caller: object,
    session_evidence: object,
    natural_person_ref: str,
    verification_ref: str,
    authorisation_ref: str,
    ticket_ref: str,
    valid_until: datetime,
    reason: str,
    renews_entry_id: uuid.UUID | None = None,
) -> RegisterEntryView:
    """A representative enrols `subject_user_id` as an approver after an
    independent verification that the subject is a distinct natural person.
    Eligible from 120 days after this write, until `valid_until` (at most
    12 months)."""
    operation = PERMISSION_GRANT_LEDGER_APPROVER_ENROL
    with refusals_recorded(caller, operation, _TARGET):
        subject = validated_uuid(subject_user_id, "subject_user_id")
        reason, ticket = _check_reason_and_ticket(reason, ticket_ref)
        person = validated_reference(natural_person_ref, "natural_person_ref")
        verification = validated_reference(verification_ref, "verification_ref")
        authorisation = validated_reference(authorisation_ref, "authorisation_ref")
        validated_time(valid_until, "valid_until")
        if renews_entry_id is not None:
            validated_uuid(renews_entry_id, "renews_entry_id")
        with platform_change_session(caller, operation) as session:
            authorize_platform_caller(caller, session=session, operation=operation)
            assert isinstance(caller, UserCaller)
            verified = verify_session(session, caller, session_evidence, require_multi_factor=True)
            lock_register(session, shared=False)
            at = database_time(session)
            until = _validity(valid_until, at, after=at + ELIGIBILITY_DELAY)
            if _holds(session, caller.user_id, P.AUTHORITY_MANAGE):
                raise refuse("party_holds_authority_manage")
            designation = active_designation(session, caller.user_id, at)
            if designation is None:
                raise refuse("not_a_representative")
            if not _user_exists(session, subject):
                raise LedgerApprovalRecordNotFoundError("subject_not_found")
            if subject == caller.user_id:
                raise refuse("register_subject_is_caller")
            for existing in _active_enrolments(session, subject=subject, at=at):
                if (
                    existing.recorded_by_user_id == caller.user_id
                    and (existing.natural_person_ref, existing.verification_ref)
                    == (person, verification)
                    and (existing.authorisation_ref, existing.ticket_ref) == (authorisation, ticket)
                    and existing.valid_until == until
                    and existing.renews_entry_id == renews_entry_id
                    and same_act(
                        session,
                        existing.recorded_by_platform_audit_id,
                        caller,
                        reason,
                        platform_operation(operation).audit_action,
                    )
                ):
                    return _replay(
                        session,
                        caller=caller,
                        operation=operation,
                        reason=reason,
                        entry=existing,
                        extra=verified.metadata(),
                    )
            if _holds(session, subject, P.AUTHORITY_MANAGE):
                raise refuse("subject_holds_authority_manage")
            if _holds(session, subject, P.SECURITY_RETENTION_HOLD_MANAGE):
                raise refuse("subject_holds_hold_manage")
            if active_designation(session, subject, at) is not None:
                raise refuse("subject_is_representative")
            # Defence in depth, as between approver and requester: the
            # representative never enrols someone whose operator they
            # enrolled or to whom they granted the report permission.
            if provenance_linked(session, caller.user_id, subject):
                raise refuse("subject_linked_to_representative")
            own_person = session.execute(
                select(ApproverRegisterEntry.id).where(
                    ApproverRegisterEntry.entry_type == REGISTER_ENROLMENT,
                    ApproverRegisterEntry.subject_user_id == caller.user_id,
                    ApproverRegisterEntry.natural_person_ref == person,
                )
            ).first()
            if own_person is not None:
                raise refuse("natural_person_already_enrolled")
            by_subject = [
                e
                for e in _active_enrolments(session, subject=subject, at=at)
                if e.id != renews_entry_id
            ]
            if by_subject:
                raise refuse("approver_already_enrolled")
            by_person = [
                e
                for e in _active_enrolments(session, person=person, at=at)
                if e.id != renews_entry_id
            ]
            if by_person:
                raise refuse("natural_person_already_enrolled")
            if _suspended_verification_reused(
                session, subject=subject, person=person, verification=verification, at=at
            ):
                raise refuse("verification_not_fresh")
            if renews_entry_id is not None:
                renewed = session.get(ApproverRegisterEntry, renews_entry_id)
                current = {e.id for e in _active_enrolments(session, subject=subject, at=at)}
                already = session.execute(
                    select(ApproverRegisterEntry.id).where(
                        ApproverRegisterEntry.renews_entry_id == renews_entry_id
                    )
                ).first()
                if (
                    renewed is None
                    or renewed.id not in current
                    or renewed.natural_person_ref != person
                    or already is not None
                ):
                    raise refuse("invalid_renewal")
            entry = ApproverRegisterEntry(
                id=uuid.uuid4(),
                entry_type=REGISTER_ENROLMENT,
                subject_user_id=subject,
                recorded_by_user_id=caller.user_id,
                natural_person_ref=person,
                verification_ref=verification,
                authorisation_ref=authorisation,
                ticket_ref=ticket,
                authorised_by_entry_id=designation.id,
                renews_entry_id=renews_entry_id,
                valid_until=until,
                recorded_by_platform_audit_id=uuid.uuid4(),
            )
            written = _write(
                session,
                caller=caller,
                operation=operation,
                reason=reason,
                entry=entry,
                extra=verified.metadata(),
            )
            return _view(written)
    raise AssertionError("unreachable")  # pragma: no cover


@dataclass(frozen=True)
class RevocationResult:
    """A revocation entry and what it invalidated in its own transaction."""

    entry: RegisterEntryView
    suspended_enrolments: int
    invalidated_approvals: int
    invalidated_execution_authorizations: int


def _invalidate(
    session: Session, users: Sequence[uuid.UUID], audit_id: uuid.UUID
) -> tuple[int, int]:
    """Invalidate every outstanding approval and execution authorisation
    made by `users`, naming the revocation's audit row (decision 2)."""
    if not users:
        return 0, 0
    approvals = (
        session.execute(
            update(LedgerDeletionApproval)
            .where(
                LedgerDeletionApproval.approved_by_user_id.in_(sorted(users)),
                LedgerDeletionApproval.consumed_at.is_(None),
                LedgerDeletionApproval.invalidated_at.is_(None),
                LedgerDeletionApproval.expires_at > db_now(),
            )
            .values(invalidated_at=db_now(), invalidated_by_platform_audit_id=audit_id)
            .returning(LedgerDeletionApproval.id)
        )
        .scalars()
        .all()
    )
    authorizations = (
        session.execute(
            update(LedgerExecutionAuthorization)
            .where(
                LedgerExecutionAuthorization.authorized_by_user_id.in_(sorted(users)),
                LedgerExecutionAuthorization.consumed_at.is_(None),
                LedgerExecutionAuthorization.invalidated_at.is_(None),
                LedgerExecutionAuthorization.expires_at > db_now(),
            )
            .values(invalidated_at=db_now(), invalidated_by_platform_audit_id=audit_id)
            .returning(LedgerExecutionAuthorization.id)
        )
        .scalars()
        .all()
    )
    return len(approvals), len(authorizations)


def revoke_register_entry(
    subject_user_id: uuid.UUID,
    entry_id: uuid.UUID,
    *,
    operation: str,
    caller: object,
    session_evidence: object,
    ticket_ref: str,
    reason: str,
) -> RevocationResult:
    """Revoke an approver enrolment or a representative designation. The
    operation names who revokes: a representative or an independent
    security operator (an enrolment); a platform owner or an independent
    security operator (a designation). Immediate: in the same transaction
    every outstanding approval and execution authorisation of the affected
    approvers is invalidated (a designation suspends every enrolment it
    authorised)."""
    if operation not in _REVOCATIONS:
        raise InvalidLedgerRetentionRequestError("not a register revocation operation.")
    revoked_kind, revocation_kind = _REVOCATIONS[operation]
    with refusals_recorded(caller, operation, _TARGET):
        subject = validated_uuid(subject_user_id, "subject_user_id")
        target_id = validated_uuid(entry_id, "entry_id")
        reason, ticket = _check_reason_and_ticket(reason, ticket_ref)
        with platform_change_session(caller, operation) as session:
            authorize_platform_caller(caller, session=session, operation=operation)
            assert isinstance(caller, UserCaller)
            verified = verify_session(session, caller, session_evidence, require_multi_factor=True)
            lock_register(session, shared=False)
            at = database_time(session)
            target = _entry(session, target_id, revoked_kind, subject)
            if operation != PERMISSION_GRANT_LEDGER_REPRESENTATIVE_REVOKE_BY_OWNER and _holds(
                session, caller.user_id, P.AUTHORITY_MANAGE
            ):
                raise refuse("party_holds_authority_manage")
            if operation == PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_REPRESENTATIVE and (
                active_designation(session, caller.user_id, at) is None
            ):
                raise refuse("not_a_representative")
            existing = session.execute(
                select(ApproverRegisterEntry).where(
                    ApproverRegisterEntry.revokes_entry_id == target.id
                )
            ).scalar_one_or_none()
            if existing is not None:
                if existing.ticket_ref == ticket and same_act(
                    session,
                    existing.recorded_by_platform_audit_id,
                    caller,
                    reason,
                    platform_operation(operation).audit_action,
                ):
                    view = _replay(
                        session,
                        caller=caller,
                        operation=operation,
                        reason=reason,
                        entry=existing,
                        extra=verified.metadata(),
                    )
                    return RevocationResult(view, 0, 0, 0)
                raise refuse("entry_already_revoked")
            if revoked_kind == REGISTER_ENROLMENT:
                suspended: list[ApproverRegisterEntry] = []
                affected = [target.subject_user_id]
            else:
                suspended = _active_enrolments_of_designation(session, target.id, at)
                affected = sorted({e.subject_user_id for e in suspended})
            audit_id = uuid.uuid4()
            entry = ApproverRegisterEntry(
                id=uuid.uuid4(),
                entry_type=revocation_kind,
                subject_user_id=subject,
                recorded_by_user_id=caller.user_id,
                ticket_ref=ticket,
                revokes_entry_id=target.id,
                recorded_by_platform_audit_id=audit_id,
            )
            # The invalidation names the revocation's audit row, written below
            # in the same transaction (the deferred check sees both at commit).
            approvals, authorizations = _invalidate(session, affected, audit_id)
            written = _write(
                session,
                caller=caller,
                operation=operation,
                reason=reason,
                entry=entry,
                extra={
                    **verified.metadata(),
                    "suspended_enrolments": len(suspended),
                    "invalidated_approvals": approvals,
                    "invalidated_execution_authorizations": authorizations,
                },
            )
            return RevocationResult(_view(written), len(suspended), approvals, authorizations)
    raise AssertionError("unreachable")  # pragma: no cover


def _active_enrolments_of_designation(
    session: Session, designation_id: uuid.UUID, at: datetime
) -> list[ApproverRegisterEntry]:
    found = list(
        session.execute(
            select(ApproverRegisterEntry).where(
                ApproverRegisterEntry.entry_type == REGISTER_ENROLMENT,
                ApproverRegisterEntry.authorised_by_entry_id == designation_id,
                ApproverRegisterEntry.valid_until > at,
            )
        ).scalars()
    )
    revoked = _revoked_ids(session, [e.id for e in found])
    return [e for e in found if e.id not in revoked]


# --- reads (R10, R11; `platform.audit:read`) ---------------------------------------------


def read_approver_register(
    *,
    caller: object,
    subject_user_id: uuid.UUID | None = None,
    entry_type: str | None = None,
    cursor: uuid.UUID | None = None,
    limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE,
) -> RegisterPage:
    """The register, in id order (the independent reviewer's export)."""
    validate_page_request(cursor, limit, maximum=MAX_OVERSIGHT_PAGE_SIZE)
    if subject_user_id is not None:
        validated_uuid(subject_user_id, "subject_user_id")
    if entry_type is not None and entry_type not in {
        REGISTER_PROPOSAL,
        REGISTER_DESIGNATION,
        REGISTER_DESIGNATION_REVOCATION,
        REGISTER_ENROLMENT,
        REGISTER_ENROLMENT_REVOCATION,
    }:
        raise InvalidLedgerRetentionRequestError("unknown entry_type.")

    def read(session: Session) -> OversightOutcome[RegisterPage]:
        query = select(ApproverRegisterEntry).order_by(ApproverRegisterEntry.id).limit(limit + 1)
        if cursor is not None:
            query = query.where(ApproverRegisterEntry.id > cursor)
        if subject_user_id is not None:
            query = query.where(ApproverRegisterEntry.subject_user_id == subject_user_id)
        if entry_type is not None:
            query = query.where(ApproverRegisterEntry.entry_type == entry_type)
        rows = list(session.execute(query).scalars())
        page = rows[:limit]
        value = RegisterPage(
            tuple(_view(e) for e in page), page[-1].id if len(rows) > limit else None
        )
        return OversightOutcome(value=value, returned=len(page))

    return run_oversight_read(
        caller=caller,
        operation=PERMISSION_GRANT_LEDGER_APPROVER_REGISTER_READ,
        target_type=_TARGET,
        read=read,
        request_metadata={
            "cursor": str(cursor) if cursor is not None else None,
            "limit": limit,
            "filtered": subject_user_id is not None or entry_type is not None,
        },
    )


def read_approver_eligibility(
    *, caller: object, cursor: uuid.UUID | None = None, limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE
) -> EligibilityPage:
    """Every approver enrolment with its state now, from the register
    alone, in entry id order."""
    validate_page_request(cursor, limit, maximum=MAX_OVERSIGHT_PAGE_SIZE)

    def read(session: Session) -> OversightOutcome[EligibilityPage]:
        at = database_time(session)
        query = (
            select(ApproverRegisterEntry)
            .where(ApproverRegisterEntry.entry_type == REGISTER_ENROLMENT)
            .order_by(ApproverRegisterEntry.id)
            .limit(limit + 1)
        )
        if cursor is not None:
            query = query.where(ApproverRegisterEntry.id > cursor)
        rows = list(session.execute(query).scalars())
        page = rows[:limit]
        revoked = _revoked_ids(
            session, [e.id for e in page] + [e.authorised_by_entry_id for e in page]
        )
        validity = _designation_validity(session, [e.authorised_by_entry_id for e in page])
        approvers = []
        for entry in page:
            view = _view(entry)
            assert view.natural_person_ref is not None and view.authorised_by_entry_id is not None
            assert view.eligible_from is not None and view.valid_until is not None
            approvers.append(
                EnrolmentEligibility(
                    entry_id=view.id,
                    subject_user_id=view.subject_user_id,
                    natural_person_ref=view.natural_person_ref,
                    state=enrolment_state(
                        view,
                        revoked_entry_ids=revoked,
                        designation_valid_until=validity.get(view.authorised_by_entry_id),
                        now=at,
                    ),
                    eligible_from=view.eligible_from,
                    valid_until=view.valid_until,
                    authorised_by_entry_id=view.authorised_by_entry_id,
                )
            )
        value = EligibilityPage(at, tuple(approvers), page[-1].id if len(rows) > limit else None)
        return OversightOutcome(value=value, returned=len(page))

    return run_oversight_read(
        caller=caller,
        operation=PERMISSION_GRANT_LEDGER_APPROVER_ELIGIBILITY_READ,
        target_type=_TARGET,
        read=read,
        request_metadata={"cursor": str(cursor) if cursor is not None else None, "limit": limit},
    )
