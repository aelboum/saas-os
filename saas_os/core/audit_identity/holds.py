"""Legal holds on platform audit references: audit identity phase P2
(docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md section 4.9;
owner decisions D4, O8 and the hold route permission of 2026-11-03).

A hold keeps platform audit subject links from being deleted by the expiry
command and from being unlinked by identity erasure. It names an opaque
legal-matter `reference` (letters, digits and `._:-`, at most 100
characters; never a name), an optional inclusive UTC day range
(`from_day`, `to_day`; `None` is open-ended) and an optional `subject_ref`
(one reference; `None` covers every subject of the platform scope). A hold
never names a user id: a person-scoped hold names that person's references.

Placing and releasing are platform operations under
`platform.security_retention_hold:manage` (no new permission), each with one
platform audit row written in the same transaction as the hold change and
whose id the hold row records (`placed_by_platform_audit_id`,
`released_by_platform_audit_id`), the convention of the permission grant
ledger holds (PR #198). The database checks that evidence at commit
(migration `b6d2f8a4c1e7`, a deferred constraint trigger): a hold row whose
placing or releasing audit id does not name the matching successful
`platform.audit_identity.hold_place` or `hold_release` row of that hold is
refused.

**Who may release (owner decision O8).** Placing errs towards retention, so
the operator command may place a hold under a declared operator id.
Releasing can lead to removal, so it runs through the authenticated
platform-admin route only: `release_audit_identity_hold` requires the
route's session evidence, which must name a live session of the caller.
No command releases a hold (`tests/architecture/
test_audit_identity_hold_boundary.py`).

**Locks.** Placing and releasing take the platform scope's hold lock `H`
exclusively (proposal 4.7); identity erasure and the expiry command take it
shared and read the holds after it, so a hold change and an erasure or an
expiry run of the platform scope never interleave.

Every change also writes one structured log line (`audit_identity_hold_placed`,
`audit_identity_hold_released`: hold id, scope, day range, matter reference;
never a user id), so holds can be rebuilt after a restore (proposal 4.12).

A refusal writes one `denied` platform row with its code.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime

from saas_os.core.audit_identity.errors import (
    AuditIdentityHoldAlreadyActiveError,
    AuditIdentityHoldAlreadyReleasedError,
    AuditIdentityHoldNotFoundError,
    AuditIdentityRetentionError,
    AuditIdentitySessionEvidenceError,
    InvalidAuditIdentityRequestError,
)
from saas_os.core.permission_grants.approval_support import verify_session
from saas_os.core.permission_grants.errors import PermissionGrantLedgerRetentionError
from saas_os.core.platform_authority import (
    DEFAULT_OVERSIGHT_PAGE_SIZE,
    MAX_OVERSIGHT_PAGE_SIZE,
    OversightOutcome,
    authorize_platform_caller,
    platform_change_session,
    platform_operation,
    record_platform_event_in_transaction,
    record_platform_refusal,
    recording_platform_refusal,
    run_oversight_read,
    validate_page_request,
    validate_reason,
)
from saas_os.core.platform_authority.operations import (
    AUDIT_IDENTITY_HOLD_PLACE,
    AUDIT_IDENTITY_HOLD_READ,
    AUDIT_IDENTITY_HOLD_RELEASE,
)
from saas_os.core.platform_authority.subject_models import PlatformAuditIdentityHold
from saas_os.core.platform_authority.subjects import (
    PLATFORM_HOLDS_LOCK_KEY,
    PLATFORM_HOLDS_LOCK_NAMESPACE,
)
from saas_os.infra.db import Session, acquire_global_advisory_lock, select
from saas_os.infra.db import now as db_now

logger = logging.getLogger(__name__)

HOLD_TARGET_TYPE = "audit_identity_hold"
PLATFORM_SCOPE = "platform"

_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")


@dataclass(frozen=True)
class AuditIdentityHold:
    """One hold, as placed or released. `platform_audit_id` is the id of the
    platform audit row of this act (placing or releasing)."""

    hold_id: uuid.UUID
    scope: str
    reference: str
    from_day: date | None
    to_day: date | None
    subject_ref: uuid.UUID | None
    placed_at: datetime
    released_at: datetime | None
    platform_audit_id: uuid.UUID


@dataclass(frozen=True)
class AuditIdentityHoldView:
    id: uuid.UUID
    scope: str
    reference: str
    from_day: date | None
    to_day: date | None
    subject_ref: uuid.UUID | None
    placed_at: datetime
    released_at: datetime | None


@dataclass(frozen=True)
class AuditIdentityHoldPage:
    holds: tuple[AuditIdentityHoldView, ...]
    next_cursor: uuid.UUID | None


def _validated_reference(reference: object) -> str:
    if not isinstance(reference, str) or _REFERENCE.fullmatch(reference) is None:
        raise InvalidAuditIdentityRequestError(
            "reference must be 1 to 100 characters: letters, digits and . _ : - "
            "(an opaque matter reference, never a name)."
        )
    return reference


def _validated_day(value: object, name: str) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime) or not isinstance(value, date):
        raise InvalidAuditIdentityRequestError(f"{name} must be a date (a UTC calendar day).")
    return value


def _validated_scope(
    reference: object, from_day: object, to_day: object, subject_ref: object
) -> tuple[str, date | None, date | None, uuid.UUID | None]:
    checked_reference = _validated_reference(reference)
    first = _validated_day(from_day, "from_day")
    last = _validated_day(to_day, "to_day")
    if first is not None and last is not None and first > last:
        raise InvalidAuditIdentityRequestError("from_day must not be after to_day.")
    if subject_ref is not None and not isinstance(subject_ref, uuid.UUID):
        raise InvalidAuditIdentityRequestError("subject_ref must be a uuid.UUID.")
    return checked_reference, first, last, subject_ref


def _hold_metadata(hold: PlatformAuditIdentityHold) -> dict[str, object]:
    return {
        "hold_id": str(hold.id),
        "scope": PLATFORM_SCOPE,
        "reference": hold.reference,
        "from_day": hold.from_day.isoformat() if hold.from_day is not None else None,
        "to_day": hold.to_day.isoformat() if hold.to_day is not None else None,
        "subject_ref": str(hold.subject_ref) if hold.subject_ref is not None else None,
    }


def _result(hold: PlatformAuditIdentityHold, audit_id: uuid.UUID) -> AuditIdentityHold:
    return AuditIdentityHold(
        hold_id=hold.id,
        scope=PLATFORM_SCOPE,
        reference=hold.reference,
        from_day=hold.from_day,
        to_day=hold.to_day,
        subject_ref=hold.subject_ref,
        placed_at=hold.placed_at,
        released_at=hold.released_at,
        platform_audit_id=audit_id,
    )


def _channel(session: Session, caller: object, evidence: object) -> dict[str, object]:
    """The route's session evidence, checked against storage and recorded;
    `{}` for the operator command (no evidence)."""
    if evidence is None:
        return {}
    try:
        verified = verify_session(session, caller, evidence, require_multi_factor=False)
    except PermissionGrantLedgerRetentionError as refused:
        raise AuditIdentitySessionEvidenceError() from refused
    return verified.metadata()


def _lock_holds(session: Session) -> None:
    acquire_global_advisory_lock(
        session, PLATFORM_HOLDS_LOCK_NAMESPACE, PLATFORM_HOLDS_LOCK_KEY, shared=False
    )


def place_audit_identity_hold(
    *,
    reference: str,
    caller: object,
    reason: str,
    from_day: date | None = None,
    to_day: date | None = None,
    subject_ref: uuid.UUID | None = None,
    session_evidence: object = None,
) -> AuditIdentityHold:
    """Place a legal hold on platform audit references (module docstring).
    One platform audit row in the same transaction; its id is the hold's
    `placed_by_platform_audit_id`. Through the platform-admin route
    (`session_evidence` given) the session is checked and recorded; the
    operator command passes none. An active hold with the same reference
    and subject is refused (`hold_already_active`).

    The subject reference is not checked against the link table: a hold
    errs towards retention, and a reference read from an audit export may
    already be unlinked."""
    operation = AUDIT_IDENTITY_HOLD_PLACE
    spec = platform_operation(operation)
    try:
        reference, from_day, to_day, subject_ref = _validated_scope(
            reference, from_day, to_day, subject_ref
        )
        reason = validate_reason(reason)
        with (
            recording_platform_refusal(
                caller=caller, operation=operation, target_type=HOLD_TARGET_TYPE
            ),
            platform_change_session(caller, operation) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=operation)
            channel = _channel(session, caller, session_evidence)
            _lock_holds(session)
            active = session.execute(
                select(PlatformAuditIdentityHold.id).where(
                    PlatformAuditIdentityHold.reference == reference,
                    PlatformAuditIdentityHold.subject_ref.is_(None)
                    if subject_ref is None
                    else PlatformAuditIdentityHold.subject_ref == subject_ref,
                    PlatformAuditIdentityHold.released_at.is_(None),
                )
            ).first()
            if active is not None:
                raise AuditIdentityHoldAlreadyActiveError()
            audit_id = uuid.uuid4()
            hold = PlatformAuditIdentityHold(
                reference=reference,
                from_day=from_day,
                to_day=to_day,
                subject_ref=subject_ref,
                placed_by_platform_audit_id=audit_id,
            )
            session.add(hold)
            session.flush()
            session.refresh(hold)
            metadata = _hold_metadata(hold)
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=HOLD_TARGET_TYPE,
                target_id=str(hold.id),
                reason=reason,
                metadata={**channel, **metadata},
                entry_id=audit_id,
            )
            result = _result(hold, audit_id)
        logger.info("audit_identity_hold_placed", extra=metadata)
        return result
    except AuditIdentityRetentionError as refused:
        record_platform_refusal(
            caller=caller,
            action=spec.audit_action,
            target_type=HOLD_TARGET_TYPE,
            code=refused.code,
        )
        raise


def release_audit_identity_hold(
    hold_id: uuid.UUID, *, caller: object, reason: str, session_evidence: object
) -> AuditIdentityHold:
    """Release an active hold, through the authenticated platform-admin route
    only (owner decision O8): `session_evidence` must name a live session of
    `caller` (`session_evidence_invalid`). The hold row stays, with the
    release time and the id of the platform audit row written in the same
    transaction. Releasing deletes and unlinks nothing; the first expiry run
    afterwards processes what became eligible (D4). A released hold is
    never changed (`hold_already_released`; the database trigger refuses it
    for every role)."""
    operation = AUDIT_IDENTITY_HOLD_RELEASE
    spec = platform_operation(operation)
    target_id = str(hold_id) if isinstance(hold_id, uuid.UUID) else None
    try:
        if not isinstance(hold_id, uuid.UUID):
            raise InvalidAuditIdentityRequestError("hold_id must be a uuid.UUID.")
        reason = validate_reason(reason)
        if session_evidence is None:
            raise AuditIdentitySessionEvidenceError()
        with (
            recording_platform_refusal(
                caller=caller,
                operation=operation,
                target_type=HOLD_TARGET_TYPE,
                target_id=target_id,
            ),
            platform_change_session(caller, operation) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=operation)
            channel = _channel(session, caller, session_evidence)
            _lock_holds(session)
            hold = session.get(PlatformAuditIdentityHold, hold_id, with_for_update=True)
            if hold is None:
                raise AuditIdentityHoldNotFoundError(hold_id)
            if hold.released_at is not None:
                raise AuditIdentityHoldAlreadyReleasedError(hold_id)
            audit_id = uuid.uuid4()
            hold.released_at = session.execute(select(db_now())).scalar_one()
            hold.released_by_platform_audit_id = audit_id
            session.flush()
            metadata = _hold_metadata(hold)
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=HOLD_TARGET_TYPE,
                target_id=str(hold.id),
                reason=reason,
                metadata={**channel, **metadata},
                entry_id=audit_id,
            )
            result = _result(hold, audit_id)
        logger.info("audit_identity_hold_released", extra=metadata)
        return result
    except AuditIdentityRetentionError as refused:
        record_platform_refusal(
            caller=caller,
            action=spec.audit_action,
            target_type=HOLD_TARGET_TYPE,
            target_id=target_id,
            code=refused.code,
        )
        raise


def list_audit_identity_holds(
    *,
    caller: object,
    active: bool | None = None,
    cursor: uuid.UUID | None = None,
    limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE,
) -> AuditIdentityHoldPage:
    """The platform scope's holds in id order (operation
    `audit_identity.hold_read`, the hold management permission), optionally
    active or released only. An audited oversight read: an attempt row
    before the read, a completion row after it."""
    validate_page_request(cursor, limit, maximum=MAX_OVERSIGHT_PAGE_SIZE)
    if active is not None and not isinstance(active, bool):
        raise InvalidAuditIdentityRequestError("active must be a bool.")

    def read(session: Session) -> OversightOutcome[AuditIdentityHoldPage]:
        query = (
            select(PlatformAuditIdentityHold)
            .order_by(PlatformAuditIdentityHold.id)
            .limit(limit + 1)
        )
        if cursor is not None:
            query = query.where(PlatformAuditIdentityHold.id > cursor)
        if active is True:
            query = query.where(PlatformAuditIdentityHold.released_at.is_(None))
        if active is False:
            query = query.where(PlatformAuditIdentityHold.released_at.is_not(None))
        found = list(session.execute(query).scalars())
        page = found[:limit]
        holds = tuple(
            AuditIdentityHoldView(
                id=hold.id,
                scope=PLATFORM_SCOPE,
                reference=hold.reference,
                from_day=hold.from_day,
                to_day=hold.to_day,
                subject_ref=hold.subject_ref,
                placed_at=hold.placed_at,
                released_at=hold.released_at,
            )
            for hold in page
        )
        value = AuditIdentityHoldPage(holds, page[-1].id if len(found) > limit else None)
        return OversightOutcome(value=value, returned=len(page))

    return run_oversight_read(
        caller=caller,
        operation=AUDIT_IDENTITY_HOLD_READ,
        target_type=HOLD_TARGET_TYPE,
        read=read,
        request_metadata={
            "cursor": str(cursor) if cursor is not None else None,
            "limit": limit,
            "filtered": active is not None,
        },
    )


__all__ = [
    "HOLD_TARGET_TYPE",
    "PLATFORM_SCOPE",
    "AuditIdentityHold",
    "AuditIdentityHoldPage",
    "AuditIdentityHoldView",
    "list_audit_identity_holds",
    "place_audit_identity_hold",
    "release_audit_identity_hold",
]
