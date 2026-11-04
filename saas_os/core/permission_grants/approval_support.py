"""Shared steps of the permission grant ledger's approval mechanism (owner
decisions of 2026-11-02 and 2026-11-03;
`docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`): the register lock,
the check of the platform-admin session a request presented, the refusal
wrapper, replay comparison and the common audit metadata. Used by
`saas_os.core.permission_grants.register`, `.approvals`, `.retention` and
`.expiry`; it decides nothing on its own.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta

from saas_os.core.authority import UserCaller
from saas_os.core.permission_grants.errors import (
    InvalidLedgerRetentionRequestError,
    LedgerApprovalRefusedError,
    PermissionGrantLedgerRetentionError,
)
from saas_os.core.platform_authority import (
    platform_operation,
    record_platform_refusal,
    recording_platform_refusal,
)
from saas_os.core.platform_authority.retention_evidence import (
    PLATFORM_HTTP_CHANNEL,
    AuditActRecord,
    PlatformSessionEvidence,
    platform_audit_acts,
    platform_session_record,
)
from saas_os.infra.db import Session, acquire_global_advisory_lock, clock_timestamp, select
from saas_os.infra.db import now as db_now

# The register's transaction-level advisory lock (migration `c3f9e1a7b5d2`
# takes the same lock in its insert trigger with the same two literals).
REGISTER_LOCK_NAMESPACE = "saas_os.permission_grant_ledger"
REGISTER_LOCK_KEY = "approver_register"

REQUEST_VALIDITY = timedelta(hours=72)
APPROVAL_VALIDITY = timedelta(hours=72)
EXECUTION_AUTHORIZATION_VALIDITY = timedelta(minutes=60)
PROPOSAL_VALIDITY = timedelta(hours=72)
ELIGIBILITY_DELAY = timedelta(days=120)
MAX_VALIDITY_MONTHS = 12

_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


def lock_register(session: Session, *, shared: bool) -> None:
    """The register lock, exclusive for a register write, shared for a use
    of an eligibility (approval, execution authorisation, execution): a
    revocation either commits before a use checks eligibility, or waits
    until that use commits and then invalidates it. Always taken before any
    tenant row lock."""
    acquire_global_advisory_lock(session, REGISTER_LOCK_NAMESPACE, REGISTER_LOCK_KEY, shared=shared)


def database_time(session: Session) -> datetime:
    """`now()`: the transaction's start, the time the triggers record."""
    return session.execute(select(db_now())).scalar_one()


def wall_time(session: Session) -> datetime:
    """`clock_timestamp()`: the time after the locks taken so far."""
    return session.execute(select(clock_timestamp())).scalar_one()


def twelve_months_after(moment: datetime) -> datetime:
    """`moment + interval '12 months'` as PostgreSQL computes it: the same
    day a year later, or the last day of February."""
    try:
        return moment.replace(year=moment.year + 1)
    except ValueError:  # 29 February
        return moment.replace(year=moment.year + 1, day=28)


def validated_reference(value: object, name: str) -> str:
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        raise InvalidLedgerRetentionRequestError(
            f"{name} must be 1 to 100 characters: letters, digits and . _ : - "
            "(an opaque reference, never a name or personal data)."
        )
    return value


def validated_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise InvalidLedgerRetentionRequestError(f"{name} must be 64 lower-case hex characters.")
    return value


def validated_count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvalidLedgerRetentionRequestError(f"{name} must be a positive int.")
    return value


def validated_uuid(value: object, name: str) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise InvalidLedgerRetentionRequestError(f"{name} must be a uuid.UUID.")
    return value


def validated_time(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise InvalidLedgerRetentionRequestError(f"{name} must be a datetime with a UTC offset.")
    return value


def refuse(code: str) -> LedgerApprovalRefusedError:
    return LedgerApprovalRefusedError(code)


@dataclass(frozen=True)
class VerifiedSession:
    """The platform-admin session of the request, checked in the act's own
    transaction: the caller's, unrevoked, unexpired."""

    session_id: uuid.UUID
    age_seconds: int

    def metadata(self) -> dict[str, object]:
        """The keys every authenticated act records."""
        return {
            "channel": PLATFORM_HTTP_CHANNEL,
            "session_id": str(self.session_id),
            "session_verified": True,
            "session_age_seconds": self.age_seconds,
        }


def verify_session(
    session: Session, caller: object, evidence: object, *, require_multi_factor: bool
) -> VerifiedSession:
    """Check the session evidence the platform-admin route passed: it must
    name a live `core.sessions` row of `caller` (`session_evidence_invalid`).
    With `require_multi_factor` (approval, execution authorisation and every
    register write; decision 6), the deployment must require a multi-factor
    login and the session must record one (`multi_factor_not_enforced`).
    This checks the evidence against storage; it does not authenticate the
    route (a holder of the application credential can write a session row,
    threat T6)."""
    if not isinstance(evidence, PlatformSessionEvidence) or not isinstance(caller, UserCaller):
        raise refuse("session_evidence_invalid")
    record = platform_session_record(session, evidence.session_id)
    if record is None or record.user_id != caller.user_id or not record.live:
        raise refuse("session_evidence_invalid")
    if require_multi_factor and not (evidence.multi_factor_required and record.multi_factor):
        raise refuse("multi_factor_not_enforced")
    return VerifiedSession(record.session_id, record.age_seconds)


def original_act(session: Session, audit_id: uuid.UUID) -> AuditActRecord | None:
    return platform_audit_acts(session, [audit_id]).get(audit_id)


def same_act(
    session: Session, audit_id: uuid.UUID, caller: UserCaller, reason: str, action: str
) -> bool:
    """Whether the act recorded under `audit_id` is this caller's, under
    this action, with this reason: one half of the replay test (the other
    is the record's own bound values)."""
    record = original_act(session, audit_id)
    return (
        record is not None
        and record.actor_user_id == caller.user_id
        and record.action == action
        and record.outcome == "success"
        and record.reason == reason
    )


@contextmanager
def refusals_recorded(
    caller: object,
    operation: str,
    target_type: str,
    target_id: str | None = None,
    *,
    platform_refusals: bool = True,
) -> Iterator[None]:
    """One `denied` platform row per refusal, after the rollback: a
    `PermissionGrantLedgerRetentionError` with its code here, and (unless
    `platform_refusals` is false because an oversight read records them
    itself) a `PlatformRefusalError` through `recording_platform_refusal`."""
    action = platform_operation(operation).audit_action
    try:
        if platform_refusals:
            with recording_platform_refusal(
                caller=caller, operation=operation, target_type=target_type, target_id=target_id
            ):
                yield
        else:
            yield
    except PermissionGrantLedgerRetentionError as refused:
        record_platform_refusal(
            caller=caller,
            action=action,
            target_type=target_type,
            target_id=target_id,
            code=refused.code,
        )
        raise
