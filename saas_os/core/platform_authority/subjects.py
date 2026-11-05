"""Platform audit subject references: get-or-create and the erasure step
(docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections 4.2,
4.4, 4.6 and 4.7, platform variants; owner decisions D1, D6, O2, O6, OD-2
and the foreign-key decision of 2026-11-04, option A1 of
docs/architecture/AUDIT-P1-FOREIGN-KEY-OPTIONS.md).

A platform audit row that targets a user never stores the user id. It
stores a **random, non-identifying reference** (`target_type =
'user_subject'`, `target_id = str(reference)`), one live reference per user
and UTC calendar day, mapped to the user in `core.platform_audit_subject_links`.
Every platform writer that targets a user goes through `user_audit_target()`,
operators included: there is no operator test (owner decision OD-2).

**Unknown ids (A1).** `user_audit_target()` first reads the user row with
`SELECT ... FOR KEY SHARE` in the audit write's own transaction. A row: the
reference is got or created and the target is `('user_subject', reference)`.
No row: nothing is linked and the target is `('user', None)`, a shape the
external-identity lookup already writes. The foreign key from the link table
to `core.users` therefore never fires for a write made by this module, and a
refused or failed request about an id that names nobody is still recorded.
The lock blocks a concurrent delete of the user until the audit transaction
ends and does not block the non-key updates other code makes to the row.
Core never deletes a user.

**Get-or-create (`platform_audit_subject_ref`).** In the audit write's
transaction (ADR-0031), under READ COMMITTED (any other level raises
`AuditSubjectLinkUnavailableError`; nothing works around it): a shared
advisory lock on the subject, the erasure-marker check, then
`INSERT ... ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO
NOTHING RETURNING subject_ref` and, when another transaction committed the
link first, a re-select. A reference collision (primary key) is retried in a
savepoint, at most three times; a lost race is retried once. An erased user
gets a reference that is born unlinked and names nobody. Reviewed on
PostgreSQL 16: docs/architecture/AUDIT-P1-SQL-REVIEW.md.

**Erasure (`erase_platform_audit_subject`).** The platform step of identity
erasure (proposal 4.6): marker, then unlink every live link of the user that
no active hold covers. Idempotent.

**Locks.** The advisory locks use `acquire_global_advisory_lock()` (the
two-int4 key space the repository already uses): `H`, namespace
`saas_os.audit_identity_holds`, key `platform`; `S`, namespace
`saas_os.audit_subject`, key `platform:<user id>`. A writer takes `S` shared
after its business locks and takes nothing afterwards; the erasure takes `H`
shared and then `S` exclusive, after the platform-owners lock (proposal 4.7).

This module and `subject_models` are the only code that names the link
tables (owner decision O11, interim: `tests/architecture/
test_audit_subject_link_boundary.py`).
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import date

from saas_os.core.identity.models import User
from saas_os.core.platform_authority.subject_models import (
    PlatformAuditIdentityHold,
    PlatformAuditSubjectErasure,
    PlatformAuditSubjectLink,
)
from saas_os.infra.db import (
    IntegrityError,
    Session,
    acquire_global_advisory_lock,
    current_transaction_isolation,
    insert_ignoring_conflict_returning,
    now,
    select,
    utc_transaction_date,
)

logger = logging.getLogger(__name__)

USER_TARGET_TYPE = "user"
USER_SUBJECT_TARGET_TYPE = "user_subject"

_LOCK_HOLDS_NAMESPACE = "saas_os.audit_identity_holds"
_LOCK_HOLDS_KEY = "platform"
_LOCK_SUBJECT_NAMESPACE = "saas_os.audit_subject"

_READ_COMMITTED = "read committed"
_MAX_COLLISION_ATTEMPTS = 3
_MAX_RACE_ATTEMPTS = 2
_PRIMARY_KEY = "pk_platform_audit_subject_links"
_UNLINK_REASON_ERASURE = "erasure"


class AuditSubjectLinkUnavailableError(RuntimeError):
    """A reference could not be got or created: the transaction does not run
    at READ COMMITTED, three consecutive reference collisions, or the link
    that another transaction committed could not be read back. There is no
    fallback to the raw user id. The message names no user."""


@dataclass(frozen=True)
class AuditTarget:
    """What a platform audit row records for a user target: the target type
    and id columns. `('user', None)` is the row of an id that names no
    user."""

    target_type: str
    target_id: str | None


@dataclass(frozen=True)
class PlatformSubjectErasure:
    """Counts of the platform erasure step. Never a reference."""

    links_unlinked: int = 0
    links_kept_under_hold: int = 0


def _subject_lock_key(user_id: uuid.UUID) -> str:
    return f"platform:{user_id}"


def _constraint_name(error: IntegrityError) -> str | None:
    diag = getattr(getattr(error, "orig", None), "diag", None)
    name = getattr(diag, "constraint_name", None)
    return name if isinstance(name, str) else None


def _live_ref(session: Session, user_id: uuid.UUID) -> uuid.UUID | None:
    return session.execute(
        select(PlatformAuditSubjectLink.subject_ref).where(
            PlatformAuditSubjectLink.user_id == user_id,
            PlatformAuditSubjectLink.user_id.is_not(None),
            PlatformAuditSubjectLink.subject_day == utc_transaction_date(),
        )
    ).scalar_one_or_none()


def _insert_live(session: Session, user_id: uuid.UUID) -> uuid.UUID | None:
    """Step 3a: the day's live link, in a savepoint so that a reference
    collision rolls back only this statement. `None` when another
    transaction committed the link first (the arbiter conflicted)."""
    for _ in range(_MAX_COLLISION_ATTEMPTS):
        try:
            with session.begin_nested():
                return session.execute(
                    insert_ignoring_conflict_returning(
                        PlatformAuditSubjectLink,
                        {"user_id": user_id, "subject_day": utc_transaction_date()},
                        index_elements=[
                            PlatformAuditSubjectLink.user_id,
                            PlatformAuditSubjectLink.subject_day,
                        ],
                        index_where=PlatformAuditSubjectLink.user_id.is_not(None),
                        returning=PlatformAuditSubjectLink.subject_ref,
                    )
                ).scalar_one_or_none()
        except IntegrityError as error:
            if _constraint_name(error) != _PRIMARY_KEY:
                raise
    raise AuditSubjectLinkUnavailableError("a reference could not be generated")


def _insert_born_unlinked(session: Session) -> uuid.UUID:
    """Step 3c: a reference that never holds a user id."""
    for _ in range(_MAX_COLLISION_ATTEMPTS):
        link = PlatformAuditSubjectLink(
            subject_ref=uuid.uuid4(),
            user_id=None,
            subject_day=session.execute(select(utc_transaction_date())).scalar_one(),
            unlinked_at=now(),
            unlink_reason=_UNLINK_REASON_ERASURE,
        )
        try:
            with session.begin_nested():
                session.add(link)
                session.flush()
                return link.subject_ref
        except IntegrityError as error:
            if _constraint_name(error) != _PRIMARY_KEY:
                raise
    raise AuditSubjectLinkUnavailableError("a reference could not be generated")


def platform_audit_subject_ref(session: Session, *, user_id: uuid.UUID) -> uuid.UUID:
    """Get or create the reference of `user_id` for today's UTC date, in
    `session`'s transaction; never commits. `session` must have no tenant
    bound (the link table is excluded from tenant transactions) and run at
    READ COMMITTED. `user_id` must name an existing user: the foreign key
    refuses anything else (`user_audit_target()` decides existence first).

    Raises `AuditSubjectLinkUnavailableError`; the caller's transaction
    then rolls back with the audited change."""
    if not isinstance(user_id, uuid.UUID):
        raise TypeError("user_id must be a uuid.UUID.")
    if current_transaction_isolation(session) != _READ_COMMITTED:
        raise AuditSubjectLinkUnavailableError(
            "audit subject references need a READ COMMITTED transaction"
        )
    acquire_global_advisory_lock(
        session, _LOCK_SUBJECT_NAMESPACE, _subject_lock_key(user_id), shared=True
    )
    erased = session.execute(
        select(PlatformAuditSubjectErasure.user_id).where(
            PlatformAuditSubjectErasure.user_id == user_id
        )
    ).first()
    if erased is not None:
        return _insert_born_unlinked(session)
    for _ in range(_MAX_RACE_ATTEMPTS):
        inserted = _insert_live(session, user_id)
        if inserted is not None:
            return inserted
        committed = _live_ref(session, user_id)
        if committed is not None:
            return committed
    raise AuditSubjectLinkUnavailableError("the committed link could not be read back")


def user_exists_for_audit(session: Session, user_id: uuid.UUID) -> bool:
    """Option A1's existence decision: `SELECT ... FOR KEY SHARE` on the
    user row, in the audit write's own transaction. The lock lasts until
    the transaction ends."""
    row = session.execute(
        select(User.id).where(User.id == user_id).with_for_update(read=True, key_share=True)
    ).first()
    return row is not None


def user_audit_target(session: Session, *, user_id: uuid.UUID) -> AuditTarget:
    """The `(target_type, target_id)` a platform audit row records for the
    user `user_id`: `('user_subject', '<reference>')` for an existing user,
    `('user', None)` for an id that names nobody (option A1; owner decision
    O6, option (a)). No operator test (OD-2). Never returns the user id."""
    if not isinstance(user_id, uuid.UUID):
        raise TypeError("user_id must be a uuid.UUID.")
    if not user_exists_for_audit(session, user_id):
        return AuditTarget(USER_TARGET_TYPE, None)
    reference = platform_audit_subject_ref(session, user_id=user_id)
    return AuditTarget(USER_SUBJECT_TARGET_TYPE, str(reference))


def _covered_by_hold(
    link: PlatformAuditSubjectLink, holds: list[PlatformAuditIdentityHold]
) -> bool:
    day: date = link.subject_day
    return any(
        (hold.subject_ref is None or hold.subject_ref == link.subject_ref)
        and (hold.from_day is None or hold.from_day <= day)
        and (hold.to_day is None or hold.to_day >= day)
        for hold in holds
    )


def erase_platform_audit_subject(session: Session, *, user_id: uuid.UUID) -> PlatformSubjectErasure:
    """The platform step of identity erasure (proposal 4.6), in `session`'s
    transaction, which must have no tenant bound and already hold the
    platform-owners lock: the user row `FOR KEY SHARE`, shared `H`, exclusive `S`,
    the erasure marker, then
    every live link of the user not covered by an active hold is unlinked
    (`user_id` NULL, `unlinked_at`, reason `erasure`). A link under a hold
    stays live; the first expiry run after the hold's release unlinks it
    (the marker remains).

    An id that names no user changes nothing and returns zeros: the marker
    has a foreign key, and erasure never reveals whether an id exists. A
    rerun changes nothing."""
    if not isinstance(user_id, uuid.UUID):
        raise TypeError("user_id must be a uuid.UUID.")
    # The user row first (`FOR KEY SHARE`), then the advisory locks: the order
    # of an audit writer (business row locks, then `S`), so the two cannot
    # wait on each other in a cycle (proposal 4.7).
    if not user_exists_for_audit(session, user_id):
        return PlatformSubjectErasure()
    acquire_global_advisory_lock(session, _LOCK_HOLDS_NAMESPACE, _LOCK_HOLDS_KEY, shared=True)
    acquire_global_advisory_lock(
        session, _LOCK_SUBJECT_NAMESPACE, _subject_lock_key(user_id), shared=False
    )
    if session.get(PlatformAuditSubjectErasure, user_id) is None:
        session.add(PlatformAuditSubjectErasure(user_id=user_id))
        session.flush()
    links = list(
        session.execute(
            select(PlatformAuditSubjectLink)
            .where(PlatformAuditSubjectLink.user_id == user_id)
            .order_by(PlatformAuditSubjectLink.subject_ref)
            .with_for_update()
        ).scalars()
    )
    holds = list(
        session.execute(
            select(PlatformAuditIdentityHold).where(PlatformAuditIdentityHold.released_at.is_(None))
        ).scalars()
    )
    unlinked = 0
    kept = 0
    for link in links:
        if _covered_by_hold(link, holds):
            kept += 1
            continue
        link.user_id = None
        link.unlinked_at = now()
        link.unlink_reason = _UNLINK_REASON_ERASURE
        unlinked += 1
    session.flush()
    return PlatformSubjectErasure(links_unlinked=unlinked, links_kept_under_hold=kept)
