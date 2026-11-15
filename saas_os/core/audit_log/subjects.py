"""Tenant audit subject references: get-or-create and the tenant erasure
step (docs/architecture/AUDIT-IDENTITY-P3-PLAN.md, phase P3a;
docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections 4.2,
4.4, 4.6 and 4.7, tenant variants; owner decisions D1, D2, D4, OD-3 and
ADR-0063 option A).

A tenant audit row that names a user through a reference never stores the
user id. It stores a **random, non-identifying reference**, one live
reference per tenant, user and UTC calendar day, mapped to the user in
`core.audit_subject_links`. A reference of tenant A means nothing in
tenant B: the table is under the tenant RLS policy, and every query here
also names the tenant (proposal 4.3, items 1 to 3). The platform scope's
counterpart is `saas_os.core.platform_authority.subjects`; a platform
reference and a tenant reference of the same person are independent random
values.

**Get-or-create (`audit_subject_ref`).** In the audit write's own
transaction (ADR-0031) and tenant-bound session, under READ COMMITTED (any
other level raises `AuditSubjectLinkUnavailableError`): a shared advisory
lock on the subject, the erasure-marker check, then `INSERT ... ON CONFLICT
(tenant_id, user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING
RETURNING subject_ref` and, when another transaction committed the link
first, a re-select. A reference collision (primary key) is retried in a
savepoint, at most three times; a lost race is retried once. An erased user
gets a reference that is born unlinked and names nobody. An id that names
no user or tenant fails the foreign key: the audit write fails closed with
`AuditSubjectLinkUnavailableError`, whose message names no id.

**Erasure (`erase_tenant_audit_subject`).** The tenant step of identity
erasure (proposal 4.6): marker, then unlink every live link of the user in
the tenant that no active tenant hold covers. Idempotent.

**Locks.** `acquire_global_advisory_lock()`, namespaced away from the
platform keys: `H`, namespace `saas_os.audit_identity_holds`, key
`tenant:<tenant id>`; `S`, namespace `saas_os.audit_subject`, key
`tenant:<tenant id>:<user id>` (the platform keys are `platform` and
`platform:<user id>`). A writer takes `S` shared after its business locks
and takes nothing afterwards; the erasure takes `H` shared and then `S`
exclusive, after its own row locks (proposal 4.7).

This module and `subject_models` are the only code that names the tenant
link tables (ADR-0063 option A: `tests/architecture/
test_audit_subject_link_boundary.py`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date

from saas_os.core.audit_log.errors import AuditSubjectLinkUnavailableError
from saas_os.core.audit_log.subject_models import (
    TenantAuditIdentityHold,
    TenantAuditSubjectErasure,
    TenantAuditSubjectLink,
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

_LOCK_HOLDS_NAMESPACE = "saas_os.audit_identity_holds"
_LOCK_SUBJECT_NAMESPACE = "saas_os.audit_subject"

_READ_COMMITTED = "read committed"
_MAX_COLLISION_ATTEMPTS = 3
_MAX_RACE_ATTEMPTS = 2
_PRIMARY_KEY = "pk_audit_subject_links"
_UNKNOWN_SUBJECT_KEYS = frozenset(
    {"fk_audit_subject_links_user_id", "fk_audit_subject_links_tenant_id"}
)
_UNLINK_REASON_ERASURE = "erasure"


@dataclass(frozen=True)
class TenantSubjectErasure:
    """Counts of one tenant's erasure step. Never a reference."""

    links_unlinked: int = 0
    links_kept_under_hold: int = 0


def tenant_holds_lock_key(tenant_id: uuid.UUID) -> str:
    """The key of a tenant's hold lock `H` (namespace
    `saas_os.audit_identity_holds`), shared with the hold and expiry code of
    later phases."""
    return f"tenant:{tenant_id}"


def _subject_lock_key(tenant_id: uuid.UUID, user_id: uuid.UUID) -> str:
    return f"tenant:{tenant_id}:{user_id}"


def _constraint_name(error: IntegrityError) -> str | None:
    diag = getattr(getattr(error, "orig", None), "diag", None)
    name = getattr(diag, "constraint_name", None)
    return name if isinstance(name, str) else None


def _check_ids(tenant_id: object, user_id: object) -> None:
    if not isinstance(tenant_id, uuid.UUID) or not isinstance(user_id, uuid.UUID):
        raise TypeError("tenant_id and user_id must be uuid.UUID values.")


def _live_ref(session: Session, tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID | None:
    return session.execute(
        select(TenantAuditSubjectLink.subject_ref).where(
            TenantAuditSubjectLink.tenant_id == tenant_id,
            TenantAuditSubjectLink.user_id == user_id,
            TenantAuditSubjectLink.user_id.is_not(None),
            TenantAuditSubjectLink.subject_day == utc_transaction_date(),
        )
    ).scalar_one_or_none()


def _insert_live(session: Session, tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID | None:
    """Step 3a: the day's live link, in a savepoint so that a reference
    collision rolls back only this statement. `None` when another
    transaction committed the link first (the arbiter conflicted)."""
    for _ in range(_MAX_COLLISION_ATTEMPTS):
        try:
            with session.begin_nested():
                return session.execute(
                    insert_ignoring_conflict_returning(
                        TenantAuditSubjectLink,
                        {
                            "tenant_id": tenant_id,
                            "user_id": user_id,
                            "subject_day": utc_transaction_date(),
                        },
                        index_elements=[
                            TenantAuditSubjectLink.tenant_id,
                            TenantAuditSubjectLink.user_id,
                            TenantAuditSubjectLink.subject_day,
                        ],
                        index_where=TenantAuditSubjectLink.user_id.is_not(None),
                        returning=TenantAuditSubjectLink.subject_ref,
                    )
                ).scalar_one_or_none()
        except IntegrityError as error:
            name = _constraint_name(error)
            if name in _UNKNOWN_SUBJECT_KEYS:
                # The message must not carry the database's detail, which
                # names the id.
                raise AuditSubjectLinkUnavailableError(
                    "the audited user or tenant does not exist"
                ) from None
            if name != _PRIMARY_KEY:
                raise
    raise AuditSubjectLinkUnavailableError("a reference could not be generated")


def _insert_born_unlinked(session: Session, tenant_id: uuid.UUID) -> uuid.UUID:
    """Step 3c: a reference that never holds a user id."""
    for _ in range(_MAX_COLLISION_ATTEMPTS):
        link = TenantAuditSubjectLink(
            subject_ref=uuid.uuid4(),
            tenant_id=tenant_id,
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


def audit_subject_ref(session: Session, *, tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
    """Get or create the reference of `user_id` in `tenant_id` for today's
    UTC date, in `session`'s transaction; never commits. `session` must be
    bound to `tenant_id` (`tenant_session_scope()` or `bind_tenant_scope()`):
    row-level security refuses a link of any other tenant (fail closed), and
    every statement here also names `tenant_id`. It must run at READ
    COMMITTED.

    Raises `AuditSubjectLinkUnavailableError` (the message names no id); the
    caller's transaction then rolls back with the audited change. There is
    no fallback to the raw user id."""
    _check_ids(tenant_id, user_id)
    if current_transaction_isolation(session) != _READ_COMMITTED:
        raise AuditSubjectLinkUnavailableError(
            "audit subject references need a READ COMMITTED transaction"
        )
    acquire_global_advisory_lock(
        session, _LOCK_SUBJECT_NAMESPACE, _subject_lock_key(tenant_id, user_id), shared=True
    )
    erased = session.execute(
        select(TenantAuditSubjectErasure.user_id).where(
            TenantAuditSubjectErasure.tenant_id == tenant_id,
            TenantAuditSubjectErasure.user_id == user_id,
        )
    ).first()
    if erased is not None:
        return _insert_born_unlinked(session, tenant_id)
    for _ in range(_MAX_RACE_ATTEMPTS):
        inserted = _insert_live(session, tenant_id, user_id)
        if inserted is not None:
            return inserted
        committed = _live_ref(session, tenant_id, user_id)
        if committed is not None:
            return committed
    raise AuditSubjectLinkUnavailableError("the committed link could not be read back")


def _covered_by_hold(link: TenantAuditSubjectLink, holds: list[TenantAuditIdentityHold]) -> bool:
    day: date = link.subject_day
    return any(
        (hold.subject_ref is None or hold.subject_ref == link.subject_ref)
        and (hold.from_day is None or hold.from_day <= day)
        and (hold.to_day is None or hold.to_day >= day)
        for hold in holds
    )


def erase_tenant_audit_subject(
    session: Session, *, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> TenantSubjectErasure:
    """The tenant step of identity erasure (proposal 4.6), in `session`'s
    transaction, which must be bound to `tenant_id` and must already hold
    the erasure's own row locks (the caller locks the user row `FOR KEY
    SHARE` and calls this only for an existing user: the marker has a
    foreign key). Then: shared `H`, exclusive `S`, the erasure marker, and
    every live link of the user in the tenant not covered by an active
    tenant hold is unlinked (`user_id` NULL, `unlinked_at`, reason
    `erasure`). A link under a hold stays live; the first expiry run after
    the hold's release unlinks it (the marker remains). A rerun changes
    nothing."""
    _check_ids(tenant_id, user_id)
    acquire_global_advisory_lock(
        session, _LOCK_HOLDS_NAMESPACE, tenant_holds_lock_key(tenant_id), shared=True
    )
    acquire_global_advisory_lock(
        session, _LOCK_SUBJECT_NAMESPACE, _subject_lock_key(tenant_id, user_id), shared=False
    )
    marker = session.execute(
        select(TenantAuditSubjectErasure.user_id).where(
            TenantAuditSubjectErasure.tenant_id == tenant_id,
            TenantAuditSubjectErasure.user_id == user_id,
        )
    ).first()
    if marker is None:
        session.add(TenantAuditSubjectErasure(tenant_id=tenant_id, user_id=user_id))
        session.flush()
    links = list(
        session.execute(
            select(TenantAuditSubjectLink)
            .where(
                TenantAuditSubjectLink.tenant_id == tenant_id,
                TenantAuditSubjectLink.user_id == user_id,
            )
            .order_by(TenantAuditSubjectLink.subject_ref)
            .with_for_update()
        ).scalars()
    )
    holds = list(
        session.execute(
            select(TenantAuditIdentityHold).where(
                TenantAuditIdentityHold.tenant_id == tenant_id,
                TenantAuditIdentityHold.released_at.is_(None),
            )
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
    return TenantSubjectErasure(links_unlinked=unlinked, links_kept_under_hold=kept)
