"""The plan of audit identity expiry: the exact two-year rule, the canonical
set digests and the eligible sets of the platform scope (audit identity phase
P2; docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections
4.8 and 4.11; owner decisions D4, D7, D8 and O10, and the exact two-year rule
kept on 2026-11-03).

Read only. It deletes nothing and needs no migrations role, so the
application-role report job (`saas_os.core.audit_identity.jobs`) uses it; the
command that applies a plan is `saas_os.core.audit_identity.expiry`, which
the runtime may not import.

**The rule (normative; decision record, "Two-year expiry calculation").**
A record `r` expires at `E(r)`: its `created_at` in UTC, with the year
plus two; 29 February becomes 28 February, nothing else moves
(`record_expires_at`). A link may be deleted only when (a) every platform
audit row that carries its reference as user identification satisfies
`E(r) + 1 day <= now` and (b) the day bound `((subject_day + 2 years) + 2
days) 00:00 UTC <= now` holds (`link_day_bound`); and no active hold covers
it. `now` is the database clock (`now()`, the transaction start). A link
never expires early.

The identifying locations searched for (a) are the two places Core writes
a platform reference (phase P1): `target_type = 'user_subject'` with the
reference as `target_id`, and the operator-event metadata key
`user_subject_ref`. Rows that mention a reference as the object of a hold
do not extend a link (proposal R3, as narrowed). They are read with plain
equality on `target_id` (indexed) and on `metadata ->> 'user_subject_ref'`
(not indexed: a scan of the platform audit log per batch of 500 candidate
references, acceptable for a person-run command and a daily report).

**Erased subjects and markers (D4, O10).** A live link of an erased user
that no active hold covers is unlinked by a run (a hold kept it live at the
erasure and was released since). A marker may be deleted when `erased_at`'s
expiry plus one day has passed and no live link of the user remains under a
hold.

**Evidence (D8).** The deleted links are identified by
`reference_set_digest`, a SHA-256 over the canonical form v1 of proposal
section 4.11; the active holds by `hold_set_digest` (prefix
`saas-os/audit-identity-hold-set/v1`). It does not prove what the deleted
rows contained.

This module may name the link tables (owner decision O11, interim:
`tests/architecture/test_audit_subject_link_boundary.py`). Its output holds
counts, digests, a day and hold ids: never a user id and never a reference.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta

from saas_os.core.audit_identity.errors import InvalidAuditIdentityRequestError
from saas_os.core.platform_authority.subject_models import (
    PlatformAuditIdentityHold,
    PlatformAuditSubjectErasure,
    PlatformAuditSubjectLink,
)
from saas_os.core.platform_authority.subjects import latest_subject_reference_use
from saas_os.infra.db import Session, select, session_scope
from saas_os.infra.db import now as db_now

RETENTION_YEARS = 2
PLATFORM_SCOPE = "platform"
REFERENCE_SET_PREFIX = "saas-os/audit-subject-ref-set/v1"
HOLD_SET_PREFIX = "saas-os/audit-identity-hold-set/v1"

_MARGIN = timedelta(days=1)
_BUCKET_AND_MARGIN = timedelta(days=2)


# --- the exact two-year rule -------------------------------------------------------------


def _plus_years(value: date, years: int) -> date:
    """The same month and day `years` later; 29 February becomes 28 February
    when the target year has none. No other date moves."""
    try:
        return value.replace(year=value.year + years)
    except ValueError:  # only 29 February
        return value.replace(year=value.year + years, day=28)


def record_expires_at(created_at: datetime) -> datetime:
    """`E(r)`: `created_at` expressed in UTC first, then its date moved two
    years (29 February to 28 February), the time of day unchanged. Aware,
    in UTC."""
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise InvalidAuditIdentityRequestError("created_at must carry a UTC offset.")
    utc = created_at.astimezone(UTC)
    return datetime.combine(_plus_years(utc.date(), RETENTION_YEARS), utc.timetz())


def link_day_bound(subject_day: date) -> datetime:
    """The day bound of a link: 00:00 UTC of `(subject_day + 2 years) + 2
    days` (one day for the bucket, one day of margin; proposal 4.8)."""
    return datetime.combine(
        _plus_years(subject_day, RETENTION_YEARS) + _BUCKET_AND_MARGIN, time(0, tzinfo=UTC)
    )


def record_past_retention(created_at: datetime, now: datetime) -> bool:
    """Is a referencing record past retention plus the one-day margin?"""
    return record_expires_at(created_at) + _MARGIN <= now


# --- canonical set digests (D8, proposal 4.11) ---------------------------------------------


def _canonical_items(items: Iterable[object]) -> list[str]:
    canonical: list[str] = []
    for item in items:
        if isinstance(item, uuid.UUID):
            text = str(item)
        elif isinstance(item, str):
            try:
                parsed = uuid.UUID(item)
            except ValueError as exc:
                raise InvalidAuditIdentityRequestError("an item is not a UUID.") from exc
            text = str(parsed)
            if text != item:
                raise InvalidAuditIdentityRequestError(
                    "an item is not in canonical form (36 lowercase characters)."
                )
        else:
            raise InvalidAuditIdentityRequestError("an item is not a UUID.")
        canonical.append(text)
    canonical.sort(key=lambda value: value.encode("ascii"))
    for first, second in zip(canonical, canonical[1:], strict=False):
        if first == second:
            raise InvalidAuditIdentityRequestError("a duplicate item; the set must be exact.")
    return canonical


def _set_digest(prefix: str, scope: str, items: Iterable[object]) -> str:
    if scope != PLATFORM_SCOPE and not scope.startswith("tenant:"):
        raise InvalidAuditIdentityRequestError("scope must be 'platform' or 'tenant:<uuid>'.")
    canonical = _canonical_items(items)
    message = (
        prefix
        + "\n"
        + scope
        + "\n"
        + str(len(canonical))
        + "\n"
        + "".join(f"{item}\n" for item in canonical)
    )
    return hashlib.sha256(message.encode("ascii")).hexdigest()


def reference_set_digest(scope: str, references: Iterable[object]) -> str:
    """SHA-256 (lowercase hex) of the canonical form v1 of a set of
    references (proposal 4.11): prefix, scope, count, then each reference
    as `str(uuid)` in ascending byte order, every line ending in LF. A
    duplicate or a non-canonical string is refused, never repaired."""
    return _set_digest(REFERENCE_SET_PREFIX, scope, references)


def hold_set_digest(scope: str, hold_ids: Iterable[object]) -> str:
    """The same canonical form over hold ids, prefix
    `saas-os/audit-identity-hold-set/v1` (`--confirm-holds`)."""
    return _set_digest(HOLD_SET_PREFIX, scope, hold_ids)


# --- the plan --------------------------------------------------------------------------------


def _covered(hold: PlatformAuditIdentityHold, subject_ref: uuid.UUID, day: date) -> bool:
    return (
        (hold.subject_ref is None or hold.subject_ref == subject_ref)
        and (hold.from_day is None or hold.from_day <= day)
        and (hold.to_day is None or hold.to_day >= day)
    )


def _held(holds: Sequence[PlatformAuditIdentityHold], link: PlatformAuditSubjectLink) -> bool:
    return any(_covered(hold, link.subject_ref, link.subject_day) for hold in holds)


@dataclass(frozen=True)
class AuditIdentityPlan:
    as_of: datetime
    delete_refs: tuple[uuid.UUID, ...]
    unlink_refs: tuple[uuid.UUID, ...]
    marker_users: tuple[uuid.UUID, ...]
    active_holds: tuple[uuid.UUID, ...]
    oldest_eligible_day: date | None


def audit_identity_expiry_plan(session: Session, *, lock: bool) -> AuditIdentityPlan:
    """The run's sets, decided with the database clock. With `lock`, every
    link and marker read is locked `FOR UPDATE` in key order."""
    as_of = session.execute(select(db_now())).scalar_one()
    holds = list(
        session.execute(
            select(PlatformAuditIdentityHold)
            .where(PlatformAuditIdentityHold.released_at.is_(None))
            .order_by(PlatformAuditIdentityHold.id)
        ).scalars()
    )
    # A superset of the links whose day bound can have passed: adding two
    # years adds at least 730 days.
    latest_day = as_of.astimezone(UTC).date() - timedelta(days=730)
    candidates_query = (
        select(PlatformAuditSubjectLink)
        .where(PlatformAuditSubjectLink.subject_day <= latest_day)
        .order_by(PlatformAuditSubjectLink.subject_ref)
    )
    if lock:
        candidates_query = candidates_query.with_for_update()
    candidates = [
        link
        for link in session.execute(candidates_query).scalars()
        if link_day_bound(link.subject_day) <= as_of and not _held(holds, link)
    ]
    latest = latest_subject_reference_use(session, [str(link.subject_ref) for link in candidates])
    deletable = [
        link
        for link in candidates
        if str(link.subject_ref) not in latest
        or record_past_retention(latest[str(link.subject_ref)], as_of)
    ]
    deleted = {link.subject_ref for link in deletable}

    markers_query = select(PlatformAuditSubjectErasure).order_by(
        PlatformAuditSubjectErasure.user_id
    )
    if lock:
        markers_query = markers_query.with_for_update()
    markers = list(session.execute(markers_query).scalars())
    erased = [marker.user_id for marker in markers]
    unlinks: list[uuid.UUID] = []
    held_live_users: set[uuid.UUID] = set()
    if erased:
        live_query = (
            select(PlatformAuditSubjectLink)
            .where(PlatformAuditSubjectLink.user_id.in_(erased))
            .order_by(PlatformAuditSubjectLink.subject_ref)
        )
        if lock:
            live_query = live_query.with_for_update()
        for link in session.execute(live_query).scalars():
            if link.subject_ref in deleted:
                continue
            if _held(holds, link):
                assert link.user_id is not None
                held_live_users.add(link.user_id)
            else:
                unlinks.append(link.subject_ref)
    marker_users = tuple(
        marker.user_id
        for marker in markers
        if record_past_retention(marker.erased_at, as_of) and marker.user_id not in held_live_users
    )
    return AuditIdentityPlan(
        as_of=as_of,
        delete_refs=tuple(link.subject_ref for link in deletable),
        unlink_refs=tuple(unlinks),
        marker_users=marker_users,
        active_holds=tuple(hold.id for hold in holds),
        oldest_eligible_day=min((link.subject_day for link in deletable), default=None),
    )


@dataclass(frozen=True)
class AuditIdentityExpiryReport:
    """A dry run (`applied` false) or an applied run of the platform scope.
    Counts, digests, a day and hold ids; never a user id or a reference.
    `run_id` is the id of the run's start row (with `apply`)."""

    as_of: datetime
    scope: str
    eligible_links: int
    eligible_links_digest: str
    links_to_unlink: int
    markers: int
    active_holds: int
    active_holds_digest: str
    oldest_eligible_day: date | None
    applied: bool = False
    run_id: uuid.UUID | None = None


def expiry_report(
    plan: AuditIdentityPlan, *, applied: bool = False, run_id: uuid.UUID | None = None
) -> AuditIdentityExpiryReport:
    return AuditIdentityExpiryReport(
        as_of=plan.as_of,
        scope=PLATFORM_SCOPE,
        eligible_links=len(plan.delete_refs),
        eligible_links_digest=reference_set_digest(PLATFORM_SCOPE, plan.delete_refs),
        links_to_unlink=len(plan.unlink_refs),
        markers=len(plan.marker_users),
        active_holds=len(plan.active_holds),
        active_holds_digest=hold_set_digest(PLATFORM_SCOPE, plan.active_holds),
        oldest_eligible_day=plan.oldest_eligible_day,
        applied=applied,
        run_id=run_id,
    )


def audit_identity_expiry_report() -> AuditIdentityExpiryReport:
    """The plan of the platform scope, computed as the application role in
    an untenanted read-only transaction (the scheduled report job; D7).
    Writes nothing; the application role has no `DELETE` on these tables."""
    with session_scope() as session:
        return expiry_report(audit_identity_expiry_plan(session, lock=False))


__all__ = [
    "HOLD_SET_PREFIX",
    "PLATFORM_SCOPE",
    "REFERENCE_SET_PREFIX",
    "RETENTION_YEARS",
    "AuditIdentityExpiryReport",
    "AuditIdentityPlan",
    "audit_identity_expiry_plan",
    "audit_identity_expiry_report",
    "expiry_report",
    "hold_set_digest",
    "link_day_bound",
    "record_expires_at",
    "record_past_retention",
    "reference_set_digest",
]
