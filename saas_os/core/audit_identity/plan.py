"""The plan of audit identity expiry: the exact two-year rule, the canonical
set digests and the eligible sets of the platform scope (audit identity phase
P2) and of each tenant (phase P3c;
docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections 4.8
and 4.11; docs/architecture/AUDIT-IDENTITY-P3-PLAN.md scope item 6; owner
decisions D4, D7, D8 and O10, and the exact two-year rule kept on
2026-11-03).

**Tenant scope.** The same rule over the tenant's own link, marker and hold
tables, in a transaction bound to the tenant (tenant RLS; every query also
names the tenant). The record bound reads the tenant's `core.audit_log` rows
that carry a reference as user identification: `initiated_by.subject_ref`,
`owner_user_subject_ref` (both under the phase P3b indexes) and
`operator_user_subject_ref`. A tenant plan is refused while a P3b index is
missing or invalid (`AuditIdentityIndexUnavailableError`).

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
from typing import Any

from saas_os.core.audit_identity.errors import (
    AuditIdentityIndexUnavailableError,
    InvalidAuditIdentityRequestError,
)
from saas_os.core.audit_log.models import AuditLogEntry
from saas_os.core.audit_log.subject_models import (
    TenantAuditIdentityHold,
    TenantAuditSubjectErasure,
    TenantAuditSubjectLink,
)
from saas_os.core.platform_authority.subject_models import (
    PlatformAuditIdentityHold,
    PlatformAuditSubjectErasure,
    PlatformAuditSubjectLink,
)
from saas_os.core.platform_authority.subjects import latest_subject_reference_use
from saas_os.core.tenancy import Tenant
from saas_os.infra.db import (
    Session,
    bind_tenant_scope,
    index_is_valid,
    json_text_at,
    max_,
    select,
    session_scope,
)
from saas_os.infra.db import now as db_now

RETENTION_YEARS = 2
PLATFORM_SCOPE = "platform"
TENANT_SCOPE_PREFIX = "tenant:"

# Phase P3b's partial expression indexes (migration `d4f8b2e6a9c1`), which the
# tenant record bound needs (docs/architecture/AUDIT-IDENTITY-P3-PLAN.md,
# section 3, M2, deployment order).
TENANT_REFERENCE_INDEXES = (
    "core.ix_audit_log_initiated_by_subject_ref",
    "core.ix_audit_log_owner_user_subject_ref",
)
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


type _AnyHold = PlatformAuditIdentityHold | TenantAuditIdentityHold
type _AnyLink = PlatformAuditSubjectLink | TenantAuditSubjectLink
type _AnyMarker = PlatformAuditSubjectErasure | TenantAuditSubjectErasure


def _covered(hold: _AnyHold, subject_ref: uuid.UUID, day: date) -> bool:
    return (
        (hold.subject_ref is None or hold.subject_ref == subject_ref)
        and (hold.from_day is None or hold.from_day <= day)
        and (hold.to_day is None or hold.to_day >= day)
    )


def _held(holds: Sequence[_AnyHold], link: _AnyLink) -> bool:
    return any(_covered(hold, link.subject_ref, link.subject_day) for hold in holds)


@dataclass(frozen=True)
class AuditIdentityPlan:
    as_of: datetime
    delete_refs: tuple[uuid.UUID, ...]
    unlink_refs: tuple[uuid.UUID, ...]
    marker_users: tuple[uuid.UUID, ...]
    active_holds: tuple[uuid.UUID, ...]
    oldest_eligible_day: date | None
    scope: str = PLATFORM_SCOPE


def tenant_scope(tenant_id: uuid.UUID) -> str:
    """The scope name of one tenant in reports and digests: `tenant:<id>`."""
    return f"{TENANT_SCOPE_PREFIX}{tenant_id}"


def _latest_day(as_of: datetime) -> date:
    """A superset of the days whose day bound can have passed: adding two
    years adds at least 730 days."""
    return as_of.astimezone(UTC).date() - timedelta(days=730)


def _decide(
    *,
    scope: str,
    as_of: datetime,
    holds: Sequence[_AnyHold],
    candidates: Sequence[_AnyLink],
    latest: dict[str, datetime],
    markers: Sequence[_AnyMarker],
    erased_links: Sequence[_AnyLink],
) -> AuditIdentityPlan:
    """The rule of the module docstring over rows already read: `candidates`
    are the links past their day bound and not held; `latest` the record
    bound per candidate; `erased_links` the live links of the markers'
    users."""
    deletable = [
        link
        for link in candidates
        if str(link.subject_ref) not in latest
        or record_past_retention(latest[str(link.subject_ref)], as_of)
    ]
    deleted = {link.subject_ref for link in deletable}
    unlinks: list[uuid.UUID] = []
    held_live_users: set[uuid.UUID] = set()
    for link in erased_links:
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
        scope=scope,
    )


def audit_identity_expiry_plan(
    session: Session, *, lock: bool, tenant_id: uuid.UUID | None = None
) -> AuditIdentityPlan:
    """The run's sets for the platform scope (`tenant_id` `None`) or for one
    tenant, decided with the database clock. With `lock`, every link and
    marker read is locked `FOR UPDATE` in key order. For a tenant, `session`
    must be bound to it (`bind_tenant_scope`), and the plan is refused
    (`AuditIdentityIndexUnavailableError`) while an index of
    `TENANT_REFERENCE_INDEXES` is missing or not valid."""
    if tenant_id is not None:
        return _tenant_plan(session, tenant_id=tenant_id, lock=lock)
    as_of = session.execute(select(db_now())).scalar_one()
    holds = list(
        session.execute(
            select(PlatformAuditIdentityHold)
            .where(PlatformAuditIdentityHold.released_at.is_(None))
            .order_by(PlatformAuditIdentityHold.id)
        ).scalars()
    )
    candidates_query = (
        select(PlatformAuditSubjectLink)
        .where(PlatformAuditSubjectLink.subject_day <= _latest_day(as_of))
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
    markers_query = select(PlatformAuditSubjectErasure).order_by(
        PlatformAuditSubjectErasure.user_id
    )
    if lock:
        markers_query = markers_query.with_for_update()
    markers = list(session.execute(markers_query).scalars())
    erased_links: list[PlatformAuditSubjectLink] = []
    if markers:
        live_query = (
            select(PlatformAuditSubjectLink)
            .where(PlatformAuditSubjectLink.user_id.in_([marker.user_id for marker in markers]))
            .order_by(PlatformAuditSubjectLink.subject_ref)
        )
        if lock:
            live_query = live_query.with_for_update()
        erased_links = list(session.execute(live_query).scalars())
    return _decide(
        scope=PLATFORM_SCOPE,
        as_of=as_of,
        holds=holds,
        candidates=candidates,
        latest=latest,
        markers=markers,
        erased_links=erased_links,
    )


# --- the tenant scope (phase P3c) ----------------------------------------------------------

# Where Core writes a tenant reference as user identification (phase P3a): a
# user initiator, OD-3's key owner, and `apply.py`'s operator. The first two
# are indexed by phase P3b; the third is rare (permission grant applications)
# and is read through the tenant's `ix_audit_log_tenant_created_at` rows, as
# the platform scope reads its unindexed metadata key.
_INITIATED_BY_KEYS = ("initiated_by", "subject_ref")
_OWNER_KEY = "owner_user_subject_ref"
_OPERATOR_KEY = "operator_user_subject_ref"
_REFERENCE_CHUNK = 500


def require_tenant_reference_indexes(session: Session) -> None:
    """Refuse a tenant plan while a phase P3b index is missing or invalid."""
    for qualified in TENANT_REFERENCE_INDEXES:
        if not index_is_valid(session, qualified):
            raise AuditIdentityIndexUnavailableError(qualified.split(".", 1)[1])


def latest_tenant_reference_use(
    session: Session, *, tenant_id: uuid.UUID, references: Sequence[str]
) -> dict[str, datetime]:
    """For each reference (canonical `str(uuid)`) of `tenant_id`, the latest
    `created_at` of the tenant's audit rows that carry it as user
    identification: `initiated_by.subject_ref`, `owner_user_subject_ref` or
    `operator_user_subject_ref`. A reference no row carries is absent. Read
    only; `session` must be bound to `tenant_id`, and every query also names
    it. The key paths are inlined (`json_text_at`) so that the phase P3b
    expression indexes match."""
    latest: dict[str, datetime] = {}
    for start in range(0, len(references), _REFERENCE_CHUNK):
        chunk = list(references[start : start + _REFERENCE_CHUNK])
        for query in tenant_reference_use_queries(tenant_id, chunk):
            for row in session.execute(query).all():
                reference, created_at = tuple(row)
                if isinstance(reference, str) and (
                    reference not in latest or latest[reference] < created_at
                ):
                    latest[reference] = created_at
    return latest


def tenant_reference_use_queries(tenant_id: uuid.UUID, references: Sequence[str]) -> list[Any]:
    """The record-bound queries of `latest_tenant_reference_use`, one per
    identifying location: `(reference, max(created_at))` grouped by
    reference. Separate so a test can check their query plans against the
    phase P3b indexes."""
    metadata = AuditLogEntry.entry_metadata
    queries = []
    for expression in (
        json_text_at(metadata, *_INITIATED_BY_KEYS),
        json_text_at(metadata, _OWNER_KEY),
        json_text_at(metadata, _OPERATOR_KEY),
    ):
        queries.append(
            select(expression, max_(AuditLogEntry.created_at))
            .where(AuditLogEntry.tenant_id == tenant_id, expression.in_(list(references)))
            .group_by(expression)
        )
    return queries


def _tenant_plan(session: Session, *, tenant_id: uuid.UUID, lock: bool) -> AuditIdentityPlan:
    require_tenant_reference_indexes(session)
    as_of = session.execute(select(db_now())).scalar_one()
    holds = list(
        session.execute(
            select(TenantAuditIdentityHold)
            .where(
                TenantAuditIdentityHold.tenant_id == tenant_id,
                TenantAuditIdentityHold.released_at.is_(None),
            )
            .order_by(TenantAuditIdentityHold.id)
        ).scalars()
    )
    candidates_query = (
        select(TenantAuditSubjectLink)
        .where(
            TenantAuditSubjectLink.tenant_id == tenant_id,
            TenantAuditSubjectLink.subject_day <= _latest_day(as_of),
        )
        .order_by(TenantAuditSubjectLink.subject_ref)
    )
    if lock:
        candidates_query = candidates_query.with_for_update()
    candidates = [
        link
        for link in session.execute(candidates_query).scalars()
        if link_day_bound(link.subject_day) <= as_of and not _held(holds, link)
    ]
    latest = latest_tenant_reference_use(
        session, tenant_id=tenant_id, references=[str(link.subject_ref) for link in candidates]
    )
    markers_query = (
        select(TenantAuditSubjectErasure)
        .where(TenantAuditSubjectErasure.tenant_id == tenant_id)
        .order_by(TenantAuditSubjectErasure.user_id)
    )
    if lock:
        markers_query = markers_query.with_for_update()
    markers = list(session.execute(markers_query).scalars())
    erased_links: list[TenantAuditSubjectLink] = []
    if markers:
        live_query = (
            select(TenantAuditSubjectLink)
            .where(
                TenantAuditSubjectLink.tenant_id == tenant_id,
                TenantAuditSubjectLink.user_id.in_([marker.user_id for marker in markers]),
            )
            .order_by(TenantAuditSubjectLink.subject_ref)
        )
        if lock:
            live_query = live_query.with_for_update()
        erased_links = list(session.execute(live_query).scalars())
    return _decide(
        scope=tenant_scope(tenant_id),
        as_of=as_of,
        holds=holds,
        candidates=candidates,
        latest=latest,
        markers=markers,
        erased_links=erased_links,
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
        scope=plan.scope,
        eligible_links=len(plan.delete_refs),
        eligible_links_digest=reference_set_digest(plan.scope, plan.delete_refs),
        links_to_unlink=len(plan.unlink_refs),
        markers=len(plan.marker_users),
        active_holds=len(plan.active_holds),
        active_holds_digest=hold_set_digest(plan.scope, plan.active_holds),
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


def tenant_ids(session: Session) -> list[uuid.UUID]:
    """Every tenant, in any status and in id order: a purged tenant keeps its
    tombstone row and its `SECURITY_RETAIN` reference tables (proposal
    4.3), so its links still expire."""
    return list(session.execute(select(Tenant.id).order_by(Tenant.id)).scalars())


def tenant_audit_identity_expiry_report(tenant_id: uuid.UUID) -> AuditIdentityExpiryReport:
    """The plan of one tenant, as the application role in a read-only
    transaction bound to that tenant (the scheduled report job; D7). Refused
    while a phase P3b index is missing or invalid."""
    with session_scope() as session, bind_tenant_scope(session, tenant_id):
        return expiry_report(audit_identity_expiry_plan(session, lock=False, tenant_id=tenant_id))


def all_tenant_ids() -> list[uuid.UUID]:
    """`tenant_ids()` in its own read-only transaction."""
    with session_scope() as session:
        return tenant_ids(session)


__all__ = [
    "HOLD_SET_PREFIX",
    "PLATFORM_SCOPE",
    "REFERENCE_SET_PREFIX",
    "RETENTION_YEARS",
    "TENANT_REFERENCE_INDEXES",
    "TENANT_SCOPE_PREFIX",
    "AuditIdentityExpiryReport",
    "AuditIdentityPlan",
    "all_tenant_ids",
    "audit_identity_expiry_plan",
    "audit_identity_expiry_report",
    "expiry_report",
    "hold_set_digest",
    "latest_tenant_reference_use",
    "link_day_bound",
    "record_expires_at",
    "record_past_retention",
    "reference_set_digest",
    "require_tenant_reference_indexes",
    "tenant_audit_identity_expiry_report",
    "tenant_ids",
    "tenant_reference_use_queries",
    "tenant_scope",
]
