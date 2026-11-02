"""Retention of the permission grant ledger (owner policy of 2026-11-02;
proposed ADR-0045 amendment of 2026-11-02).

`core.permission_grant_applications` is `SECURITY_RETAIN`
(`saas_os/core/tenancy/retention.py`): a tenant purge keeps its rows next
to the `PURGED` tombstone. This module decides *when* a tenant's rows may
expire, and records the legal holds that extend that. It deletes nothing,
and the runtime role has no `DELETE` on the ledger: expired rows are
deleted only by the manual procedure of owner decision B of 2026-11-02
(`saas_os.core.permission_grants.expiry`, run with the migrations database
role), which applies the same decision under lock.

**Expiry.** A tenant's ledger rows are eligible for expiry when, and only
when, all of these hold (`retention_eligibility`, a pure function):

1. the tenant's `core.tenants` row exists and its status is `purged` (the
   tombstone; `PURGED` is terminal);
2. exactly one piece of purge evidence exists: the `success` platform audit
   row of the `PURGING -> PURGED` transition
   (`platform.tenant.purge_transition`, metadata `to_status = purged`,
   actor `SystemCaller(TENANT_PURGE)`), which `transition_tenant_status()`
   writes in the same transaction as the status change. Its `created_at`
   is the purge time `T`. The runtime role cannot update or delete platform
   audit rows. No row (a purge recorded before ADR-0045 Phase C wrote that
   row) is `purge_time_unknown`; more than one is `purge_time_ambiguous`;
   both are retained, never eligible;
3. `now >= T + 2 years` (calendar years; a purge on 29 February expires on
   1 March, the later of the two candidates);
4. no legal hold on the tenant is active.

**Legal holds.** `core.permission_grant_ledger_holds` (migration
`a9c3e5f7b1d4`), a global platform table no tenant-scoped transaction can
see. A hold names the tenant and an opaque reference to the legal matter;
it is active until released, and a released hold stays as history. Placing
and releasing are platform operations (`permission_grant_ledger.hold_place`,
`permission_grant_ledger.hold_release`) under
`platform.security_retention_hold:manage`, each with one platform audit row
in the same transaction, whose id the hold row records. A hold may be placed on a
tenant in any status, before or after its purge.

**Report.** `permission_grant_ledger_retention_report` (operation
`permission_grant_ledger.retention_report`, permission
`platform.security_retention:report`) computes the decision for the
named tenants, or for every `PURGED` tenant, and counts each tenant's
ledger rows under that tenant's RLS scope. It writes one platform audit row
with counts and the eligible-row digest (`eligible_ledger_digest`), and
changes nothing else. Its output and its audit row hold ids, statuses,
times, counts and the digest: no name and no personal data. The deletion
procedure must be confirmed with that count and digest.

Every refusal (`PlatformNotAuthorizedError`, or a
`PermissionGrantLedgerRetentionError`) writes one `denied` platform row
after its rollback.
"""

from __future__ import annotations

import enum
import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from saas_os.core.permission_grants.errors import (
    InvalidLedgerRetentionRequestError,
    LedgerHoldAlreadyActiveError,
    LedgerHoldAlreadyReleasedError,
    LedgerHoldNotFoundError,
    LedgerHoldTenantNotFoundError,
    PermissionGrantLedgerRetentionError,
)
from saas_os.core.permission_grants.models import (
    PermissionGrantApplication,
    PermissionGrantLedgerHold,
)
from saas_os.core.platform_authority import (
    authorize_platform_caller,
    platform_change_session,
    platform_operation,
    record_platform_event_in_transaction,
    record_platform_refusal,
    recording_platform_refusal,
    validate_reason,
)
from saas_os.core.platform_authority.operations import (
    PERMISSION_GRANT_LEDGER_HOLD_PLACE,
    PERMISSION_GRANT_LEDGER_HOLD_RELEASE,
    PERMISSION_GRANT_LEDGER_RETENTION_REPORT,
)
from saas_os.core.platform_authority.purge_evidence import tenant_purge_completion_times
from saas_os.core.tenancy import Tenant, TenantStatus
from saas_os.infra.db import Session, bind_tenant_scope, select
from saas_os.infra.db import now as db_now

RETENTION_PERIOD_YEARS = 2
MAX_REPORT_TENANTS = 1000

_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
_LEDGER_TARGET = "permission_grant_ledger"
_HOLD_TARGET = "permission_grant_ledger_hold"


class RetentionStatus(enum.StrEnum):
    """The closed set of retention decisions for one tenant's ledger rows.
    Only `ELIGIBLE` allows expiry."""

    TENANT_NOT_FOUND = "tenant_not_found"
    NOT_PURGED = "not_purged"
    PURGE_TIME_UNKNOWN = "purge_time_unknown"
    PURGE_TIME_AMBIGUOUS = "purge_time_ambiguous"
    LEGAL_HOLD = "legal_hold"
    RETENTION_RUNNING = "retention_running"
    ELIGIBLE = "eligible"


@dataclass(frozen=True)
class RetentionDecision:
    """`purged_at` is the purge time `T` when exactly one piece of purge
    evidence exists, and `expires_at` is `T + 2 years`; otherwise both are
    `None`."""

    status: RetentionStatus
    purged_at: datetime | None = None
    expires_at: datetime | None = None

    @property
    def eligible(self) -> bool:
        return self.status is RetentionStatus.ELIGIBLE


def _require_aware(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise InvalidLedgerRetentionRequestError(f"{name} must be a datetime with a UTC offset.")
    return value


def retention_expires_at(purged_at: datetime) -> datetime:
    """`purged_at` plus `RETENTION_PERIOD_YEARS` calendar years, computed in
    UTC and returned in UTC: the calendar of the database session's time
    zone never decides the date. A purge on 29 February (UTC) expires on
    1 March of the target year (never earlier than the anniversary)."""
    purged_at = _require_aware(purged_at, "purged_at").astimezone(UTC)
    year = purged_at.year + RETENTION_PERIOD_YEARS
    try:
        return purged_at.replace(year=year)
    except ValueError:  # 29 February, target year not a leap year
        return purged_at.replace(year=year, month=2, day=28) + timedelta(days=1)


def retention_eligibility(
    *,
    tenant_status: str | None,
    purge_evidence: Sequence[datetime],
    active_holds: int,
    now: datetime,
) -> RetentionDecision:
    """The retention decision for one tenant's ledger rows (module
    docstring). Pure: no database, no clock. `tenant_status` is the
    tenant's `core.tenants.status`, or `None` when no row exists;
    `purge_evidence` the `created_at` of every `success` platform row of
    its `PURGING -> PURGED` transition; `active_holds` the number of its
    unreleased legal holds; `now` the time to decide at."""
    now = _require_aware(now, "now")
    if isinstance(active_holds, bool) or not isinstance(active_holds, int) or active_holds < 0:
        raise InvalidLedgerRetentionRequestError("active_holds must be a non-negative int.")
    if isinstance(purge_evidence, str | bytes) or not isinstance(purge_evidence, Sequence):
        raise InvalidLedgerRetentionRequestError("purge_evidence must be a sequence.")
    evidence = [_require_aware(item, "purge evidence") for item in purge_evidence]
    if tenant_status is None:
        return RetentionDecision(RetentionStatus.TENANT_NOT_FOUND)
    if tenant_status != TenantStatus.PURGED.value:
        return RetentionDecision(RetentionStatus.NOT_PURGED)
    if not evidence:
        return RetentionDecision(RetentionStatus.PURGE_TIME_UNKNOWN)
    if len(evidence) > 1:
        return RetentionDecision(RetentionStatus.PURGE_TIME_AMBIGUOUS)
    purged_at = evidence[0]
    expires_at = retention_expires_at(purged_at)
    if active_holds > 0:
        return RetentionDecision(RetentionStatus.LEGAL_HOLD, purged_at, expires_at)
    if now < expires_at:
        return RetentionDecision(RetentionStatus.RETENTION_RUNNING, purged_at, expires_at)
    return RetentionDecision(RetentionStatus.ELIGIBLE, purged_at, expires_at)


# --- database reads (the session must have no tenant bound) -----------------


def _tenant_status(session: Session, tenant_id: uuid.UUID) -> str | None:
    return session.execute(select(Tenant.status).where(Tenant.id == tenant_id)).scalar_one_or_none()


def _purge_evidence(session: Session, tenant_id: uuid.UUID) -> list[datetime]:
    """The purge times recorded for `tenant_id` (module docstring, step 2),
    read through the platform package (ADR-0045: only it touches the
    platform models)."""
    return tenant_purge_completion_times(session, tenant_id)


def _active_holds(session: Session, tenant_id: uuid.UUID) -> int:
    return len(
        session.execute(
            select(PermissionGrantLedgerHold.id).where(
                PermissionGrantLedgerHold.target_tenant_id == tenant_id,
                PermissionGrantLedgerHold.released_at.is_(None),
            )
        )
        .scalars()
        .all()
    )


def _ledger_row_ids(session: Session, tenant_id: uuid.UUID) -> tuple[uuid.UUID, ...]:
    """The ids of `tenant_id`'s ledger rows, read under its own RLS scope,
    in id order."""
    with bind_tenant_scope(session, tenant_id):
        return tuple(
            session.execute(
                select(PermissionGrantApplication.id)
                .where(PermissionGrantApplication.tenant_id == tenant_id)
                .order_by(PermissionGrantApplication.id)
            )
            .scalars()
            .all()
        )


def eligible_ledger_digest(rows: Mapping[uuid.UUID, Sequence[uuid.UUID]]) -> str:
    """SHA-256 (hex) of the canonical JSON of the eligible ledger rows:
    `[[tenant id, [row id, ...]], ...]`, tenants and rows in id order. The
    retention report records it; the deletion procedure recomputes it under
    lock and refuses unless the operator confirms exactly this value, so it
    deletes exactly the rows a prior report showed, or nothing."""
    canonical = [
        [str(tenant), sorted(str(row) for row in rows[tenant])] for tenant in sorted(rows, key=str)
    ]
    encoded = json.dumps(canonical, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


# --- the report ---------------------------------------------------------------


@dataclass(frozen=True)
class TenantLedgerRetention:
    """One tenant in the report: ids, a status, times and a count."""

    tenant_id: uuid.UUID
    status: RetentionStatus
    ledger_rows: int
    active_holds: int
    purged_at: datetime | None
    expires_at: datetime | None


@dataclass(frozen=True)
class LedgerRetentionReport:
    """`as_of` is the time the decisions were made at (the database's
    clock unless the caller gave one). `more` is true when `all_purged`
    stopped at `limit`: continue with `after` set to the last tenant id.
    `eligible_digest` is `eligible_ledger_digest` of the row ids of the
    eligible tenants that have ledger rows: with `eligible_ledger_rows`,
    what the deletion procedure must be confirmed with."""

    as_of: datetime
    tenants: tuple[TenantLedgerRetention, ...] = field(default_factory=tuple)
    more: bool = False
    eligible_digest: str = ""

    def status_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in RetentionStatus}
        for tenant in self.tenants:
            counts[tenant.status.value] += 1
        return counts

    @property
    def eligible_ledger_rows(self) -> int:
        return sum(t.ledger_rows for t in self.tenants if t.status is RetentionStatus.ELIGIBLE)


def _report_scope(
    tenant_ids: Sequence[uuid.UUID], all_purged: bool, after: uuid.UUID | None, limit: int
) -> tuple[uuid.UUID, ...] | None:
    if not isinstance(all_purged, bool):
        raise InvalidLedgerRetentionRequestError("all_purged must be a bool.")
    if isinstance(tenant_ids, str | bytes) or not isinstance(tenant_ids, Sequence):
        raise InvalidLedgerRetentionRequestError("tenant_ids must be a list or tuple.")
    if all_purged == bool(tenant_ids):
        raise InvalidLedgerRetentionRequestError("Name the tenants or all_purged, not both.")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 < limit <= MAX_REPORT_TENANTS:
        raise InvalidLedgerRetentionRequestError(
            f"limit must be an int from 1 to {MAX_REPORT_TENANTS}."
        )
    if after is not None and (not all_purged or not isinstance(after, uuid.UUID)):
        raise InvalidLedgerRetentionRequestError("after is a uuid.UUID, with all_purged only.")
    if all_purged:
        return None
    if not all(isinstance(t, uuid.UUID) for t in tenant_ids):
        raise InvalidLedgerRetentionRequestError("Every tenant id must be a uuid.UUID.")
    named = tuple(dict.fromkeys(tenant_ids))
    if len(named) > MAX_REPORT_TENANTS:
        raise InvalidLedgerRetentionRequestError(
            f"At most {MAX_REPORT_TENANTS} named tenants; use all_purged."
        )
    return named


def _purged_tenants(
    session: Session, after: uuid.UUID | None, limit: int
) -> tuple[tuple[uuid.UUID, ...], bool]:
    query = select(Tenant.id).where(Tenant.status == TenantStatus.PURGED.value)
    if after is not None:
        query = query.where(Tenant.id > after)
    ids = tuple(session.execute(query.order_by(Tenant.id).limit(limit + 1)).scalars().all())
    return ids[:limit], len(ids) > limit


def permission_grant_ledger_retention_report(
    *,
    caller: object,
    reason: str,
    tenant_ids: Sequence[uuid.UUID] = (),
    all_purged: bool = False,
    after: uuid.UUID | None = None,
    limit: int = MAX_REPORT_TENANTS,
    as_of: datetime | None = None,
) -> LedgerRetentionReport:
    """The retention decision for each named tenant, or with `all_purged`
    for every `PURGED` tenant (in id order, at most `limit`, after `after`).
    Read only: it changes nothing but writes one platform audit row with
    counts. `as_of` overrides the database clock (the value is recorded,
    in UTC, in the audit row); the operator command never sets it, and no
    deletion may ever rely on a report made with `as_of`."""
    operation = PERMISSION_GRANT_LEDGER_RETENTION_REPORT
    spec = platform_operation(operation)
    try:
        named = _report_scope(tenant_ids, all_purged, after, limit)
        if as_of is not None:
            _require_aware(as_of, "as_of")
        reason = validate_reason(reason)
        with (
            recording_platform_refusal(
                caller=caller, operation=operation, target_type=_LEDGER_TARGET
            ),
            platform_change_session(caller, operation) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=operation)
            decided_at = (
                as_of if as_of is not None else session.execute(select(db_now())).scalar_one()
            )
            more = False
            if named is None:
                targets, more = _purged_tenants(session, after, limit)
            else:
                targets = named
            tenants: list[TenantLedgerRetention] = []
            eligible_rows: dict[uuid.UUID, tuple[uuid.UUID, ...]] = {}
            for tenant_id in targets:
                status = _tenant_status(session, tenant_id)
                holds = _active_holds(session, tenant_id) if status is not None else 0
                decision = retention_eligibility(
                    tenant_status=status,
                    purge_evidence=_purge_evidence(session, tenant_id),
                    active_holds=holds,
                    now=decided_at,
                )
                row_ids = _ledger_row_ids(session, tenant_id) if status is not None else ()
                if decision.eligible and row_ids:
                    eligible_rows[tenant_id] = row_ids
                tenants.append(
                    TenantLedgerRetention(
                        tenant_id=tenant_id,
                        status=decision.status,
                        ledger_rows=len(row_ids),
                        active_holds=holds,
                        purged_at=decision.purged_at,
                        expires_at=decision.expires_at,
                    )
                )
            report = LedgerRetentionReport(
                decided_at, tuple(tenants), more, eligible_ledger_digest(eligible_rows)
            )
            metadata: dict[str, object] = {
                "scope": "all_purged" if named is None else "tenants",
                "tenants": len(report.tenants),
                "more": more,
                "retention_years": RETENTION_PERIOD_YEARS,
                "as_of_overridden": as_of is not None,
                # The overriding time itself, so a report made "as of" some
                # other moment is never mistaken for one made now.
                "as_of": as_of.astimezone(UTC).isoformat() if as_of is not None else None,
                "ledger_rows": sum(t.ledger_rows for t in report.tenants),
                "eligible_ledger_rows": report.eligible_ledger_rows,
                "eligible_digest": report.eligible_digest,
            }
            for key, value in report.status_counts().items():
                metadata[f"tenants_{key}"] = value
            single = named[0] if named is not None and len(named) == 1 else None
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=_LEDGER_TARGET,
                target_tenant_id=single
                if single is not None and tenants[0].status is not RetentionStatus.TENANT_NOT_FOUND
                else None,
                reason=reason,
                metadata=metadata,
            )
    except PermissionGrantLedgerRetentionError as refused:
        record_platform_refusal(
            caller=caller, action=spec.audit_action, target_type=_LEDGER_TARGET, code=refused.code
        )
        raise
    return report


# --- legal holds ----------------------------------------------------------------


@dataclass(frozen=True)
class LedgerHoldResult:
    """A hold placed or released: `platform_audit_id` is the id of the
    platform audit row of this act, which the hold row records."""

    hold_id: uuid.UUID
    tenant_id: uuid.UUID
    reference: str
    placed_at: datetime
    released_at: datetime | None
    platform_audit_id: uuid.UUID


def _validated_reference(reference: object) -> str:
    if not isinstance(reference, str) or _REFERENCE.fullmatch(reference) is None:
        raise InvalidLedgerRetentionRequestError(
            "reference must be 1 to 100 characters: letters, digits and . _ : - "
            "(an opaque matter reference, never a name)."
        )
    return reference


def place_permission_grant_ledger_hold(
    tenant_id: uuid.UUID, *, reference: str, caller: object, reason: str
) -> LedgerHoldResult:
    """Place a legal hold on `tenant_id`'s ledger rows: while it is active
    they never become eligible for expiry. The tenant must exist (any
    status). One platform audit row, in the same transaction; its id is
    the hold's `placed_by_platform_audit_id`."""
    operation = PERMISSION_GRANT_LEDGER_HOLD_PLACE
    spec = platform_operation(operation)
    target_id = str(tenant_id) if isinstance(tenant_id, uuid.UUID) else None
    try:
        if not isinstance(tenant_id, uuid.UUID):
            raise InvalidLedgerRetentionRequestError("tenant_id must be a uuid.UUID.")
        reference = _validated_reference(reference)
        reason = validate_reason(reason)
        with (
            recording_platform_refusal(
                caller=caller, operation=operation, target_type=_HOLD_TARGET, target_id=target_id
            ),
            platform_change_session(caller, operation) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=operation)
            # The tenant row is locked so that the hold and the existence
            # check see the same tenant; `core.tenants` is never deleted.
            if (
                session.execute(
                    select(Tenant.id).where(Tenant.id == tenant_id).with_for_update()
                ).scalar_one_or_none()
                is None
            ):
                raise LedgerHoldTenantNotFoundError(tenant_id)
            active = session.execute(
                select(PermissionGrantLedgerHold.id).where(
                    PermissionGrantLedgerHold.target_tenant_id == tenant_id,
                    PermissionGrantLedgerHold.reference == reference,
                    PermissionGrantLedgerHold.released_at.is_(None),
                )
            ).scalar_one_or_none()
            if active is not None:
                raise LedgerHoldAlreadyActiveError(tenant_id, reference)
            audit_id = uuid.uuid4()
            hold = PermissionGrantLedgerHold(
                target_tenant_id=tenant_id,
                reference=reference,
                placed_by_platform_audit_id=audit_id,
            )
            session.add(hold)
            session.flush()
            session.refresh(hold)
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=_HOLD_TARGET,
                target_id=str(hold.id),
                target_tenant_id=tenant_id,
                reason=reason,
                metadata={"hold_id": str(hold.id), "reference": reference},
                entry_id=audit_id,
            )
            return LedgerHoldResult(
                hold_id=hold.id,
                tenant_id=tenant_id,
                reference=reference,
                placed_at=hold.placed_at,
                released_at=None,
                platform_audit_id=audit_id,
            )
    except PermissionGrantLedgerRetentionError as refused:
        record_platform_refusal(
            caller=caller,
            action=spec.audit_action,
            target_type=_HOLD_TARGET,
            target_id=target_id,
            code=refused.code,
        )
        raise


def release_permission_grant_ledger_hold(
    hold_id: uuid.UUID, *, caller: object, reason: str
) -> LedgerHoldResult:
    """Release an active legal hold. The hold row stays, with the release
    time and the id of the platform audit row written in the same
    transaction. Releasing makes nothing eligible by itself: the other
    conditions still apply, and no deletion follows from it."""
    operation = PERMISSION_GRANT_LEDGER_HOLD_RELEASE
    spec = platform_operation(operation)
    target_id = str(hold_id) if isinstance(hold_id, uuid.UUID) else None
    try:
        if not isinstance(hold_id, uuid.UUID):
            raise InvalidLedgerRetentionRequestError("hold_id must be a uuid.UUID.")
        reason = validate_reason(reason)
        with (
            recording_platform_refusal(
                caller=caller, operation=operation, target_type=_HOLD_TARGET, target_id=target_id
            ),
            platform_change_session(caller, operation) as session,
        ):
            authorize_platform_caller(caller, session=session, operation=operation)
            hold = session.get(PermissionGrantLedgerHold, hold_id, with_for_update=True)
            if hold is None:
                raise LedgerHoldNotFoundError(hold_id)
            if hold.released_at is not None:
                raise LedgerHoldAlreadyReleasedError(hold_id)
            audit_id = uuid.uuid4()
            hold.released_at = session.execute(select(db_now())).scalar_one()
            hold.released_by_platform_audit_id = audit_id
            session.flush()
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=_HOLD_TARGET,
                target_id=str(hold.id),
                target_tenant_id=hold.target_tenant_id,
                reason=reason,
                metadata={"hold_id": str(hold.id), "reference": hold.reference},
                entry_id=audit_id,
            )
            return LedgerHoldResult(
                hold_id=hold.id,
                tenant_id=hold.target_tenant_id,
                reference=hold.reference,
                placed_at=hold.placed_at,
                released_at=hold.released_at,
                platform_audit_id=audit_id,
            )
    except PermissionGrantLedgerRetentionError as refused:
        record_platform_refusal(
            caller=caller,
            action=spec.audit_action,
            target_type=_HOLD_TARGET,
            target_id=target_id,
            code=refused.code,
        )
        raise
