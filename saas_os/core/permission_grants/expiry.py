"""Deleting expired permission grant ledger rows: the controlled manual
procedure of owner decision B of 2026-11-02 (ADR-0045 amendment of
2026-11-02; `docs/RUNBOOKS.md`, "Deleting expired permission grant ledger
rows").

**Deletion is disabled** (owner decision of 2026-11-02, separation of
duties). The operator this procedure names is *declared* by whoever holds
the migrations credential, as every `saas-os-operator` command's
`--operator` is declared by whoever holds the application credential;
neither is an authenticated identity. So nothing here can verify that the
person authorising a deletion did not release a legal hold on the same
rows, or that an approver is a different person from the executor. Until
a verifiable approval control is approved and built, `apply=True` is
refused with `LedgerDeletionDisabledError` (code `deletion_disabled`, one
`denied` platform audit row) before any database connection for the run,
and nothing is deleted. The dry run (report) is unchanged. The deletion
steps below are kept, behind the module constant `_DELETION_ENABLED`
(`False`; no setting, argument or environment variable changes it), and
are exercised by integration tests that switch it on in-process, so the
mechanism stays correct for the control it will sit behind.

Not a runtime capability. There is no platform permission for deletion, and
the runtime role keeps no `DELETE` on `core.permission_grant_applications`.
`expire_permission_grant_ledger_rows` opens its transaction **only** on the
migrations database role (`saas_os.infra.db.migrations_role`, which refuses
any connection that is not the ledger's owner or that is the application
role), and is run by an operator with `python -m
saas_os.ops.permission_grant_ledger_expiry`. No purge step, job, route or
other Core path calls it (`tests/architecture/test_migrations_role_boundary.py`).

One transaction, in this order:

1. **The declared operator.** `authorize_platform_caller` for the
   operation `permission_grant_ledger.expired_delete`: the named user must
   be an enrolled, active platform operator holding
   `platform.security_retention:report`. This is a declaration recorded
   in the audit rows, not an authenticated identity: whoever holds the
   migrations credential names the operator, and could name anyone who
   holds the permission. It is not what allows the deletion (the
   migrations role is); the controls are that credential and the audit
   record.
2. **The lock** (with `apply`): every tenant row in scope `FOR UPDATE`, in
   id order. Placing a hold locks the same tenant row first
   (`place_permission_grant_ledger_hold`), so a hold placed concurrently is
   either seen here or placed after this transaction commits.
3. **The decision again**, under that lock, with the database clock (never
   an `as_of`): `retention_eligibility` from the tenant's status, its purge
   evidence and its active holds, exactly as the report decides. Only
   `ELIGIBLE` tenants are deleted from; every other status keeps its rows.
4. **The confirmation** (with `apply`): the number of eligible rows and
   their digest (`eligible_ledger_digest`) must equal what the operator
   confirmed from a prior report; otherwise `confirmation_mismatch` and
   nothing is deleted (nothing eligible never matches: a confirmation
   names at least one row).
5. **The deletion**, per tenant inside its own RLS scope
   (`bind_tenant_scope`), by row id; each tenant must lose exactly the rows
   counted, or the whole transaction rolls back.
6. **The evidence**, in the same transaction: one platform audit row for
   the run (its id is the run id: counts, the digest, the decision time)
   and one per tenant (the tenant, the run id, the rows deleted, the purge
   and expiry times). Ids, counts and times only; no name.

Without `apply` the same transaction only reports (steps 1 and 3) and
writes nothing. A refusal writes one `denied` platform row (code
`not_authorized`, `invalid_request`, `deletion_disabled` or
`confirmation_mismatch`), on the
same migrations-role connection, in a transaction of its own; a refused
connection writes nothing.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from saas_os.core.permission_grants.errors import (
    InvalidLedgerRetentionRequestError,
    LedgerDeletionDisabledError,
    LedgerExpiryConfirmationMismatchError,
    PermissionGrantLedgerRetentionError,
)
from saas_os.core.permission_grants.models import PermissionGrantApplication
from saas_os.core.permission_grants.retention import (
    MAX_REPORT_TENANTS,
    RETENTION_PERIOD_YEARS,
    RetentionStatus,
    _active_holds,
    _ledger_row_ids,
    _purge_evidence,
    _purged_tenants,
    _report_scope,
    _tenant_status,
    eligible_ledger_digest,
    retention_eligibility,
)
from saas_os.core.platform_authority import (
    PlatformAuditOutcome,
    PlatformRefusalError,
    authorize_platform_caller,
    platform_operation,
    record_platform_event_in_transaction,
    validate_reason,
)
from saas_os.core.platform_authority.operations import PERMISSION_GRANT_LEDGER_EXPIRED_DELETE
from saas_os.core.tenancy import Tenant
from saas_os.infra.db import Session, bind_tenant_scope, delete, select
from saas_os.infra.db import now as db_now
from saas_os.infra.db.migrations_role import migrations_role_session_scope

logger = logging.getLogger(__name__)

LEDGER_TABLE = "core.permission_grant_applications"
_TARGET = "permission_grant_ledger"
_DIGEST = re.compile(r"[0-9a-f]{64}")

# Separation of duties (module docstring): deletion stays off until a
# verifiable approval control exists. Deliberately a module constant, not a
# setting: switching it on is a reviewed code change. Integration tests
# switch it on in-process to keep the deletion steps verified.
_DELETION_ENABLED = False


@dataclass(frozen=True)
class ExpiredLedgerTenant:
    """One eligible tenant with ledger rows: its rows (counted, or deleted
    with `apply`) and the times its eligibility was decided from. An
    eligible tenant without ledger rows is not part of a run."""

    tenant_id: uuid.UUID
    ledger_rows: int
    purged_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class LedgerExpiryResult:
    """`applied` is false for a dry run, which deleted and wrote nothing.
    `run_id` is the id of the run's platform audit row (with `apply`).
    `not_eligible` counts the other tenants in scope by status."""

    as_of: datetime
    applied: bool
    eligible: tuple[ExpiredLedgerTenant, ...]
    eligible_ledger_rows: int
    eligible_digest: str
    not_eligible: dict[str, int] = field(default_factory=dict)
    more: bool = False
    run_id: uuid.UUID | None = None


def _confirmation(apply: object, confirm_rows: object, confirm_digest: object) -> None:
    if not isinstance(apply, bool):
        raise InvalidLedgerRetentionRequestError("apply must be a bool.")
    if not apply:
        if confirm_rows is not None or confirm_digest is not None:
            raise InvalidLedgerRetentionRequestError("A confirmation goes with apply only.")
        return
    if isinstance(confirm_rows, bool) or not isinstance(confirm_rows, int) or confirm_rows < 1:
        raise InvalidLedgerRetentionRequestError(
            "apply needs confirm_rows: the eligible row count of a prior report."
        )
    if not isinstance(confirm_digest, str) or _DIGEST.fullmatch(confirm_digest) is None:
        raise InvalidLedgerRetentionRequestError(
            "apply needs confirm_digest: the eligible digest of a prior report."
        )


def _record_denied(caller: object, code: str) -> None:
    """Best effort, never raises: the refusal must reach the operator. A
    caller that is not a person or a system purpose (a service account) is
    refused by `record_platform_event_in_transaction` and not recorded."""
    try:
        with migrations_role_session_scope(owned_table=LEDGER_TABLE) as session:
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=platform_operation(PERMISSION_GRANT_LEDGER_EXPIRED_DELETE).audit_action,
                target_type=_TARGET,
                outcome=PlatformAuditOutcome.DENIED,
                reason=code,
            )
    except Exception:  # noqa: BLE001 -- best effort by contract
        logger.warning("ledger_expiry_refusal_audit_failed", extra={"code": code}, exc_info=True)


def _decide(
    session: Session, targets: Sequence[uuid.UUID], decided_at: datetime
) -> tuple[dict[uuid.UUID, tuple[uuid.UUID, ...]], list[ExpiredLedgerTenant], dict[str, int]]:
    rows: dict[uuid.UUID, tuple[uuid.UUID, ...]] = {}
    eligible: list[ExpiredLedgerTenant] = []
    not_eligible: dict[str, int] = {}
    for tenant_id in targets:
        status = _tenant_status(session, tenant_id)
        decision = retention_eligibility(
            tenant_status=status,
            purge_evidence=_purge_evidence(session, tenant_id),
            active_holds=_active_holds(session, tenant_id) if status is not None else 0,
            now=decided_at,
        )
        if decision.status is not RetentionStatus.ELIGIBLE:
            not_eligible[decision.status.value] = not_eligible.get(decision.status.value, 0) + 1
            continue
        assert decision.purged_at is not None and decision.expires_at is not None
        ids = _ledger_row_ids(session, tenant_id)
        if not ids:  # eligible, but nothing to delete: not part of the run
            continue
        rows[tenant_id] = ids
        eligible.append(
            ExpiredLedgerTenant(tenant_id, len(ids), decision.purged_at, decision.expires_at)
        )
    return rows, eligible, not_eligible


def expire_permission_grant_ledger_rows(
    *,
    caller: object,
    reason: str,
    tenant_ids: Sequence[uuid.UUID] = (),
    all_purged: bool = False,
    after: uuid.UUID | None = None,
    limit: int = MAX_REPORT_TENANTS,
    apply: bool = False,
    confirm_rows: int | None = None,
    confirm_digest: str | None = None,
) -> LedgerExpiryResult:
    """Report (default) or -- once deletion is enabled, which it is not
    (module docstring) -- with `apply` and a matching confirmation, delete
    the expired ledger rows of the named tenants or of every `PURGED`
    tenant (in id order, at most `limit`, after `after`). Module docstring:
    the migrations role only, one transaction, the decision re-checked
    under lock, audited in the same transaction."""
    operation = PERMISSION_GRANT_LEDGER_EXPIRED_DELETE
    spec = platform_operation(operation)
    try:
        named = _report_scope(tenant_ids, all_purged, after, limit)
        _confirmation(apply, confirm_rows, confirm_digest)
        reason = validate_reason(reason)
        if apply and not _DELETION_ENABLED:
            raise LedgerDeletionDisabledError()
        with migrations_role_session_scope(owned_table=LEDGER_TABLE) as session:
            authorize_platform_caller(caller, session=session, operation=operation)
            more = False
            if named is None:
                targets, more = _purged_tenants(session, after, limit)
            else:
                targets = named
            if apply:
                # Step 2: the tenant rows, in id order (module docstring).
                session.execute(
                    select(Tenant.id)
                    .where(Tenant.id.in_(targets))
                    .order_by(Tenant.id)
                    .with_for_update()
                ).all()
            decided_at = session.execute(select(db_now())).scalar_one()
            rows, eligible, not_eligible = _decide(session, targets, decided_at)
            total = sum(len(ids) for ids in rows.values())
            digest = eligible_ledger_digest(rows)
            result = LedgerExpiryResult(
                as_of=decided_at,
                applied=False,
                eligible=tuple(eligible),
                eligible_ledger_rows=total,
                eligible_digest=digest,
                not_eligible=not_eligible,
                more=more,
            )
            if not apply:
                return result
            # `confirm_rows` is at least 1, so nothing eligible never matches.
            if confirm_rows != total or confirm_digest != digest:
                raise LedgerExpiryConfirmationMismatchError()
            for tenant_id, ids in rows.items():
                with bind_tenant_scope(session, tenant_id):
                    deleted = (
                        session.execute(
                            delete(PermissionGrantApplication)
                            .where(
                                PermissionGrantApplication.tenant_id == tenant_id,
                                PermissionGrantApplication.id.in_(ids),
                            )
                            .returning(PermissionGrantApplication.id)
                        )
                        .scalars()
                        .all()
                    )
                if sorted(deleted) != sorted(ids):
                    raise RuntimeError("The ledger changed under the deletion; rolled back.")
            run_id = uuid.uuid4()
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=spec.audit_action,
                target_type=_TARGET,
                reason=reason,
                metadata={
                    "phase": "run",
                    "scope": "all_purged" if named is None else "tenants",
                    "tenants": len(eligible),
                    "deleted_ledger_rows": total,
                    "eligible_digest": digest,
                    "as_of": decided_at.astimezone(UTC).isoformat(),
                    "retention_years": RETENTION_PERIOD_YEARS,
                    "not_eligible": not_eligible,
                },
                entry_id=run_id,
            )
            for tenant in eligible:
                record_platform_event_in_transaction(
                    session,
                    caller=caller,
                    action=spec.audit_action,
                    target_type=_TARGET,
                    target_id=str(tenant.tenant_id),
                    target_tenant_id=tenant.tenant_id,
                    reason=reason,
                    metadata={
                        "phase": "tenant",
                        "run_id": str(run_id),
                        "deleted_ledger_rows": tenant.ledger_rows,
                        "purged_at": tenant.purged_at.astimezone(UTC).isoformat(),
                        "expires_at": tenant.expires_at.astimezone(UTC).isoformat(),
                    },
                )
            return LedgerExpiryResult(
                as_of=decided_at,
                applied=True,
                eligible=tuple(eligible),
                eligible_ledger_rows=total,
                eligible_digest=digest,
                not_eligible=not_eligible,
                more=more,
                run_id=run_id,
            )
    except (PermissionGrantLedgerRetentionError, PlatformRefusalError) as refused:
        _record_denied(caller, refused.code)
        raise
