"""Expiry of audit subject links and erasure markers: the platform scope
(audit identity phase P2) and one tenant at a time (phase P3c)
(docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections 4.8,
4.10 and 4.11; owner decisions D4, D7, D8, O9 and O10, and the exact
two-year rule kept on 2026-11-03). A tenant scope runs in its own
transaction with the tenant bound: the tenant tables are under FORCE row-level
security, which binds the migrations role too; its platform rows are written
outside the bound block (ADR-0045 section 9c).

**`--apply` is disabled (owner decision O9).** "Ledger expiry `--apply`
stays disabled until an authenticated, register-eligible approval mechanism
is implemented, independently reviewed and tested." `apply=True` is refused
with `AuditIdentityExpiryDisabledError` before any database connection is
opened, while the module constant `_APPLY_ENABLED` is `False`; no setting,
argument or environment variable changes it, and only a separate,
owner-approved code change may flip it. The apply steps below are kept and
are exercised by integration tests that switch the constant on in-process,
so the mechanism stays correct for the control it will sit behind. Until
then links and markers are kept beyond two years (towards retention).

The rule, the eligible sets and the digests are
`saas_os.core.audit_identity.plan` (read only, also used by the report job).

**Report (default).** Without `apply`, `expire_audit_identity_links` runs on
the migrations role, authorises the declared operator for
`audit_identity.expiry` (`platform.security_retention:report`) and returns
the counts and digests of the plan; it writes nothing.

**Apply (when enabled).** A start platform row is committed first; then one
migrations-role transaction takes the platform hold lock `H` shared,
recomputes the plan with the rows locked `FOR UPDATE`, refuses
(`confirmation_mismatch`, nothing changed) unless the deleted-link count
and digest, the hold digest, the unlink count and the marker count equal
the confirmation, deletes the links, unlinks, deletes the markers and
writes its scope row with the counts and the digest; a finish row closes
the run. The operator is declared, not authenticated: the control is the
migrations credential.

Not a runtime capability: no route, job or product imports this module
(import-linter, "Ledger expiry is not an application-runtime capability").
It may name the link tables (owner decision O11, interim:
`tests/architecture/test_audit_subject_link_boundary.py`). Its output holds
counts, digests, a day and hold ids: never a user id and never a reference.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC

from saas_os.core.audit_identity.errors import (
    AuditIdentityExpiryConfirmationMismatchError,
    AuditIdentityExpiryDisabledError,
    AuditIdentityRetentionError,
    InvalidAuditIdentityRequestError,
)
from saas_os.core.audit_identity.plan import (
    PLATFORM_SCOPE,
    RETENTION_YEARS,
    AuditIdentityExpiryReport,
    AuditIdentityPlan,
    audit_identity_expiry_plan,
    expiry_report,
    hold_set_digest,
    reference_set_digest,
    tenant_scope,
)
from saas_os.core.audit_log.subject_models import (
    TenantAuditSubjectErasure,
    TenantAuditSubjectLink,
)
from saas_os.core.audit_log.subjects import TENANT_HOLDS_LOCK_NAMESPACE, tenant_holds_lock_key
from saas_os.core.platform_authority import (
    PlatformAuditOutcome,
    PlatformRefusalError,
    authorize_platform_caller,
    platform_operation,
    record_platform_event_in_transaction,
    validate_reason,
)
from saas_os.core.platform_authority.operations import AUDIT_IDENTITY_EXPIRY
from saas_os.core.platform_authority.subject_models import (
    PlatformAuditSubjectErasure,
    PlatformAuditSubjectLink,
)
from saas_os.core.platform_authority.subjects import (
    PLATFORM_HOLDS_LOCK_KEY,
    PLATFORM_HOLDS_LOCK_NAMESPACE,
)
from saas_os.infra.db import (
    Session,
    acquire_global_advisory_lock,
    bind_tenant_scope,
    delete,
    select,
)
from saas_os.infra.db.migrations_role import migrations_role_session_scope

logger = logging.getLogger(__name__)

LINKS_TABLE = "core.platform_audit_subject_links"
EXPIRY_TARGET_TYPE = "audit_identity_expiry"

_DIGEST = re.compile(r"[0-9a-f]{64}")
_UNLINK_REASON_ERASURE = "erasure"

# Owner decision O9 (module docstring): deliberately a module constant, not a
# setting; switching it on is a separate, owner-approved code change.
# Integration tests switch it on in-process to keep the apply steps verified.
_APPLY_ENABLED = False


# --- the command ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExpiryConfirmation:
    """What an apply confirms, copied from a dry-run report."""

    rows: int
    digest: str
    holds: str
    unlinks: int
    markers: int


def _validated_confirmation(apply: object, confirmation: object) -> ExpiryConfirmation | None:
    if not isinstance(apply, bool):
        raise InvalidAuditIdentityRequestError("apply must be a bool.")
    if not apply:
        if confirmation is not None:
            raise InvalidAuditIdentityRequestError("A confirmation goes with apply only.")
        return None
    if not isinstance(confirmation, ExpiryConfirmation):
        raise InvalidAuditIdentityRequestError(
            "apply needs the confirmation of a prior dry run: rows, digest, holds, "
            "unlinks and markers."
        )
    for count in (confirmation.rows, confirmation.unlinks, confirmation.markers):
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvalidAuditIdentityRequestError("a confirmed count must be an integer >= 0.")
    for digest in (confirmation.digest, confirmation.holds):
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise InvalidAuditIdentityRequestError(
                "a confirmed digest must be 64 lowercase hexadecimal characters."
            )
    return confirmation


def _record(
    session: Session,
    caller: object,
    reason: str,
    metadata: dict[str, object],
    *,
    entry_id: uuid.UUID | None = None,
) -> None:
    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(AUDIT_IDENTITY_EXPIRY).audit_action,
        target_type=EXPIRY_TARGET_TYPE,
        reason=reason,
        metadata=metadata,
        entry_id=entry_id,
    )


def _record_denied(caller: object, code: str) -> None:
    """Best effort, never raises; on the migrations role, its own
    transaction."""
    try:
        with migrations_role_session_scope(owned_table=LINKS_TABLE) as session:
            record_platform_event_in_transaction(
                session,
                caller=caller,
                action=platform_operation(AUDIT_IDENTITY_EXPIRY).audit_action,
                target_type=EXPIRY_TARGET_TYPE,
                outcome=PlatformAuditOutcome.DENIED,
                reason=code,
            )
    except Exception:  # noqa: BLE001 -- best effort by contract
        logger.warning("audit_identity_expiry_refusal_audit_failed", extra={"code": code})


def _matches(plan: AuditIdentityPlan, confirmation: ExpiryConfirmation) -> bool:
    return (
        confirmation.rows == len(plan.delete_refs)
        and confirmation.digest == reference_set_digest(plan.scope, plan.delete_refs)
        and confirmation.holds == hold_set_digest(plan.scope, plan.active_holds)
        and confirmation.unlinks == len(plan.unlink_refs)
        and confirmation.markers == len(plan.marker_users)
    )


def _apply(session: Session, plan: AuditIdentityPlan) -> None:
    if plan.delete_refs:
        deleted = (
            session.execute(
                delete(PlatformAuditSubjectLink)
                .where(PlatformAuditSubjectLink.subject_ref.in_(plan.delete_refs))
                .returning(PlatformAuditSubjectLink.subject_ref)
            )
            .scalars()
            .all()
        )
        if sorted(deleted) != sorted(plan.delete_refs):
            raise RuntimeError("The links changed under the run; rolled back.")
    unlinked_at = plan.as_of
    for reference in plan.unlink_refs:
        link = session.get(PlatformAuditSubjectLink, reference)
        if link is None or link.user_id is None:
            raise RuntimeError("The links changed under the run; rolled back.")
        link.user_id = None
        link.unlinked_at = unlinked_at
        link.unlink_reason = _UNLINK_REASON_ERASURE
    session.flush()
    if plan.marker_users:
        removed = (
            session.execute(
                delete(PlatformAuditSubjectErasure)
                .where(PlatformAuditSubjectErasure.user_id.in_(plan.marker_users))
                .returning(PlatformAuditSubjectErasure.user_id)
            )
            .scalars()
            .all()
        )
        if sorted(removed) != sorted(plan.marker_users):
            raise RuntimeError("The markers changed under the run; rolled back.")


def _apply_tenant(session: Session, plan: AuditIdentityPlan, tenant_id: uuid.UUID) -> None:
    """`_apply` for one tenant, in a transaction bound to it; every statement
    also names the tenant."""
    if plan.delete_refs:
        deleted = (
            session.execute(
                delete(TenantAuditSubjectLink)
                .where(
                    TenantAuditSubjectLink.tenant_id == tenant_id,
                    TenantAuditSubjectLink.subject_ref.in_(plan.delete_refs),
                )
                .returning(TenantAuditSubjectLink.subject_ref)
            )
            .scalars()
            .all()
        )
        if sorted(deleted) != sorted(plan.delete_refs):
            raise RuntimeError("The links changed under the run; rolled back.")
    unlinked_at = plan.as_of
    for reference in plan.unlink_refs:
        link = session.execute(
            select(TenantAuditSubjectLink).where(
                TenantAuditSubjectLink.tenant_id == tenant_id,
                TenantAuditSubjectLink.subject_ref == reference,
            )
        ).scalar_one_or_none()
        if link is None or link.user_id is None:
            raise RuntimeError("The links changed under the run; rolled back.")
        link.user_id = None
        link.unlinked_at = unlinked_at
        link.unlink_reason = _UNLINK_REASON_ERASURE
    session.flush()
    if plan.marker_users:
        removed = (
            session.execute(
                delete(TenantAuditSubjectErasure)
                .where(
                    TenantAuditSubjectErasure.tenant_id == tenant_id,
                    TenantAuditSubjectErasure.user_id.in_(plan.marker_users),
                )
                .returning(TenantAuditSubjectErasure.user_id)
            )
            .scalars()
            .all()
        )
        if sorted(removed) != sorted(plan.marker_users):
            raise RuntimeError("The markers changed under the run; rolled back.")


def _lock_scope_holds(session: Session, tenant_id: uuid.UUID | None) -> None:
    if tenant_id is None:
        acquire_global_advisory_lock(
            session, PLATFORM_HOLDS_LOCK_NAMESPACE, PLATFORM_HOLDS_LOCK_KEY, shared=True
        )
    else:
        acquire_global_advisory_lock(
            session, TENANT_HOLDS_LOCK_NAMESPACE, tenant_holds_lock_key(tenant_id), shared=True
        )


def _scope_report(session: Session, tenant_id: uuid.UUID | None) -> AuditIdentityExpiryReport:
    if tenant_id is None:
        return expiry_report(audit_identity_expiry_plan(session, lock=False))
    with bind_tenant_scope(session, tenant_id):
        return expiry_report(audit_identity_expiry_plan(session, lock=False, tenant_id=tenant_id))


def _scope_apply(
    session: Session,
    tenant_id: uuid.UUID | None,
    checked: ExpiryConfirmation,
    run_id: uuid.UUID,
) -> AuditIdentityExpiryReport:
    """The scope's transaction: `H` shared, the plan under row locks, the
    confirmation check, the changes. A tenant's rows are read and changed
    with the tenant bound; the caller writes the platform row afterwards,
    with no tenant bound."""
    _lock_scope_holds(session, tenant_id)
    if tenant_id is None:
        plan = audit_identity_expiry_plan(session, lock=True)
        if not _matches(plan, checked):
            raise AuditIdentityExpiryConfirmationMismatchError()
        _apply(session, plan)
    else:
        with bind_tenant_scope(session, tenant_id):
            plan = audit_identity_expiry_plan(session, lock=True, tenant_id=tenant_id)
            if not _matches(plan, checked):
                raise AuditIdentityExpiryConfirmationMismatchError()
            _apply_tenant(session, plan, tenant_id)
    return expiry_report(plan, applied=True, run_id=run_id)


def expire_audit_identity_links(
    *,
    caller: object,
    reason: str,
    apply: bool = False,
    confirmation: ExpiryConfirmation | None = None,
    tenant_id: uuid.UUID | None = None,
) -> AuditIdentityExpiryReport:
    """Report (default) or -- once `_APPLY_ENABLED` is set, which it is not
    (owner decision O9) -- with `apply` and a matching confirmation, expire
    the links and markers of the platform scope (`tenant_id` `None`) or of
    one tenant (phase P3c; its rows read and changed with the tenant bound,
    its plan refused while a phase P3b index is missing or invalid). Module
    docstring: the migrations role only; the declared operator must hold
    `platform.security_retention:report`."""
    try:
        checked = _validated_confirmation(apply, confirmation)
        if tenant_id is not None and not isinstance(tenant_id, uuid.UUID):
            raise InvalidAuditIdentityRequestError("tenant_id must be a uuid.UUID.")
        reason = validate_reason(reason)
        if apply and not _APPLY_ENABLED:
            # Refused before any connection (owner decision O9).
            raise AuditIdentityExpiryDisabledError()
    except AuditIdentityExpiryDisabledError:
        raise
    except AuditIdentityRetentionError as refused:
        _record_denied(caller, refused.code)
        raise
    try:
        scope = PLATFORM_SCOPE if tenant_id is None else tenant_scope(tenant_id)
        if checked is None:
            with migrations_role_session_scope(owned_table=LINKS_TABLE) as session:
                authorize_platform_caller(caller, session=session, operation=AUDIT_IDENTITY_EXPIRY)
                return _scope_report(session, tenant_id)
        run_id = uuid.uuid4()
        with migrations_role_session_scope(owned_table=LINKS_TABLE) as session:
            authorize_platform_caller(caller, session=session, operation=AUDIT_IDENTITY_EXPIRY)
            _record(
                session,
                caller,
                reason,
                {"phase": "start", "scopes": [scope], **_confirmed(checked)},
                entry_id=run_id,
            )
        with migrations_role_session_scope(owned_table=LINKS_TABLE) as session:
            authorize_platform_caller(caller, session=session, operation=AUDIT_IDENTITY_EXPIRY)
            report = _scope_apply(session, tenant_id, checked, run_id)
            # With no tenant bound (ADR-0045 section 9c).
            _record(session, caller, reason, {"phase": "scope", **_evidence(run_id, report)})
        with migrations_role_session_scope(owned_table=LINKS_TABLE) as session:
            _record(
                session,
                caller,
                reason,
                {"phase": "finish", "run_id": str(run_id), "scopes_completed": 1},
            )
        logger.info(
            "audit_identity_expiry_applied",
            extra={
                "run_id": str(run_id),
                "links_deleted": report.eligible_links,
                "links_unlinked": report.links_to_unlink,
                "markers_deleted": report.markers,
            },
        )
        return report
    except (AuditIdentityRetentionError, PlatformRefusalError) as refused:
        _record_denied(caller, refused.code)
        raise


def _confirmed(confirmation: ExpiryConfirmation) -> dict[str, object]:
    return {
        "confirm_rows": confirmation.rows,
        "confirm_digest": confirmation.digest,
        "confirm_holds": confirmation.holds,
        "confirm_unlinks": confirmation.unlinks,
        "confirm_markers": confirmation.markers,
    }


def _evidence(run_id: uuid.UUID, report: AuditIdentityExpiryReport) -> dict[str, object]:
    return {
        "run_id": str(run_id),
        "scope": report.scope,
        "links_deleted": report.eligible_links,
        "links_deleted_digest": report.eligible_links_digest,
        "links_unlinked": report.links_to_unlink,
        "markers_deleted": report.markers,
        "active_holds": report.active_holds,
        "active_holds_digest": report.active_holds_digest,
        "as_of": report.as_of.astimezone(UTC).isoformat(),
        "retention_years": RETENTION_YEARS,
    }


__all__ = [
    "EXPIRY_TARGET_TYPE",
    "ExpiryConfirmation",
    "expire_audit_identity_links",
]
