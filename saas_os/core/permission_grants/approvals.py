"""The authenticated approval of a deletion of expired permission grant
ledger rows (owner decisions of 2026-11-02 and 2026-11-03;
`docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`).

Three acts, each by the authenticated user of a platform-admin session
(never a declared id), each a platform operation under
`platform.security_retention:report`, each with its audit row in its own
transaction:

1. **request** (`request_permission_grant_ledger_deletion`): exactly the
   named tenants (sorted, distinct; every one eligible with rows), bound to
   the eligible row count and digest a report showed, recomputed under the
   tenant locks. One live request per tenant. Expires after 72 hours unless
   approved. Refused to a holder of `platform.authority:manage`.
2. **approval** (`approve_permission_grant_ledger_deletion`): by an eligible
   registered approver (`saas_os.core.permission_grants.register`) who is
   not the requester, not an authenticated releaser of any hold on a tenant
   in scope, not provenance-linked to the requester, and does not hold
   `platform.authority:manage`; the approver restates the count and digest.
   Single use, valid for 72 hours (database clock).
3. **execution authorisation**
   (`authorize_permission_grant_ledger_deletion_execution`): by another
   eligible registered approver naming a different natural person, with the
   same refusals; valid for 60 minutes and never past the approval.

A release made without authenticated evidence (every release the removed
command made) blocks its tenant (decision 2). The migrations-role deletion
(`saas_os.core.permission_grants.expiry`) re-checks the whole chain under
the same locks with `verify_deletion_chain`, and consumes both records. It
stays disabled (`_DELETION_ENABLED` is `False`).

Lock order everywhere: the register lock (shared), the tenant rows in id
order, the request, the approval, the authorisation. A revocation takes
the register lock exclusively and invalidates outstanding approvals and
authorisations in its own transaction.

Retrying an act with the same caller and identical content (bound values
and reason) returns the existing record flagged `replay`; any difference is
the act's refusal.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from saas_os.core.authority import UserCaller
from saas_os.core.permission_grants.approval_support import (
    lock_register,
    refusals_recorded,
    refuse,
    same_act,
    validated_count,
    validated_digest,
    validated_uuid,
    verify_session,
    wall_time,
)
from saas_os.core.permission_grants.errors import (
    InvalidLedgerRetentionRequestError,
    LedgerApprovalRecordNotFoundError,
    LedgerExpiryConfirmationMismatchError,
)
from saas_os.core.permission_grants.models import (
    LedgerDeletionApproval,
    LedgerDeletionRequest,
    LedgerExecutionAuthorization,
    PermissionGrantLedgerHold,
)
from saas_os.core.permission_grants.register import RegisterEntryView, eligible_enrolment
from saas_os.core.permission_grants.retention import (
    MAX_REPORT_TENANTS,
    _active_holds,
    _ledger_row_ids,
    _purge_evidence,
    _tenant_status,
    eligible_ledger_digest,
    retention_eligibility,
)
from saas_os.core.platform_authority import (
    DEFAULT_OVERSIGHT_PAGE_SIZE,
    MAX_OVERSIGHT_PAGE_SIZE,
    OversightOutcome,
    PlatformPermission,
    authorize_platform_caller,
    platform_can,
    platform_change_session,
    platform_operation,
    record_platform_event_in_transaction,
    run_oversight_read,
    validate_page_request,
    validate_reason,
)
from saas_os.core.platform_authority.operations import (
    PERMISSION_GRANT_LEDGER_DELETION_APPROVE,
    PERMISSION_GRANT_LEDGER_DELETION_EXECUTION_AUTHORIZE,
    PERMISSION_GRANT_LEDGER_DELETION_READ,
    PERMISSION_GRANT_LEDGER_DELETION_REQUEST,
)
from saas_os.core.platform_authority.retention_evidence import (
    holds_platform_permission,
    platform_audit_acts,
    provenance_linked,
)
from saas_os.core.tenancy import Tenant
from saas_os.infra.db import Session, select

_TARGET = "permission_grant_ledger_deletion_request"
P = PlatformPermission


# --- scope ------------------------------------------------------------------------------


def canonical_scope(tenant_ids: object) -> tuple[uuid.UUID, ...]:
    """The sorted, distinct tenant ids of a request (1 to 1000)."""
    if isinstance(tenant_ids, str | bytes) or not isinstance(tenant_ids, Sequence):
        raise InvalidLedgerRetentionRequestError("tenant_ids must be a list or tuple.")
    if not all(isinstance(t, uuid.UUID) for t in tenant_ids):
        raise InvalidLedgerRetentionRequestError("Every tenant id must be a uuid.UUID.")
    scope = tuple(sorted(set(tenant_ids)))  # type: ignore[arg-type]
    if not 0 < len(scope) <= MAX_REPORT_TENANTS:
        raise InvalidLedgerRetentionRequestError(
            f"A request names 1 to {MAX_REPORT_TENANTS} tenants."
        )
    return scope


def scope_digest(tenant_ids: Sequence[uuid.UUID]) -> str:
    """SHA-256 (hex) of the canonical JSON array of the sorted, distinct
    tenant ids; the database recomputes it in the request's insert
    trigger."""
    canonical = json.dumps([str(t) for t in sorted(set(tenant_ids))], separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def lock_tenants(session: Session, tenant_ids: Sequence[uuid.UUID]) -> None:
    """The tenant rows `FOR UPDATE`, in id order: the lock that hold
    placement and hold release take first."""
    session.execute(
        select(Tenant.id)
        .where(Tenant.id.in_(sorted(tenant_ids)))
        .order_by(Tenant.id)
        .with_for_update()
    ).all()


@dataclass(frozen=True)
class ScopeState:
    rows: dict[uuid.UUID, tuple[uuid.UUID, ...]]
    not_eligible: tuple[uuid.UUID, ...]

    @property
    def total(self) -> int:
        return sum(len(ids) for ids in self.rows.values())

    @property
    def digest(self) -> str:
        return eligible_ledger_digest(self.rows)


def scope_state(session: Session, tenant_ids: Sequence[uuid.UUID], at: datetime) -> ScopeState:
    """Each tenant's retention decision at `at`; eligible tenants with rows
    keep their row ids, every other tenant is `not_eligible`."""
    rows: dict[uuid.UUID, tuple[uuid.UUID, ...]] = {}
    refused: list[uuid.UUID] = []
    for tenant_id in tenant_ids:
        status = _tenant_status(session, tenant_id)
        decision = retention_eligibility(
            tenant_status=status,
            purge_evidence=_purge_evidence(session, tenant_id),
            active_holds=_active_holds(session, tenant_id) if status is not None else 0,
            now=at,
        )
        ids = _ledger_row_ids(session, tenant_id) if decision.eligible else ()
        if decision.eligible and ids:
            rows[tenant_id] = ids
        else:
            refused.append(tenant_id)
    return ScopeState(rows, tuple(refused))


@dataclass(frozen=True)
class ReleaseEvidence:
    authenticated_releasers: frozenset[uuid.UUID]
    unauthenticated: bool


def releases_in_scope(session: Session, tenant_ids: Sequence[uuid.UUID]) -> ReleaseEvidence:
    """Who released holds on these tenants, from any time: the actor of
    each release with authenticated evidence, and whether any release
    lacks it (a release the removed command made blocks its tenant)."""
    audit_ids = list(
        session.execute(
            select(PermissionGrantLedgerHold.released_by_platform_audit_id).where(
                PermissionGrantLedgerHold.target_tenant_id.in_(sorted(tenant_ids)),
                PermissionGrantLedgerHold.released_at.is_not(None),
            )
        ).scalars()
    )
    acts = platform_audit_acts(session, [a for a in audit_ids if a is not None])
    releasers: set[uuid.UUID] = set()
    unauthenticated = False
    for audit_id in audit_ids:
        act = acts.get(audit_id) if audit_id is not None else None
        if act is not None and act.authenticated_http_act and act.actor_user_id is not None:
            releasers.add(act.actor_user_id)
        else:
            unauthenticated = True
    return ReleaseEvidence(frozenset(releasers), unauthenticated)


def _holds_authority(session: Session, user_id: uuid.UUID) -> bool:
    return platform_can(user_id=user_id, permission=P.AUTHORITY_MANAGE, session=session)


def _holds_hold_manage(session: Session, user_id: uuid.UUID) -> bool:
    return holds_platform_permission(session, user_id, P.SECURITY_RETENTION_HOLD_MANAGE)


# --- the chain, as approval, authorisation and execution check it ------------------------


@dataclass(frozen=True)
class VerifiedChain:
    """What a check of the chain established, under the locks."""

    approver_entry: RegisterEntryView
    authorizer_entry: RegisterEntryView | None
    scope: ScopeState


def verify_deletion_chain(
    session: Session,
    *,
    request: LedgerDeletionRequest,
    approver_id: uuid.UUID,
    authorizer_id: uuid.UUID | None,
    at: datetime,
    approval: LedgerDeletionApproval | None = None,
) -> VerifiedChain:
    """The person rules, eligibility and scope of one deletion, at `at`,
    with the register lock (shared) and the tenant locks held. Without an
    authoriser (the approval itself) the authoriser rules are skipped. Each
    refusal is a `LedgerApprovalRefusedError` with its code."""
    requester_id = request.requested_by_user_id
    parties = [requester_id, approver_id] + ([authorizer_id] if authorizer_id else [])
    if any(_holds_authority(session, party) for party in parties):
        raise refuse("party_holds_authority_manage")
    if approver_id == requester_id:
        raise refuse("approver_is_requester")
    if authorizer_id is not None and authorizer_id == approver_id:
        raise refuse("authorizer_is_approver")
    if authorizer_id is not None and not platform_can(
        user_id=approver_id, permission=P.SECURITY_RETENTION_REPORT, session=session
    ):
        raise refuse("approval_no_longer_authorized")
    approver_entry = eligible_enrolment(session, approver_id, at)
    if approver_entry is None:
        raise refuse("approver_not_eligible")
    authorizer_entry: RegisterEntryView | None = None
    if authorizer_id is not None:
        authorizer_entry = eligible_enrolment(session, authorizer_id, at)
        if authorizer_entry is None:
            raise refuse("authorizer_not_eligible")
        if authorizer_entry.natural_person_ref == approver_entry.natural_person_ref:
            raise refuse("same_natural_person")
    if provenance_linked(session, approver_id, requester_id):
        raise refuse("approver_linked_to_requester")
    if authorizer_id is not None and provenance_linked(session, authorizer_id, approver_id):
        raise refuse("authorizer_linked_to_approver")
    releases = releases_in_scope(session, request.tenant_ids)
    if releases.unauthenticated:
        raise refuse("unauthenticated_release_in_scope")
    if approver_id in releases.authenticated_releasers:
        raise refuse("approver_released_hold")
    if authorizer_id is not None and authorizer_id in releases.authenticated_releasers:
        raise refuse("authorizer_released_hold")
    # Representatives and hold managers stay out of the chain: the register
    # refuses to enrol a hold manager, and a grant made afterwards (only the
    # break-glass `recover --grant` can make one) does not let them act.
    holders = [approver_id] + ([authorizer_id] if authorizer_id else [])
    if any(_holds_hold_manage(session, party) for party in holders):
        raise refuse("party_holds_hold_manage")
    state = scope_state(session, request.tenant_ids, at)
    if state.not_eligible:
        raise refuse("scope_not_eligible")
    bound = approval if approval is not None else request
    if (
        state.total != bound.eligible_ledger_rows
        or state.digest != bound.eligible_digest
        or scope_digest(request.tenant_ids) != bound.scope_digest
        or list(bound.tenant_ids) != list(request.tenant_ids)
    ):
        raise LedgerExpiryConfirmationMismatchError()
    return VerifiedChain(approver_entry, authorizer_entry, state)


# --- views ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class DeletionApprovalView:
    id: uuid.UUID
    approved_by_user_id: uuid.UUID
    approved_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    invalidated_at: datetime | None


@dataclass(frozen=True)
class DeletionRequestView:
    """A request with its state at `as_of` (the database clock):
    `pending`, `approved`, `consumed`, `expired` or `invalidated`."""

    id: uuid.UUID
    tenant_ids: tuple[uuid.UUID, ...]
    scope_digest: str
    eligible_ledger_rows: int
    eligible_digest: str
    requested_by_user_id: uuid.UUID
    requested_at: datetime
    request_expires_at: datetime
    state: str
    approval: DeletionApprovalView | None
    replay: bool = False


@dataclass(frozen=True)
class DeletionRequestPage:
    requests: tuple[DeletionRequestView, ...]
    next_cursor: uuid.UUID | None


@dataclass(frozen=True)
class ExecutionAuthorizationView:
    """The id is what the operator gives the migrations-role command."""

    id: uuid.UUID
    approval_id: uuid.UUID
    request_id: uuid.UUID
    authorized_by_user_id: uuid.UUID
    authorized_at: datetime
    expires_at: datetime
    eligible_ledger_rows: int
    eligible_digest: str
    scope_digest: str
    replay: bool = False


def _state(
    request: LedgerDeletionRequest, approval: LedgerDeletionApproval | None, at: datetime
) -> str:
    if approval is None:
        return "pending" if at < request.expires_at else "expired"
    if approval.consumed_at is not None:
        return "consumed"
    if approval.invalidated_at is not None:
        return "invalidated"
    return "approved" if at < approval.expires_at else "expired"


def _request_view(
    request: LedgerDeletionRequest,
    approval: LedgerDeletionApproval | None,
    at: datetime,
    *,
    replay: bool = False,
) -> DeletionRequestView:
    return DeletionRequestView(
        id=request.id,
        tenant_ids=tuple(request.tenant_ids),
        scope_digest=request.scope_digest,
        eligible_ledger_rows=request.eligible_ledger_rows,
        eligible_digest=request.eligible_digest,
        requested_by_user_id=request.requested_by_user_id,
        requested_at=request.requested_at,
        request_expires_at=request.expires_at,
        state=_state(request, approval, at),
        approval=None
        if approval is None
        else DeletionApprovalView(
            id=approval.id,
            approved_by_user_id=approval.approved_by_user_id,
            approved_at=approval.approved_at,
            expires_at=approval.expires_at,
            consumed_at=approval.consumed_at,
            invalidated_at=approval.invalidated_at,
        ),
        replay=replay,
    )


def _authorization_view(
    authorization: LedgerExecutionAuthorization,
    approval: LedgerDeletionApproval,
    *,
    replay: bool = False,
) -> ExecutionAuthorizationView:
    return ExecutionAuthorizationView(
        id=authorization.id,
        approval_id=approval.id,
        request_id=approval.request_id,
        authorized_by_user_id=authorization.authorized_by_user_id,
        authorized_at=authorization.authorized_at,
        expires_at=authorization.expires_at,
        eligible_ledger_rows=approval.eligible_ledger_rows,
        eligible_digest=approval.eligible_digest,
        scope_digest=approval.scope_digest,
        replay=replay,
    )


def _approval_of(
    session: Session, request_id: uuid.UUID, *, lock: bool = False
) -> LedgerDeletionApproval | None:
    query = select(LedgerDeletionApproval).where(LedgerDeletionApproval.request_id == request_id)
    if lock:
        query = query.with_for_update()
    return session.execute(query).scalar_one_or_none()


def _audit(
    session: Session,
    *,
    caller: UserCaller,
    operation: str,
    request_id: uuid.UUID,
    reason: str,
    metadata: dict[str, object],
    entry_id: uuid.UUID | None = None,
) -> None:
    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(operation).audit_action,
        target_type=_TARGET,
        target_id=str(request_id),
        reason=reason,
        metadata=metadata,
        entry_id=entry_id,
    )


# --- R5: the request ---------------------------------------------------------------------


def _live_requests(
    session: Session, scope: Sequence[uuid.UUID], at: datetime
) -> list[tuple[LedgerDeletionRequest, LedgerDeletionApproval | None]]:
    """Requests naming a tenant in `scope` that are live at `at`: no
    approval and unexpired, or an approval that is unexpired, unconsumed and
    not invalidated."""
    overlapping = session.execute(
        select(LedgerDeletionRequest).where(LedgerDeletionRequest.tenant_ids.overlap(list(scope)))
    ).scalars()
    live = []
    for request in overlapping:
        approval = _approval_of(session, request.id)
        if _state(request, approval, at) in ("pending", "approved"):
            live.append((request, approval))
    return live


def request_permission_grant_ledger_deletion(
    *,
    caller: object,
    session_evidence: object,
    tenant_ids: Sequence[uuid.UUID],
    eligible_ledger_rows: int,
    eligible_digest: str,
    reason: str,
) -> DeletionRequestView:
    """Request the deletion of the expired ledger rows of exactly
    `tenant_ids`, confirmed with the count and digest a report showed."""
    operation = PERMISSION_GRANT_LEDGER_DELETION_REQUEST
    with refusals_recorded(caller, operation, _TARGET):
        scope = canonical_scope(tenant_ids)
        rows = validated_count(eligible_ledger_rows, "eligible_ledger_rows")
        digest = validated_digest(eligible_digest, "eligible_digest")
        reason = validate_reason(reason)
        with platform_change_session(caller, operation) as session:
            authorize_platform_caller(caller, session=session, operation=operation)
            assert isinstance(caller, UserCaller)
            verified = verify_session(session, caller, session_evidence, require_multi_factor=False)
            if _holds_authority(session, caller.user_id):
                raise refuse("party_holds_authority_manage")
            lock_tenants(session, scope)
            at = wall_time(session)
            live = _live_requests(session, scope, at)
            if live:
                (existing, approval), *others = live
                if (
                    not others
                    and existing.requested_by_user_id == caller.user_id
                    and tuple(existing.tenant_ids) == scope
                    and (existing.eligible_ledger_rows, existing.eligible_digest) == (rows, digest)
                    and same_act(
                        session,
                        existing.requested_by_platform_audit_id,
                        caller,
                        reason,
                        platform_operation(operation).audit_action,
                    )
                ):
                    _audit(
                        session,
                        caller=caller,
                        operation=operation,
                        request_id=existing.id,
                        reason=reason,
                        metadata={
                            **verified.metadata(),
                            "request_id": str(existing.id),
                            "replay": True,
                        },
                    )
                    return _request_view(existing, approval, at, replay=True)
                raise refuse("overlapping_request")
            if releases_in_scope(session, scope).unauthenticated:
                raise refuse("unauthenticated_release_in_scope")
            state = scope_state(session, scope, at)
            if state.not_eligible:
                raise refuse("scope_not_eligible")
            if (state.total, state.digest) != (rows, digest):
                raise LedgerExpiryConfirmationMismatchError()
            audit_id = uuid.uuid4()
            request = LedgerDeletionRequest(
                id=uuid.uuid4(),
                tenant_ids=list(scope),
                scope_digest=scope_digest(scope),
                eligible_ledger_rows=rows,
                eligible_digest=digest,
                requested_by_user_id=caller.user_id,
                requested_by_platform_audit_id=audit_id,
            )
            session.add(request)
            session.flush()
            session.refresh(request)
            _audit(
                session,
                caller=caller,
                operation=operation,
                request_id=request.id,
                reason=reason,
                entry_id=audit_id,
                metadata={
                    **verified.metadata(),
                    "request_id": str(request.id),
                    "tenants": len(scope),
                    "scope_digest": request.scope_digest,
                    "eligible_ledger_rows": rows,
                    "eligible_digest": digest,
                    "expires_at": request.expires_at.isoformat(),
                },
            )
            return _request_view(request, None, at)
    raise AssertionError("unreachable")  # pragma: no cover


def _request_for(session: Session, request_id: object) -> LedgerDeletionRequest:
    request = session.get(LedgerDeletionRequest, validated_uuid(request_id, "request_id"))
    if request is None:
        raise LedgerApprovalRecordNotFoundError("request_not_found")
    return request


def _locked_request(session: Session, request: LedgerDeletionRequest) -> LedgerDeletionRequest:
    """The request after its tenant rows are locked. The request row itself
    is never updated (its trigger refuses every UPDATE) and the runtime role
    holds no UPDATE on it, so it is not locked: two acts on one request are
    serialised by the tenant locks they both take first."""
    lock_tenants(session, request.tenant_ids)
    return session.execute(
        select(LedgerDeletionRequest)
        .where(LedgerDeletionRequest.id == request.id)
        .execution_options(populate_existing=True)
    ).scalar_one()


# --- R8: the approval ---------------------------------------------------------------------


def approve_permission_grant_ledger_deletion(
    request_id: uuid.UUID,
    *,
    caller: object,
    session_evidence: object,
    eligible_ledger_rows: int,
    eligible_digest: str,
    reason: str,
) -> DeletionRequestView:
    """Approve one request. The approver restates the count and digest they
    verified; everything is recomputed under the locks."""
    operation = PERMISSION_GRANT_LEDGER_DELETION_APPROVE
    target = str(request_id) if isinstance(request_id, uuid.UUID) else None
    with refusals_recorded(caller, operation, _TARGET, target):
        rows = validated_count(eligible_ledger_rows, "eligible_ledger_rows")
        digest = validated_digest(eligible_digest, "eligible_digest")
        reason = validate_reason(reason)
        with platform_change_session(caller, operation) as session:
            authorize_platform_caller(caller, session=session, operation=operation)
            assert isinstance(caller, UserCaller)
            verified = verify_session(session, caller, session_evidence, require_multi_factor=True)
            request = _request_for(session, request_id)
            lock_register(session, shared=True)
            request = _locked_request(session, request)
            at = wall_time(session)
            approval = _approval_of(session, request.id, lock=True)
            if approval is not None:
                if (
                    approval.approved_by_user_id == caller.user_id
                    and _state(request, approval, at) == "approved"
                    and (approval.eligible_ledger_rows, approval.eligible_digest) == (rows, digest)
                    and same_act(
                        session,
                        approval.approved_by_platform_audit_id,
                        caller,
                        reason,
                        platform_operation(operation).audit_action,
                    )
                ):
                    # A replay is answered only if the approval would still
                    # be given now: the same chain checks, first.
                    verify_deletion_chain(
                        session,
                        request=request,
                        approver_id=caller.user_id,
                        authorizer_id=None,
                        at=at,
                        approval=approval,
                    )
                    _audit(
                        session,
                        caller=caller,
                        operation=operation,
                        request_id=request.id,
                        reason=reason,
                        metadata={
                            **verified.metadata(),
                            "request_id": str(request.id),
                            "approval_id": str(approval.id),
                            "replay": True,
                        },
                    )
                    return _request_view(request, approval, at, replay=True)
                raise refuse("request_already_approved")
            if at >= request.expires_at:
                raise refuse("request_expired")
            if (rows, digest) != (request.eligible_ledger_rows, request.eligible_digest):
                raise LedgerExpiryConfirmationMismatchError()
            chain = verify_deletion_chain(
                session, request=request, approver_id=caller.user_id, authorizer_id=None, at=at
            )
            audit_id = uuid.uuid4()
            approval = LedgerDeletionApproval(
                id=uuid.uuid4(),
                request_id=request.id,
                tenant_ids=list(request.tenant_ids),
                scope_digest=request.scope_digest,
                eligible_ledger_rows=request.eligible_ledger_rows,
                eligible_digest=request.eligible_digest,
                approved_by_user_id=caller.user_id,
                approved_by_platform_audit_id=audit_id,
            )
            session.add(approval)
            session.flush()
            session.refresh(approval)
            _audit(
                session,
                caller=caller,
                operation=operation,
                request_id=request.id,
                reason=reason,
                entry_id=audit_id,
                metadata={
                    **verified.metadata(),
                    "request_id": str(request.id),
                    "approval_id": str(approval.id),
                    "tenants": len(request.tenant_ids),
                    "scope_digest": request.scope_digest,
                    "eligible_ledger_rows": request.eligible_ledger_rows,
                    "eligible_digest": request.eligible_digest,
                    "expires_at": approval.expires_at.isoformat(),
                    "approver_entry_id": str(chain.approver_entry.id),
                },
            )
            return _request_view(request, approval, at)
    raise AssertionError("unreachable")  # pragma: no cover


# --- R9: the execution authorisation --------------------------------------------------------


def approval_refusal(approval: LedgerDeletionApproval, at: datetime) -> str | None:
    if approval.consumed_at is not None:
        return "approval_consumed"
    if approval.invalidated_at is not None:
        return "approval_invalidated"
    if at >= approval.expires_at:
        return "approval_expired"
    return None


def authorize_permission_grant_ledger_deletion_execution(
    request_id: uuid.UUID, *, caller: object, session_evidence: object, reason: str
) -> ExecutionAuthorizationView:
    """Authorise the migrations-role deletion of an approved request. Its
    id is what the operator gives `python -m
    saas_os.ops.permission_grant_ledger_expiry --execution-authorization`."""
    operation = PERMISSION_GRANT_LEDGER_DELETION_EXECUTION_AUTHORIZE
    target = str(request_id) if isinstance(request_id, uuid.UUID) else None
    with refusals_recorded(caller, operation, _TARGET, target):
        reason = validate_reason(reason)
        with platform_change_session(caller, operation) as session:
            authorize_platform_caller(caller, session=session, operation=operation)
            assert isinstance(caller, UserCaller)
            verified = verify_session(session, caller, session_evidence, require_multi_factor=True)
            request = _request_for(session, request_id)
            if _approval_of(session, request.id) is None:
                raise refuse("approval_missing")
            lock_register(session, shared=True)
            request = _locked_request(session, request)
            approval = _approval_of(session, request.id, lock=True)
            assert approval is not None
            at = wall_time(session)
            refused = approval_refusal(approval, at)
            if refused is not None:
                raise refuse(refused)
            chain = verify_deletion_chain(
                session,
                request=request,
                approver_id=approval.approved_by_user_id,
                authorizer_id=caller.user_id,
                at=at,
                approval=approval,
            )
            # A replay is answered only after the same checks as a new one.
            existing = session.execute(
                select(LedgerExecutionAuthorization).where(
                    LedgerExecutionAuthorization.approval_id == approval.id,
                    LedgerExecutionAuthorization.authorized_by_user_id == caller.user_id,
                    LedgerExecutionAuthorization.consumed_at.is_(None),
                    LedgerExecutionAuthorization.invalidated_at.is_(None),
                    LedgerExecutionAuthorization.expires_at > at,
                )
            ).scalars()
            for authorization in existing:
                if same_act(
                    session,
                    authorization.authorized_by_platform_audit_id,
                    caller,
                    reason,
                    platform_operation(operation).audit_action,
                ):
                    _audit(
                        session,
                        caller=caller,
                        operation=operation,
                        request_id=request.id,
                        reason=reason,
                        metadata={
                            **verified.metadata(),
                            "request_id": str(request.id),
                            "approval_id": str(approval.id),
                            "execution_authorization_id": str(authorization.id),
                            "replay": True,
                        },
                    )
                    return _authorization_view(authorization, approval, replay=True)
            assert chain.authorizer_entry is not None
            audit_id = uuid.uuid4()
            authorization = LedgerExecutionAuthorization(
                id=uuid.uuid4(),
                approval_id=approval.id,
                authorized_by_user_id=caller.user_id,
                authorized_by_platform_audit_id=audit_id,
            )
            session.add(authorization)
            session.flush()
            session.refresh(authorization)
            _audit(
                session,
                caller=caller,
                operation=operation,
                request_id=request.id,
                reason=reason,
                entry_id=audit_id,
                metadata={
                    **verified.metadata(),
                    "request_id": str(request.id),
                    "approval_id": str(approval.id),
                    "execution_authorization_id": str(authorization.id),
                    "expires_at": authorization.expires_at.isoformat(),
                    "approver_entry_id": str(chain.approver_entry.id),
                    "authorizer_entry_id": str(chain.authorizer_entry.id),
                },
            )
            return _authorization_view(authorization, approval)
    raise AssertionError("unreachable")  # pragma: no cover


# --- R6, R7: reads ----------------------------------------------------------------------------


def read_permission_grant_ledger_deletion_requests(
    *,
    caller: object,
    request_id: uuid.UUID | None = None,
    cursor: uuid.UUID | None = None,
    limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE,
) -> DeletionRequestPage:
    """The requests in id order with their state now, or the one named."""
    validate_page_request(cursor, limit, maximum=MAX_OVERSIGHT_PAGE_SIZE)
    if request_id is not None:
        validated_uuid(request_id, "request_id")

    def read(session: Session) -> OversightOutcome[DeletionRequestPage]:
        at = wall_time(session)
        query = select(LedgerDeletionRequest).order_by(LedgerDeletionRequest.id).limit(limit + 1)
        if request_id is not None:
            query = query.where(LedgerDeletionRequest.id == request_id)
        if cursor is not None:
            query = query.where(LedgerDeletionRequest.id > cursor)
        found = list(session.execute(query).scalars())
        if request_id is not None and not found:
            raise LedgerApprovalRecordNotFoundError("request_not_found")
        page = found[:limit]
        value = DeletionRequestPage(
            tuple(_request_view(r, _approval_of(session, r.id), at) for r in page),
            page[-1].id if len(found) > limit else None,
        )
        return OversightOutcome(value=value, returned=len(page))

    with refusals_recorded(
        caller,
        PERMISSION_GRANT_LEDGER_DELETION_READ,
        _TARGET,
        str(request_id) if request_id is not None else None,
        platform_refusals=False,
    ):
        return run_oversight_read(
            caller=caller,
            operation=PERMISSION_GRANT_LEDGER_DELETION_READ,
            target_type=_TARGET,
            target_id=str(request_id) if request_id is not None else None,
            read=read,
            request_metadata={
                "cursor": str(cursor) if cursor is not None else None,
                "limit": limit,
            },
        )
    raise AssertionError("unreachable")  # pragma: no cover
