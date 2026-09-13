"""The tier-1 propose -> approve -> execute workflow
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.2; docs/AI-CONTROL-PLANE.md
section 5: "tier 1 -- propose + approval ... Approval is itself an
audited, attributable action -- not an out-of-band chat message").

Three distinct steps, three distinct calls -- `propose_action()` stages a
tool invocation without executing it; `approve()`/`reject()` records a
human decision (and is itself audit-logged, per this phase's own
Acceptance Criteria); `execute_approved()` is the only function that
actually invokes the underlying tool, and it refuses to run against
anything but an `"approved"` request -- "a rejected proposal never
executes" (this phase's own Acceptance Criteria) is therefore a
structural property of `status`, not a convention a caller must
remember to honor.

`execute_approved()` calls `control_plane.orchestration.service
._execute_tool()` directly -- the one sanctioned bypass of
`invoke_tool()`'s tier>=1 refusal (that module's own docstring) -- using
the *proposer's* `agent_user_id`, never the approver's: the approving
human authorizes the agent's proposed action, they do not become the
actor performing it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from control_plane.approvals.errors import (
    ApprovalNotPendingError,
    ApprovalRequestNotFoundError,
    SelfApprovalNotAllowedError,
)
from control_plane.approvals.models import ApprovalRequest
from control_plane.data_authorization import DataAuthorizationDecision
from control_plane.orchestration.service import _execute_tool
from control_plane.orchestration.tools import ToolRegistry
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from infra.db import select, tenant_session_scope, update

_AUDIT_RESOURCE_TYPE = "control_plane_approval_request"


def propose_action(
    tenant_id: uuid.UUID,
    proposer_user_id: uuid.UUID,
    tool_key: str,
    *,
    agent_scope_value: str | None = None,
    payload: dict[str, object] | None = None,
) -> ApprovalRequest:
    """Stage `tool_key` for `proposer_user_id`'s approval-gated
    invocation. Does not execute anything -- this is the "propose" step
    only."""
    with tenant_session_scope(tenant_id) as session:
        approval = ApprovalRequest(
            tenant_id=tenant_id,
            proposer_user_id=proposer_user_id,
            tool_key=tool_key,
            agent_scope_value=agent_scope_value,
            payload=payload or {},
            status="pending",
        )
        session.add(approval)
        session.flush()
        session.refresh(approval)
        session.expunge(approval)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=proposer_user_id,
        action="control_plane.action_proposed",
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(approval.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"tool_key": tool_key},
    )
    return approval


def get_approval(tenant_id: uuid.UUID, approval_id: uuid.UUID) -> ApprovalRequest:
    with tenant_session_scope(tenant_id) as session:
        approval = session.get(ApprovalRequest, approval_id)
        if approval is None or approval.tenant_id != tenant_id:
            raise ApprovalRequestNotFoundError(tenant_id, approval_id)
        session.expunge(approval)
        return approval


def list_approvals(tenant_id: uuid.UUID, *, status: str | None = None) -> list[ApprovalRequest]:
    with tenant_session_scope(tenant_id) as session:
        stmt = select(ApprovalRequest).where(ApprovalRequest.tenant_id == tenant_id)
        if status is not None:
            stmt = stmt.where(ApprovalRequest.status == status)
        approvals = session.execute(stmt).scalars().all()
        for approval in approvals:
            session.expunge(approval)
        return list(approvals)


def approve(
    tenant_id: uuid.UUID, approval_id: uuid.UUID, approver_user_id: uuid.UUID
) -> ApprovalRequest:
    """Record a human approval decision. Raises
    `SelfApprovalNotAllowedError` when `approver_user_id` is the same
    identity that proposed the action (separation of duties, this
    phase's own Security Requirement) -- checked here *and* enforced by
    the table's own `CHECK` constraint (`control_plane/approvals/models.py`).
    """
    approval = get_approval(tenant_id, approval_id)
    if approval.status != "pending":
        raise ApprovalNotPendingError(approval_id, approval.status)
    if approver_user_id == approval.proposer_user_id:
        record_audit_event(
            tenant_id=tenant_id,
            actor_type=ActorType.USER,
            actor_user_id=approver_user_id,
            action="control_plane.action_approved",
            resource_type=_AUDIT_RESOURCE_TYPE,
            resource_id=str(approval_id),
            outcome=AuditOutcome.DENIED,
            metadata={"reason": "self_approval_not_allowed"},
        )
        raise SelfApprovalNotAllowedError(approval_id)

    with tenant_session_scope(tenant_id) as session:
        row = session.get(ApprovalRequest, approval_id)
        if row is None or row.tenant_id != tenant_id:
            raise ApprovalRequestNotFoundError(tenant_id, approval_id)
        row.status = "approved"
        row.approver_user_id = approver_user_id
        row.decided_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        approval = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=approver_user_id,
        action="control_plane.action_approved",
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(approval_id),
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "tool_key": approval.tool_key,
            "proposer_user_id": str(approval.proposer_user_id),
        },
    )
    return approval


def reject(
    tenant_id: uuid.UUID, approval_id: uuid.UUID, approver_user_id: uuid.UUID
) -> ApprovalRequest:
    approval = get_approval(tenant_id, approval_id)
    if approval.status != "pending":
        raise ApprovalNotPendingError(approval_id, approval.status)

    with tenant_session_scope(tenant_id) as session:
        row = session.get(ApprovalRequest, approval_id)
        if row is None or row.tenant_id != tenant_id:
            raise ApprovalRequestNotFoundError(tenant_id, approval_id)
        row.status = "rejected"
        row.approver_user_id = approver_user_id
        row.decided_at = datetime.now(UTC)
        session.flush()
        session.refresh(row)
        session.expunge(row)
        approval = row

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=approver_user_id,
        action="control_plane.action_rejected",
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(approval_id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"tool_key": approval.tool_key},
    )
    return approval


async def _claim_for_execution(tenant_id: uuid.UUID, approval_id: uuid.UUID) -> ApprovalRequest:
    """Phase J-R1 (CP-01): the atomic exclusive claim that closes the
    `execute_approved()` TOCTOU race -- a plain, single-statement
    `UPDATE ... WHERE status = 'approved'` is PostgreSQL's own
    compare-and-swap: two concurrent callers racing this same approval
    both attempt the identical `UPDATE`, but the row lock the first
    caller's statement takes forces the second to wait, then re-evaluate
    its own `WHERE status = 'approved'` against the row *as the first
    caller left it* -- already `"executing"` -- so at most one `UPDATE`
    can ever match and change a row. No advisory lock, no `SELECT ...
    FOR UPDATE`, and no new locking primitive is introduced: this is the
    same "database atomicity is the real guarantee" discipline
    `control_plane/approvals/models.py`'s own separation-of-duties CHECK
    constraint already uses, applied to a state transition instead of a
    row-insert constraint.

    Raises `ApprovalRequestNotFoundError`/`ApprovalNotPendingError`
    exactly like the rest of this module when the claim is not won --
    "not won" and "never was approved" are indistinguishable to a caller
    by design (both mean "you may not execute this"), the same non-
    disclosure precedent `get_approval()` already uses for tenant
    mismatch vs. genuine absence.
    """
    with tenant_session_scope(tenant_id) as session:
        result = session.execute(
            update(ApprovalRequest)
            .where(
                ApprovalRequest.id == approval_id,
                ApprovalRequest.tenant_id == tenant_id,
                ApprovalRequest.status == "approved",
            )
            .values(status="executing")
        )
        if result.rowcount == 0:  # type: ignore[reportAttributeAccessIssue] -- CursorResult has it at runtime
            row = session.get(ApprovalRequest, approval_id)
            if row is None or row.tenant_id != tenant_id:
                raise ApprovalRequestNotFoundError(tenant_id, approval_id)
            raise ApprovalNotPendingError(approval_id, row.status)

        claimed = session.get(ApprovalRequest, approval_id)
        assert claimed is not None  # the UPDATE above just matched this exact row
        session.expunge(claimed)
        return claimed


async def execute_approved(
    tenant_id: uuid.UUID,
    approval_id: uuid.UUID,
    *,
    registry: ToolRegistry | None = None,
    data_authorization_decision: DataAuthorizationDecision | None = None,
) -> ApprovalRequest:
    """Execute a previously-approved action. Refuses to run against
    anything but `status == "approved"` -- this is what makes "a
    rejected proposal never executes" true structurally, not by
    convention.

    Phase J-R1 (CP-01): between the `"approved"` read and the
    `"executed"` write, this function now claims exclusive ownership via
    an atomic `"approved" -> "executing"` transition
    (`_claim_for_execution()`) *before* invoking the tool -- so two
    concurrent calls against the same `approval_id` can no longer both
    observe `"approved"` and both execute it; only the one that wins the
    claim proceeds. If `_execute_tool()` itself raises, the claim is
    rolled back to `"approved"` (never left stuck at `"executing"`, and
    never advanced to `"executed"`) so a genuine retry remains possible
    without inventing a lease/timeout-recovery mechanism -- a failed
    execution must never be silently recorded as a successful one, and
    must never permanently strand the approval either.

    `data_authorization_decision` is forwarded, unmodified, to
    `_execute_tool()` -- it is required (and checked against this same
    `tenant_id`) only when `approval.tool_key` names a tool declaring
    `requires_data_authorization=True`; every other approved tool ignores
    it, exactly as `control_plane.orchestration.invoke_tool()` does. This
    keeps the ordering RBAC -> approval (already enforced by the claim
    above) -> Data Authorization -> handler, never the reverse."""
    approval = await _claim_for_execution(tenant_id, approval_id)

    try:
        await _execute_tool(
            approval.tool_key,
            agent_user_id=approval.proposer_user_id,
            tenant_id=tenant_id,
            agent_scope_value=approval.agent_scope_value,
            payload=approval.payload,
            registry=registry,
            data_authorization_decision=data_authorization_decision,
        )
    except Exception:
        with tenant_session_scope(tenant_id) as session:
            row = session.get(ApprovalRequest, approval_id)
            if row is not None and row.tenant_id == tenant_id and row.status == "executing":
                row.status = "approved"
        raise

    with tenant_session_scope(tenant_id) as session:
        row = session.get(ApprovalRequest, approval_id)
        if row is None or row.tenant_id != tenant_id:
            raise ApprovalRequestNotFoundError(tenant_id, approval_id)
        row.status = "executed"
        session.flush()
        session.refresh(row)
        session.expunge(row)
        return row
