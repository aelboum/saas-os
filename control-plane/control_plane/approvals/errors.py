"""Typed errors for `control_plane.approvals`
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.2)."""

from __future__ import annotations

import uuid


class ApprovalRequestNotFoundError(LookupError):
    def __init__(self, tenant_id: uuid.UUID, approval_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.approval_id = approval_id
        super().__init__(f"Approval request {approval_id} not found in tenant {tenant_id}.")


class ApprovalNotPendingError(ValueError):
    """Raised when `approve()`/`reject()` is called against an approval
    request that has already been decided -- an approval decision is
    made exactly once (docs/IMPLEMENTATION-ROADMAP.md Phase 7.2's own
    "first-class state" objective: a decision is not silently
    overwritable)."""

    def __init__(self, approval_id: uuid.UUID, status: str) -> None:
        self.approval_id = approval_id
        self.status = status
        super().__init__(f"Approval request {approval_id} is not pending (status={status!r}).")


class SelfApprovalNotAllowedError(PermissionError):
    """docs/IMPLEMENTATION-ROADMAP.md Phase 7.2's own Security
    Requirement: "an approval cannot be self-granted by the same
    identity that proposed the action" -- separation of duties."""

    def __init__(self, approval_id: uuid.UUID) -> None:
        self.approval_id = approval_id
        super().__init__(f"Approval request {approval_id} cannot be approved by its own proposer.")
