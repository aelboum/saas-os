"""`control_plane.approvals` -- the tier-1 human approval gate workflow
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.2; docs/AI-CONTROL-PLANE.md
section 5).

Owns:
- the tenant-owned `ApprovalRequest` entity (`control_plane.approval_requests`,
  RLS-protected) -- staged, decided, or executed tier>=1 tool proposals;
- `propose_action()` / `approve()` / `reject()` / `execute_approved()` --
  first-class state for the full propose -> approve -> execute cycle,
  never an out-of-band process.

Does NOT own: tool definitions or the tenant-scoped/scope-matched
authorization check itself (`control_plane.orchestration`, which
`execute_approved()` calls into once a request is approved); the
first real tool (`control_plane.development`, `control_plane.tools`,
Phase 7.3).
"""

from control_plane.approvals.errors import (
    ApprovalNotPendingError,
    ApprovalRequestNotFoundError,
    SelfApprovalNotAllowedError,
)
from control_plane.approvals.models import ApprovalRequest
from control_plane.approvals.service import (
    approve,
    execute_approved,
    get_approval,
    list_approvals,
    propose_action,
    reject,
)

__all__ = [
    "ApprovalRequest",
    "propose_action",
    "approve",
    "reject",
    "execute_approved",
    "get_approval",
    "list_approvals",
    "ApprovalRequestNotFoundError",
    "ApprovalNotPendingError",
    "SelfApprovalNotAllowedError",
]
