"""Typed errors for `control_plane.self_learning.system_learning`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.5)."""

from __future__ import annotations

import uuid


class InvalidProblemCategoryError(ValueError):
    """Raised when a proposed problem category names a value outside
    `ProblemCategory` -- structurally unreachable through the typed enum
    parameter, so this only fires against a raw/untyped bypass attempt."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(
            f"{category!r} is not a permitted L2 problem category "
            "(docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own allowlist)."
        )


class InvalidProposedChangeTargetError(ValueError):
    """Raised when a proposed change names a target outside
    `ProposedChangeTarget` -- structurally unreachable through the typed
    enum parameter (see `models.py`'s "Closed proposal vocabulary"), so
    this only fires against a raw/untyped bypass attempt."""

    def __init__(self, target: str) -> None:
        self.target = target
        super().__init__(
            f"{target!r} is not a permitted L2 proposed-change target "
            "(docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own closed vocabulary)."
        )


class UnauthorizedProposalEvidenceError(PermissionError):
    """Raised when a proposal's `LearningAuthorizationDecision` is not an
    ALLOW for the proposing tenant, or when its evidence type is not a
    member of `control_plane.self_learning.models.VALID_EVIDENCE_TYPES`
    (Phase 9.2's gate, never bypassed)."""


class CrossTenantProposalNotAuthorizedError(PermissionError):
    """docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own Tenant-Isolation
    Requirement: "a proposal's affected-tenant(s) field is enforced
    structurally -- a proposal sourced from Tenant A's evidence cannot
    silently list Tenant B as affected without an explicit cross-tenant
    justification path." Raised when `affected_tenant_ids` names a tenant
    other than the proposing tenant with no exactly-matching
    `CrossTenantLearningPolicy`."""

    def __init__(self, tenant_id: uuid.UUID, other_tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.other_tenant_id = other_tenant_id
        super().__init__(
            f"Tenant {other_tenant_id} is not authorized as an affected tenant for a "
            f"proposal sourced from tenant {tenant_id}'s evidence."
        )


class PlatformWideProposalScopeNotAuthorizedError(PermissionError):
    """Mirrors `control_plane.self_learning.adaptive.errors
    .PlatformWideScopeNotAuthorizedError` (Phase 9.4): platform-wide scope
    requires an explicit, separate authorization -- never inferred from
    Learning Authorization alone."""

    def __init__(self, tenant_id: uuid.UUID, purpose: str) -> None:
        self.tenant_id = tenant_id
        self.purpose = purpose
        super().__init__(
            f"Platform-wide proposal scope is not authorized for tenant {tenant_id} "
            f"and purpose {purpose!r}."
        )


class ProposalNotWithdrawableError(ValueError):
    """Raised by `service.withdraw_system_learning_proposal()` when the
    target proposal is not `ProposalStatus.PROPOSED` -- a proposal may be
    withdrawn exactly once, from that status."""

    def __init__(self, proposal_id: uuid.UUID, status: str) -> None:
        self.proposal_id = proposal_id
        self.status = status
        super().__init__(f"Proposal {proposal_id} is not withdrawable (status={status!r}).")
