"""Typed errors for `control_plane.self_learning.adaptive`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.4)."""

from __future__ import annotations

import uuid


class InvalidAdaptationSurfaceError(ValueError):
    """Raised when a proposed adaptation names a surface outside
    `AdaptationSurface` -- structurally unreachable through the typed
    enum parameter, so this only fires against a raw/untyped bypass
    attempt (e.g. a string smuggled past the type checker)."""

    def __init__(self, surface: str) -> None:
        self.surface = surface
        super().__init__(
            f"{surface!r} is not a permitted L1 adaptation surface "
            "(docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own allowlist)."
        )


class UnauthorizedAdaptationEvidenceError(PermissionError):
    """Raised when a proposed adaptation's `LearningAuthorizationDecision`
    is not an ALLOW for the proposing tenant, or when its evidence type
    is not `user_feedback`/`operator_feedback` (docs/IMPLEMENTATION-ROADMAP.md
    Phase 9.4's own Objective: "driven by explicit feedback and operator
    corrections only")."""


class AdaptationNotFoundError(LookupError):
    def __init__(self, tenant_id: uuid.UUID, adaptation_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.adaptation_id = adaptation_id
        super().__init__(f"Adaptation {adaptation_id} not found in tenant {tenant_id}.")


class AdaptationNotCandidateError(ValueError):
    """Raised by `activate_adaptation()` when the target row is not in
    `AdaptationStatus.CANDIDATE` -- an adaptation may be activated
    exactly once from that state."""

    def __init__(self, adaptation_id: uuid.UUID, status: str) -> None:
        self.adaptation_id = adaptation_id
        self.status = status
        super().__init__(f"Adaptation {adaptation_id} is not a candidate (status={status!r}).")


class AdaptationNotEvaluatedError(ValueError):
    """docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Security
    Requirement, verbatim: "adaptation candidates are evaluated (9.3)
    before taking effect, never applied directly from raw model output."
    Raised when `activate_adaptation()` is called against a candidate
    with no recorded evaluation outcome, or an outcome other than
    `EvaluationOutcome.PASS`."""

    def __init__(self, adaptation_id: uuid.UUID, evaluation_outcome: str | None) -> None:
        self.adaptation_id = adaptation_id
        self.evaluation_outcome = evaluation_outcome
        super().__init__(
            f"Adaptation {adaptation_id} cannot be activated: evaluation_outcome="
            f"{evaluation_outcome!r} (must be 'pass')."
        )


class AdaptationNotActiveError(ValueError):
    """Raised by `rollback_adaptation()` when the target row is not
    `AdaptationStatus.ACTIVE` -- only an active adaptation can be rolled
    back."""

    def __init__(self, adaptation_id: uuid.UUID, status: str) -> None:
        self.adaptation_id = adaptation_id
        self.status = status
        super().__init__(f"Adaptation {adaptation_id} is not active (status={status!r}).")


class NoPreviousVersionError(ValueError):
    """Raised by `rollback_adaptation()` when the active adaptation has no
    `previous_adaptation_id` to roll back to -- the very first version in
    a lineage has nothing to revert to."""

    def __init__(self, adaptation_id: uuid.UUID) -> None:
        self.adaptation_id = adaptation_id
        super().__init__(f"Adaptation {adaptation_id} has no previous version to roll back to.")


class PlatformWideScopeNotAuthorizedError(PermissionError):
    """docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Tenant-Isolation
    Requirement: platform-wide scope requires an explicit, separate
    authorization -- never inferred from tenant-scoped Learning
    Authorization alone."""

    def __init__(self, tenant_id: uuid.UUID, purpose: str) -> None:
        self.tenant_id = tenant_id
        self.purpose = purpose
        super().__init__(
            f"Platform-wide adaptation scope is not authorized for tenant {tenant_id} "
            f"and purpose {purpose!r}."
        )
