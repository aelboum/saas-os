"""`control_plane.self_learning.adaptive` -- L1 Adaptive Learning
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.4): the first phase where
Self-Learning may produce a bounded adaptation *proposal*. Level 1 only
-- see docs/AI-CONTROL-PLANE.md section 12's own L1 row: "versioned,
reversible adaptations: prompt/instruction candidates, model
selection/routing, tool selection, retrieval/response strategy,
permitted personalization, learning from explicit feedback/operator
corrections" / "Must not: modify source code, database schemas, security
policies, authorization, or secrets; deploy infrastructure; bypass
approval/policy; access unrestricted tenant data."

Owns:
- `Adaptation` (`self_learning.adaptations`, tenant-owned, RLS-protected
  -- the first table ever created in the `self_learning` schema Phase
  9.1 reserved) and its typed allowlists (`AdaptationSurface`,
  `AdaptationStatus`, `AdaptationScope`) (`models.py`);
- `propose_adaptation()` / `record_adaptation_evaluation()` /
  `activate_adaptation()` / `rollback_adaptation()` (`service.py`).

Does NOT own: Data Authorization or Learning Authorization (consumes an
already-ALLOW `LearningAuthorizationDecision`, never re-derives one --
`control_plane.data_authorization`, `control_plane.self_learning.service`,
Phase 9.2); evaluation (consumes an already-computed
`EvaluationComparison`, never scores anything itself --
`control_plane.self_learning.evaluation`, Phase 9.3); the tier-1
propose/approve/execute workflow for activation/rollback
(`control_plane.approvals`, `control_plane.tools.activate_adaptation`/
`.rollback_adaptation`, Phase 7.2); L2 system learning, experimentation,
autonomy/policy-gate promotion, L3 autonomous improvement, or a
continuous learning loop (Phase 9.5-9.9, not built here).
"""

from control_plane.self_learning.adaptive.errors import (
    AdaptationNotActiveError,
    AdaptationNotCandidateError,
    AdaptationNotEvaluatedError,
    AdaptationNotFoundError,
    InvalidAdaptationSurfaceError,
    NoPreviousVersionError,
    PlatformWideScopeNotAuthorizedError,
    UnauthorizedAdaptationEvidenceError,
)
from control_plane.self_learning.adaptive.models import (
    VALID_ADAPTATION_EVIDENCE_TYPES,
    VALID_ADAPTATION_SCOPES,
    VALID_ADAPTATION_STATUSES,
    VALID_ADAPTATION_SURFACES,
    Adaptation,
    AdaptationEvidenceType,
    AdaptationScope,
    AdaptationStatus,
    AdaptationSurface,
    PlatformWideAdaptationAuthorization,
)
from control_plane.self_learning.adaptive.service import (
    activate_adaptation,
    get_adaptation,
    propose_adaptation,
    record_adaptation_evaluation,
    rollback_adaptation,
)

__all__ = [
    "AdaptationSurface",
    "VALID_ADAPTATION_SURFACES",
    "AdaptationStatus",
    "VALID_ADAPTATION_STATUSES",
    "AdaptationScope",
    "VALID_ADAPTATION_SCOPES",
    "AdaptationEvidenceType",
    "VALID_ADAPTATION_EVIDENCE_TYPES",
    "PlatformWideAdaptationAuthorization",
    "Adaptation",
    "propose_adaptation",
    "get_adaptation",
    "record_adaptation_evaluation",
    "activate_adaptation",
    "rollback_adaptation",
    "AdaptationNotFoundError",
    "AdaptationNotCandidateError",
    "AdaptationNotEvaluatedError",
    "AdaptationNotActiveError",
    "NoPreviousVersionError",
    "InvalidAdaptationSurfaceError",
    "UnauthorizedAdaptationEvidenceError",
    "PlatformWideScopeNotAuthorizedError",
]
