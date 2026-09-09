"""`control_plane.self_learning.system_learning` -- L2 System Learning
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.5): discover recurring problems
(agent/tool failures, support/latency/cost/routing/workflow problems,
missing regression tests, recurring policy violations, operational
failures) and produce structured, evidence-backed improvement
**proposals** -- never an arbitrary production modification
(Phase 9.5's own Objective, verbatim).

**Layer**: AI Control Plane, never SaaS Core (docs/ARCHITECTURE.md
sections 1-2) -- the same placement as every other module in
`control_plane.self_learning`. `core` must never acquire a dependency on
this package.

**Scope (this phase)**: proposal generation only. Phase 9.5's own Scope,
verbatim: "a proposal is data, never auto-applied by this phase." This
package has no path that deploys, promotes, activates a production
change, modifies RBAC/authorization/security/secrets/autonomy-tier
policy, alters infrastructure, modifies source code, executes an
unrestricted shell/database command, or bypasses Data Authorization
(ADR-0013), Learning Authorization (ADR-0014), Evaluation (Phase 9.3), or
approvals (Phase 7.2).

Owns:
- `SystemLearningObservation` / `RecurrenceAssessment` -- typed evidence
  and a deterministic, testable recurrence verdict (`models.py`);
- `ProblemCategory` / `ProposedChangeTarget` -- closed, typed vocabularies
  (`models.py`). `ProposedChangeTarget` has no member for security policy,
  RBAC, permissions, secrets, autonomy tiers, deployment, or
  infrastructure control -- proposing a change to any of those is not
  merely rejected by a runtime check, it is *impossible to construct*
  (same discipline as `control_plane.self_learning.adaptive.models
  .AdaptationSurface`, Phase 9.4);
- `SystemLearningProposal` -- the schema-complete, immutable proposal
  shape (`models.py`);
- `detect_recurrence()` -- pure, deterministic recurrence/confidence
  computation (`service.py`);
- `propose_system_learning_proposal()` / `withdraw_system_learning_proposal()`
  -- the audited entrypoints (`service.py`).

Does NOT own: Data Authorization or Learning Authorization (consumes an
already-ALLOW `LearningAuthorizationDecision`, never re-derives one --
`control_plane.data_authorization`, `control_plane.self_learning.service`,
Phase 9.2); Evaluation (may reference an already-computed
`EvaluationComparison`'s outcome as provenance, never scores anything
itself -- `control_plane.self_learning.evaluation`, Phase 9.3); L1
Adaptive Learning (`control_plane.self_learning.adaptive`, Phase 9.4 --
a proposal generated here may eventually *inform* a future L1 adaptation,
but this package never constructs or activates one); Experimentation,
the Autonomy & Policy Gate, L3 Autonomous Improvement, or a continuous
learning loop (Phase 9.6-9.9, not built here); any Tool Registry tool or
HTTP route (not required by Phase 9.5's own Files/Modules Affected).

**No persistence**: Phase 9.5's own Files/Modules Affected names only
`control-plane/self-learning/system-learning/*` -- no migration, no
table. Every `SystemLearningProposal` is a plain, immutable (frozen
dataclass) in-memory value, exactly like `control_plane.self_learning`'s
own `LearningAuthorizationDecision` (Phase 9.2) and
`control_plane.self_learning.evaluation`'s own `EvaluationComparison`
(Phase 9.3). Recurring-failure evidence is read through
`core.audit_log`'s existing `list()` query interface (Phase 3.4,
Phase 9.5's own Dependencies) -- this package never adds a second,
parallel observation store. Proposal creation and every state change are
still recorded through `core.audit_log`'s existing `record()` interface
(`learning.proposal_created` / `learning.proposal_state_changed`) --
never a second audit mechanism.
"""

from control_plane import CONTROL_PLANE_MARKER
from control_plane.self_learning.system_learning.errors import (
    CrossTenantProposalNotAuthorizedError,
    InvalidProblemCategoryError,
    InvalidProposedChangeTargetError,
    PlatformWideProposalScopeNotAuthorizedError,
    ProposalNotWithdrawableError,
    UnauthorizedProposalEvidenceError,
)
from control_plane.self_learning.system_learning.models import (
    VALID_PROBLEM_CATEGORIES,
    VALID_PROPOSED_CHANGE_TARGETS,
    ConfidenceLevel,
    PlatformWideProposalAuthorization,
    ProblemCategory,
    ProposalScope,
    ProposalStatus,
    ProposedChangeTarget,
    RecurrenceAssessment,
    RiskLevel,
    SystemLearningImpactMetrics,
    SystemLearningObservation,
    SystemLearningProposal,
)
from control_plane.self_learning.system_learning.service import (
    build_system_learning_proposal,
    build_withdrawn_proposal,
    detect_recurrence,
    propose_system_learning_proposal,
    withdraw_system_learning_proposal,
)

SYSTEM_LEARNING_MARKER = "system_learning"

__all__ = [
    "CONTROL_PLANE_MARKER",
    "SYSTEM_LEARNING_MARKER",
    "ProblemCategory",
    "VALID_PROBLEM_CATEGORIES",
    "ProposedChangeTarget",
    "VALID_PROPOSED_CHANGE_TARGETS",
    "ProposalScope",
    "ProposalStatus",
    "RiskLevel",
    "ConfidenceLevel",
    "SystemLearningObservation",
    "RecurrenceAssessment",
    "SystemLearningImpactMetrics",
    "PlatformWideProposalAuthorization",
    "SystemLearningProposal",
    "detect_recurrence",
    "build_system_learning_proposal",
    "propose_system_learning_proposal",
    "build_withdrawn_proposal",
    "withdraw_system_learning_proposal",
    "UnauthorizedProposalEvidenceError",
    "InvalidProblemCategoryError",
    "InvalidProposedChangeTargetError",
    "CrossTenantProposalNotAuthorizedError",
    "PlatformWideProposalScopeNotAuthorizedError",
    "ProposalNotWithdrawableError",
]
