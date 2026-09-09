"""`control_plane.self_learning.experiments` -- Experimentation
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.6): let an authorized adaptation
candidate (Phase 9.4) or system-learning proposal (Phase 9.5) run as an
**isolated experiment, evaluated (Phase 9.3) against a baseline, with
zero production-binding effect** (Phase 9.6's own Objective, verbatim).

**Layer**: AI Control Plane, never SaaS Core (docs/ARCHITECTURE.md
sections 1-2) -- the same placement as every other module in
`control_plane.self_learning`. `core` must never acquire a dependency on
this package.

**Scope (this phase)**: experiment execution + evaluation only -- no
canary, no autonomous deployment (Phase 9.6's own Scope, verbatim). This
package has no path that deploys, promotes, activates a production
change, modifies RBAC/authorization/security/secrets/autonomy-tier
policy, alters infrastructure, modifies source code, executes an
unrestricted shell/database command, or bypasses Data Authorization
(ADR-0013), Learning Authorization (ADR-0014), or Evaluation (Phase 9.3).

Owns:
- `Experiment` (`self_learning.experiments`, tenant-owned, RLS-protected)
  and its typed allowlists (`ExperimentCandidateSourceKind`,
  `ExperimentStatus`) (`models.py`);
- `create_experiment()` / `execute_experiment()` /
  `record_experiment_result()` / `cancel_experiment()` (`service.py`).

Does NOT own: Data Authorization or Learning Authorization (consumes an
already-ALLOW `LearningAuthorizationDecision`, never re-derives one --
`control_plane.data_authorization`, `control_plane.self_learning.service`,
Phase 9.2); Evaluation (consumes an already-computed `EvaluationComparison`,
never scores anything itself -- `control_plane.self_learning.evaluation`,
Phase 9.3); L1 Adaptive Learning or L2 System Learning (reads an existing
`Adaptation`/`SystemLearningProposal` as its candidate's provenance,
never constructs, mutates, or activates either --
`control_plane.self_learning.adaptive`, `control_plane.self_learning
.system_learning`, Phase 9.4/9.5); the Autonomy & Policy Gate, L3
Autonomous Improvement, or a continuous learning loop (Phase 9.7-9.9, not
built here); any Tool Registry tool or HTTP route (not required by Phase
9.6's own Files/Modules Affected).

**Tenant isolation**: `self_learning.experiments` is RLS-protected
exactly like `self_learning.adaptations` (`FORCE ROW LEVEL SECURITY`,
reusing `infra.db.rls.tenant_rls_statements()` -- Phase 9.6's own
Tenant-Isolation Requirement, verbatim: "experiment records/results are
RLS-protected exactly like every other tenant-owned table"). Experiment
creation, execution, result recording, and cancellation are each recorded
through `core.audit_log`'s existing interface
(`learning.experiment_created` / `.executed` / `.result_recorded` /
`.cancelled`) -- never a second audit mechanism.
"""

from control_plane import CONTROL_PLANE_MARKER
from control_plane.self_learning.experiments.errors import (
    ExperimentAlreadyTerminalError,
    ExperimentNotConfiguredError,
    ExperimentNotFoundError,
    ExperimentNotRunningError,
    ExperimentResultMismatchError,
    InvalidCandidateSourceError,
    UnauthorizedExperimentEvidenceError,
)
from control_plane.self_learning.experiments.models import (
    TERMINAL_EXPERIMENT_STATUSES,
    VALID_CANDIDATE_SOURCE_KINDS,
    VALID_EXPERIMENT_STATUSES,
    Experiment,
    ExperimentCandidateSourceKind,
    ExperimentStatus,
)
from control_plane.self_learning.experiments.service import (
    cancel_experiment,
    create_experiment,
    execute_experiment,
    get_experiment,
    record_experiment_result,
)

__all__ = [
    "CONTROL_PLANE_MARKER",
    "ExperimentCandidateSourceKind",
    "VALID_CANDIDATE_SOURCE_KINDS",
    "ExperimentStatus",
    "VALID_EXPERIMENT_STATUSES",
    "TERMINAL_EXPERIMENT_STATUSES",
    "Experiment",
    "create_experiment",
    "get_experiment",
    "execute_experiment",
    "record_experiment_result",
    "cancel_experiment",
    "InvalidCandidateSourceError",
    "UnauthorizedExperimentEvidenceError",
    "ExperimentNotFoundError",
    "ExperimentNotConfiguredError",
    "ExperimentNotRunningError",
    "ExperimentResultMismatchError",
    "ExperimentAlreadyTerminalError",
]
