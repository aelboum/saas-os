"""`control_plane.self_learning.autonomous_improvement` -- L3 Autonomous
Improvement (docs/IMPLEMENTATION-ROADMAP.md Phase 9.8): bounded autonomous
improvement through Experiment -> Policy Gate -> Canary -> Monitoring ->
Promote OR Rollback. Explicitly **bounded autonomy, not unrestricted
self-modification** (Phase 9.8's own Objective, verbatim).

**Autonomy tier: 2 at most, never 3** -- Phase 9.8's own Non-Goal,
verbatim: "no tier-3 (fully autonomous, no standing checkpoint)
capability -- canary + monitoring + promote/rollback is tier 2 at most,
per `docs/AI-CONTROL-PLANE.md` section 5." "L3" names the *learning
level* (bounded autonomous improvement -- `docs/AI-CONTROL-PLANE.md`
section 12's three learning levels, an axis independent of the autonomy
tiers in section 5), not autonomy tier 3. Tier 3 remains not enabled for
anything, unchanged by this phase -- `control_plane.self_learning
.policy_gate.evaluate_policy_gate()` refuses it unconditionally, and
`service.create_canary()` here independently refuses any
`PolicyGateDecision` not carrying `requested_autonomy_tier == 2`.

**Scope (this phase)**: exactly the pipeline above -- a canary is a
scoped, monitored, reversible partial rollout, never a direct
full-production change (Phase 9.8's own Scope, verbatim). "Scoped"
means, structurally, exactly one tenant: `Adaptation` (Phase 9.4) has no
platform-wide/multi-tenant activation mechanism, so this package
implements none either -- see `models.py`'s own docstring. This package
never activates, mutates, or promotes a `SystemLearningProposal` (Phase
9.5's own binding Non-Goal: "no automatic application of a proposal to
production").

Owns:
- `Canary` (`self_learning.canaries`, tenant-owned, RLS-protected) and its
  typed lifecycle (`CanaryStatus`) (`models.py`);
- `create_canary()` / `start_canary()` / `record_canary_observation()` /
  `conclude_canary_monitoring()` / `promote_canary()` /
  `rollback_canary()` / `cancel_canary()` (`service.py`).

Does NOT own: Learning Authorization, Data Authorization, Evaluation,
Adaptive Learning, System Learning, Experimentation, or the Autonomy &
Policy Gate (Phases 9.2-9.7, consumed here only as already-authoritative
typed inputs -- an already-ALLOW `PolicyGateDecision`, an already-`PASS`
`Experiment`, an already-`CANDIDATE` `Adaptation` -- never re-derived,
re-scored, or re-evaluated); the tier-1 propose/approve/execute workflow
(`control_plane.approvals`, still the only route for a tool declaring
`autonomy_tier=1`); any new Tool Registry tool (none required by this
phase's own Files/Modules Affected); the continuous learning loop (Phase
9.9, not built here).
"""

from control_plane.self_learning.autonomous_improvement.errors import (
    AdaptationNotCandidateForCanaryError,
    CanaryAlreadyTerminalError,
    CanaryNotConfiguredError,
    CanaryNotFoundError,
    CanaryNotRunningError,
    CanaryNotSucceededError,
    CanaryRollbackFailedError,
    ExperimentNotEvaluatedForCanaryError,
    InvalidCanaryCandidateError,
    UnauthorizedCanaryPolicyDecisionError,
)
from control_plane.self_learning.autonomous_improvement.models import (
    TERMINAL_CANARY_STATUSES,
    VALID_CANARY_STATUSES,
    Canary,
    CanaryStatus,
)
from control_plane.self_learning.autonomous_improvement.service import (
    cancel_canary,
    conclude_canary_monitoring,
    create_canary,
    get_canary,
    promote_canary,
    record_canary_observation,
    rollback_canary,
    start_canary,
)

__all__ = [
    "CanaryStatus",
    "VALID_CANARY_STATUSES",
    "TERMINAL_CANARY_STATUSES",
    "Canary",
    "create_canary",
    "get_canary",
    "start_canary",
    "record_canary_observation",
    "conclude_canary_monitoring",
    "promote_canary",
    "rollback_canary",
    "cancel_canary",
    "InvalidCanaryCandidateError",
    "ExperimentNotEvaluatedForCanaryError",
    "AdaptationNotCandidateForCanaryError",
    "UnauthorizedCanaryPolicyDecisionError",
    "CanaryNotFoundError",
    "CanaryNotConfiguredError",
    "CanaryNotRunningError",
    "CanaryNotSucceededError",
    "CanaryAlreadyTerminalError",
    "CanaryRollbackFailedError",
]
