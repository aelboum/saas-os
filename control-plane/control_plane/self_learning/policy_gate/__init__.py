"""`control_plane.self_learning.policy_gate` -- the Autonomy & Policy Gate
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.7): the boundary every self-learning
candidate must pass before any bounded autonomous action (Phase 9.8) is
permitted, reusing docs/AI-CONTROL-PLANE.md section 5's existing
autonomy-tier vocabulary (tiers 0-3) rather than inventing a parallel
model.

**Architectural principle (this phase's own, verbatim)**:

    Tool Authorization -> Data Authorization -> Learning Authorization ->
    Autonomy/Policy Gate -> Permitted Action

Each is a separate authority; passing one never implicitly grants the
next. Default is **DENY**. Learning-derived evidence, feedback,
evaluation results, adaptations, experiments, and system-learning
proposals are inputs to policy evaluation, never authority themselves
(ADR-0014: "external input is evidence, not trusted policy").

**Scope (this phase)**: the gate mechanism itself (policy evaluation +
approval-state composition), not any specific promotion decision -- this
package never activates an `Adaptation`, applies a `SystemLearningProposal`,
or promotes an `Experiment`; it only decides whether a caller-described
candidate action, at a caller-declared autonomy tier, is permitted. Tier 3
(fully autonomous) remains explicitly not enabled -- refused
unconditionally, not by omission from the vocabulary (`models.py`'s own
`AutonomyTier` docstring).

Owns:
- `PolicyGateRequest` / `PolicyGateDecision` and their typed allowlists
  (`AutonomyTier`, `RequestedAction`, `PolicyGateDenialReason`,
  `PolicyGateScope`, `Tier2PromotionEvidence`) (`models.py`);
- `evaluate_policy_gate()` -- the pure decision function;
- `evaluate_and_record_policy_gate_decision()` -- the audited entrypoint
  (`learning.policy_gate_decision`, this phase's own Audit Requirement).

Does NOT own: Tool Authorization (`core.rbac`, `control_plane.orchestration`),
Data Authorization (`control_plane.data_authorization`), Learning
Authorization (`control_plane.self_learning`), Evaluation
(`control_plane.self_learning.evaluation`), the tier-1 propose/approve/
execute workflow (`control_plane.approvals`), Adaptive Learning, System
Learning, or Experimentation (Phase 9.4/9.5/9.6, consumed here only as
already-authoritative typed inputs, never re-derived or mutated); L3
Autonomous Improvement, canary deployment, or any production-promotion
pipeline (Phase 9.8, not built here); any new AI Control Plane tool, RBAC
grant, or secrets access (none required by this phase's own Files/Modules
Affected).

No database table, migration, or ORM model is defined here -- see
`models.py`'s own no-persistence discipline.
"""

from control_plane.self_learning.policy_gate.models import (
    VALID_AUTONOMY_TIERS,
    VALID_POLICY_GATE_ACTIONS,
    AutonomyTier,
    PolicyGateDecision,
    PolicyGateDenialReason,
    PolicyGateOutcome,
    PolicyGateRequest,
    PolicyGateScope,
    RequestedAction,
    Tier2PromotionEvidence,
)
from control_plane.self_learning.policy_gate.service import (
    evaluate_and_record_policy_gate_decision,
    evaluate_policy_gate,
)

__all__ = [
    "AutonomyTier",
    "VALID_AUTONOMY_TIERS",
    "RequestedAction",
    "VALID_POLICY_GATE_ACTIONS",
    "PolicyGateOutcome",
    "PolicyGateDenialReason",
    "PolicyGateScope",
    "Tier2PromotionEvidence",
    "PolicyGateRequest",
    "PolicyGateDecision",
    "evaluate_policy_gate",
    "evaluate_and_record_policy_gate_decision",
]
