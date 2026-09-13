"""Typed errors for `control_plane.self_learning.evaluation`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.3; CP-04, Phase J audit)."""

from __future__ import annotations

import uuid


class EvaluationProvenanceError(PermissionError):
    """Raised by a consumer of `EvaluationComparison` (`adaptive.service
    .record_adaptation_evaluation()`, `experiments.service
    .record_experiment_result()`) when `service
    .verify_evaluation_provenance()` returns `False` for the supplied
    comparison -- its `decision_id` has no genuine, matching
    `learning.evaluation_run` `core.audit_log` record for the caller's own
    tenant. `EvaluationComparison` is a same-process, non-persisted,
    non-cryptographically-bound dataclass (same discipline as
    `DataAuthorizationDecision`/`LearningAuthorizationDecision`/
    `PolicyGateDecision`, CP-02) -- any in-process caller can construct a
    plausible-looking one with a fresh `decision_id` and any claimed
    `outcome`, including `PASS`. CP-04 (Phase J audit): a forged `PASS`
    accepted here previously satisfied `activate_adaptation()`'s own
    "structurally enforced" `AdaptationNotEvaluatedError` gate with no
    audit trace of the forgery -- this error is CP-04's fail-closed
    remediation of that gap."""

    def __init__(self, decision_id: uuid.UUID) -> None:
        self.decision_id = decision_id
        super().__init__(
            f"EvaluationComparison {decision_id} has no genuine, audited "
            "learning.evaluation_run record for this tenant."
        )
