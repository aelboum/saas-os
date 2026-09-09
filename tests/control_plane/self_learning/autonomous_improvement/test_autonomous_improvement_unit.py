"""Unit tests for `control_plane.self_learning.autonomous_improvement`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.8). No database required --
`create_canary()`'s entire five-part authority-composition check (see
`service.py`'s own docstring) runs before its `tenant_session_scope()`
call, so every denial path is reachable with plain, unpersisted
`Experiment`/`Adaptation`/`PolicyGateDecision` objects, mirroring
`tests/control_plane/self_learning/experiments/test_experiments_unit.py`'s
own discipline. Full lifecycle (start/observe/conclude/promote/rollback,
which all require a persisted row) is covered by
`test_autonomous_improvement_integration.py` (marked `integration`).
"""

from __future__ import annotations

import uuid

import pytest

from control_plane.self_learning.adaptive.models import Adaptation, AdaptationStatus
from control_plane.self_learning.autonomous_improvement.errors import (
    AdaptationNotCandidateForCanaryError,
    ExperimentNotEvaluatedForCanaryError,
    InvalidCanaryCandidateError,
    UnauthorizedCanaryPolicyDecisionError,
)
from control_plane.self_learning.autonomous_improvement.service import (
    _deserialize_rules,
    _serialize_rules,
    _violated_metrics,
    create_canary,
)
from control_plane.self_learning.evaluation.models import (
    EvaluationMetrics,
    EvaluationRules,
    MetricDirection,
    MetricThreshold,
)
from control_plane.self_learning.experiments.models import Experiment, ExperimentCandidateSourceKind
from control_plane.self_learning.policy_gate.models import (
    AutonomyTier,
    PolicyGateDecision,
    PolicyGateDenialReason,
    PolicyGateOutcome,
    RequestedAction,
)

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()
ACTOR = uuid.uuid4()

RULES = EvaluationRules(
    thresholds=(
        MetricThreshold(
            metric_name="error_rate",
            direction=MetricDirection.LOWER_IS_BETTER,
            maximum_absolute=0.1,
        ),
        MetricThreshold(
            metric_name="task_success_rate",
            direction=MetricDirection.HIGHER_IS_BETTER,
            minimum_absolute=0.5,
        ),
    )
)


def _experiment(
    *,
    tenant_id: uuid.UUID = TENANT_A,
    status: str = "completed",
    evaluation_outcome: str | None = "pass",
    candidate_source_kind: str = ExperimentCandidateSourceKind.ADAPTATION.value,
    candidate_source_id: uuid.UUID | None = None,
    baseline_version: str = "v0",
) -> Experiment:
    return Experiment(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        status=status,
        candidate_source_kind=candidate_source_kind,
        candidate_source_id=candidate_source_id or uuid.uuid4(),
        candidate_version="1",
        baseline_version=baseline_version,
        learning_authorization_decision_id=uuid.uuid4(),
        evidence_type="user_feedback",
        evidence_source_reference="ref-1",
        evaluation_comparison_id=uuid.uuid4(),
        evaluation_outcome=evaluation_outcome,
        created_by_user_id=ACTOR,
    )


def _adaptation(
    *,
    tenant_id: uuid.UUID = TENANT_A,
    status: str = AdaptationStatus.CANDIDATE.value,
    evaluation_outcome: str | None = "pass",
) -> Adaptation:
    return Adaptation(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        surface="prompt_instruction",
        lineage_key="support_agent.system_prompt",
        version=1,
        status=status,
        scope="tenant",
        proposed_value="Be courteous.",
        learning_purpose="adaptive_prompt_tuning",
        evidence_type="user_feedback",
        evidence_source_reference="ref-1",
        learning_authorization_decision_id=uuid.uuid4(),
        evaluation_outcome=evaluation_outcome,
        created_by_user_id=ACTOR,
    )


def _policy_decision(
    *,
    tenant_id: uuid.UUID | None = TENANT_A,
    outcome: PolicyGateOutcome = PolicyGateOutcome.ALLOW,
    requested_action: str = RequestedAction.ACTIVATE_ADAPTATION.value,
    requested_autonomy_tier: int = AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED.value,
    reason=None,
) -> PolicyGateDecision:
    return PolicyGateDecision(
        outcome=outcome,
        tenant_id=tenant_id,
        requested_action=requested_action,
        requested_autonomy_tier=requested_autonomy_tier,
        reason=reason,
    )


def _matched_pair(tenant_id: uuid.UUID = TENANT_A) -> tuple[Experiment, Adaptation]:
    adaptation = _adaptation(tenant_id=tenant_id)
    experiment = _experiment(tenant_id=tenant_id, candidate_source_id=adaptation.id)
    return experiment, adaptation


# --------------------------------------------------------------------- #
# Tenant / candidate identity
# --------------------------------------------------------------------- #


def test_tenant_mismatch_between_call_and_experiment_is_denied() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    with pytest.raises(InvalidCanaryCandidateError):
        create_canary(
            tenant_id=TENANT_B,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(tenant_id=TENANT_B),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_tenant_mismatch_between_experiment_and_adaptation_is_denied() -> None:
    adaptation = _adaptation(tenant_id=TENANT_B)
    experiment = _experiment(tenant_id=TENANT_A, candidate_source_id=adaptation.id)
    with pytest.raises(InvalidCanaryCandidateError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(tenant_id=TENANT_A),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_candidate_substitution_is_denied() -> None:
    """A different Adaptation than the one the Experiment names as its
    candidate must be refused -- confused-deputy / candidate-substitution
    protection."""
    experiment, real_adaptation = _matched_pair(TENANT_A)
    other_adaptation = _adaptation(tenant_id=TENANT_A)
    with pytest.raises(InvalidCanaryCandidateError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=other_adaptation,
            policy_gate_decision=_policy_decision(),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_system_learning_proposal_sourced_experiment_is_denied() -> None:
    """Phase 9.5's own binding Non-Goal: a proposal is never automatically
    applied to production -- structurally refused here regardless of any
    other field."""
    adaptation = _adaptation(tenant_id=TENANT_A)
    experiment = _experiment(
        tenant_id=TENANT_A,
        candidate_source_kind="system_learning_proposal",
        candidate_source_id=adaptation.id,
    )
    with pytest.raises(InvalidCanaryCandidateError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


# --------------------------------------------------------------------- #
# Experiment / Adaptation state
# --------------------------------------------------------------------- #


def test_regression_experiment_blocks_canary_creation() -> None:
    """Non-vacuous enforcement of Phase 9.8's own Tests bullet: a
    deliberately-failed regression suite blocks promotion."""
    experiment, adaptation = _matched_pair(TENANT_A)
    experiment.evaluation_outcome = "regression"
    with pytest.raises(ExperimentNotEvaluatedForCanaryError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_failed_experiment_blocks_canary_creation() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    experiment.evaluation_outcome = "fail"
    with pytest.raises(ExperimentNotEvaluatedForCanaryError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_incomplete_experiment_blocks_canary_creation() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    experiment.status = "running"
    with pytest.raises(ExperimentNotEvaluatedForCanaryError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_already_active_adaptation_blocks_canary_creation() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    adaptation.status = AdaptationStatus.ACTIVE.value
    with pytest.raises(AdaptationNotCandidateForCanaryError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


# --------------------------------------------------------------------- #
# Policy gate composition -- forged Tier 3 / wrong tier / wrong action
# --------------------------------------------------------------------- #


def test_tier0_policy_decision_is_refused_for_canary() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    with pytest.raises(UnauthorizedCanaryPolicyDecisionError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(requested_autonomy_tier=0),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_tier1_policy_decision_is_refused_for_canary() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    with pytest.raises(UnauthorizedCanaryPolicyDecisionError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(requested_autonomy_tier=1),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_forged_tier3_policy_decision_is_refused_for_canary() -> None:
    """A hand-built `PolicyGateDecision` claiming `outcome=ALLOW` at tier
    3 (impossible from `evaluate_policy_gate()` itself, but this module
    must not trust that invariant blindly) is refused."""
    experiment, adaptation = _matched_pair(TENANT_A)
    forged = PolicyGateDecision(
        outcome=PolicyGateOutcome.ALLOW,
        tenant_id=TENANT_A,
        requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
        requested_autonomy_tier=3,
        reason=None,
    )
    with pytest.raises(UnauthorizedCanaryPolicyDecisionError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=forged,
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_denied_policy_decision_is_refused_for_canary() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    denied = _policy_decision(
        outcome=PolicyGateOutcome.DENY, reason=PolicyGateDenialReason.MISSING_REQUIRED_APPROVAL
    )
    with pytest.raises(UnauthorizedCanaryPolicyDecisionError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=denied,
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_cross_tenant_policy_decision_is_refused_for_canary() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    with pytest.raises(UnauthorizedCanaryPolicyDecisionError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(tenant_id=TENANT_B),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_wrong_action_policy_decision_is_refused_for_canary() -> None:
    experiment, adaptation = _matched_pair(TENANT_A)
    with pytest.raises(UnauthorizedCanaryPolicyDecisionError):
        create_canary(
            tenant_id=TENANT_A,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=_policy_decision(requested_action="promote_experiment"),
            monitoring_rules=RULES,
            created_by_user_id=ACTOR,
        )


def test_model_claim_of_evaluation_pass_has_no_effect() -> None:
    """A candidate cannot "declare" evaluation_passed=true -- there is no
    such field anywhere on `PolicyGateDecision`; the only fields
    `create_canary()` reads are the real, structurally-typed
    `status`/`evaluation_outcome`/`outcome` values."""
    with pytest.raises(TypeError):
        PolicyGateDecision(  # type: ignore[call-arg]
            outcome=PolicyGateOutcome.ALLOW,
            tenant_id=TENANT_A,
            requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
            requested_autonomy_tier=2,
            reason=None,
            evaluation_passed=True,  # type: ignore[call-arg]
        )


# --------------------------------------------------------------------- #
# Monitoring metric checks (pure helper)
# --------------------------------------------------------------------- #


def test_violated_metrics_empty_when_all_thresholds_cleared() -> None:
    metrics = EvaluationMetrics(error_rate=0.05, task_success_rate=0.9)
    assert _violated_metrics(metrics, RULES) == ()


def test_violated_metrics_reports_absolute_bar_breach() -> None:
    metrics = EvaluationMetrics(error_rate=0.5, task_success_rate=0.9)
    assert _violated_metrics(metrics, RULES) == ("error_rate",)


def test_violated_metrics_reports_missing_metric_as_violation() -> None:
    metrics = EvaluationMetrics(error_rate=0.05, task_success_rate=None)
    assert _violated_metrics(metrics, RULES) == ("task_success_rate",)


def test_violated_metrics_never_checks_regression_bar() -> None:
    rules = EvaluationRules(
        thresholds=(
            MetricThreshold(
                metric_name="cost",
                direction=MetricDirection.LOWER_IS_BETTER,
                maximum_regression=0.01,
            ),
        )
    )
    # No `maximum_absolute` on this threshold -- an arbitrarily high cost
    # is never flagged by the (regression-only) rule during monitoring,
    # since there is no live baseline to regress against.
    metrics = EvaluationMetrics(cost=999.0)
    assert _violated_metrics(metrics, rules) == ()


def test_rules_serialization_roundtrip() -> None:
    assert _deserialize_rules(_serialize_rules(RULES)) == RULES
