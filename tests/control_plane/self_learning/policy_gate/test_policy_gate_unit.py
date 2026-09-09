"""Unit tests for `control_plane.self_learning.policy_gate.service
.evaluate_policy_gate()` (docs/IMPLEMENTATION-ROADMAP.md Phase 9.7).

Pure-function tests only -- no database, mirroring
`tests/control_plane/self_learning/evaluation/test_evaluation_unit.py`'s
own split between pure-evaluator unit tests and audited-entrypoint
integration tests. Every test here constructs its own
`PolicyGateRequest` and asserts on the returned `PolicyGateDecision`
alone.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from control_plane.approvals.models import ApprovalRequest
from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationInvalidReason,
    EvaluationOutcome,
)
from control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
    LearningDenialReason,
)
from control_plane.self_learning.policy_gate.models import (
    AutonomyTier,
    PolicyGateDecision,
    PolicyGateDenialReason,
    PolicyGateOutcome,
    PolicyGateRequest,
    PolicyGateScope,
    RequestedAction,
    Tier2PromotionEvidence,
)
from control_plane.self_learning.policy_gate.service import evaluate_policy_gate

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()
PROPOSER = uuid.uuid4()
APPROVER = uuid.uuid4()


def _learning_allow(tenant_id: uuid.UUID) -> LearningAuthorizationDecision:
    data_decision = DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        data_classification="tenant_data",
        purpose="adaptive_prompt_tuning",
        provider="anthropic",
        reason=None,
    )
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        purpose="adaptive_prompt_tuning",
        reason=None,
        data_authorization_decision_id=data_decision.decision_id,
    )


def _learning_deny(tenant_id: uuid.UUID) -> LearningAuthorizationDecision:
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.DENY,
        tenant_id=tenant_id,
        purpose="adaptive_prompt_tuning",
        reason=LearningDenialReason.NO_LEARNING_POLICY,
        data_authorization_decision_id=uuid.uuid4(),
    )


def _eval_pass() -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.PASS,
        baseline_version="v0",
        candidate_version="v1",
        benchmark=Benchmark(benchmark_id="b", version="1"),
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=(),
    )


def _eval_fail() -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.FAIL,
        baseline_version="v0",
        candidate_version="v1",
        benchmark=Benchmark(benchmark_id="b", version="1"),
        invalid_reason=None,
        failed_metrics=("task_success_rate",),
        regressed_metrics=(),
    )


def _eval_invalid() -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.INVALID,
        baseline_version="v0",
        candidate_version="v1",
        benchmark=None,
        invalid_reason=EvaluationInvalidReason.BENCHMARK_MISMATCH,
        failed_metrics=(),
        regressed_metrics=(),
    )


def _scope(
    authorized: frozenset[str] | None = None, requested: frozenset[str] | None = None
) -> PolicyGateScope:
    return PolicyGateScope(
        authorized=authorized
        if authorized is not None
        else frozenset({"support_agent.system_prompt"}),
        requested=requested
        if requested is not None
        else frozenset({"support_agent.system_prompt"}),
    )


def _approval(
    *,
    tenant_id: uuid.UUID = TENANT_A,
    status: str = "approved",
    proposer_user_id: uuid.UUID = PROPOSER,
    approver_user_id: uuid.UUID | None = APPROVER,
) -> ApprovalRequest:
    return ApprovalRequest(
        tenant_id=tenant_id,
        proposer_user_id=proposer_user_id,
        tool_key="control_plane.self_learning.policy_gate.stub",
        agent_scope_value=None,
        payload={},
        status=status,
        approver_user_id=approver_user_id,
    )


_UNSET: Any = object()


def _request(
    *,
    tenant_id: uuid.UUID | None = TENANT_A,
    actor_user_id: uuid.UUID = PROPOSER,
    requested_action: str = RequestedAction.ACTIVATE_ADAPTATION.value,
    requested_autonomy_tier: int = AutonomyTier.TIER_0_PROPOSE_ONLY.value,
    scope: PolicyGateScope | None | Any = _UNSET,
    learning_authorization_decision: LearningAuthorizationDecision | None | Any = _UNSET,
    evaluation_comparison: EvaluationComparison | None | Any = _UNSET,
    approval: ApprovalRequest | None = None,
    tier2_promotion_evidence: Tier2PromotionEvidence | None = None,
    tier2_eligible_actions: frozenset[str] = frozenset(),
) -> PolicyGateRequest:
    resolved_scope: PolicyGateScope | None = _scope() if scope is _UNSET else scope
    resolved_learning_authorization_decision: LearningAuthorizationDecision | None = (
        (_learning_allow(tenant_id) if tenant_id is not None else None)
        if learning_authorization_decision is _UNSET
        else learning_authorization_decision
    )
    resolved_evaluation_comparison: EvaluationComparison | None = (
        _eval_pass() if evaluation_comparison is _UNSET else evaluation_comparison
    )
    return PolicyGateRequest(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        requested_action=requested_action,
        requested_autonomy_tier=requested_autonomy_tier,
        scope=resolved_scope,
        learning_authorization_decision=resolved_learning_authorization_decision,
        evaluation_comparison=resolved_evaluation_comparison,
        approval=approval,
        tier2_promotion_evidence=tier2_promotion_evidence,
        tier2_eligible_actions=tier2_eligible_actions,
    )


# --------------------------------------------------------------------- #
# Basic decisions
# --------------------------------------------------------------------- #


def test_tier0_fully_authorized_request_is_allowed() -> None:
    decision = evaluate_policy_gate(_request())
    assert decision.outcome is PolicyGateOutcome.ALLOW
    assert decision.reason is None


def test_unknown_action_is_denied() -> None:
    decision = evaluate_policy_gate(_request(requested_action="delete_production_database"))
    assert decision.outcome is PolicyGateOutcome.DENY
    assert decision.reason is PolicyGateDenialReason.UNKNOWN_ACTION


def test_unknown_autonomy_tier_is_denied() -> None:
    decision = evaluate_policy_gate(_request(requested_autonomy_tier=99))
    assert decision.reason is PolicyGateDenialReason.UNKNOWN_AUTONOMY_TIER


def test_negative_autonomy_tier_is_denied() -> None:
    decision = evaluate_policy_gate(_request(requested_autonomy_tier=-1))
    assert decision.reason is PolicyGateDenialReason.UNKNOWN_AUTONOMY_TIER


def test_missing_learning_authorization_is_denied() -> None:
    decision = evaluate_policy_gate(_request(learning_authorization_decision=None))
    assert decision.reason is PolicyGateDenialReason.LEARNING_AUTHORIZATION_NOT_ALLOWED


def test_denied_learning_authorization_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(learning_authorization_decision=_learning_deny(TENANT_A))
    )
    assert decision.reason is PolicyGateDenialReason.LEARNING_AUTHORIZATION_NOT_ALLOWED


# --------------------------------------------------------------------- #
# Tenant isolation
# --------------------------------------------------------------------- #


def test_missing_tenant_context_is_denied() -> None:
    decision = evaluate_policy_gate(_request(tenant_id=None, learning_authorization_decision=None))
    assert decision.reason is PolicyGateDenialReason.MISSING_TENANT


def test_tenant_a_allowed_when_everything_is_tenant_a() -> None:
    decision = evaluate_policy_gate(_request(tenant_id=TENANT_A))
    assert decision.outcome is PolicyGateOutcome.ALLOW


def test_tenant_b_cannot_reuse_tenant_a_learning_authorization() -> None:
    decision = evaluate_policy_gate(
        _request(tenant_id=TENANT_B, learning_authorization_decision=_learning_allow(TENANT_A))
    )
    assert decision.reason is PolicyGateDenialReason.CROSS_TENANT_NOT_AUTHORIZED


def test_tenant_a_cannot_use_tenant_b_approval_for_tier1() -> None:
    decision = evaluate_policy_gate(
        _request(
            tenant_id=TENANT_A,
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            approval=_approval(tenant_id=TENANT_B),
        )
    )
    assert decision.reason is PolicyGateDenialReason.CROSS_TENANT_NOT_AUTHORIZED


# --------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------- #


def test_exact_scope_is_allowed() -> None:
    decision = evaluate_policy_gate(
        _request(scope=_scope(authorized=frozenset({"a", "b"}), requested=frozenset({"a", "b"})))
    )
    assert decision.outcome is PolicyGateOutcome.ALLOW


def test_narrower_scope_is_allowed() -> None:
    decision = evaluate_policy_gate(
        _request(scope=_scope(authorized=frozenset({"a", "b"}), requested=frozenset({"a"})))
    )
    assert decision.outcome is PolicyGateOutcome.ALLOW


def test_broader_scope_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(
            scope=_scope(authorized=frozenset({"a", "b"}), requested=frozenset({"a", "b", "c"}))
        )
    )
    assert decision.reason is PolicyGateDenialReason.SCOPE_MISMATCH


def test_unrelated_scope_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(scope=_scope(authorized=frozenset({"a", "b"}), requested=frozenset({"z"})))
    )
    assert decision.reason is PolicyGateDenialReason.SCOPE_MISMATCH


def test_missing_scope_is_denied() -> None:
    decision = evaluate_policy_gate(_request(scope=None))
    assert decision.reason is PolicyGateDenialReason.MISSING_SCOPE


def test_empty_authorized_scope_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(scope=_scope(authorized=frozenset(), requested=frozenset({"a"})))
    )
    assert decision.reason is PolicyGateDenialReason.MISSING_SCOPE


# --------------------------------------------------------------------- #
# Autonomy tiers
# --------------------------------------------------------------------- #


def test_tier0_requires_no_approval_or_evidence() -> None:
    decision = evaluate_policy_gate(
        _request(requested_autonomy_tier=AutonomyTier.TIER_0_PROPOSE_ONLY.value)
    )
    assert decision.outcome is PolicyGateOutcome.ALLOW


def test_tier1_allowed_with_valid_approval() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            approval=_approval(),
        )
    )
    assert decision.outcome is PolicyGateOutcome.ALLOW


def test_tier1_missing_approval_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value, approval=None
        )
    )
    assert decision.reason is PolicyGateDenialReason.MISSING_REQUIRED_APPROVAL


def test_tier2_allowed_with_evidence_and_eligible_action() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED.value,
            tier2_promotion_evidence=Tier2PromotionEvidence(
                adr_reference="docs/ADR/0020-example.md",
                reliability_summary="99.9% success over 90 days",
            ),
            tier2_eligible_actions=frozenset({RequestedAction.ACTIVATE_ADAPTATION.value}),
        )
    )
    assert decision.outcome is PolicyGateOutcome.ALLOW


def test_tier2_without_evidence_is_denied() -> None:
    """Phase 9.7's own named Tests bullet: promotion to tier 2 requires an
    ADR citing demonstrated reliability evidence; a test proves the gate
    rejects a promotion attempt lacking that evidence reference."""
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED.value,
            tier2_promotion_evidence=None,
            tier2_eligible_actions=frozenset({RequestedAction.ACTIVATE_ADAPTATION.value}),
        )
    )
    assert decision.reason is PolicyGateDenialReason.TIER2_EVIDENCE_MISSING


def test_tier2_action_not_on_eligible_list_is_denied_even_with_evidence() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED.value,
            tier2_promotion_evidence=Tier2PromotionEvidence(
                adr_reference="docs/ADR/0020-example.md",
                reliability_summary="demonstrated reliability",
            ),
            tier2_eligible_actions=frozenset(),  # no human decision has approved anything yet
        )
    )
    assert decision.reason is PolicyGateDenialReason.ACTION_NOT_TIER2_ELIGIBLE


def test_tier3_is_always_denied_even_with_every_other_field_satisfied() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_3_FULLY_AUTONOMOUS.value,
            approval=_approval(),
            tier2_promotion_evidence=Tier2PromotionEvidence(
                adr_reference="docs/ADR/0020-example.md",
                reliability_summary="demonstrated reliability",
            ),
            tier2_eligible_actions=frozenset({RequestedAction.ACTIVATE_ADAPTATION.value}),
        )
    )
    assert decision.outcome is PolicyGateOutcome.DENY
    assert decision.reason is PolicyGateDenialReason.TIER_3_NOT_ENABLED


# --------------------------------------------------------------------- #
# Authorization composition -- passing one gate never implies another
# --------------------------------------------------------------------- #


def test_learning_denied_overrides_valid_approval() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            learning_authorization_decision=_learning_deny(TENANT_A),
            approval=_approval(),
        )
    )
    assert decision.reason is PolicyGateDenialReason.LEARNING_AUTHORIZATION_NOT_ALLOWED


def test_evaluation_fail_denies_regardless_of_approval() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            evaluation_comparison=_eval_fail(),
            approval=_approval(),
        )
    )
    assert decision.reason is PolicyGateDenialReason.EVALUATION_NOT_PASSED


def test_evaluation_invalid_denies_regardless_of_approval() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            evaluation_comparison=_eval_invalid(),
            approval=_approval(),
        )
    )
    assert decision.reason is PolicyGateDenialReason.EVALUATION_NOT_PASSED


def test_missing_evaluation_denies_even_at_tier0() -> None:
    decision = evaluate_policy_gate(_request(evaluation_comparison=None))
    assert decision.reason is PolicyGateDenialReason.EVALUATION_NOT_PASSED


def test_experiment_pass_result_alone_does_not_grant_tier1_without_approval() -> None:
    """Phase 9.6 experiment PASS + policy gate without approval -> DENY."""
    decision = evaluate_policy_gate(
        _request(
            requested_action=RequestedAction.PROMOTE_EXPERIMENT.value,
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            evaluation_comparison=_eval_pass(),
            approval=None,
        )
    )
    assert decision.reason is PolicyGateDenialReason.MISSING_REQUIRED_APPROVAL


# --------------------------------------------------------------------- #
# Approval
# --------------------------------------------------------------------- #


def test_approval_rejected_status_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            approval=_approval(status="rejected"),
        )
    )
    assert decision.reason is PolicyGateDenialReason.APPROVAL_NOT_APPROVED


def test_approval_still_pending_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            approval=_approval(status="pending", approver_user_id=None),
        )
    )
    assert decision.reason is PolicyGateDenialReason.APPROVAL_NOT_APPROVED


def test_approval_without_an_approver_is_denied() -> None:
    """An `ApprovalRequest` claiming `status="approved"` but carrying no
    `approver_user_id` (malformed/forged provenance) fails closed."""
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            approval=_approval(approver_user_id=None),
        )
    )
    assert decision.reason is PolicyGateDenialReason.SELF_APPROVAL_NOT_ALLOWED


def test_self_approval_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            approval=_approval(proposer_user_id=PROPOSER, approver_user_id=PROPOSER),
        )
    )
    assert decision.reason is PolicyGateDenialReason.SELF_APPROVAL_NOT_ALLOWED


def test_unauthorized_actor_cannot_reuse_someone_elses_approval() -> None:
    """Confused deputy: an approval genuinely proposed by/for `PROPOSER`
    must not authorize execution by a different actor."""
    other_actor = uuid.uuid4()
    decision = evaluate_policy_gate(
        _request(
            actor_user_id=other_actor,
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            approval=_approval(proposer_user_id=PROPOSER, approver_user_id=APPROVER),
        )
    )
    assert decision.reason is PolicyGateDenialReason.ACTOR_MISMATCH


# --------------------------------------------------------------------- #
# Model claims have no policy effect -- structural, not a runtime check
# --------------------------------------------------------------------- #


def test_policy_gate_request_has_no_self_attestation_field() -> None:
    """`PolicyGateRequest` has no `authorized=`/`approved=`/`safe=`/
    `autonomous=` constructor parameter at all -- a caller cannot smuggle
    a claim of authority into a request; Python raises `TypeError` before
    any policy logic ever runs."""
    with pytest.raises(TypeError):
        PolicyGateRequest(  # type: ignore[call-arg]
            tenant_id=TENANT_A,
            actor_user_id=PROPOSER,
            requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
            requested_autonomy_tier=0,
            scope=_scope(),
            learning_authorization_decision=_learning_allow(TENANT_A),
            authorized=True,  # type: ignore[call-arg]
        )


def test_policy_gate_decision_has_no_model_supplied_field() -> None:
    with pytest.raises(TypeError):
        PolicyGateDecision(  # type: ignore[call-arg]
            outcome=PolicyGateOutcome.ALLOW,
            tenant_id=TENANT_A,
            requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
            requested_autonomy_tier=0,
            reason=None,
            safe=True,  # type: ignore[call-arg]
        )


# --------------------------------------------------------------------- #
# Adversarial substitution
# --------------------------------------------------------------------- #


def test_stale_approval_id_reused_for_a_different_tenant_is_denied() -> None:
    decision = evaluate_policy_gate(
        _request(
            tenant_id=TENANT_B,
            requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
            learning_authorization_decision=_learning_allow(TENANT_B),
            approval=_approval(tenant_id=TENANT_A),  # approval belongs to Tenant A
        )
    )
    assert decision.reason is PolicyGateDenialReason.CROSS_TENANT_NOT_AUTHORIZED


def test_conflicting_policy_inputs_still_deny_when_any_check_fails() -> None:
    """A request that is simultaneously missing scope AND carries an
    invalid tier must still deny -- ambiguity/unsupported combinations
    never resolve to ALLOW."""
    decision = evaluate_policy_gate(
        _request(requested_autonomy_tier=7, scope=None, learning_authorization_decision=None)
    )
    assert decision.outcome is PolicyGateOutcome.DENY


# --------------------------------------------------------------------- #
# Decision invariants
# --------------------------------------------------------------------- #


def test_allow_decision_never_carries_a_denial_reason() -> None:
    decision = evaluate_policy_gate(_request())
    assert decision.is_allowed
    assert decision.reason is None


def test_deny_decision_always_carries_a_denial_reason() -> None:
    decision = evaluate_policy_gate(_request(requested_action="unknown"))
    assert not decision.is_allowed
    assert decision.reason is not None
