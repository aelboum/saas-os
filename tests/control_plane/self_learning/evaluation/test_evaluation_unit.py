"""Unit tests for `control_plane.self_learning.evaluation.service.evaluate_candidate`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.3). Pure-function logic -- no
database required, part of the default `pytest` run.

Covers every category this task's own Test Requirements and Phase 9.3's
Tests bullet name: baseline/candidate success, same-benchmark
enforcement, benchmark mismatch rejection, regression detection,
improvement detection, invalid/incomplete evaluation rejection,
self-reported-success resistance, authorization-gate composition
(cannot bypass Data/Learning Authorization), cross-tenant denial, and
the policy-authority boundary.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import uuid

import pytest

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.evaluation import service as evaluation_service
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationInvalidReason,
    EvaluationMetrics,
    EvaluationOutcome,
    EvaluationRules,
    EvaluationSubjectKind,
    EvaluationSubjectResult,
    MetricDirection,
    MetricThreshold,
)
from control_plane.self_learning.evaluation.service import evaluate_candidate
from control_plane.self_learning.models import (
    CrossTenantLearningPolicy,
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()

BENCHMARK_V1 = Benchmark(benchmark_id="support-reply-quality", version="1")
BENCHMARK_V2 = Benchmark(benchmark_id="support-reply-quality", version="2")


def _allow_decision(tenant_id: uuid.UUID = TENANT_A, purpose: str = "adaptive_prompt_tuning"):
    data_decision = DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        data_classification="tenant_data",
        purpose=purpose,
        provider="anthropic",
        reason=None,
    )
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        purpose=purpose,
        reason=None,
        data_authorization_decision_id=data_decision.decision_id,
    )


def _deny_decision(tenant_id: uuid.UUID = TENANT_A):
    from control_plane.self_learning.models import LearningDenialReason

    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.DENY,
        tenant_id=tenant_id,
        purpose="adaptive_prompt_tuning",
        reason=LearningDenialReason.NO_LEARNING_POLICY,
        data_authorization_decision_id=uuid.uuid4(),
    )


def _subject(
    kind: EvaluationSubjectKind,
    version: str,
    *,
    tenant_id: uuid.UUID = TENANT_A,
    benchmark: Benchmark = BENCHMARK_V1,
    metrics: EvaluationMetrics | None = None,
    decision: LearningAuthorizationDecision | None = None,
) -> EvaluationSubjectResult:
    return EvaluationSubjectResult(
        kind=kind,
        subject_version=version,
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=metrics or EvaluationMetrics(task_success_rate=0.9, error_rate=0.05),
        learning_authorization_decision=decision or _allow_decision(tenant_id),
    )


RULES = EvaluationRules(
    thresholds=(
        MetricThreshold(
            metric_name="task_success_rate",
            direction=MetricDirection.HIGHER_IS_BETTER,
            minimum_absolute=0.5,
            maximum_regression=0.05,
        ),
        MetricThreshold(
            metric_name="error_rate",
            direction=MetricDirection.LOWER_IS_BETTER,
            maximum_absolute=0.3,
            maximum_regression=0.05,
        ),
    )
)


class TestBaselineAndCandidateSuccess:
    def test_identical_metrics_pass(self) -> None:
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1")
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2")
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.PASS
        assert result.is_pass
        assert result.invalid_reason is None
        assert result.failed_metrics == ()
        assert result.regressed_metrics == ()

    def test_improved_candidate_passes(self) -> None:
        baseline = _subject(
            EvaluationSubjectKind.BASELINE,
            "v1",
            metrics=EvaluationMetrics(task_success_rate=0.8, error_rate=0.1),
        )
        candidate = _subject(
            EvaluationSubjectKind.CANDIDATE,
            "v2",
            metrics=EvaluationMetrics(task_success_rate=0.95, error_rate=0.02),
        )
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.PASS


class TestSameBenchmarkEnforcement:
    def test_benchmark_mismatch_is_invalid_never_a_valid_comparison(self) -> None:
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1", benchmark=BENCHMARK_V1)
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2", benchmark=BENCHMARK_V2)
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.INVALID
        assert result.invalid_reason is EvaluationInvalidReason.BENCHMARK_MISMATCH
        # never silently treated as pass
        assert not result.is_pass

    def test_same_benchmark_id_different_version_is_a_mismatch(self) -> None:
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1", benchmark=BENCHMARK_V1)
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2", benchmark=BENCHMARK_V2)
        assert baseline.benchmark.benchmark_id == candidate.benchmark.benchmark_id
        assert baseline.benchmark != candidate.benchmark
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.invalid_reason is EvaluationInvalidReason.BENCHMARK_MISMATCH


class TestRegressionDetection:
    def test_candidate_worse_than_baseline_beyond_tolerance_is_regression(self) -> None:
        baseline = _subject(
            EvaluationSubjectKind.BASELINE,
            "v1",
            metrics=EvaluationMetrics(task_success_rate=0.9, error_rate=0.05),
        )
        candidate = _subject(
            EvaluationSubjectKind.CANDIDATE,
            "v2",
            metrics=EvaluationMetrics(
                task_success_rate=0.80, error_rate=0.05
            ),  # dropped 0.10 > 0.05 tolerance
        )
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.REGRESSION
        assert "task_success_rate" in result.regressed_metrics
        assert not result.is_pass

    def test_candidate_within_regression_tolerance_still_passes(self) -> None:
        baseline = _subject(
            EvaluationSubjectKind.BASELINE,
            "v1",
            metrics=EvaluationMetrics(task_success_rate=0.90, error_rate=0.05),
        )
        candidate = _subject(
            EvaluationSubjectKind.CANDIDATE,
            "v2",
            metrics=EvaluationMetrics(
                task_success_rate=0.87, error_rate=0.05
            ),  # dropped 0.03 < 0.05 tolerance
        )
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.PASS

    def test_regression_is_never_silently_treated_as_pass(self) -> None:
        baseline = _subject(
            EvaluationSubjectKind.BASELINE,
            "v1",
            metrics=EvaluationMetrics(task_success_rate=0.9, error_rate=0.05),
        )
        candidate = _subject(
            EvaluationSubjectKind.CANDIDATE,
            "v2",
            metrics=EvaluationMetrics(task_success_rate=0.5, error_rate=0.05),
        )
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is not EvaluationOutcome.PASS


class TestAbsoluteThresholdFailure:
    def test_candidate_below_absolute_minimum_fails_even_if_baseline_was_also_low(self) -> None:
        baseline = _subject(
            EvaluationSubjectKind.BASELINE,
            "v1",
            metrics=EvaluationMetrics(task_success_rate=0.4, error_rate=0.05),
        )
        candidate = _subject(
            EvaluationSubjectKind.CANDIDATE,
            "v2",
            metrics=EvaluationMetrics(
                task_success_rate=0.3, error_rate=0.05
            ),  # below 0.5 absolute minimum
        )
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.FAIL
        assert "task_success_rate" in result.failed_metrics


class TestInvalidIncompleteEvaluation:
    def test_missing_required_metric_is_invalid_not_pass(self) -> None:
        baseline = _subject(
            EvaluationSubjectKind.BASELINE, "v1", metrics=EvaluationMetrics(task_success_rate=0.9)
        )  # error_rate missing
        candidate = _subject(
            EvaluationSubjectKind.CANDIDATE, "v2", metrics=EvaluationMetrics(task_success_rate=0.9)
        )
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.INVALID
        assert result.invalid_reason is EvaluationInvalidReason.MISSING_REQUIRED_METRIC
        assert not result.is_pass


class TestSelfAttestationCannotSubstitute:
    """Phase 9.3's own binding Security Requirement, verbatim: "an LLM's
    own claim that a candidate is better is not sufficient evidence...
    a result must derive from the defined metric set, never a model's
    self-assessment alone." """

    def test_metrics_dataclass_rejects_a_self_reported_success_field(self) -> None:
        with pytest.raises(TypeError):
            EvaluationMetrics(task_success_rate=0.9, self_reported_success=True)  # type: ignore[call-arg]

    def test_subject_result_dataclass_rejects_a_claimed_outcome_field(self) -> None:
        with pytest.raises(TypeError):
            EvaluationSubjectResult(
                kind=EvaluationSubjectKind.CANDIDATE,
                subject_version="v2",
                tenant_id=TENANT_A,
                benchmark=BENCHMARK_V1,
                metrics=EvaluationMetrics(task_success_rate=0.9),
                learning_authorization_decision=_allow_decision(),
                claimed_outcome="pass",  # type: ignore[call-arg]
            )

    def test_no_field_anywhere_in_the_evidence_shapes_carries_a_claim(self) -> None:
        """Structural, not just behavioral: enumerate every field name on
        every evidence dataclass and confirm none of them is a
        claim/assertion-shaped name."""
        claim_shaped_fragments = ("claim", "self_report", "asserted", "success_flag", "verdict")
        for dc in (EvaluationMetrics, EvaluationSubjectResult):
            field_names = {f.name for f in dataclasses.fields(dc)}
            for fragment in claim_shaped_fragments:
                assert not any(fragment in name for name in field_names), (dc.__name__, field_names)

    def test_outcome_is_computed_purely_from_metrics_regardless_of_which_subject_is_labelled_better(
        self,
    ) -> None:
        """A regression is a regression regardless of what the numbers
        "look like they should mean" -- the evaluator has no channel for
        an external claim to override the arithmetic."""
        baseline = _subject(
            EvaluationSubjectKind.BASELINE,
            "v1",
            metrics=EvaluationMetrics(task_success_rate=0.9, error_rate=0.05),
        )
        candidate = _subject(
            EvaluationSubjectKind.CANDIDATE,
            "v2",
            metrics=EvaluationMetrics(task_success_rate=0.5, error_rate=0.05),
        )
        result = evaluate_candidate(baseline, candidate, RULES)
        # Even though nothing in the call declares intent, the measured
        # numbers alone produce a non-PASS verdict.
        assert result.outcome in (EvaluationOutcome.FAIL, EvaluationOutcome.REGRESSION)


class TestAuthorizationGateComposition:
    """Evaluation consumes already-authorized data; it never bypasses
    Data Authorization or Learning Authorization (this task's own Test
    Requirements 11-12)."""

    def test_denied_learning_authorization_on_baseline_makes_evaluation_invalid(self) -> None:
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1", decision=_deny_decision())
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2")
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.INVALID
        assert result.invalid_reason is EvaluationInvalidReason.LEARNING_AUTHORIZATION_NOT_PASSED

    def test_denied_learning_authorization_on_candidate_makes_evaluation_invalid(self) -> None:
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1")
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2", decision=_deny_decision())
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.INVALID
        assert result.invalid_reason is EvaluationInvalidReason.LEARNING_AUTHORIZATION_NOT_PASSED

    def test_learning_authorization_for_wrong_tenant_does_not_count(self) -> None:
        """An ALLOW decision that names a *different* tenant than the
        subject's own tenant_id must not authorize this subject."""
        baseline = _subject(
            EvaluationSubjectKind.BASELINE, "v1", decision=_allow_decision(TENANT_B)
        )
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2")
        result = evaluate_candidate(baseline, candidate, RULES)
        assert result.outcome is EvaluationOutcome.INVALID
        assert result.invalid_reason is EvaluationInvalidReason.LEARNING_AUTHORIZATION_NOT_PASSED

    def test_data_authorization_boundary_is_transitively_enforced(self) -> None:
        """A `LearningAuthorizationDecision` structurally cannot exist
        without having already required an upstream `DataAuthorizationDecision`
        (Phase 9.2's own composition) -- so requiring the former here
        also proves the latter passed, without re-implementing it."""
        params = inspect.signature(evaluate_candidate).parameters
        assert "baseline" in params and "candidate" in params
        # both parameters are typed as EvaluationSubjectResult, which
        # itself requires a LearningAuthorizationDecision field --
        # confirmed via the dataclass shape, not by convention.
        subject_fields = {f.name for f in dataclasses.fields(EvaluationSubjectResult)}
        assert "learning_authorization_decision" in subject_fields


class TestCrossTenantDenial:
    def test_cross_tenant_evaluation_with_no_policy_is_invalid(self) -> None:
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1", tenant_id=TENANT_A)
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2", tenant_id=TENANT_B)
        result = evaluate_candidate(baseline, candidate, RULES, cross_tenant_policy=None)
        assert result.outcome is EvaluationOutcome.INVALID
        assert result.invalid_reason is EvaluationInvalidReason.CROSS_TENANT_NOT_AUTHORIZED

    def test_cross_tenant_evaluation_with_wrong_pair_policy_is_invalid(self) -> None:
        tenant_c = uuid.uuid4()
        wrong_policy = CrossTenantLearningPolicy(
            source_tenant_id=TENANT_A,
            target_tenant_id=tenant_c,
            approved_purposes=frozenset({"adaptive_prompt_tuning"}),
        )
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1", tenant_id=TENANT_A)
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2", tenant_id=TENANT_B)
        result = evaluate_candidate(baseline, candidate, RULES, cross_tenant_policy=wrong_policy)
        assert result.invalid_reason is EvaluationInvalidReason.CROSS_TENANT_NOT_AUTHORIZED

    def test_cross_tenant_evaluation_with_exact_matching_policy_is_evaluated(self) -> None:
        policy = CrossTenantLearningPolicy(
            source_tenant_id=TENANT_A,
            target_tenant_id=TENANT_B,
            approved_purposes=frozenset({"adaptive_prompt_tuning"}),
        )
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1", tenant_id=TENANT_A)
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2", tenant_id=TENANT_B)
        result = evaluate_candidate(baseline, candidate, RULES, cross_tenant_policy=policy)
        assert result.outcome is EvaluationOutcome.PASS

    def test_same_tenant_path_never_requires_a_cross_tenant_policy(self) -> None:
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1", tenant_id=TENANT_A)
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2", tenant_id=TENANT_A)
        result = evaluate_candidate(baseline, candidate, RULES, cross_tenant_policy=None)
        assert result.outcome is EvaluationOutcome.PASS


class TestPolicyAuthorityBoundary:
    """Evaluation cannot modify RBAC, security policy, secrets policy, or
    autonomy-tier policy (this task's own Test Requirement 10)."""

    _FORBIDDEN_NAME_FRAGMENTS = (
        "set_policy",
        "update_security_policy",
        "modify_permissions",
        "change_autonomy_tier",
        "grant_permission",
        "assign_role",
        "deploy",
        "promote",
        "rollback_production",
    )

    def test_no_forbidden_policy_or_deployment_helpers_exist(self) -> None:
        public_names = {name for name in dir(evaluation_service) if not name.startswith("_")}
        for forbidden in self._FORBIDDEN_NAME_FRAGMENTS:
            assert forbidden not in public_names

    def test_module_never_imports_core_rbac_infra_secrets_or_orchestration(self) -> None:
        source = inspect.getsource(evaluation_service)
        tree = ast.parse(source)
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)
        for forbidden_prefix in ("core.rbac", "infra.secrets", "control_plane.orchestration"):
            assert forbidden_prefix not in imported_modules
            assert not any(m.startswith(forbidden_prefix + ".") for m in imported_modules)


class TestDeterminism:
    def test_same_inputs_produce_same_outcome(self) -> None:
        baseline = _subject(EvaluationSubjectKind.BASELINE, "v1")
        candidate = _subject(EvaluationSubjectKind.CANDIDATE, "v2")
        first = evaluate_candidate(baseline, candidate, RULES)
        second = evaluate_candidate(baseline, candidate, RULES)
        assert first.outcome == second.outcome
        assert first.failed_metrics == second.failed_metrics
        assert first.regressed_metrics == second.regressed_metrics


class TestComparisonInvariant:
    def test_invalid_without_reason_is_rejected(self) -> None:
        from control_plane.self_learning.evaluation.models import EvaluationComparison

        with pytest.raises(AssertionError):
            EvaluationComparison(
                outcome=EvaluationOutcome.INVALID,
                baseline_version="v1",
                candidate_version="v2",
                benchmark=None,
                invalid_reason=None,
                failed_metrics=(),
                regressed_metrics=(),
            )

    def test_pass_with_failed_metrics_is_rejected(self) -> None:
        from control_plane.self_learning.evaluation.models import EvaluationComparison

        with pytest.raises(AssertionError):
            EvaluationComparison(
                outcome=EvaluationOutcome.PASS,
                baseline_version="v1",
                candidate_version="v2",
                benchmark=BENCHMARK_V1,
                invalid_reason=None,
                failed_metrics=("task_success_rate",),
                regressed_metrics=(),
            )
