"""Evaluation Foundation: Baseline -> Benchmark -> Metrics; Candidate ->
same Benchmark -> Metrics; Compare -> Pass/Fail
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.3).

`evaluate_candidate()` is a pure function -- same inputs always produce
the same `EvaluationComparison`, no I/O, no database, no audit write, no
model/provider call. It never trusts a claim: it reads only the two
subjects' typed `EvaluationMetrics` (numbers) against `EvaluationRules`
(typed thresholds) -- there is no parameter anywhere in this module's
signatures for a self-reported or model-asserted verdict
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.3's own binding Security
Requirement: "an LLM's own claim that a candidate is better is not
sufficient evidence... a result must derive from the defined metric set,
never a model's self-assessment alone").

Checks run in this fixed order, matching this task's own Threat Model
priority (an authorization or comparability failure must never be masked
by a metric-level result):

1. **Authorization composition** -- both subjects' `LearningAuthorizationDecision`
   must already be ALLOW, for their own subject's `tenant_id`
   (docs/IMPLEMENTATION-ROADMAP.md Phase 9.3: "every evaluation input
   passes 9.2's gate first"). Reused, never re-implemented -- this
   module never imports `core.rbac` or re-derives an authorization
   decision itself.
2. **Benchmark identity** -- `baseline.benchmark == candidate.benchmark`
   (both `benchmark_id` and `version`) or the comparison is `INVALID`.
   This is the literal enforcement of "baseline and candidate are
   evaluated under the same benchmark" -- `baseline -> benchmark A`,
   `candidate -> benchmark B` can never produce anything but `INVALID`.
3. **Cross-tenant reuse** -- if `baseline.tenant_id != candidate.tenant_id`,
   an exactly-matching `CrossTenantLearningPolicy` (same shape and same
   discipline as `control_plane.self_learning.service
   .evaluate_learning_authorization`'s own cross-tenant check) is
   required, or `INVALID` -- "a candidate evaluated against Tenant A's
   benchmark data is never scored ... using Tenant B's data without
   explicit cross-tenant policy (reuses 9.2's gate)."
4. **Metric thresholds** -- each `MetricThreshold` in `EvaluationRules`
   is checked for an absolute-bar violation (-> `FAIL`) and, separately,
   a regression-versus-baseline violation (-> `REGRESSION`); a metric
   missing from either subject is `INVALID`, never silently skipped or
   treated as passing.

`run_evaluation()` is the audited entrypoint (Phase 9.3's own Audit
Requirement: `learning.evaluation_run`, "including baseline/candidate
version and pass/fail outcome") -- it wraps the pure evaluator with
exactly one `core.audit_log` entry, reusing `core/audit_log`'s existing
interface, never a second audit or Learning Ledger mechanism.
"""

from __future__ import annotations

import uuid

from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationInvalidReason,
    EvaluationOutcome,
    EvaluationRules,
    EvaluationSubjectResult,
    MetricDirection,
)
from control_plane.self_learning.models import (
    CrossTenantLearningPolicy,
    LearningAuthorizationOutcome,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event

_AUDIT_RESOURCE_TYPE = "learning_evaluation"
_AUDIT_ACTION = "learning.evaluation_run"

# docs/IMPLEMENTATION-ROADMAP.md Phase 9.3's own audit outcome mapping:
# a conclusive verdict (PASS/FAIL/REGRESSION) means the evaluation *ran*
# successfully -- the candidate's own verdict is recorded in metadata,
# not conflated with whether the run itself succeeded. INVALID means the
# comparison could not be validly performed at all (unauthorized data,
# mismatched benchmark, unauthorized cross-tenant reuse, missing metric)
# -- mapped to DENIED, the same outcome Phase 9.2's own gates use for "this
# was refused before a verdict could be reached."
_AUDIT_OUTCOME_BY_EVALUATION_OUTCOME = {
    EvaluationOutcome.PASS: AuditOutcome.SUCCESS,
    EvaluationOutcome.FAIL: AuditOutcome.FAILURE,
    EvaluationOutcome.REGRESSION: AuditOutcome.FAILURE,
    EvaluationOutcome.INVALID: AuditOutcome.DENIED,
}


def _invalid(
    baseline: EvaluationSubjectResult,
    candidate: EvaluationSubjectResult,
    reason: EvaluationInvalidReason,
    benchmark: Benchmark | None = None,
) -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.INVALID,
        baseline_version=baseline.subject_version,
        candidate_version=candidate.subject_version,
        benchmark=benchmark,
        invalid_reason=reason,
        failed_metrics=(),
        regressed_metrics=(),
    )


def evaluate_candidate(
    baseline: EvaluationSubjectResult,
    candidate: EvaluationSubjectResult,
    rules: EvaluationRules,
    *,
    cross_tenant_policy: CrossTenantLearningPolicy | None = None,
) -> EvaluationComparison:
    """Default-deny-shaped comparison: every `return` before the final
    line is `INVALID`, `FAIL`, or `REGRESSION`; the final line is the one
    and only `PASS` path, reached only once every prior check has passed
    explicitly. See module docstring for the fixed check order."""
    for subject in (baseline, candidate):
        decision = subject.learning_authorization_decision
        if (
            decision.outcome is not LearningAuthorizationOutcome.ALLOW
            or decision.tenant_id != subject.tenant_id
        ):
            return _invalid(
                baseline, candidate, EvaluationInvalidReason.LEARNING_AUTHORIZATION_NOT_PASSED
            )

    if baseline.benchmark != candidate.benchmark:
        return _invalid(baseline, candidate, EvaluationInvalidReason.BENCHMARK_MISMATCH)

    if baseline.tenant_id != candidate.tenant_id:
        candidate_purpose = candidate.learning_authorization_decision.purpose
        if (
            cross_tenant_policy is None
            or cross_tenant_policy.source_tenant_id != baseline.tenant_id
            or cross_tenant_policy.target_tenant_id != candidate.tenant_id
            or candidate_purpose not in cross_tenant_policy.approved_purposes
        ):
            return _invalid(
                baseline,
                candidate,
                EvaluationInvalidReason.CROSS_TENANT_NOT_AUTHORIZED,
                benchmark=candidate.benchmark,
            )

    failed_metrics: list[str] = []
    regressed_metrics: list[str] = []
    for threshold in rules.thresholds:
        baseline_value = getattr(baseline.metrics, threshold.metric_name, None)
        candidate_value = getattr(candidate.metrics, threshold.metric_name, None)
        if baseline_value is None or candidate_value is None:
            return _invalid(
                baseline,
                candidate,
                EvaluationInvalidReason.MISSING_REQUIRED_METRIC,
                benchmark=candidate.benchmark,
            )

        if threshold.direction is MetricDirection.HIGHER_IS_BETTER:
            if (
                threshold.minimum_absolute is not None
                and candidate_value < threshold.minimum_absolute
            ):
                failed_metrics.append(threshold.metric_name)
            elif (
                threshold.maximum_regression is not None
                and (baseline_value - candidate_value) > threshold.maximum_regression
            ):
                regressed_metrics.append(threshold.metric_name)
        else:  # LOWER_IS_BETTER
            if (
                threshold.maximum_absolute is not None
                and candidate_value > threshold.maximum_absolute
            ):
                failed_metrics.append(threshold.metric_name)
            elif (
                threshold.maximum_regression is not None
                and (candidate_value - baseline_value) > threshold.maximum_regression
            ):
                regressed_metrics.append(threshold.metric_name)

    if failed_metrics:
        outcome = EvaluationOutcome.FAIL
    elif regressed_metrics:
        outcome = EvaluationOutcome.REGRESSION
    else:
        outcome = EvaluationOutcome.PASS

    return EvaluationComparison(
        outcome=outcome,
        baseline_version=baseline.subject_version,
        candidate_version=candidate.subject_version,
        benchmark=candidate.benchmark,
        invalid_reason=None,
        failed_metrics=tuple(failed_metrics),
        regressed_metrics=tuple(regressed_metrics),
    )


def run_evaluation(
    baseline: EvaluationSubjectResult,
    candidate: EvaluationSubjectResult,
    rules: EvaluationRules,
    *,
    cross_tenant_policy: CrossTenantLearningPolicy | None = None,
    actor_user_id: uuid.UUID,
    correlation_id: str | None = None,
) -> EvaluationComparison:
    """`evaluate_candidate()` plus exactly one `core.audit_log` entry
    (`learning.evaluation_run`), regardless of outcome. Metadata never
    carries raw evaluation input -- only identity/version, benchmark,
    outcome, and (when applicable) the specific failed/regressed metric
    names or invalid reason."""
    comparison = evaluate_candidate(
        baseline, candidate, rules, cross_tenant_policy=cross_tenant_policy
    )

    metadata: dict[str, object] = {
        "baseline_version": comparison.baseline_version,
        "candidate_version": comparison.candidate_version,
        "evaluation_outcome": comparison.outcome.value,
        "decision_id": str(comparison.decision_id),
    }
    if comparison.benchmark is not None:
        metadata["benchmark_id"] = comparison.benchmark.benchmark_id
        metadata["benchmark_version"] = comparison.benchmark.version
    if comparison.invalid_reason is not None:
        metadata["invalid_reason"] = comparison.invalid_reason.value
    if comparison.failed_metrics:
        metadata["failed_metrics"] = list(comparison.failed_metrics)
    if comparison.regressed_metrics:
        metadata["regressed_metrics"] = list(comparison.regressed_metrics)

    record_audit_event(
        tenant_id=candidate.tenant_id,
        actor_type=ActorType.USER,
        actor_user_id=actor_user_id,
        action=_AUDIT_ACTION,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(comparison.decision_id),
        outcome=_AUDIT_OUTCOME_BY_EVALUATION_OUTCOME[comparison.outcome],
        correlation_id=correlation_id,
        metadata=metadata,
    )
    return comparison
