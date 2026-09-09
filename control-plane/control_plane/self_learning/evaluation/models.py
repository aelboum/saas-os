"""Typed baseline/candidate/benchmark/metrics/comparison shapes for the
Evaluation Foundation (docs/IMPLEMENTATION-ROADMAP.md Phase 9.3).

**Immutable evidence, explicitly**: `EvaluationSubjectResult` and
`EvaluationComparison` are frozen dataclasses -- once constructed, a
recorded evaluation result cannot be mutated. This is a design property
made explicit, not merely a convention (docs/IMPLEMENTATION-ROADMAP.md
Phase 9.3's own framing: "Evaluation is evidence").

**No self-attestation surface**: neither `EvaluationMetrics` nor
`EvaluationSubjectResult` has any field that carries a claim, assertion,
or self-reported verdict (no `self_reported_success`, no `notes`, no
free-text "why this is better"). Every field is either a measured
numeric metric or an identity/provenance value. This is a structural
property, not a convention -- Python dataclasses reject an unknown
keyword argument at construction time, so there is no field to smuggle a
claim into (proven in
`tests/control_plane/self_learning/evaluation/test_evaluation_unit.py`).
The metric names mirror docs/IMPLEMENTATION-ROADMAP.md Phase 9.3's own
"Potential metrics" list verbatim (task success, hallucination/error
rate, latency, cost, tool success, user feedback, safety violations,
regression rate) -- illustrative there, made concrete typed fields here,
not a new taxonomy.

**Authorization composition, not re-implementation**: every
`EvaluationSubjectResult` carries the `LearningAuthorizationDecision`
(ADR-0014, Phase 9.2) that authorized the data behind it. `service.py`'s
evaluator requires this decision's outcome to be ALLOW for the same
tenant before comparing anything -- Phase 9.3's own dependency note,
verbatim: "evaluation inputs must already be authorized data." Because a
`LearningAuthorizationDecision` itself requires an upstream
`DataAuthorizationDecision` (ADR-0013, also Phase 9.2), one check proves
both gates already passed -- this module never re-implements either.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field

from control_plane.self_learning.models import LearningAuthorizationDecision


class EvaluationSubjectKind(enum.StrEnum):
    BASELINE = "baseline"
    CANDIDATE = "candidate"


@dataclass(frozen=True)
class Benchmark:
    """A benchmark's identity/version (docs/IMPLEMENTATION-ROADMAP.md
    Phase 9.3: "Baseline -> Benchmark -> Metrics; Candidate -> same
    Benchmark -> Metrics"). Two `Benchmark` values are comparable only
    when both `benchmark_id` and `version` are equal -- this is the
    literal enforcement of "baseline and candidate are evaluated under
    the same benchmark" (see `service.py`'s first comparability check)."""

    benchmark_id: str
    version: str


@dataclass(frozen=True)
class EvaluationMetrics:
    """A measured metric set -- every field is `None` unless actually
    measured; a `None` field is never treated as passing or failing any
    threshold that names it (see `service.py`'s `MISSING_REQUIRED_METRIC`
    handling). Field names and meaning mirror
    docs/IMPLEMENTATION-ROADMAP.md Phase 9.3's own "Potential metrics"
    list verbatim -- illustrative there, concrete typed fields here, not
    an expanded taxonomy."""

    task_success_rate: float | None = None
    error_rate: float | None = None
    latency_ms: float | None = None
    cost: float | None = None
    tool_success_rate: float | None = None
    user_feedback_score: float | None = None
    safety_violations: float | None = None
    regression_rate: float | None = None


@dataclass(frozen=True)
class EvaluationSubjectResult:
    """ "Baseline -> Benchmark -> Metrics" or "Candidate -> Benchmark ->
    Metrics" (docs/IMPLEMENTATION-ROADMAP.md Phase 9.3), immutable once
    constructed. `subject_version` is the baseline's or candidate's own
    identity/version (e.g. a prompt/model/config version string) -- this
    module never generates a candidate (Phase 9.3 Non-Goal), only
    evaluates an already-produced one."""

    kind: EvaluationSubjectKind
    subject_version: str
    tenant_id: uuid.UUID
    benchmark: Benchmark
    metrics: EvaluationMetrics
    learning_authorization_decision: LearningAuthorizationDecision


class MetricDirection(enum.StrEnum):
    HIGHER_IS_BETTER = "higher_is_better"
    LOWER_IS_BETTER = "lower_is_better"


@dataclass(frozen=True)
class MetricThreshold:
    """One monitored metric's pass/regression rule. `metric_name` must
    name an `EvaluationMetrics` field. `minimum_absolute` (direction
    `HIGHER_IS_BETTER`) or `maximum_absolute` (`LOWER_IS_BETTER`) is an
    absolute bar the candidate must clear regardless of the baseline
    (violating it is a FAIL); `maximum_regression` is the largest
    tolerated *worsening* relative to the baseline's own measured value
    on this metric (violating it, while still clearing the absolute bar,
    is a REGRESSION) -- docs/IMPLEMENTATION-ROADMAP.md Phase 9.3's own
    "Compare -> Pass/Fail" plus this task's Regression Detection
    requirement ("candidate worse than baseline" vs. "candidate fails
    required benchmark" as distinct categories)."""

    metric_name: str
    direction: MetricDirection
    minimum_absolute: float | None = None
    maximum_absolute: float | None = None
    maximum_regression: float | None = None


@dataclass(frozen=True)
class EvaluationRules:
    thresholds: tuple[MetricThreshold, ...]


class EvaluationOutcome(enum.StrEnum):
    """Four, deliberately distinct, states -- "an inconclusive/degraded
    result is never silently treated as pass" (Phase 9.3's own Tests
    bullet) holds because PASS is the *only* member reachable when every
    other check has explicitly cleared; every other path is one of the
    other three, never conflated with PASS."""

    PASS = "pass"
    FAIL = "fail"
    REGRESSION = "regression"
    INVALID = "invalid"


class EvaluationInvalidReason(enum.StrEnum):
    """Every reason `service.evaluate_candidate()` can return `INVALID`
    for -- a comparison that could not be validly performed at all
    (never a verdict on the candidate itself)."""

    LEARNING_AUTHORIZATION_NOT_PASSED = "learning_authorization_not_passed"
    BENCHMARK_MISMATCH = "benchmark_mismatch"
    CROSS_TENANT_NOT_AUTHORIZED = "cross_tenant_not_authorized"
    MISSING_REQUIRED_METRIC = "missing_required_metric"


@dataclass(frozen=True)
class EvaluationComparison:
    outcome: EvaluationOutcome
    baseline_version: str
    candidate_version: str
    benchmark: Benchmark | None
    invalid_reason: EvaluationInvalidReason | None
    failed_metrics: tuple[str, ...]
    regressed_metrics: tuple[str, ...]
    decision_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        # Structural invariants (docs/IMPLEMENTATION-ROADMAP.md Phase
        # 9.3's own "default deny must be structurally obvious" analogue
        # for evaluation: a bug in service.py, not caller input, would
        # trip these).
        if self.outcome is EvaluationOutcome.INVALID and self.invalid_reason is None:
            raise AssertionError("An INVALID outcome must carry an invalid_reason.")
        if self.outcome is not EvaluationOutcome.INVALID and self.invalid_reason is not None:
            raise AssertionError("Only an INVALID outcome may carry an invalid_reason.")
        if self.outcome is EvaluationOutcome.PASS and (
            self.failed_metrics or self.regressed_metrics
        ):
            raise AssertionError("A PASS outcome must carry no failed or regressed metrics.")
        if self.outcome is EvaluationOutcome.FAIL and not self.failed_metrics:
            raise AssertionError("A FAIL outcome must name at least one failed metric.")
        if self.outcome is EvaluationOutcome.REGRESSION and not self.regressed_metrics:
            raise AssertionError("A REGRESSION outcome must name at least one regressed metric.")

    @property
    def is_pass(self) -> bool:
        return self.outcome is EvaluationOutcome.PASS


__all__ = [
    "EvaluationSubjectKind",
    "Benchmark",
    "EvaluationMetrics",
    "EvaluationSubjectResult",
    "MetricDirection",
    "MetricThreshold",
    "EvaluationRules",
    "EvaluationOutcome",
    "EvaluationInvalidReason",
    "EvaluationComparison",
]
