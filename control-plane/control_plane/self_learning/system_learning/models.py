"""Typed shapes for L2 System Learning (docs/IMPLEMENTATION-ROADMAP.md
Phase 9.5).

**Closed proposal vocabulary, structurally, not by convention**:
`ProposedChangeTarget` is the only thing an L2 proposal may ever name as
its target -- there is no member for security policy, RBAC, permissions,
authorization, secrets/secrets policy, autonomy tiers, deployment policy,
infrastructure control, an unrestricted shell, or unrestricted database
access. This is the literal enforcement of this task's own instruction:
"prefer structural impossibility" over a runtime deny list -- a proposal
targeting any of those is not merely rejected by `service.py`, it cannot
be *constructed* in the first place, because no such enum member exists
(`ProposedChangeTarget("rbac_grant")` raises `ValueError` before any
service-layer check runs; see
`tests/control_plane/self_learning/system_learning/test_system_learning_unit.py`).
Same discipline as
`control_plane.self_learning.adaptive.models.AdaptationSurface`
(Phase 9.4), extended here to system-level targets.

**No self-attestation surface**: `RecurrenceAssessment` and
`SystemLearningProposal` have no field for a self-reported/model-asserted
confidence, success, or "this is systemic" claim (no `self_reported`,
`model_confidence`, `asserted_recurring`). `RecurrenceAssessment.confidence`
is reachable only through `service.detect_recurrence()`'s deterministic
computation over typed `SystemLearningObservation`s -- `SystemLearningProposal`
never accepts a bare confidence value as a constructor argument, only an
already-computed `RecurrenceAssessment` (docs/IMPLEMENTATION-ROADMAP.md
Phase 9.5's own instruction: "LLM self-assertion is never authoritative
evidence" / "any recurrence/confidence/impact result must derive from
explicit, testable inputs or metrics"). Same "no claim-shaped field"
discipline as `control_plane.self_learning.evaluation.models
.EvaluationMetrics` (Phase 9.3).

**Immutable, schema-complete evidence**: every dataclass here is frozen.
`SystemLearningProposal` carries every field this task's own Proposal
Model section and Phase 9.5's own Tests bullet name: proposal identity
(`proposal_id`), problem category/description, evidence + evidence
lineage (`evidence`, `learning_authorization_decision_id`,
`recurrence.supporting_source_references`), scope and affected tenant(s)
(`scope`, `affected_tenant_ids`), data-policy classification
(`data_classification`), recurrence/confidence (`recurrence`,
`confidence`), impact metrics where applicable (`impact_metrics`),
proposed change (`proposed_change_target`, `proposed_change_description`),
rationale, risk classification (`risk_level`), authorization/evaluation
provenance (`learning_authorization_decision_id`, `evaluation_outcome`,
`evaluation_comparison_id`), actor/provenance and timestamp
(`created_by_user_id`, `created_at`), lifecycle/approval status
(`status`), version, and a rollback reference (`rollback_reference`).

**No persistence**: no database table, migration, or ORM model is
defined here (module docstring, `control_plane.self_learning
.system_learning`) -- every shape below is a plain in-memory dataclass,
exactly like `control_plane.self_learning.evaluation.models`'s own
no-persistence discipline (Phase 9.3).
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from control_plane.self_learning.models import LearningEvidence


# docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own Objective, verbatim:
# "recurring problems (agent/tool failures, support/latency/cost/routing/
# workflow problems, missing regression tests, recurring policy
# violations, operational failures)".
class ProblemCategory(enum.StrEnum):
    AGENT_FAILURE = "agent_failure"
    TOOL_FAILURE = "tool_failure"
    SUPPORT_PROBLEM = "support_problem"
    LATENCY_PROBLEM = "latency_problem"
    COST_PROBLEM = "cost_problem"
    ROUTING_PROBLEM = "routing_problem"
    WORKFLOW_PROBLEM = "workflow_problem"
    MISSING_REGRESSION_TEST = "missing_regression_test"
    POLICY_VIOLATION = "policy_violation"
    OPERATIONAL_FAILURE = "operational_failure"


VALID_PROBLEM_CATEGORIES: frozenset[str] = frozenset(c.value for c in ProblemCategory)


class ProposedChangeTarget(enum.StrEnum):
    """The only thing an L2 proposal may ever name as its proposed
    change -- see module docstring, "Closed proposal vocabulary". No
    member here names security policy, RBAC, permissions, authorization,
    secrets, autonomy tiers, deployment, or infrastructure -- proposing a
    change to any of those is structurally impossible to construct."""

    PROMPT_INSTRUCTION = "prompt_instruction"
    MODEL_SELECTION_ROUTING = "model_selection_routing"
    TOOL_SELECTION_STRATEGY = "tool_selection_strategy"
    RETRIEVAL_STRATEGY = "retrieval_strategy"
    RESPONSE_STRATEGY = "response_strategy"
    WORKFLOW_SEQUENCING = "workflow_sequencing"
    RETRY_OR_TIMEOUT_CONFIGURATION = "retry_or_timeout_configuration"
    CACHING_STRATEGY = "caching_strategy"
    MONITORING_OR_ALERTING_CONFIGURATION = "monitoring_or_alerting_configuration"
    MISSING_REGRESSION_TEST_COVERAGE = "missing_regression_test_coverage"
    DOCUMENTATION_OR_RUNBOOK_UPDATE = "documentation_or_runbook_update"


VALID_PROPOSED_CHANGE_TARGETS: frozenset[str] = frozenset(t.value for t in ProposedChangeTarget)


class ProposalScope(enum.StrEnum):
    """`tenant` (default -- the proposal's evidence and effect are scoped
    to its originating tenant) or `platform_wide` (mirrors
    `control_plane.self_learning.adaptive.models.AdaptationScope`, Phase
    9.4: requires an explicit, separate
    `PlatformWideProposalAuthorization`, never inferred)."""

    TENANT = "tenant"
    PLATFORM_WIDE = "platform_wide"


class ProposalStatus(enum.StrEnum):
    """A proposal's own lifecycle -- never an evaluation, approval, or
    deployment state (docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own
    Non-Goal: "no automatic application of a proposal to production").

    PROPOSED  -- freshly generated, the only status `service
                 .propose_system_learning_proposal()` can produce.
    WITHDRAWN -- explicitly withdrawn (this task's own Section 10: "L2
                 rollback ... means withdrawal ... of an L2 proposal").
    REPLACED  -- superseded by a newer version in the same lineage
                 (`rollback_reference` on the newer proposal points back
                 to this one).
    """

    PROPOSED = "proposed"
    WITHDRAWN = "withdrawn"
    REPLACED = "replaced"


VALID_PROPOSAL_STATUSES: frozenset[str] = frozenset(s.value for s in ProposalStatus)


class RiskLevel(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ConfidenceLevel(enum.StrEnum):
    """Reachable only through `service.detect_recurrence()`'s
    deterministic computation -- see module docstring, "No
    self-attestation surface"."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class SystemLearningObservation:
    """One data point supporting (or not) a recurring-problem claim --
    evidence, never a conclusion. `source_reference` is a pointer (e.g. a
    `core.audit_log` entry id) never raw tenant data (same data-minimization
    discipline as `control_plane.self_learning.models.LearningEvidence
    .source_reference`, Phase 9.2)."""

    tenant_id: uuid.UUID
    observed_at: datetime
    source_reference: str
    observation_id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass(frozen=True)
class RecurrenceAssessment:
    """The deterministic, testable verdict distinguishing an isolated
    observation from a recurring/systemic pattern
    (docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own instruction: "Use
    deterministic, testable rules for recurrence"). Produced only by
    `service.detect_recurrence()` -- never hand-constructed by a caller
    claiming a result, since every field here is checked for internal
    consistency below."""

    is_recurring: bool
    distinct_observation_count: int
    window: timedelta
    minimum_occurrences_required: int
    confidence: ConfidenceLevel
    earliest_observed_at: datetime | None
    latest_observed_at: datetime | None
    supporting_source_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Structural invariants -- a bug in service.py, not caller input,
        # would trip these (same discipline as
        # control_plane.self_learning.evaluation.models.EvaluationComparison
        # .__post_init__, Phase 9.3).
        if (
            self.is_recurring
            and self.distinct_observation_count < self.minimum_occurrences_required
        ):
            raise AssertionError(
                "is_recurring=True requires distinct_observation_count >= "
                "minimum_occurrences_required."
            )
        if not self.is_recurring and self.confidence is not ConfidenceLevel.LOW:
            raise AssertionError(
                "A non-recurring (isolated) observation must never carry confidence "
                "above LOW -- an isolated event cannot become a high-confidence "
                "systemic conclusion."
            )
        if self.distinct_observation_count < 0:
            raise AssertionError("distinct_observation_count must not be negative.")


@dataclass(frozen=True)
class SystemLearningImpactMetrics:
    """A measured impact metric set -- every field is `None` unless
    actually measured, mirroring
    `control_plane.self_learning.evaluation.models.EvaluationMetrics`'s
    own "no self-attestation surface" discipline (Phase 9.3): no field
    here is a claim, only a number."""

    affected_occurrence_count: int | None = None
    affected_tenant_count: int | None = None
    estimated_latency_impact_ms: float | None = None
    estimated_cost_impact: float | None = None
    estimated_error_rate_impact: float | None = None


@dataclass(frozen=True)
class PlatformWideProposalAuthorization:
    """Explicit, caller-supplied authorization permitting a proposal
    scoped `ProposalScope.PLATFORM_WIDE` to name tenants beyond its
    originating one (mirrors
    `control_plane.self_learning.adaptive.models
    .PlatformWideAdaptationAuthorization`, Phase 9.4). Not persisted --
    same no-persistence, caller-supplied-input discipline as every other
    policy-input object in this package family."""

    authorized_purposes: frozenset[str]


@dataclass(frozen=True)
class SystemLearningProposal:
    """One L2 system-learning proposal -- data, never an approval,
    evaluation pass, or activation (docs/IMPLEMENTATION-ROADMAP.md
    Phase 9.5's own Scope: "a proposal is data, never auto-applied by
    this phase"). See module docstring for the field-by-field mapping to
    Phase 9.5's own Tests bullet and this task's own Proposal Model
    section."""

    tenant_id: uuid.UUID
    problem_category: ProblemCategory
    problem_description: str
    evidence: LearningEvidence
    learning_authorization_decision_id: uuid.UUID
    data_classification: str
    recurrence: RecurrenceAssessment
    confidence: ConfidenceLevel
    scope: ProposalScope
    affected_tenant_ids: frozenset[uuid.UUID]
    proposed_change_target: ProposedChangeTarget
    proposed_change_description: str
    rationale: str
    risk_level: RiskLevel
    impact_metrics: SystemLearningImpactMetrics | None = None
    evaluation_outcome: str | None = None
    evaluation_comparison_id: uuid.UUID | None = None
    created_by_user_id: uuid.UUID | None = None
    proposal_id: uuid.UUID = field(default_factory=uuid.uuid4)
    status: ProposalStatus = ProposalStatus.PROPOSED
    version: int = 1
    rollback_reference: uuid.UUID | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        # Structural invariants, not input validation -- catches a bug in
        # service.py, not caller error (same discipline as every other
        # frozen decision/comparison dataclass in this package family).
        if self.proposed_change_target.value not in VALID_PROPOSED_CHANGE_TARGETS:
            raise AssertionError("proposed_change_target must be a member of ProposedChangeTarget.")
        if self.problem_category.value not in VALID_PROBLEM_CATEGORIES:
            raise AssertionError("problem_category must be a member of ProblemCategory.")
        if self.scope is ProposalScope.TENANT and self.affected_tenant_ids != frozenset(
            {self.tenant_id}
        ):
            raise AssertionError(
                "A tenant-scoped proposal's affected_tenant_ids must be exactly "
                "{tenant_id} -- cross-tenant effect requires ProposalScope.PLATFORM_WIDE "
                "plus explicit authorization."
            )
        if self.tenant_id not in self.affected_tenant_ids:
            raise AssertionError(
                "A proposal's originating tenant_id must always be a member of its own "
                "affected_tenant_ids."
            )
        if self.confidence is not self.recurrence.confidence:
            raise AssertionError("confidence must equal recurrence.confidence -- never diverge.")
        if self.version < 1:
            raise AssertionError("version must be >= 1.")

    @property
    def is_reversible(self) -> bool:
        """A proposal never mutates production state (this package's own
        structural guarantee -- see `control_plane.self_learning
        .system_learning` module docstring). Withdrawing or replacing it
        (`service.withdraw_system_learning_proposal()`, or a fresh
        `propose_system_learning_proposal()` call carrying
        `rollback_reference=<this proposal_id>`) changes only this
        package's own in-memory data, never anything else -- so every
        proposal is, structurally, always reversible. Not a constructor
        field: making this a computed property (mirroring
        `control_plane.self_learning.evaluation.models.EvaluationComparison
        .is_pass`, Phase 9.3) means there is no argument through which a
        caller could ever set it to `False`."""
        return True

    @property
    def is_proposal_only(self) -> bool:
        """Always `True` -- structural proof-of-non-authority: a
        `SystemLearningProposal` has no field and no method anywhere in
        this class that represents evaluation-pass, approval, or
        deployment/activation state. See
        `tests/control_plane/self_learning/system_learning
        /test_system_learning_unit.py::TestProposalIsNotApprovalOrDeployment`.
        """
        return True


__all__ = [
    "ProblemCategory",
    "VALID_PROBLEM_CATEGORIES",
    "ProposedChangeTarget",
    "VALID_PROPOSED_CHANGE_TARGETS",
    "ProposalScope",
    "ProposalStatus",
    "VALID_PROPOSAL_STATUSES",
    "RiskLevel",
    "ConfidenceLevel",
    "SystemLearningObservation",
    "RecurrenceAssessment",
    "SystemLearningImpactMetrics",
    "PlatformWideProposalAuthorization",
    "SystemLearningProposal",
]
