"""L2 System Learning: observe -> assess recurrence -> propose -> withdraw
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.5).

Two independent pure/audited operations, mirroring
`control_plane.self_learning.adaptive.service`'s own
"domain function, then an audited wrapper" discipline (Phase 9.4):

- `detect_recurrence()` -- a pure function over typed
  `SystemLearningObservation`s. Same inputs always produce the same
  `RecurrenceAssessment`; no I/O, no database, no model/provider call, no
  channel for a self-reported "this is recurring" claim to influence the
  result (docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own instruction: "Use
  deterministic, testable rules for recurrence... LLM self-assertion is
  never authoritative evidence").
- `propose_system_learning_proposal()` / `withdraw_system_learning_proposal()`
  -- construct/transition a `SystemLearningProposal` and write exactly one
  `core.audit_log` entry per call (Phase 9.5's own Audit Requirement:
  `learning.proposal_created` / `.state_changed`). Both are Tier 0: a
  proposal has no production effect by construction (`models.py`'s
  `SystemLearningProposal.is_reversible`/`.is_proposal_only`), so neither
  operation is wrapped as a Tool Registry tool or gated behind
  `control_plane.approvals` -- unlike `activate_adaptation()`/
  `rollback_adaptation()` (Phase 9.4), which are Tier 1 because they
  *do* have a production effect.

`propose_system_learning_proposal()` requires an already-ALLOW
`LearningAuthorizationDecision` for the same tenant (Phase 9.2's gate,
never bypassed or re-implemented) and a caller-supplied `RecurrenceAssessment`
(never a bare confidence value -- see `models.py`'s "No self-attestation
surface"). It never accepts, computes, or is influenced by:

- a model's own claim that a problem is "systemic" or that a proposed
  change "will work" (no such parameter exists on this function's
  signature);
- an already-computed evaluation outcome as a *gate* -- an optional
  `evaluation_comparison` may be attached as *provenance* only
  (`SystemLearningProposal.evaluation_outcome`), reusing
  `control_plane.self_learning.evaluation`'s own `EvaluationComparison`
  rather than re-deriving one (Phase 9.3's boundary, never duplicated
  here); a proposal is created regardless of whether an evaluation exists
  yet or what it says -- "a proposal is not equivalent to an evaluation
  PASS" (docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own Scope);
- an approval or activation state -- every proposal this function returns
  has `status=ProposalStatus.PROPOSED`, structurally (see
  `models.SystemLearningProposal.is_proposal_only`).

Cross-tenant `affected_tenant_ids` (any tenant other than the proposing
`tenant_id`) is denied unless an exactly-matching
`control_plane.self_learning.models.CrossTenantLearningPolicy` is
supplied -- reusing Phase 9.2's own cross-tenant mechanism, never a
second one (this task's own instruction: "never create a second
authorization mechanism").

This module never imports `sqlalchemy`, `infra.db`, `infra.secrets`,
`core.rbac`, or `control_plane.orchestration` -- it writes nothing of its
own to any database; the only persistence anywhere in this call chain is
`core.audit_log.record()`'s own table, written through that module's
existing public interface.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime, timedelta

from control_plane.data_authorization.models import VALID_DATA_CLASSIFICATIONS
from control_plane.self_learning.evaluation.models import EvaluationComparison
from control_plane.self_learning.models import (
    VALID_EVIDENCE_TYPES,
    CrossTenantLearningPolicy,
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
    LearningEvidence,
)
from control_plane.self_learning.system_learning.errors import (
    CrossTenantProposalNotAuthorizedError,
    InvalidProblemCategoryError,
    InvalidProposedChangeTargetError,
    PlatformWideProposalScopeNotAuthorizedError,
    ProposalNotWithdrawableError,
    UnauthorizedProposalEvidenceError,
)
from control_plane.self_learning.system_learning.models import (
    VALID_PROBLEM_CATEGORIES,
    VALID_PROPOSED_CHANGE_TARGETS,
    ConfidenceLevel,
    PlatformWideProposalAuthorization,
    ProblemCategory,
    ProposalScope,
    ProposalStatus,
    ProposedChangeTarget,
    RecurrenceAssessment,
    RiskLevel,
    SystemLearningImpactMetrics,
    SystemLearningObservation,
    SystemLearningProposal,
)
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event

_AUDIT_RESOURCE_TYPE = "self_learning_system_learning_proposal"
_AUDIT_ACTION_CREATED = "learning.proposal_created"
_AUDIT_ACTION_STATE_CHANGED = "learning.proposal_state_changed"


def detect_recurrence(
    observations: tuple[SystemLearningObservation, ...],
    *,
    window: timedelta,
    minimum_occurrences: int,
) -> RecurrenceAssessment:
    """Deterministic recurrence/confidence computation over a fixed,
    trailing window ending at the most recent observation. Fixed
    algorithm, no randomness, no model call:

    1. If there are no observations at all, the result is
       `is_recurring=False`, `confidence=LOW` -- there is no evidence to
       claim otherwise.
    2. Otherwise, take every observation whose `observed_at` falls within
       `window` of the *latest* observation's timestamp (a trailing
       window, not a fixed calendar window -- deterministic given the
       same observation set).
    3. Count *distinct* `source_reference`s within that window (the same
       evidence pointer reported twice is one occurrence, not two --
       this is the literal enforcement of "a single arbitrary observation
       [must not] automatically become a high-confidence systemic
       conclusion").
    4. `is_recurring` is `distinct_count >= minimum_occurrences`.
    5. `confidence` is `LOW` when not recurring; `MEDIUM` when recurring
       but below double the required threshold; `HIGH` only at or above
       double the threshold -- an explicit, testable formula, never a
       model's self-assessment.
    """
    if minimum_occurrences < 1:
        raise ValueError("minimum_occurrences must be >= 1.")
    if window <= timedelta(0):
        raise ValueError("window must be a positive timedelta.")

    if not observations:
        return RecurrenceAssessment(
            is_recurring=False,
            distinct_observation_count=0,
            window=window,
            minimum_occurrences_required=minimum_occurrences,
            confidence=ConfidenceLevel.LOW,
            earliest_observed_at=None,
            latest_observed_at=None,
            supporting_source_references=(),
        )

    latest_observed_at: datetime = max(o.observed_at for o in observations)
    window_start = latest_observed_at - window
    within_window = [o for o in observations if o.observed_at >= window_start]

    distinct_references = tuple(sorted({o.source_reference for o in within_window}))
    distinct_count = len(distinct_references)
    earliest_observed_at = min(o.observed_at for o in within_window)

    is_recurring = distinct_count >= minimum_occurrences
    if not is_recurring:
        confidence = ConfidenceLevel.LOW
    elif distinct_count >= minimum_occurrences * 2:
        confidence = ConfidenceLevel.HIGH
    else:
        confidence = ConfidenceLevel.MEDIUM

    return RecurrenceAssessment(
        is_recurring=is_recurring,
        distinct_observation_count=distinct_count,
        window=window,
        minimum_occurrences_required=minimum_occurrences,
        confidence=confidence,
        earliest_observed_at=earliest_observed_at,
        latest_observed_at=latest_observed_at,
        supporting_source_references=distinct_references,
    )


def _resolve_affected_tenant_ids(
    *,
    tenant_id: uuid.UUID,
    scope: ProposalScope,
    affected_tenant_ids: frozenset[uuid.UUID] | None,
    cross_tenant_policy: CrossTenantLearningPolicy | None,
    purpose: str,
) -> frozenset[uuid.UUID]:
    resolved = frozenset({tenant_id}) | (affected_tenant_ids or frozenset())
    other_tenant_ids = resolved - {tenant_id}
    if not other_tenant_ids:
        return resolved

    if scope is not ProposalScope.PLATFORM_WIDE:
        other = sorted(other_tenant_ids, key=str)[0]
        raise CrossTenantProposalNotAuthorizedError(tenant_id, other)

    for other_tenant_id in sorted(other_tenant_ids, key=str):
        if (
            cross_tenant_policy is None
            or cross_tenant_policy.source_tenant_id != tenant_id
            or cross_tenant_policy.target_tenant_id != other_tenant_id
            or purpose not in cross_tenant_policy.approved_purposes
        ):
            raise CrossTenantProposalNotAuthorizedError(tenant_id, other_tenant_id)

    return resolved


def build_system_learning_proposal(
    *,
    tenant_id: uuid.UUID,
    problem_category: ProblemCategory,
    problem_description: str,
    evidence: LearningEvidence,
    learning_authorization_decision: LearningAuthorizationDecision,
    data_classification: str,
    recurrence: RecurrenceAssessment,
    proposed_change_target: ProposedChangeTarget,
    proposed_change_description: str,
    rationale: str,
    risk_level: RiskLevel,
    created_by_user_id: uuid.UUID | None = None,
    impact_metrics: SystemLearningImpactMetrics | None = None,
    evaluation_comparison: EvaluationComparison | None = None,
    scope: ProposalScope = ProposalScope.TENANT,
    affected_tenant_ids: frozenset[uuid.UUID] | None = None,
    platform_wide_authorization: PlatformWideProposalAuthorization | None = None,
    cross_tenant_policy: CrossTenantLearningPolicy | None = None,
    rollback_reference: uuid.UUID | None = None,
    version: int = 1,
) -> SystemLearningProposal:
    """Pure construction of one `ProposalStatus.PROPOSED`
    `SystemLearningProposal` -- no I/O, no database, no audit write (same
    "pure function, then an audited wrapper" split as
    `control_plane.self_learning.evaluation.service.evaluate_candidate()`
    vs. `.run_evaluation()`, Phase 9.3). Raises rather than silently
    downgrading scope, evidence, or target -- default deny, matching every
    other gate this platform ships. Call `propose_system_learning_proposal()`
    instead unless you specifically need the unaudited construction (e.g.
    building a `RecurrenceAssessment`-driven proposal for inspection before
    deciding whether to record it)."""
    if proposed_change_target.value not in VALID_PROPOSED_CHANGE_TARGETS:
        raise InvalidProposedChangeTargetError(str(proposed_change_target))
    if problem_category.value not in VALID_PROBLEM_CATEGORIES:
        raise InvalidProblemCategoryError(str(problem_category))
    if data_classification not in VALID_DATA_CLASSIFICATIONS:
        raise ValueError(f"{data_classification!r} is not a permitted data classification.")

    if (
        learning_authorization_decision.outcome is not LearningAuthorizationOutcome.ALLOW
        or learning_authorization_decision.tenant_id != tenant_id
    ):
        raise UnauthorizedProposalEvidenceError(
            "Learning Authorization for this tenant must be ALLOW before generating a "
            "system-learning proposal."
        )

    if (
        not evidence.evidence_type
        or evidence.evidence_type not in VALID_EVIDENCE_TYPES
        or not evidence.source_reference
    ):
        raise UnauthorizedProposalEvidenceError(
            f"{evidence.evidence_type!r} is not permitted learning evidence "
            "(docs/IMPLEMENTATION-ROADMAP.md Phase 9.2's VALID_EVIDENCE_TYPES)."
        )

    if scope is ProposalScope.PLATFORM_WIDE:
        if platform_wide_authorization is None or (
            learning_authorization_decision.purpose
            not in platform_wide_authorization.authorized_purposes
        ):
            raise PlatformWideProposalScopeNotAuthorizedError(
                tenant_id, learning_authorization_decision.purpose
            )

    resolved_affected_tenant_ids = _resolve_affected_tenant_ids(
        tenant_id=tenant_id,
        scope=scope,
        affected_tenant_ids=affected_tenant_ids,
        cross_tenant_policy=cross_tenant_policy,
        purpose=learning_authorization_decision.purpose,
    )

    proposal = SystemLearningProposal(
        tenant_id=tenant_id,
        problem_category=problem_category,
        problem_description=problem_description,
        evidence=evidence,
        learning_authorization_decision_id=learning_authorization_decision.decision_id,
        data_classification=data_classification,
        recurrence=recurrence,
        confidence=recurrence.confidence,
        scope=scope,
        affected_tenant_ids=resolved_affected_tenant_ids,
        proposed_change_target=proposed_change_target,
        proposed_change_description=proposed_change_description,
        rationale=rationale,
        risk_level=risk_level,
        impact_metrics=impact_metrics,
        evaluation_outcome=(
            evaluation_comparison.outcome.value if evaluation_comparison is not None else None
        ),
        evaluation_comparison_id=(
            evaluation_comparison.decision_id if evaluation_comparison is not None else None
        ),
        created_by_user_id=created_by_user_id,
        status=ProposalStatus.PROPOSED,
        version=version,
        rollback_reference=rollback_reference,
    )
    return proposal


def propose_system_learning_proposal(
    *,
    tenant_id: uuid.UUID,
    problem_category: ProblemCategory,
    problem_description: str,
    evidence: LearningEvidence,
    learning_authorization_decision: LearningAuthorizationDecision,
    data_classification: str,
    recurrence: RecurrenceAssessment,
    proposed_change_target: ProposedChangeTarget,
    proposed_change_description: str,
    rationale: str,
    risk_level: RiskLevel,
    created_by_user_id: uuid.UUID | None = None,
    impact_metrics: SystemLearningImpactMetrics | None = None,
    evaluation_comparison: EvaluationComparison | None = None,
    scope: ProposalScope = ProposalScope.TENANT,
    affected_tenant_ids: frozenset[uuid.UUID] | None = None,
    platform_wide_authorization: PlatformWideProposalAuthorization | None = None,
    cross_tenant_policy: CrossTenantLearningPolicy | None = None,
    rollback_reference: uuid.UUID | None = None,
    version: int = 1,
    correlation_id: str | None = None,
) -> SystemLearningProposal:
    """`build_system_learning_proposal()` plus exactly one
    `core.audit_log` entry (`learning.proposal_created`) -- Phase 9.5's
    own Audit Requirement. Metadata never carries the proposal's own
    free-text fields (`problem_description`, `proposed_change_description`,
    `rationale`) -- only identity, typed classification/target/scope
    values, and the evidence's pointer/type (never its content)."""
    proposal = build_system_learning_proposal(
        tenant_id=tenant_id,
        problem_category=problem_category,
        problem_description=problem_description,
        evidence=evidence,
        learning_authorization_decision=learning_authorization_decision,
        data_classification=data_classification,
        recurrence=recurrence,
        proposed_change_target=proposed_change_target,
        proposed_change_description=proposed_change_description,
        rationale=rationale,
        risk_level=risk_level,
        created_by_user_id=created_by_user_id,
        impact_metrics=impact_metrics,
        evaluation_comparison=evaluation_comparison,
        scope=scope,
        affected_tenant_ids=affected_tenant_ids,
        platform_wide_authorization=platform_wide_authorization,
        cross_tenant_policy=cross_tenant_policy,
        rollback_reference=rollback_reference,
        version=version,
    )

    metadata: dict[str, object] = {
        "problem_category": problem_category.value,
        "proposed_change_target": proposed_change_target.value,
        "scope": scope.value,
        "affected_tenant_count": len(proposal.affected_tenant_ids),
        "risk_level": risk_level.value,
        "confidence": proposal.confidence.value,
        "is_recurring": recurrence.is_recurring,
        "distinct_observation_count": recurrence.distinct_observation_count,
        "data_classification": data_classification,
        "version": version,
        "evidence_type": evidence.evidence_type,
        "evidence_source_reference": evidence.source_reference,
        "learning_authorization_decision_id": str(learning_authorization_decision.decision_id),
    }
    if rollback_reference is not None:
        metadata["rollback_reference"] = str(rollback_reference)
    if proposal.evaluation_outcome is not None:
        metadata["evaluation_outcome"] = proposal.evaluation_outcome

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if created_by_user_id is not None else ActorType.SYSTEM,
        actor_user_id=created_by_user_id,
        action=_AUDIT_ACTION_CREATED,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(proposal.proposal_id),
        outcome=AuditOutcome.SUCCESS,
        correlation_id=correlation_id,
        metadata=metadata,
    )
    return proposal


def build_withdrawn_proposal(proposal: SystemLearningProposal) -> SystemLearningProposal:
    """Pure state transition: `ProposalStatus.PROPOSED` ->
    `ProposalStatus.WITHDRAWN`. No I/O, no audit write -- see
    `build_system_learning_proposal()`'s own "pure, then audited" split.
    Returns a *new* frozen `SystemLearningProposal`; the object passed in
    is never mutated (there is no persisted row for this package to
    update)."""
    if proposal.status is not ProposalStatus.PROPOSED:
        raise ProposalNotWithdrawableError(proposal.proposal_id, proposal.status.value)
    return dataclasses.replace(proposal, status=ProposalStatus.WITHDRAWN)


def withdraw_system_learning_proposal(
    proposal: SystemLearningProposal,
    *,
    withdrawn_by_user_id: uuid.UUID | None = None,
    correlation_id: str | None = None,
) -> SystemLearningProposal:
    """Withdraw a `ProposalStatus.PROPOSED` proposal (this task's own
    Section 10: "L2 rollback ... means withdrawal ... of an L2
    proposal -- not production deployment rollback"). Writes exactly one
    `core.audit_log` entry (`learning.proposal_state_changed`)."""
    withdrawn = build_withdrawn_proposal(proposal)

    record_audit_event(
        tenant_id=proposal.tenant_id,
        actor_type=ActorType.USER if withdrawn_by_user_id is not None else ActorType.SYSTEM,
        actor_user_id=withdrawn_by_user_id,
        action=_AUDIT_ACTION_STATE_CHANGED,
        resource_type=_AUDIT_RESOURCE_TYPE,
        resource_id=str(proposal.proposal_id),
        outcome=AuditOutcome.SUCCESS,
        correlation_id=correlation_id,
        metadata={
            "previous_status": ProposalStatus.PROPOSED.value,
            "new_status": ProposalStatus.WITHDRAWN.value,
            "problem_category": proposal.problem_category.value,
            "version": proposal.version,
        },
    )
    return withdrawn
