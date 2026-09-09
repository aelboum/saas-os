"""Unit tests for `control_plane.self_learning.system_learning`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.5). Pure-function/structural/AST
checks only -- no database required, part of the default `pytest` run.
Audited-write behavior (`core.audit_log` entries) is covered by
`test_system_learning_integration.py` (marked `integration`).
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationOutcome,
)
from control_plane.self_learning.models import (
    CrossTenantLearningPolicy,
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
    LearningDenialReason,
    LearningEvidence,
)
from control_plane.self_learning.system_learning import errors as sl_errors
from control_plane.self_learning.system_learning import models as sl_models
from control_plane.self_learning.system_learning import service as sl_service
from control_plane.self_learning.system_learning.errors import (
    CrossTenantProposalNotAuthorizedError,
    PlatformWideProposalScopeNotAuthorizedError,
    ProposalNotWithdrawableError,
    UnauthorizedProposalEvidenceError,
)
from control_plane.self_learning.system_learning.models import (
    VALID_PROBLEM_CATEGORIES,
    ConfidenceLevel,
    PlatformWideProposalAuthorization,
    ProblemCategory,
    ProposalScope,
    ProposalStatus,
    ProposedChangeTarget,
    RecurrenceAssessment,
    RiskLevel,
    SystemLearningObservation,
    SystemLearningProposal,
)
from control_plane.self_learning.system_learning.service import (
    build_system_learning_proposal,
    build_withdrawn_proposal,
    detect_recurrence,
    propose_system_learning_proposal,
)

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()
TENANT_C = uuid.uuid4()

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _allow_decision(
    tenant_id: uuid.UUID = TENANT_A, purpose: str = "system_learning_analysis"
) -> LearningAuthorizationDecision:
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


def _deny_decision(tenant_id: uuid.UUID = TENANT_A) -> LearningAuthorizationDecision:
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.DENY,
        tenant_id=tenant_id,
        purpose="system_learning_analysis",
        reason=LearningDenialReason.NO_LEARNING_POLICY,
        data_authorization_decision_id=uuid.uuid4(),
    )


def _observations(
    count: int, *, tenant_id: uuid.UUID = TENANT_A, start: datetime = NOW, spacing_hours: int = 1
) -> tuple[SystemLearningObservation, ...]:
    return tuple(
        SystemLearningObservation(
            tenant_id=tenant_id,
            observed_at=start + timedelta(hours=i * spacing_hours),
            source_reference=f"audit-entry-{i}",
        )
        for i in range(count)
    )


def _recurring_assessment(count: int = 6, minimum: int = 3) -> RecurrenceAssessment:
    return detect_recurrence(
        _observations(count), window=timedelta(days=7), minimum_occurrences=minimum
    )


def _isolated_assessment() -> RecurrenceAssessment:
    return detect_recurrence(_observations(1), window=timedelta(days=7), minimum_occurrences=3)


def _propose(**overrides: object) -> SystemLearningProposal:
    kwargs: dict[str, object] = dict(
        tenant_id=TENANT_A,
        problem_category=ProblemCategory.TOOL_FAILURE,
        problem_description="The support-reply tool times out repeatedly under load.",
        evidence=LearningEvidence(evidence_type="tool_output", source_reference="audit-entry-0"),
        learning_authorization_decision=_allow_decision(),
        data_classification="tenant_data",
        recurrence=_recurring_assessment(),
        proposed_change_target=ProposedChangeTarget.RETRY_OR_TIMEOUT_CONFIGURATION,
        proposed_change_description="Increase the tool timeout from 5s to 15s.",
        rationale="6 distinct timeout failures observed in the trailing 7 days.",
        risk_level=RiskLevel.LOW,
    )
    kwargs.update(overrides)
    return build_system_learning_proposal(**kwargs)  # type: ignore[arg-type]


class TestPermittedVocabularies:
    def test_problem_category_matches_roadmaps_own_categories(self) -> None:
        assert VALID_PROBLEM_CATEGORIES == {
            "agent_failure",
            "tool_failure",
            "support_problem",
            "latency_problem",
            "cost_problem",
            "routing_problem",
            "workflow_problem",
            "missing_regression_test",
            "policy_violation",
            "operational_failure",
        }

    def test_no_security_rbac_secrets_autonomy_or_deploy_change_target_exists(self) -> None:
        """docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own Policy-Authority
        Boundary: reject targets such as security/rbac/permissions/secrets/
        autonomy/deployment/infrastructure -- structurally, by never
        defining such a member, not merely by a runtime check."""
        forbidden_fragments = (
            "security",
            "rbac",
            "permission",
            "secret",
            "autonomy",
            "tenant_isolation",
            "audit_policy",
            "deploy",
            "infrastructure",
            "shell",
            "database",
            "credential",
            "authorization",
        )
        for member in ProposedChangeTarget:
            for fragment in forbidden_fragments:
                assert fragment not in member.value, member.value

    def test_change_target_enum_rejects_an_unlisted_value(self) -> None:
        with pytest.raises(ValueError):
            ProposedChangeTarget("security.rbac_grant")

    def test_forbidden_targets_are_structurally_impossible_to_construct(self) -> None:
        for forbidden in (
            "rbac_grant",
            "modify_secrets",
            "deploy_infrastructure",
            "autonomy_tier_change",
            "unrestricted_shell",
            "database_admin",
            "security_policy_update",
        ):
            with pytest.raises(ValueError):
                ProposedChangeTarget(forbidden)

    def test_problem_category_enum_rejects_an_unlisted_value(self) -> None:
        with pytest.raises(ValueError):
            ProblemCategory("not_a_real_category")


class TestRecurrenceDetection:
    def test_no_observations_is_not_recurring_and_low_confidence(self) -> None:
        result = detect_recurrence((), window=timedelta(days=7), minimum_occurrences=3)
        assert result.is_recurring is False
        assert result.confidence is ConfidenceLevel.LOW
        assert result.distinct_observation_count == 0

    def test_isolated_single_observation_does_not_become_systemic(self) -> None:
        """docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own instruction: "Do
        not allow a single arbitrary observation to automatically become a
        high-confidence systemic conclusion."."""
        result = _isolated_assessment()
        assert result.is_recurring is False
        assert result.confidence is ConfidenceLevel.LOW
        assert result.distinct_observation_count == 1

    def test_recurring_pattern_detected_when_threshold_met(self) -> None:
        result = detect_recurrence(
            _observations(3), window=timedelta(days=7), minimum_occurrences=3
        )
        assert result.is_recurring is True
        assert result.distinct_observation_count == 3

    def test_confidence_is_medium_just_above_threshold(self) -> None:
        result = detect_recurrence(
            _observations(3), window=timedelta(days=7), minimum_occurrences=3
        )
        assert result.confidence is ConfidenceLevel.MEDIUM

    def test_confidence_is_high_only_at_double_the_threshold(self) -> None:
        result = detect_recurrence(
            _observations(6), window=timedelta(days=7), minimum_occurrences=3
        )
        assert result.confidence is ConfidenceLevel.HIGH

    def test_duplicate_source_reference_is_counted_once(self) -> None:
        duplicated = tuple(
            SystemLearningObservation(
                tenant_id=TENANT_A,
                observed_at=NOW + timedelta(hours=i),
                source_reference="same-ref",
            )
            for i in range(5)
        )
        result = detect_recurrence(duplicated, window=timedelta(days=7), minimum_occurrences=3)
        assert result.distinct_observation_count == 1
        assert result.is_recurring is False

    def test_observations_outside_the_trailing_window_are_excluded(self) -> None:
        recent = _observations(2, start=NOW, spacing_hours=1)
        stale = (
            SystemLearningObservation(
                tenant_id=TENANT_A, observed_at=NOW - timedelta(days=30), source_reference="stale-1"
            ),
        )
        result = detect_recurrence(stale + recent, window=timedelta(days=7), minimum_occurrences=3)
        # 2 recent + would-be 3rd (stale) excluded by window -> not recurring
        assert result.distinct_observation_count == 2
        assert result.is_recurring is False

    def test_same_inputs_produce_the_same_result_deterministically(self) -> None:
        obs = _observations(5)
        first = detect_recurrence(obs, window=timedelta(days=7), minimum_occurrences=3)
        second = detect_recurrence(obs, window=timedelta(days=7), minimum_occurrences=3)
        assert first == second

    def test_non_positive_minimum_occurrences_rejected(self) -> None:
        with pytest.raises(ValueError):
            detect_recurrence(_observations(3), window=timedelta(days=7), minimum_occurrences=0)

    def test_non_positive_window_rejected(self) -> None:
        with pytest.raises(ValueError):
            detect_recurrence(_observations(3), window=timedelta(0), minimum_occurrences=3)


class TestRecurrenceAssessmentInvariants:
    def test_is_recurring_true_requires_count_meet_threshold(self) -> None:
        with pytest.raises(AssertionError):
            RecurrenceAssessment(
                is_recurring=True,
                distinct_observation_count=1,
                window=timedelta(days=7),
                minimum_occurrences_required=3,
                confidence=ConfidenceLevel.HIGH,
                earliest_observed_at=NOW,
                latest_observed_at=NOW,
            )

    def test_non_recurring_cannot_carry_above_low_confidence(self) -> None:
        with pytest.raises(AssertionError):
            RecurrenceAssessment(
                is_recurring=False,
                distinct_observation_count=1,
                window=timedelta(days=7),
                minimum_occurrences_required=3,
                confidence=ConfidenceLevel.MEDIUM,
                earliest_observed_at=NOW,
                latest_observed_at=NOW,
            )


class TestBoundedProposalGeneration:
    def test_valid_proposal_is_schema_complete(self) -> None:
        proposal = _propose()
        field_names = {f.name for f in dataclasses.fields(SystemLearningProposal)}
        assert field_names >= {
            "proposal_id",
            "tenant_id",
            "problem_category",
            "problem_description",
            "evidence",
            "learning_authorization_decision_id",
            "data_classification",
            "recurrence",
            "confidence",
            "scope",
            "affected_tenant_ids",
            "proposed_change_target",
            "proposed_change_description",
            "rationale",
            "risk_level",
            "impact_metrics",
            "evaluation_outcome",
            "evaluation_comparison_id",
            "created_by_user_id",
            "status",
            "version",
            "rollback_reference",
            "created_at",
        }
        assert isinstance(proposal.proposal_id, uuid.UUID)
        assert proposal.status is ProposalStatus.PROPOSED
        assert proposal.version == 1

    def test_proposal_carries_evidence_and_authorization_provenance(self) -> None:
        decision = _allow_decision()
        proposal = _propose(learning_authorization_decision=decision)
        assert proposal.learning_authorization_decision_id == decision.decision_id
        assert proposal.evidence.source_reference == "audit-entry-0"

    def test_isolated_observation_proposal_carries_low_confidence(self) -> None:
        proposal = _propose(recurrence=_isolated_assessment())
        assert proposal.confidence is ConfidenceLevel.LOW
        assert proposal.recurrence.is_recurring is False


class TestInvalidProposalTargetRejected:
    def test_forbidden_target_string_cannot_reach_propose_system_learning_proposal(self) -> None:
        with pytest.raises(ValueError):
            _propose(proposed_change_target=ProposedChangeTarget("rbac_grant"))  # type: ignore[arg-type]


class TestEvidenceAuthorizationGate:
    def test_denied_learning_authorization_is_rejected(self) -> None:
        with pytest.raises(UnauthorizedProposalEvidenceError):
            _propose(learning_authorization_decision=_deny_decision())

    def test_wrong_tenant_decision_is_rejected(self) -> None:
        with pytest.raises(UnauthorizedProposalEvidenceError):
            _propose(learning_authorization_decision=_allow_decision(TENANT_B))

    def test_invalid_evidence_type_is_rejected(self) -> None:
        with pytest.raises(UnauthorizedProposalEvidenceError):
            _propose(
                evidence=LearningEvidence(
                    evidence_type="not_a_real_type",  # type: ignore[arg-type]
                    source_reference="ref-1",
                )
            )

    def test_missing_source_reference_is_rejected(self) -> None:
        with pytest.raises(UnauthorizedProposalEvidenceError):
            _propose(evidence=LearningEvidence(evidence_type="tool_output", source_reference=""))

    def test_tool_output_evidence_is_accepted_only_because_explicitly_authorized(self) -> None:
        """docs/IMPLEMENTATION-ROADMAP.md Phase 9.5's own Evidence
        Authorization: "Tool output is evidence only if explicitly
        authorized for learning" -- an ALLOW LearningAuthorizationDecision
        is what makes it usable, not the evidence's own type."""
        proposal = _propose(
            evidence=LearningEvidence(evidence_type="tool_output", source_reference="tool-run-9")
        )
        assert proposal.evidence.evidence_type == "tool_output"


class TestPlatformWideScopeRequiresExplicitAuthorization:
    def test_platform_wide_without_authorization_is_rejected(self) -> None:
        with pytest.raises(PlatformWideProposalScopeNotAuthorizedError):
            _propose(scope=ProposalScope.PLATFORM_WIDE, platform_wide_authorization=None)

    def test_platform_wide_with_wrong_purpose_authorization_is_rejected(self) -> None:
        wrong = PlatformWideProposalAuthorization(authorized_purposes=frozenset({"other_purpose"}))
        with pytest.raises(PlatformWideProposalScopeNotAuthorizedError):
            _propose(scope=ProposalScope.PLATFORM_WIDE, platform_wide_authorization=wrong)


class TestCrossTenantIsolation:
    def test_extra_affected_tenant_denied_by_default_under_tenant_scope(self) -> None:
        with pytest.raises(CrossTenantProposalNotAuthorizedError):
            _propose(affected_tenant_ids=frozenset({TENANT_A, TENANT_B}))

    def test_extra_affected_tenant_denied_platform_wide_without_cross_tenant_policy(self) -> None:
        auth = PlatformWideProposalAuthorization(
            authorized_purposes=frozenset({"system_learning_analysis"})
        )
        with pytest.raises(CrossTenantProposalNotAuthorizedError):
            _propose(
                scope=ProposalScope.PLATFORM_WIDE,
                platform_wide_authorization=auth,
                affected_tenant_ids=frozenset({TENANT_A, TENANT_B}),
                cross_tenant_policy=None,
            )

    def test_wrong_pair_cross_tenant_policy_is_denied(self) -> None:
        auth = PlatformWideProposalAuthorization(
            authorized_purposes=frozenset({"system_learning_analysis"})
        )
        wrong_policy = CrossTenantLearningPolicy(
            source_tenant_id=TENANT_A,
            target_tenant_id=TENANT_C,
            approved_purposes=frozenset({"system_learning_analysis"}),
        )
        with pytest.raises(CrossTenantProposalNotAuthorizedError):
            _propose(
                scope=ProposalScope.PLATFORM_WIDE,
                platform_wide_authorization=auth,
                affected_tenant_ids=frozenset({TENANT_A, TENANT_B}),
                cross_tenant_policy=wrong_policy,
            )

    def test_exactly_matching_cross_tenant_policy_is_accepted(self) -> None:
        auth = PlatformWideProposalAuthorization(
            authorized_purposes=frozenset({"system_learning_analysis"})
        )
        policy = CrossTenantLearningPolicy(
            source_tenant_id=TENANT_A,
            target_tenant_id=TENANT_B,
            approved_purposes=frozenset({"system_learning_analysis"}),
        )
        proposal = _propose(
            scope=ProposalScope.PLATFORM_WIDE,
            platform_wide_authorization=auth,
            affected_tenant_ids=frozenset({TENANT_A, TENANT_B}),
            cross_tenant_policy=policy,
        )
        assert proposal.affected_tenant_ids == frozenset({TENANT_A, TENANT_B})

    def test_same_tenant_only_never_requires_a_cross_tenant_policy(self) -> None:
        proposal = _propose(cross_tenant_policy=None)
        assert proposal.affected_tenant_ids == frozenset({TENANT_A})


class TestProposalIsNotApprovalOrDeployment:
    def test_status_field_defaults_to_proposed_in_source(self) -> None:
        source = inspect.getsource(sl_service.build_system_learning_proposal)
        assert "status=ProposalStatus.PROPOSED" in source.replace(" ", "").replace("\n", "")

    def test_propose_and_withdraw_are_separate_functions(self) -> None:
        assert (
            sl_service.propose_system_learning_proposal
            is not sl_service.withdraw_system_learning_proposal
        )

    def test_is_reversible_and_is_proposal_only_properties_are_always_true(self) -> None:
        proposal = _propose()
        assert proposal.is_reversible is True
        assert proposal.is_proposal_only is True

    def test_no_evaluate_approve_activate_or_deploy_function_exists(self) -> None:
        public_names = {name for name in dir(sl_service) if not name.startswith("_")}
        for forbidden in ("approve", "activate", "deploy", "promote", "evaluate_proposal"):
            assert forbidden not in public_names


class TestEvaluationBoundary:
    def test_proposal_without_an_evaluation_has_no_evaluation_outcome(self) -> None:
        proposal = _propose()
        assert proposal.evaluation_outcome is None
        assert proposal.evaluation_comparison_id is None

    def test_attached_evaluation_is_provenance_only_never_a_gate(self) -> None:
        comparison = EvaluationComparison(
            outcome=EvaluationOutcome.FAIL,
            baseline_version="v1",
            candidate_version="v2",
            benchmark=Benchmark(benchmark_id="b", version="1"),
            invalid_reason=None,
            failed_metrics=("task_success_rate",),
            regressed_metrics=(),
        )
        proposal = _propose(evaluation_comparison=comparison)
        # A FAIL evaluation does not block proposal creation -- a
        # proposal is not equivalent to an evaluation PASS, and is not
        # blocked by a FAIL either.
        assert proposal.status is ProposalStatus.PROPOSED
        assert proposal.evaluation_outcome == "fail"
        assert proposal.evaluation_comparison_id == comparison.decision_id


class TestWithdrawal:
    def test_withdraw_transitions_status_and_returns_a_new_object(self) -> None:
        proposal = _propose()
        withdrawn = build_withdrawn_proposal(proposal)
        assert withdrawn.status is ProposalStatus.WITHDRAWN
        assert proposal.status is ProposalStatus.PROPOSED  # original untouched
        assert withdrawn.proposal_id == proposal.proposal_id

    def test_double_withdraw_is_rejected(self) -> None:
        proposal = _propose()
        withdrawn = build_withdrawn_proposal(proposal)
        with pytest.raises(ProposalNotWithdrawableError):
            build_withdrawn_proposal(withdrawn)


class TestReversibilityAndVersioning:
    def test_proposal_carries_version_and_rollback_reference(self) -> None:
        previous_id = uuid.uuid4()
        proposal = _propose(version=2, rollback_reference=previous_id)
        assert proposal.version == 2
        assert proposal.rollback_reference == previous_id

    def test_first_version_has_no_rollback_reference_by_default(self) -> None:
        proposal = _propose()
        assert proposal.version == 1
        assert proposal.rollback_reference is None


class TestSelfAttestationCannotSubstitute:
    """Phase 9.5's own binding instruction: "LLM self-assertion is never
    authoritative evidence"."""

    _CLAIM_SHAPED_FRAGMENTS = ("claim", "self_report", "asserted", "success_flag", "verdict")

    def test_recurrence_assessment_has_no_claim_shaped_field(self) -> None:
        field_names = {f.name for f in dataclasses.fields(RecurrenceAssessment)}
        for fragment in self._CLAIM_SHAPED_FRAGMENTS:
            assert not any(fragment in name for name in field_names)

    def test_proposal_has_no_claim_shaped_field(self) -> None:
        field_names = {f.name for f in dataclasses.fields(SystemLearningProposal)}
        for fragment in self._CLAIM_SHAPED_FRAGMENTS:
            assert not any(fragment in name for name in field_names)

    def test_confidence_is_not_a_direct_propose_parameter(self) -> None:
        """Confidence is reachable only via a `RecurrenceAssessment`
        produced by `detect_recurrence()` -- never a bare value a caller
        (or a model) can set directly on the proposal."""
        params = inspect.signature(propose_system_learning_proposal).parameters
        assert "confidence" not in params
        assert "recurrence" in params


class TestPolicyAuthorityBoundary:
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
        "approve_proposal",
        "activate_proposal",
    )

    def test_no_forbidden_policy_or_deployment_helpers_exist(self) -> None:
        public_names = {name for name in dir(sl_service) if not name.startswith("_")}
        for forbidden in self._FORBIDDEN_NAME_FRAGMENTS:
            assert forbidden not in public_names

    def test_module_never_imports_forbidden_dependencies(self) -> None:
        for module in (sl_service, sl_models, sl_errors):
            source = inspect.getsource(module)
            tree = ast.parse(source)
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported.add(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            for forbidden_prefix in (
                "core.rbac",
                "infra.secrets",
                "infra.db",
                "sqlalchemy",
                "control_plane.orchestration",
            ):
                assert forbidden_prefix not in imported, (module.__name__, forbidden_prefix)
                assert not any(m.startswith(forbidden_prefix + ".") for m in imported)
            assert "os" not in imported

    def test_no_second_audit_mechanism_only_core_audit_log_is_used(self) -> None:
        source = inspect.getsource(sl_service)
        assert "core.audit_log" in source
        assert "learning_ledger" not in source.lower()


class TestErrorsCarryNoSensitiveContent:
    def test_error_classes_do_not_reference_free_text_content_fields(self) -> None:
        for name in dir(sl_errors):
            obj = getattr(sl_errors, name)
            if isinstance(obj, type) and issubclass(obj, Exception):
                init_source = inspect.getsource(obj)
                for forbidden in (
                    "problem_description",
                    "proposed_change_description",
                    "rationale",
                ):
                    assert forbidden not in init_source
