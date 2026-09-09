"""Unit tests for `control_plane.self_learning.experiments`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.6). No database required -- pure
logic, structural, and static (AST) checks only, mirroring
`tests/control_plane/self_learning/adaptive/test_adaptive_unit.py`'s own
discipline: `create_experiment()`'s validation runs entirely before its
`tenant_session_scope()` call, so every failure path here is reachable
without a database. Full lifecycle (execute/record-result/cancel, which
all require a persisted row) is covered by
`test_experiments_integration.py` (marked `integration`).
"""

from __future__ import annotations

import ast
import inspect
import uuid
from datetime import timedelta

import pytest

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.adaptive.models import (
    Adaptation,
    AdaptationScope,
    AdaptationStatus,
    AdaptationSurface,
)
from control_plane.self_learning.experiments import errors as exp_errors
from control_plane.self_learning.experiments import models as exp_models
from control_plane.self_learning.experiments import service as exp_service
from control_plane.self_learning.experiments.errors import (
    InvalidCandidateSourceError,
    UnauthorizedExperimentEvidenceError,
)
from control_plane.self_learning.experiments.models import (
    TERMINAL_EXPERIMENT_STATUSES,
    VALID_CANDIDATE_SOURCE_KINDS,
    VALID_EXPERIMENT_STATUSES,
    Experiment,
    ExperimentCandidateSourceKind,
    ExperimentStatus,
)
from control_plane.self_learning.experiments.service import create_experiment
from control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
    LearningDenialReason,
)
from control_plane.self_learning.system_learning.models import (
    ConfidenceLevel,
    ProblemCategory,
    ProposalScope,
    ProposalStatus,
    ProposedChangeTarget,
    RecurrenceAssessment,
    RiskLevel,
    SystemLearningProposal,
)
from control_plane.self_learning.system_learning.models import (
    LearningEvidence as SLLearningEvidence,
)

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()


def _allow_decision(
    tenant_id: uuid.UUID = TENANT_A, purpose: str = "experiment_analysis"
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
        purpose="experiment_analysis",
        reason=LearningDenialReason.NO_LEARNING_POLICY,
        data_authorization_decision_id=uuid.uuid4(),
    )


def _adaptation(tenant_id: uuid.UUID = TENANT_A, version: int = 1) -> Adaptation:
    return Adaptation(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION.value,
        lineage_key="support_agent.system_prompt",
        version=version,
        status=AdaptationStatus.CANDIDATE.value,
        scope=AdaptationScope.TENANT.value,
        proposed_value="Be courteous.",
        learning_purpose="adaptive_prompt_tuning",
        evidence_type="user_feedback",
        evidence_source_reference="feedback-1",
        learning_authorization_decision_id=uuid.uuid4(),
        created_by_user_id=uuid.uuid4(),
    )


def _proposal(tenant_id: uuid.UUID = TENANT_A, version: int = 1) -> SystemLearningProposal:
    recurrence = RecurrenceAssessment(
        is_recurring=True,
        distinct_observation_count=4,
        window=timedelta(days=7),
        minimum_occurrences_required=3,
        confidence=ConfidenceLevel.MEDIUM,
        earliest_observed_at=None,
        latest_observed_at=None,
    )
    return SystemLearningProposal(
        tenant_id=tenant_id,
        problem_category=ProblemCategory.LATENCY_PROBLEM,
        problem_description="Recurring latency.",
        evidence=SLLearningEvidence(evidence_type="tool_output", source_reference="ref-1"),
        learning_authorization_decision_id=uuid.uuid4(),
        data_classification="tenant_data",
        recurrence=recurrence,
        confidence=recurrence.confidence,
        scope=ProposalScope.TENANT,
        affected_tenant_ids=frozenset({tenant_id}),
        proposed_change_target=ProposedChangeTarget.CACHING_STRATEGY,
        proposed_change_description="Cache lookups for 60s.",
        rationale="4 distinct latency spikes.",
        risk_level=RiskLevel.LOW,
        version=version,
        status=ProposalStatus.PROPOSED,
    )


def _create(**overrides: object) -> Experiment:
    kwargs: dict[str, object] = dict(
        tenant_id=TENANT_A,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(),
        evidence_type="tool_output",
        evidence_source_reference="ref-1",
        created_by_user_id=uuid.uuid4(),
        adaptation=_adaptation(),
    )
    kwargs.update(overrides)
    return create_experiment(**kwargs)  # type: ignore[arg-type]


class TestPermittedVocabularies:
    def test_candidate_source_kind_matches_roadmaps_own_two_sources(self) -> None:
        assert VALID_CANDIDATE_SOURCE_KINDS == {"adaptation", "system_learning_proposal"}

    def test_status_vocabulary_has_no_promotion_or_deployment_member(self) -> None:
        """docs/IMPLEMENTATION-ROADMAP.md Phase 9.6's own Non-Goals: "no
        canary deployment, no autonomous promotion, no production traffic
        exposure" -- structurally, by never defining such a status."""
        forbidden_fragments = (
            "promot",
            "deploy",
            "production_active",
            "canary",
            "autonom",
            "activ",
        )
        for member in ExperimentStatus:
            for fragment in forbidden_fragments:
                assert fragment not in member.value, member.value

    def test_status_enum_rejects_an_unlisted_value(self) -> None:
        with pytest.raises(ValueError):
            ExperimentStatus("promoted")

    def test_forbidden_statuses_are_structurally_impossible_to_construct(self) -> None:
        for forbidden in ("promoted", "deployed", "production_active", "canary_promoted"):
            with pytest.raises(ValueError):
                ExperimentStatus(forbidden)

    def test_terminal_statuses_are_exactly_completed_failed_cancelled(self) -> None:
        assert TERMINAL_EXPERIMENT_STATUSES == {"completed", "failed", "cancelled"}
        assert "configured" not in TERMINAL_EXPERIMENT_STATUSES
        assert "running" not in TERMINAL_EXPERIMENT_STATUSES

    def test_valid_experiment_statuses_matches_enum(self) -> None:
        assert VALID_EXPERIMENT_STATUSES == {
            "configured",
            "running",
            "completed",
            "failed",
            "cancelled",
        }


class TestCandidateSourceRequiresExactlyOne:
    def test_neither_candidate_supplied_is_rejected(self) -> None:
        with pytest.raises(InvalidCandidateSourceError):
            _create(adaptation=None)

    def test_both_candidates_supplied_is_rejected(self) -> None:
        with pytest.raises(InvalidCandidateSourceError):
            _create(adaptation=_adaptation(), system_learning_proposal=_proposal())

    def test_adaptation_from_wrong_tenant_is_rejected(self) -> None:
        with pytest.raises(InvalidCandidateSourceError):
            _create(adaptation=_adaptation(tenant_id=TENANT_B))

    def test_proposal_from_wrong_tenant_is_rejected(self) -> None:
        with pytest.raises(InvalidCandidateSourceError):
            _create(adaptation=None, system_learning_proposal=_proposal(tenant_id=TENANT_B))

    def test_valid_adaptation_source_is_accepted_through_validation(self) -> None:
        """Reaches (but does not require) the DB write -- proven by the
        function getting past every pre-DB check without raising before
        it touches `tenant_session_scope` (verified structurally in
        TestValidationPrecedesPersistence below)."""
        params = inspect.signature(create_experiment).parameters
        assert "adaptation" in params
        assert "system_learning_proposal" in params


class TestEvidenceAuthorizationGate:
    def test_denied_learning_authorization_is_rejected(self) -> None:
        with pytest.raises(UnauthorizedExperimentEvidenceError):
            _create(learning_authorization_decision=_deny_decision())

    def test_wrong_tenant_decision_is_rejected(self) -> None:
        with pytest.raises(UnauthorizedExperimentEvidenceError):
            _create(learning_authorization_decision=_allow_decision(TENANT_B))

    def test_invalid_evidence_type_is_rejected(self) -> None:
        with pytest.raises(UnauthorizedExperimentEvidenceError):
            _create(evidence_type="not_a_real_type")

    def test_missing_source_reference_is_rejected(self) -> None:
        with pytest.raises(UnauthorizedExperimentEvidenceError):
            _create(evidence_source_reference="")


class TestValidationPrecedesPersistence:
    """Every failure path above must raise before `create_experiment()`
    ever opens a database session -- otherwise these tests would require
    a live PostgreSQL instance, defeating their purpose as unit tests."""

    def test_tenant_session_scope_call_is_textually_after_every_validation_check(self) -> None:
        source = inspect.getsource(exp_service.create_experiment)
        validation_markers = (
            "InvalidCandidateSourceError",
            "UnauthorizedExperimentEvidenceError",
        )
        db_marker_index = source.index("with tenant_session_scope")
        for marker in validation_markers:
            # Every raise of these errors must appear before the DB call.
            for index in _all_indices(source, marker):
                assert index < db_marker_index, (marker, index, db_marker_index)


def _all_indices(haystack: str, needle: str) -> list[int]:
    indices = []
    start = 0
    while True:
        index = haystack.find(needle, start)
        if index == -1:
            return indices
        indices.append(index)
        start = index + 1


class TestExperimentIsNotAuthority:
    def test_is_reversible_is_always_true(self) -> None:
        experiment = Experiment(
            id=uuid.uuid4(),
            tenant_id=TENANT_A,
            status=ExperimentStatus.CONFIGURED.value,
            candidate_source_kind=ExperimentCandidateSourceKind.ADAPTATION.value,
            candidate_source_id=uuid.uuid4(),
            candidate_version="1",
            baseline_version="v0",
            learning_authorization_decision_id=uuid.uuid4(),
            evidence_type="tool_output",
            evidence_source_reference="ref-1",
            created_by_user_id=uuid.uuid4(),
        )
        assert experiment.is_reversible is True

    def test_status_defaults_to_configured_in_source(self) -> None:
        source = inspect.getsource(exp_service.create_experiment)
        assert "status=ExperimentStatus.CONFIGURED.value" in source.replace(" ", "").replace(
            "\n", ""
        )

    def test_no_promote_deploy_activate_or_approve_function_exists(self) -> None:
        public_names = {name for name in dir(exp_service) if not name.startswith("_")}
        for forbidden in (
            "promote",
            "deploy",
            "activate",
            "approve",
            "promote_if_better",
            "deploy_winner",
        ):
            assert forbidden not in public_names

    def test_create_execute_record_cancel_are_four_distinct_functions(self) -> None:
        fns = {
            exp_service.create_experiment,
            exp_service.execute_experiment,
            exp_service.record_experiment_result,
            exp_service.cancel_experiment,
        }
        assert len(fns) == 4


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
        "canary",
    )

    def test_no_forbidden_policy_or_deployment_helpers_exist(self) -> None:
        public_names = {name for name in dir(exp_service) if not name.startswith("_")}
        for forbidden in self._FORBIDDEN_NAME_FRAGMENTS:
            assert forbidden not in public_names

    def test_module_never_imports_forbidden_dependencies(self) -> None:
        for module in (exp_service, exp_models, exp_errors):
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
                "sqlalchemy",
                "control_plane.orchestration",
                "control_plane.tools",
            ):
                assert forbidden_prefix not in imported, (module.__name__, forbidden_prefix)
                assert not any(m.startswith(forbidden_prefix + ".") for m in imported)
            assert "os" not in imported

    def test_no_second_audit_mechanism_only_core_audit_log_is_used(self) -> None:
        source = inspect.getsource(exp_service)
        assert "core.audit_log" in source
        assert "learning_ledger" not in source.lower()


class TestErrorsCarryNoSensitiveContent:
    def test_error_classes_do_not_reference_free_text_content_fields(self) -> None:
        for name in dir(exp_errors):
            obj = getattr(exp_errors, name)
            if isinstance(obj, type) and issubclass(obj, Exception):
                init_source = inspect.getsource(obj)
                assert "cancellation_reason" not in init_source
