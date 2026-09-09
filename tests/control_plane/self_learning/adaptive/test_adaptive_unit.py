"""Unit tests for `control_plane.self_learning.adaptive` (docs/IMPLEMENTATION-ROADMAP.md
Phase 9.4). No database required -- pure logic, structural, and static
(AST) checks only. State-machine behavior against real persistence is
covered by `test_adaptive_integration.py` (marked `integration`).
"""

from __future__ import annotations

import ast
import inspect
import uuid

import pytest

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.adaptive import errors as adaptive_errors
from control_plane.self_learning.adaptive import models as adaptive_models
from control_plane.self_learning.adaptive import service as adaptive_service
from control_plane.self_learning.adaptive.errors import (
    PlatformWideScopeNotAuthorizedError,
    UnauthorizedAdaptationEvidenceError,
)
from control_plane.self_learning.adaptive.models import (
    VALID_ADAPTATION_EVIDENCE_TYPES,
    VALID_ADAPTATION_SURFACES,
    Adaptation,
    AdaptationScope,
    AdaptationStatus,
    AdaptationSurface,
    PlatformWideAdaptationAuthorization,
)
from control_plane.self_learning.adaptive.service import propose_adaptation
from control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)
from control_plane.tools.activate_adaptation import build_activate_adaptation_tool
from control_plane.tools.rollback_adaptation import build_rollback_adaptation_tool

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()


def _allow_decision(tenant_id: uuid.UUID = TENANT_A) -> LearningAuthorizationDecision:
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


def _deny_decision(tenant_id: uuid.UUID = TENANT_A) -> LearningAuthorizationDecision:
    from control_plane.self_learning.models import LearningDenialReason

    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.DENY,
        tenant_id=tenant_id,
        purpose="adaptive_prompt_tuning",
        reason=LearningDenialReason.NO_LEARNING_POLICY,
        data_authorization_decision_id=uuid.uuid4(),
    )


class TestPermittedAdaptationVocabulary:
    def test_allowlist_matches_roadmaps_own_seven_surfaces(self) -> None:
        assert VALID_ADAPTATION_SURFACES == {
            "prompt_instruction",
            "model_selection",
            "routing_strategy",
            "tool_selection_strategy",
            "retrieval_strategy",
            "response_strategy",
            "personalization",
        }

    def test_no_security_rbac_secrets_or_autonomy_surface_exists(self) -> None:
        """docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own instruction:
        reject targets such as security.*/rbac.*/permissions.*/secrets.*/
        autonomy.*/tenant_isolation.*/audit_policy.* -- structurally, by
        never defining such a member, not merely by a runtime check."""
        forbidden_fragments = (
            "security",
            "rbac",
            "permission",
            "secret",
            "autonomy",
            "tenant_isolation",
            "audit_policy",
            "deploy",
        )
        for member in AdaptationSurface:
            for fragment in forbidden_fragments:
                assert fragment not in member.value, member.value

    def test_enum_cannot_be_constructed_with_an_unlisted_value(self) -> None:
        with pytest.raises(ValueError):
            AdaptationSurface("security.rbac_grant")


class TestEvidenceRestrictedToFeedback:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Objective, verbatim:
    "driven by explicit feedback and operator corrections only"."""

    def test_only_feedback_and_operator_correction_are_valid(self) -> None:
        assert VALID_ADAPTATION_EVIDENCE_TYPES == {"user_feedback", "operator_feedback"}

    def test_broader_phase_9_2_evidence_types_are_not_all_valid_here(self) -> None:
        """Phase 9.2's own `VALID_EVIDENCE_TYPES` is a strict superset --
        tool_output/model_generated_content/external_content/
        imported_learning_material/evaluation_input must NOT be valid L1
        adaptation evidence."""
        from control_plane.self_learning.models import VALID_EVIDENCE_TYPES

        assert VALID_ADAPTATION_EVIDENCE_TYPES < VALID_EVIDENCE_TYPES
        for excluded in VALID_EVIDENCE_TYPES - VALID_ADAPTATION_EVIDENCE_TYPES:
            assert excluded in {
                "tool_output",
                "model_generated_content",
                "external_content",
                "imported_learning_material",
                "evaluation_input",
            }

    def test_propose_adaptation_rejects_tool_output_evidence(self) -> None:
        with pytest.raises(UnauthorizedAdaptationEvidenceError):
            propose_adaptation(
                tenant_id=TENANT_A,
                surface=AdaptationSurface.PROMPT_INSTRUCTION,
                lineage_key="support_agent.system_prompt",
                proposed_value="Be extra courteous.",
                learning_purpose="adaptive_prompt_tuning",
                learning_authorization_decision=_allow_decision(),
                evidence_type="tool_output",  # type: ignore[arg-type]
                evidence_source_reference="tool-run-1",
                created_by_user_id=uuid.uuid4(),
            )


class TestAuthorizationGateComposition:
    def test_propose_adaptation_rejects_denied_learning_authorization(self) -> None:
        with pytest.raises(UnauthorizedAdaptationEvidenceError):
            propose_adaptation(
                tenant_id=TENANT_A,
                surface=AdaptationSurface.PROMPT_INSTRUCTION,
                lineage_key="support_agent.system_prompt",
                proposed_value="Be extra courteous.",
                learning_purpose="adaptive_prompt_tuning",
                learning_authorization_decision=_deny_decision(),
                evidence_type="user_feedback",
                evidence_source_reference="feedback-1",
                created_by_user_id=uuid.uuid4(),
            )

    def test_propose_adaptation_rejects_wrong_tenant_decision(self) -> None:
        with pytest.raises(UnauthorizedAdaptationEvidenceError):
            propose_adaptation(
                tenant_id=TENANT_A,
                surface=AdaptationSurface.PROMPT_INSTRUCTION,
                lineage_key="support_agent.system_prompt",
                proposed_value="Be extra courteous.",
                learning_purpose="adaptive_prompt_tuning",
                learning_authorization_decision=_allow_decision(TENANT_B),
                evidence_type="user_feedback",
                evidence_source_reference="feedback-1",
                created_by_user_id=uuid.uuid4(),
            )

    def test_proposal_requires_a_learning_authorization_decision_argument(self) -> None:
        params = inspect.signature(propose_adaptation).parameters
        assert "learning_authorization_decision" in params
        assert params["learning_authorization_decision"].default is inspect.Parameter.empty


class TestPlatformWideScopeRequiresExplicitAuthorization:
    def test_platform_wide_without_authorization_is_rejected(self) -> None:
        with pytest.raises(PlatformWideScopeNotAuthorizedError):
            propose_adaptation(
                tenant_id=TENANT_A,
                surface=AdaptationSurface.PROMPT_INSTRUCTION,
                lineage_key="support_agent.system_prompt",
                proposed_value="Be extra courteous.",
                learning_purpose="adaptive_prompt_tuning",
                learning_authorization_decision=_allow_decision(),
                evidence_type="user_feedback",
                evidence_source_reference="feedback-1",
                created_by_user_id=uuid.uuid4(),
                scope=AdaptationScope.PLATFORM_WIDE,
                platform_wide_authorization=None,
            )

    def test_platform_wide_with_wrong_purpose_authorization_is_rejected(self) -> None:
        wrong_purpose_auth = PlatformWideAdaptationAuthorization(
            authorized_purposes=frozenset({"a_different_purpose"})
        )
        with pytest.raises(PlatformWideScopeNotAuthorizedError):
            propose_adaptation(
                tenant_id=TENANT_A,
                surface=AdaptationSurface.PROMPT_INSTRUCTION,
                lineage_key="support_agent.system_prompt",
                proposed_value="Be extra courteous.",
                learning_purpose="adaptive_prompt_tuning",
                learning_authorization_decision=_allow_decision(),
                evidence_type="user_feedback",
                evidence_source_reference="feedback-1",
                created_by_user_id=uuid.uuid4(),
                scope=AdaptationScope.PLATFORM_WIDE,
                platform_wide_authorization=wrong_purpose_auth,
            )


class TestProposalIsNotApprovalOrDeployment:
    def test_status_field_exists_and_defaults_semantics_are_candidate_first(self) -> None:
        """A freshly-proposed adaptation is `CANDIDATE`, never `ACTIVE` --
        structural proof that `propose_adaptation()` has no path to mark
        its own output as already in effect."""
        source = inspect.getsource(adaptive_service.propose_adaptation)
        assert "status=AdaptationStatus.CANDIDATE.value" in source.replace(" ", "").replace(
            "\n", ""
        )

    def test_activation_and_rollback_are_separate_functions_from_proposal(self) -> None:
        assert adaptive_service.propose_adaptation is not adaptive_service.activate_adaptation
        assert adaptive_service.propose_adaptation is not adaptive_service.rollback_adaptation


class TestVersioningAndReversibility:
    def test_adaptation_status_enum_models_the_full_reversible_lifecycle(self) -> None:
        assert {s.value for s in AdaptationStatus} == {
            "candidate",
            "active",
            "superseded",
            "rolled_back",
        }

    def test_adaptation_carries_previous_version_pointer(self) -> None:
        column_names = set(Adaptation.__mapper__.columns.keys())
        assert "previous_adaptation_id" in column_names
        assert "version" in column_names


class TestToolWiringIsTierOneOnly:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 9.4's own Dependencies: "7.2
    ...for anything above autonomy tier 0" -- activation/rollback must be
    unreachable except through control_plane.approvals."""

    def test_activate_adaptation_tool_is_tier_1(self) -> None:
        tool = build_activate_adaptation_tool()
        assert tool.autonomy_tier == 1
        assert tool.required_scope_type == "tenant"
        assert tool.required_resource
        assert tool.required_action

    def test_rollback_adaptation_tool_is_tier_1(self) -> None:
        tool = build_rollback_adaptation_tool()
        assert tool.autonomy_tier == 1
        assert tool.required_scope_type == "tenant"

    def test_neither_tool_targets_a_forbidden_rbac_secrets_or_deploy_action(self) -> None:
        for tool in (build_activate_adaptation_tool(), build_rollback_adaptation_tool()):
            for forbidden in ("rbac", "secret", "security", "autonomy", "deploy"):
                assert forbidden not in tool.required_resource.lower()  # type: ignore[union-attr]
                assert forbidden not in tool.required_action.lower()  # type: ignore[union-attr]


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
    )

    def test_no_forbidden_policy_or_deployment_helpers_exist(self) -> None:
        public_names = {name for name in dir(adaptive_service) if not name.startswith("_")}
        for forbidden in self._FORBIDDEN_NAME_FRAGMENTS:
            assert forbidden not in public_names

    def test_module_never_imports_core_rbac_infra_secrets_or_os(self) -> None:
        for module in (adaptive_service, adaptive_models):
            source = inspect.getsource(module)
            tree = ast.parse(source)
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported.add(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            assert "core.rbac" not in imported
            assert not any(m.startswith("core.rbac.") for m in imported)
            assert "infra.secrets" not in imported
            assert not any(m.startswith("infra.secrets.") for m in imported)
            assert "os" not in imported

    def test_no_second_audit_mechanism_only_core_audit_log_is_used(self) -> None:
        source = inspect.getsource(adaptive_service)
        assert "core.audit_log" in source
        assert "learning_ledger" not in source.lower()


class TestEvaluationRemainsSeparateFromApproval:
    def test_record_adaptation_evaluation_never_changes_status(self) -> None:
        source = inspect.getsource(adaptive_service.record_adaptation_evaluation)
        assert ".status =" not in source.replace(" ", "")

    def test_evaluation_outcome_column_mirrors_phase_9_3_vocabulary(self) -> None:
        from control_plane.self_learning.evaluation.models import EvaluationOutcome

        expected = {o.value for o in EvaluationOutcome}
        source = inspect.getsource(adaptive_models)
        for value in expected:
            assert value in source


class TestErrorsCarryNoSensitiveContent:
    def test_error_classes_do_not_reference_evidence_content_fields(self) -> None:
        for name in dir(adaptive_errors):
            obj = getattr(adaptive_errors, name)
            if isinstance(obj, type) and issubclass(obj, Exception):
                init_source = inspect.getsource(obj)
                assert "proposed_value" not in init_source
