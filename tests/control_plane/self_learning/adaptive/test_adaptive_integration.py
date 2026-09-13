"""Integration tests for `control_plane.self_learning.adaptive` against a
real PostgreSQL instance (docs/IMPLEMENTATION-ROADMAP.md Phase 9.4).

Covers: the full propose -> evaluate -> activate (tier-1, through
`control_plane.approvals`) -> rollback lifecycle; every one of the three
roadmap-named `core.audit_log` events; the "adaptation candidates are
evaluated before taking effect" security requirement; and a dedicated
cross-tenant adversarial check against the real `self_learning.adaptations`
table (the first persisted tenant-owned Self-Learning data -- Phase 9.2
and 9.3 introduced none).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/self_learning/adaptive/test_adaptive_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_user, get_membership
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.secrets.config import get_secrets_provider
from sqlalchemy import text

from control_plane.approvals.service import approve, execute_approved, propose_action
from control_plane.data_authorization import (
    DataAuthorizationRequest,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    authorize_data_access,
)
from control_plane.orchestration.tools import ToolRegistry
from control_plane.self_learning import (
    LearningAuthorizationRequest,
    LearningEvidence,
    TenantLearningPolicy,
    authorize_learning_use,
)
from control_plane.self_learning.adaptive.errors import (
    AdaptationNotActiveError,
    AdaptationNotCandidateError,
    AdaptationNotEvaluatedError,
    NoPreviousVersionError,
    UnauthorizedAdaptationEvidenceError,
)
from control_plane.self_learning.adaptive.models import (
    Adaptation,
    AdaptationStatus,
    AdaptationSurface,
)
from control_plane.self_learning.adaptive.service import (
    activate_adaptation,
    propose_adaptation,
    record_adaptation_evaluation,
    rollback_adaptation,
)
from control_plane.self_learning.evaluation.errors import EvaluationProvenanceError
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationInvalidReason,
    EvaluationMetrics,
    EvaluationOutcome,
    EvaluationRules,
    EvaluationSubjectKind,
    EvaluationSubjectResult,
    MetricDirection,
    MetricThreshold,
)
from control_plane.self_learning.evaluation.service import run_evaluation
from control_plane.self_learning.models import LearningAuthorizationDecision
from control_plane.tools.activate_adaptation import (
    REQUIRED_ACTION as ACTIVATE_ACTION,
)
from control_plane.tools.activate_adaptation import (
    REQUIRED_RESOURCE as ADAPTATION_RESOURCE,
)
from control_plane.tools.activate_adaptation import (
    TOOL_KEY as ACTIVATE_TOOL_KEY,
)
from control_plane.tools.activate_adaptation import build_activate_adaptation_tool
from control_plane.tools.rollback_adaptation import (
    REQUIRED_ACTION as ROLLBACK_ACTION,
)
from control_plane.tools.rollback_adaptation import (
    TOOL_KEY as ROLLBACK_TOOL_KEY,
)
from control_plane.tools.rollback_adaptation import build_rollback_adaptation_tool
from core.tenancy import create_tenant

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM self_learning.adaptations LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/self_learning.adaptations not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture(autouse=True)
def _environment_secrets_provider(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_secrets_provider.cache_clear()
    yield
    get_secrets_provider.cache_clear()


def _admin_delete_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM self_learning.adaptations WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM control_plane.approval_requests WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _allow_decision(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> LearningAuthorizationDecision:
    """CP-02 (Phase J, third pass): `propose_adaptation()` now requires a
    genuine, matching `core.audit_log` provenance record for the
    `LearningAuthorizationDecision` it is given (see
    `control_plane.self_learning.service.verify_learning_authorization_provenance()`).
    A hand-built decision object (this helper's own previous
    implementation) is no longer sufficient -- it must be produced by the
    real `authorize_data_access()` -> `authorize_learning_use()` chain, so
    every ALLOW decision this fixture hands out is one the platform's own
    audited evaluators actually wrote to `core.audit_log`."""
    data_decision = authorize_data_access(
        DataAuthorizationRequest(
            tenant_id=tenant_id,
            data_classification="tenant_data",
            purpose="adaptive_prompt_tuning",
            provider="anthropic",
            resource_type="self_learning_adaptation_fixture",
            resource_id="fixture",
        ),
        tenant_policy=TenantAIDataPolicy(
            tenant_id=tenant_id,
            allowed_data_classifications=frozenset({"tenant_data"}),
            allowed_purposes=frozenset({"adaptive_prompt_tuning"}),
            allowed_providers=frozenset({"anthropic"}),
        ),
        provider_policy=ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"})),
        actor_user_id=actor_user_id,
    )
    return authorize_learning_use(
        LearningAuthorizationRequest(
            tenant_id=tenant_id,
            purpose="adaptive_prompt_tuning",
            target_model_or_provider="anthropic",
            retention="30d",
            evidence=LearningEvidence(
                evidence_type="user_feedback", source_reference="fixture-evidence"
            ),
        ),
        data_authorization_decision=data_decision,
        tenant_learning_policy=TenantLearningPolicy(
            tenant_id=tenant_id,
            allowed_purposes=frozenset({"adaptive_prompt_tuning"}),
            allowed_models_or_providers=frozenset({"anthropic"}),
            allowed_retentions=frozenset({"30d"}),
        ),
        actor_user_id=actor_user_id,
    )


_EVAL_RULES = EvaluationRules(
    thresholds=(
        MetricThreshold(
            metric_name="task_success_rate",
            direction=MetricDirection.HIGHER_IS_BETTER,
            minimum_absolute=0.5,
        ),
    )
)


def _pass_comparison(tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID) -> EvaluationComparison:
    """CP-04 (Phase J audit): `record_adaptation_evaluation()` now
    requires genuine `evaluation.service.verify_evaluation_provenance()`
    -- a hand-built `EvaluationComparison` (this helper's own previous
    implementation) is no longer sufficient. Produced by the real
    `run_evaluation()` so its `learning.evaluation_run` audit trail is
    genuine, exactly like `_allow_decision()` above was fixed for CP-02."""
    benchmark = Benchmark(benchmark_id="adaptive-fixture-benchmark", version="1")
    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version="v0",
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.8),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="v1",
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    comparison = run_evaluation(baseline, candidate, _EVAL_RULES, actor_user_id=actor_user_id)
    assert comparison.outcome is EvaluationOutcome.PASS
    return comparison


def _fail_comparison(tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID) -> EvaluationComparison:
    """Genuine `INVALID`/`BENCHMARK_MISMATCH` -- same shape the previous
    hand-built version claimed, now actually produced by
    `run_evaluation()` (CP-04)."""
    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version="v0",
        tenant_id=tenant_id,
        benchmark=Benchmark(benchmark_id="adaptive-fixture-benchmark", version="1"),
        metrics=EvaluationMetrics(task_success_rate=0.8),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="v1",
        tenant_id=tenant_id,
        benchmark=Benchmark(benchmark_id="adaptive-fixture-benchmark", version="2"),
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    comparison = run_evaluation(baseline, candidate, _EVAL_RULES, actor_user_id=actor_user_id)
    assert comparison.outcome is EvaluationOutcome.INVALID
    assert comparison.invalid_reason is EvaluationInvalidReason.BENCHMARK_MISMATCH
    return comparison


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique("adaptive-tenant"))
        self.agent = create_user()
        self.approver = create_user()
        add_tenant_membership(self.tenant.id, self.agent.id)
        add_tenant_membership(self.tenant.id, self.approver.id)

        role = create_role(self.tenant.id, _unique("adaptation-operator"))
        activate_permission = register_permission(ADAPTATION_RESOURCE, ACTIVATE_ACTION)
        rollback_permission = register_permission(ADAPTATION_RESOURCE, ROLLBACK_ACTION)
        grant_permission(self.tenant.id, role.id, activate_permission.id)
        grant_permission(self.tenant.id, role.id, rollback_permission.id)

        membership = get_membership(self.tenant.id, self.agent.id)
        assert membership is not None
        assign_first_role_for_new_tenant(self.tenant.id, membership.id, role.id)

        self.registry = ToolRegistry()
        self.registry.register(build_activate_adaptation_tool())
        self.registry.register(build_rollback_adaptation_tool())

    def cleanup(self) -> None:
        _admin_delete_for_tenant(self.tenant.id)
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.membership_roles WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.role_permissions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(self.tenant.id)}
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id IN (:a, :b)"),
                {"a": str(self.agent.id), "b": str(self.approver.id)},
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


async def _activate_through_approvals(fx: _Fixture, adaptation_id: uuid.UUID) -> None:
    approval = propose_action(
        fx.tenant.id, fx.agent.id, ACTIVATE_TOOL_KEY, payload={"adaptation_id": str(adaptation_id)}
    )
    approve(fx.tenant.id, approval.id, fx.approver.id)
    await execute_approved(fx.tenant.id, approval.id, registry=fx.registry)


async def _rollback_through_approvals(fx: _Fixture, adaptation_id: uuid.UUID) -> None:
    approval = propose_action(
        fx.tenant.id, fx.agent.id, ROLLBACK_TOOL_KEY, payload={"adaptation_id": str(adaptation_id)}
    )
    approve(fx.tenant.id, approval.id, fx.approver.id)
    await execute_approved(fx.tenant.id, approval.id, registry=fx.registry)


async def test_full_lifecycle_propose_evaluate_activate_rollback_is_audited(fx: _Fixture) -> None:
    decision = _allow_decision(fx.tenant.id, actor_user_id=fx.agent.id)

    v1 = propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key="support_agent.system_prompt",
        proposed_value="Be courteous and concise.",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=decision,
        evidence_type="operator_feedback",
        evidence_source_reference="correction-1",
        created_by_user_id=fx.agent.id,
    )
    assert v1.status == AdaptationStatus.CANDIDATE.value
    assert v1.version == 1

    record_adaptation_evaluation(
        fx.tenant.id, v1.id, _pass_comparison(fx.tenant.id, actor_user_id=fx.agent.id)
    )
    await _activate_through_approvals(fx, v1.id)

    entries = list_audit_entries(fx.tenant.id)
    created_events = [e for e in entries if e.action == "learning.adaptation_created"]
    activated_events = [e for e in entries if e.action == "learning.adaptation_activated"]
    assert len(created_events) == 1
    assert len(activated_events) == 1
    assert activated_events[0].outcome == "success"
    assert activated_events[0].resource_id == str(v1.id)

    # A second candidate for the same lineage, evaluated and activated,
    # must supersede v1.
    v2 = propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key="support_agent.system_prompt",
        proposed_value="Be courteous, concise, and proactive.",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=decision,
        evidence_type="user_feedback",
        evidence_source_reference="feedback-2",
        created_by_user_id=fx.agent.id,
    )
    assert v2.version == 2
    assert v2.previous_adaptation_id == v1.id

    record_adaptation_evaluation(
        fx.tenant.id, v2.id, _pass_comparison(fx.tenant.id, actor_user_id=fx.agent.id)
    )
    await _activate_through_approvals(fx, v2.id)

    with tenant_session_scope(fx.tenant.id) as session:
        refreshed_v1 = session.get(Adaptation, v1.id)
        refreshed_v2 = session.get(Adaptation, v2.id)
        assert refreshed_v1 is not None
        assert refreshed_v2 is not None
        assert refreshed_v1.status == AdaptationStatus.SUPERSEDED.value
        assert refreshed_v2.status == AdaptationStatus.ACTIVE.value

    # Roll v2 back -- v1 must become active again.
    await _rollback_through_approvals(fx, v2.id)

    with tenant_session_scope(fx.tenant.id) as session:
        refreshed_v1 = session.get(Adaptation, v1.id)
        refreshed_v2 = session.get(Adaptation, v2.id)
        assert refreshed_v1 is not None
        assert refreshed_v2 is not None
        assert refreshed_v1.status == AdaptationStatus.ACTIVE.value
        assert refreshed_v2.status == AdaptationStatus.ROLLED_BACK.value

    entries = list_audit_entries(fx.tenant.id)
    rolled_back_events = [e for e in entries if e.action == "learning.adaptation_rolled_back"]
    assert len(rolled_back_events) == 1
    assert rolled_back_events[0].resource_id == str(v2.id)
    assert rolled_back_events[0].entry_metadata is not None
    assert rolled_back_events[0].entry_metadata["reactivated_adaptation_id"] == str(v1.id)


def test_activation_without_evaluation_is_rejected(fx: _Fixture) -> None:
    v1 = propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.RESPONSE_STRATEGY,
        lineage_key="support_agent.response_strategy",
        proposed_value="prefer-bullet-points",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(fx.tenant.id, actor_user_id=fx.agent.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-3",
        created_by_user_id=fx.agent.id,
    )
    with pytest.raises(AdaptationNotEvaluatedError):
        activate_adaptation(fx.tenant.id, v1.id, activated_by_user_id=fx.agent.id)


def test_activation_after_failed_evaluation_is_rejected(fx: _Fixture) -> None:
    v1 = propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.RESPONSE_STRATEGY,
        lineage_key="support_agent.response_strategy",
        proposed_value="prefer-bullet-points",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(fx.tenant.id, actor_user_id=fx.agent.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-3",
        created_by_user_id=fx.agent.id,
    )
    record_adaptation_evaluation(
        fx.tenant.id, v1.id, _fail_comparison(fx.tenant.id, actor_user_id=fx.agent.id)
    )
    with pytest.raises(AdaptationNotEvaluatedError):
        activate_adaptation(fx.tenant.id, v1.id, activated_by_user_id=fx.agent.id)


def test_double_activation_is_rejected(fx: _Fixture) -> None:
    v1 = propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.ROUTING_STRATEGY,
        lineage_key="support_agent.routing",
        proposed_value="route-to-tier-2",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(fx.tenant.id, actor_user_id=fx.agent.id),
        evidence_type="operator_feedback",
        evidence_source_reference="correction-4",
        created_by_user_id=fx.agent.id,
    )
    record_adaptation_evaluation(
        fx.tenant.id, v1.id, _pass_comparison(fx.tenant.id, actor_user_id=fx.agent.id)
    )
    activate_adaptation(fx.tenant.id, v1.id, activated_by_user_id=fx.agent.id)
    with pytest.raises(AdaptationNotCandidateError):
        activate_adaptation(fx.tenant.id, v1.id, activated_by_user_id=fx.agent.id)


def test_rollback_without_active_status_is_rejected(fx: _Fixture) -> None:
    v1 = propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.MODEL_SELECTION,
        lineage_key="support_agent.model",
        proposed_value="claude-sonnet-5",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(fx.tenant.id, actor_user_id=fx.agent.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-5",
        created_by_user_id=fx.agent.id,
    )
    with pytest.raises(AdaptationNotActiveError):
        rollback_adaptation(fx.tenant.id, v1.id, rolled_back_by_user_id=fx.agent.id)


def test_rollback_of_first_version_has_no_previous(fx: _Fixture) -> None:
    v1 = propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.TOOL_SELECTION_STRATEGY,
        lineage_key="support_agent.tool_selection",
        proposed_value="prefer-search-tool",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(fx.tenant.id, actor_user_id=fx.agent.id),
        evidence_type="operator_feedback",
        evidence_source_reference="correction-6",
        created_by_user_id=fx.agent.id,
    )
    record_adaptation_evaluation(
        fx.tenant.id, v1.id, _pass_comparison(fx.tenant.id, actor_user_id=fx.agent.id)
    )
    activate_adaptation(fx.tenant.id, v1.id, activated_by_user_id=fx.agent.id)
    with pytest.raises(NoPreviousVersionError):
        rollback_adaptation(fx.tenant.id, v1.id, rolled_back_by_user_id=fx.agent.id)


async def test_activation_without_approval_is_rejected(fx: _Fixture) -> None:
    """Tier-1 enforcement: direct invocation (bypassing
    control_plane.approvals) must be refused by
    control_plane.orchestration itself."""
    from control_plane.orchestration.errors import TierRequiresApprovalError
    from control_plane.orchestration.service import invoke_tool

    v1 = propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.PERSONALIZATION,
        lineage_key="support_agent.personalization",
        proposed_value="greet-by-first-name",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(fx.tenant.id, actor_user_id=fx.agent.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-7",
        created_by_user_id=fx.agent.id,
    )
    record_adaptation_evaluation(
        fx.tenant.id, v1.id, _pass_comparison(fx.tenant.id, actor_user_id=fx.agent.id)
    )

    with pytest.raises(TierRequiresApprovalError):
        await invoke_tool(
            ACTIVATE_TOOL_KEY,
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"adaptation_id": str(v1.id)},
            registry=fx.registry,
        )


class TestCrossTenantAdversarial:
    """The first persisted tenant-owned Self-Learning data (Phase 9.2/9.3
    introduced none) -- a dedicated adversarial check against the real
    table, mirroring tests/core/tenancy/test_tenant_isolation_integration.py's
    own discipline."""

    def test_force_row_level_security_is_enabled_on_adaptations(self, fx: _Fixture) -> None:
        engine = build_engine(get_migrations_database_config())
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                        "WHERE oid = 'self_learning.adaptations'::regclass"
                    )
                ).one()
                assert row.relrowsecurity is True
                assert row.relforcerowsecurity is True
        finally:
            engine.dispose()

    def test_tenant_b_cannot_see_tenant_as_adaptation(self, fx: _Fixture) -> None:
        tenant_b = create_tenant(_unique("adaptive-tenant-b"))
        try:
            v1 = propose_adaptation(
                tenant_id=fx.tenant.id,
                surface=AdaptationSurface.PROMPT_INSTRUCTION,
                lineage_key="support_agent.system_prompt",
                proposed_value="Be courteous.",
                learning_purpose="adaptive_prompt_tuning",
                learning_authorization_decision=_allow_decision(
                    fx.tenant.id, actor_user_id=fx.agent.id
                ),
                evidence_type="user_feedback",
                evidence_source_reference="feedback-8",
                created_by_user_id=fx.agent.id,
            )

            with tenant_session_scope(tenant_b.id) as session:
                leaked = session.get(Adaptation, v1.id)
                assert leaked is None

            with tenant_session_scope(tenant_b.id) as session:
                from sqlalchemy import select as sa_select

                rows = session.execute(sa_select(Adaptation)).scalars().all()
                assert v1.id not in {r.id for r in rows}
        finally:
            _admin_delete_for_tenant(tenant_b.id)
            with session_scope() as session:
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_b.id)}
                )

    def test_missing_tenant_context_returns_zero_rows(self, fx: _Fixture) -> None:
        propose_adaptation(
            tenant_id=fx.tenant.id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key="support_agent.system_prompt",
            proposed_value="Be courteous.",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=_allow_decision(
                fx.tenant.id, actor_user_id=fx.agent.id
            ),
            evidence_type="user_feedback",
            evidence_source_reference="feedback-9",
            created_by_user_id=fx.agent.id,
        )
        with session_scope() as session:
            from sqlalchemy import select as sa_select

            rows = session.execute(sa_select(Adaptation)).scalars().all()
            assert len(rows) == 0


class TestCP02ForgedLearningAuthorizationDecision:
    """CP-02 (Phase J, third pass): `propose_adaptation()` must reject a
    plausible, hand-built `LearningAuthorizationDecision` -- correct
    tenant, correct outcome/purpose, but a fresh `decision_id` that
    `authorize_learning_use()` never audited. No `self_learning.adaptations`
    row may ever be created from it."""

    def test_forged_decision_with_fresh_decision_id_is_rejected(self, fx: _Fixture) -> None:
        genuine = _allow_decision(fx.tenant.id, actor_user_id=fx.agent.id)
        forged = LearningAuthorizationDecision(
            outcome=genuine.outcome,
            tenant_id=genuine.tenant_id,
            purpose=genuine.purpose,
            reason=None,
            data_authorization_decision_id=genuine.data_authorization_decision_id,
            # every other visible field copied from a genuine decision --
            # only `decision_id` is fresh (the dataclass's own default
            # factory), proving the check is provenance-based, not merely
            # "do the other fields look plausible."
        )
        assert forged.decision_id != genuine.decision_id

        with pytest.raises(UnauthorizedAdaptationEvidenceError):
            propose_adaptation(
                tenant_id=fx.tenant.id,
                surface=AdaptationSurface.PROMPT_INSTRUCTION,
                lineage_key="support_agent.system_prompt",
                proposed_value="Be courteous.",
                learning_purpose="adaptive_prompt_tuning",
                learning_authorization_decision=forged,
                evidence_type="user_feedback",
                evidence_source_reference="feedback-forged",
                created_by_user_id=fx.agent.id,
            )
        with session_scope() as session:
            from sqlalchemy import select as sa_select

            rows = (
                session.execute(sa_select(Adaptation).where(Adaptation.tenant_id == fx.tenant.id))
                .scalars()
                .all()
            )
            assert len(rows) == 0

    def test_genuine_decision_still_satisfies(self, fx: _Fixture) -> None:
        """Control: the same shape of request, with the real (audited)
        decision instead of the forged one, must still succeed --
        proving the rejection above is about provenance, not an
        unrelated regression."""
        v1 = propose_adaptation(
            tenant_id=fx.tenant.id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key="support_agent.system_prompt",
            proposed_value="Be courteous.",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=_allow_decision(
                fx.tenant.id, actor_user_id=fx.agent.id
            ),
            evidence_type="user_feedback",
            evidence_source_reference="feedback-genuine",
            created_by_user_id=fx.agent.id,
        )
        assert v1.status == AdaptationStatus.CANDIDATE.value


class TestCP04ForgedEvaluationComparison:
    """CP-04 (Phase J audit): `record_adaptation_evaluation()` must reject
    a hand-built `EvaluationComparison` -- one never produced by
    `evaluation.service.run_evaluation()`, with no matching
    `learning.evaluation_run` audit record. A Phase-J experiment proved
    that, before this remediation, a forged `EvaluationComparison(outcome
    =PASS, ...)` was accepted with zero check and was, alone, sufficient
    to clear `activate_adaptation()`'s own `AdaptationNotEvaluatedError`
    gate -- this is the anti-laundering regression proving that path is
    now closed end to end."""

    def test_forged_comparison_is_rejected_and_adaptation_untouched(self, fx: _Fixture) -> None:
        v1 = propose_adaptation(
            tenant_id=fx.tenant.id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key="support_agent.system_prompt",
            proposed_value="Be courteous.",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=_allow_decision(
                fx.tenant.id, actor_user_id=fx.agent.id
            ),
            evidence_type="user_feedback",
            evidence_source_reference="feedback-forged-eval",
            created_by_user_id=fx.agent.id,
        )
        assert v1.status == AdaptationStatus.CANDIDATE.value
        assert v1.evaluation_outcome is None

        forged = EvaluationComparison(
            outcome=EvaluationOutcome.PASS,
            baseline_version="v0",
            candidate_version=str(v1.version),
            benchmark=None,
            invalid_reason=None,
            failed_metrics=(),
            regressed_metrics=(),
        )

        with pytest.raises(EvaluationProvenanceError):
            record_adaptation_evaluation(fx.tenant.id, v1.id, forged)

        with tenant_session_scope(fx.tenant.id) as session:
            refreshed = session.get(Adaptation, v1.id)
            assert refreshed is not None
            assert refreshed.status == AdaptationStatus.CANDIDATE.value
            assert refreshed.evaluation_outcome is None
            assert refreshed.evaluation_comparison_id is None

    def test_forged_comparison_cannot_reach_activation(self, fx: _Fixture) -> None:
        """The full anti-laundering chain: forge -> record (rejected) ->
        activate must never succeed. The adaptation must remain
        `CANDIDATE` with `evaluation_outcome = NULL` throughout, and
        `activate_adaptation()` must still refuse it exactly as if no
        evaluation had ever been attempted."""
        v1 = propose_adaptation(
            tenant_id=fx.tenant.id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key="support_agent.system_prompt",
            proposed_value="Be courteous.",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=_allow_decision(
                fx.tenant.id, actor_user_id=fx.agent.id
            ),
            evidence_type="user_feedback",
            evidence_source_reference="feedback-anti-laundering",
            created_by_user_id=fx.agent.id,
        )
        forged = EvaluationComparison(
            outcome=EvaluationOutcome.PASS,
            baseline_version="v0",
            candidate_version=str(v1.version),
            benchmark=None,
            invalid_reason=None,
            failed_metrics=(),
            regressed_metrics=(),
        )

        with pytest.raises(EvaluationProvenanceError):
            record_adaptation_evaluation(fx.tenant.id, v1.id, forged)

        with pytest.raises(AdaptationNotEvaluatedError):
            activate_adaptation(fx.tenant.id, v1.id, activated_by_user_id=fx.agent.id)

        with tenant_session_scope(fx.tenant.id) as session:
            refreshed = session.get(Adaptation, v1.id)
            assert refreshed is not None
            assert refreshed.status == AdaptationStatus.CANDIDATE.value
            assert refreshed.evaluation_outcome is None

        entries = list_audit_entries(fx.tenant.id)
        assert not any(e.action == "learning.evaluation_run" for e in entries), (
            "no genuine evaluation ever ran, so this action must be absent"
        )

    def test_wrong_decision_id_is_rejected(self, fx: _Fixture) -> None:
        """A genuine, audited comparison whose `decision_id` is then
        swapped for a fresh, never-audited UUID must be rejected exactly
        like a fully hand-built one -- proves the check is decision_id
        identity, not merely "does this look like a real comparison"."""
        v1 = propose_adaptation(
            tenant_id=fx.tenant.id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key="support_agent.system_prompt",
            proposed_value="Be courteous.",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=_allow_decision(
                fx.tenant.id, actor_user_id=fx.agent.id
            ),
            evidence_type="user_feedback",
            evidence_source_reference="feedback-wrong-decision-id",
            created_by_user_id=fx.agent.id,
        )
        genuine = _pass_comparison(fx.tenant.id, actor_user_id=fx.agent.id)
        swapped = EvaluationComparison(
            outcome=genuine.outcome,
            baseline_version=genuine.baseline_version,
            candidate_version=genuine.candidate_version,
            benchmark=genuine.benchmark,
            invalid_reason=genuine.invalid_reason,
            failed_metrics=genuine.failed_metrics,
            regressed_metrics=genuine.regressed_metrics,
            # decision_id omitted -- dataclass default_factory gives it a
            # fresh, never-audited UUID, distinct from genuine.decision_id.
        )
        assert swapped.decision_id != genuine.decision_id

        with pytest.raises(EvaluationProvenanceError):
            record_adaptation_evaluation(fx.tenant.id, v1.id, swapped)

        with tenant_session_scope(fx.tenant.id) as session:
            refreshed = session.get(Adaptation, v1.id)
            assert refreshed is not None
            assert refreshed.evaluation_outcome is None

    def test_genuine_evaluation_still_activates(self, fx: _Fixture) -> None:
        """Control: a genuine `run_evaluation()` result, recorded and
        activated the normal way, must continue to work end to end --
        proving CP-04 rejects forgeries without breaking the real flow."""
        v1 = propose_adaptation(
            tenant_id=fx.tenant.id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key="support_agent.system_prompt",
            proposed_value="Be courteous.",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=_allow_decision(
                fx.tenant.id, actor_user_id=fx.agent.id
            ),
            evidence_type="user_feedback",
            evidence_source_reference="feedback-genuine-eval",
            created_by_user_id=fx.agent.id,
        )
        record_adaptation_evaluation(
            fx.tenant.id, v1.id, _pass_comparison(fx.tenant.id, actor_user_id=fx.agent.id)
        )
        activated = activate_adaptation(fx.tenant.id, v1.id, activated_by_user_id=fx.agent.id)
        assert activated.status == AdaptationStatus.ACTIVE.value
