"""Integration tests for `control_plane.self_learning.autonomous_improvement`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.8): full pipeline (Experiment ->
Policy Gate -> Canary -> Monitoring -> Promote OR Rollback), tenant
isolation, and audit behavior against a real, persisted `Canary` row.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/self_learning/autonomous_improvement/test_autonomous_improvement_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from infra.secrets.config import get_secrets_provider
from sqlalchemy import text

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.adaptive.models import (
    AdaptationScope,
    AdaptationStatus,
    AdaptationSurface,
)
from control_plane.self_learning.adaptive.service import (
    activate_adaptation,
    get_adaptation,
    propose_adaptation,
    record_adaptation_evaluation,
)
from control_plane.self_learning.autonomous_improvement.errors import (
    CanaryNotConfiguredError,
    CanaryNotFoundError,
    CanaryRollbackFailedError,
    ExperimentNotEvaluatedForCanaryError,
    InvalidCanaryCandidateError,
)
from control_plane.self_learning.autonomous_improvement.models import CanaryStatus
from control_plane.self_learning.autonomous_improvement.service import (
    cancel_canary,
    conclude_canary_monitoring,
    create_canary,
    get_canary,
    promote_canary,
    record_canary_observation,
    rollback_canary,
    start_canary,
)
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationMetrics,
    EvaluationOutcome,
    EvaluationRules,
    MetricDirection,
    MetricThreshold,
)
from control_plane.self_learning.experiments.service import (
    create_experiment,
    execute_experiment,
    record_experiment_result,
)
from control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)
from control_plane.self_learning.policy_gate.models import (
    AutonomyTier,
    PolicyGateRequest,
    PolicyGateScope,
    RequestedAction,
    Tier2PromotionEvidence,
)
from control_plane.self_learning.policy_gate.service import evaluate_and_record_policy_gate_decision
from core.tenancy import create_tenant

pytestmark = [pytest.mark.integration]

RULES = EvaluationRules(
    thresholds=(
        MetricThreshold(
            metric_name="error_rate",
            direction=MetricDirection.LOWER_IS_BETTER,
            maximum_absolute=0.1,
        ),
    )
)


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
            conn.execute(text("SELECT 1 FROM self_learning.canaries LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/self_learning.canaries not reachable: {exc}. "
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


def _admin_cleanup(tenant_id: uuid.UUID, user_ids: list[uuid.UUID]) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM self_learning.canaries WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM self_learning.experiments WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM self_learning.adaptations WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()
    with session_scope() as session:
        for user_id in user_ids:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_id)})


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def tenant_actor():
    tenant = create_tenant(_unique("canary-tenant"))
    actor = create_user()
    yield tenant, actor
    _admin_cleanup(tenant.id, [actor.id])


def _allow_decision(tenant_id: uuid.UUID) -> LearningAuthorizationDecision:
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


def _pass_comparison(baseline_version: str, candidate_version: str) -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.PASS,
        baseline_version=baseline_version,
        candidate_version=candidate_version,
        benchmark=Benchmark(benchmark_id="support-reply-quality", version="1"),
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=(),
    )


def _regression_comparison(baseline_version: str, candidate_version: str) -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.REGRESSION,
        baseline_version=baseline_version,
        candidate_version=candidate_version,
        benchmark=Benchmark(benchmark_id="support-reply-quality", version="1"),
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=("task_success_rate",),
    )


def _build_ready_canary_inputs(
    tenant, actor, *, comparison_kind: str = "pass", with_previous_version: bool = False
):
    """Build a real, persisted, PASS-evaluated Adaptation + COMPLETED
    Experiment + tier-2 ALLOW PolicyGateDecision -- the exact
    prerequisite chain `create_canary()` requires. Returns
    (experiment, adaptation, policy_decision).

    `with_previous_version=True` first proposes, evaluates, and activates
    a v1 adaptation in the same lineage (a real, already-active previous
    version to roll back to) before proposing the v2 candidate this
    canary is actually about -- `rollback_adaptation()` itself requires a
    `previous_adaptation_id`; a canary's first-ever lineage version has
    none, which is the deliberate setup `test_rollback_failure_is_audited_and_raises`
    uses instead."""
    lineage_key = _unique("support_agent.system_prompt")
    if with_previous_version:
        previous = propose_adaptation(
            tenant_id=tenant.id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key=lineage_key,
            proposed_value="Be polite.",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=_allow_decision(tenant.id),
            evidence_type="user_feedback",
            evidence_source_reference="feedback-0",
            created_by_user_id=actor.id,
            scope=AdaptationScope.TENANT,
        )
        record_adaptation_evaluation(
            tenant.id, previous.id, _pass_comparison("v-1", str(previous.version))
        )
        activate_adaptation(tenant.id, previous.id, activated_by_user_id=actor.id)

    adaptation = propose_adaptation(
        tenant_id=tenant.id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key=lineage_key,
        proposed_value="Be courteous.",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(tenant.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-1",
        created_by_user_id=actor.id,
        scope=AdaptationScope.TENANT,
    )
    comparison = (
        _pass_comparison("v0", str(adaptation.version))
        if comparison_kind == "pass"
        else _regression_comparison("v0", str(adaptation.version))
    )
    adaptation = record_adaptation_evaluation(tenant.id, adaptation.id, comparison)

    experiment = create_experiment(
        tenant_id=tenant.id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(tenant.id),
        evidence_type="tool_output",
        evidence_source_reference="experiment-seed",
        created_by_user_id=actor.id,
        adaptation=adaptation,
    )
    experiment = execute_experiment(tenant.id, experiment.id, executed_by_user_id=actor.id)
    experiment = record_experiment_result(
        tenant.id, experiment.id, comparison, recorded_by_user_id=actor.id
    )

    policy_request = PolicyGateRequest(
        tenant_id=tenant.id,
        actor_user_id=actor.id,
        requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
        requested_autonomy_tier=AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED.value,
        scope=PolicyGateScope(
            authorized=frozenset({adaptation.lineage_key}),
            requested=frozenset({adaptation.lineage_key}),
        ),
        learning_authorization_decision=_allow_decision(tenant.id),
        evaluation_comparison=comparison,
        tier2_promotion_evidence=Tier2PromotionEvidence(
            adr_reference="docs/ADR/0020-example.md",
            reliability_summary="stub demonstrated reliability",
        ),
        tier2_eligible_actions=frozenset({RequestedAction.ACTIVATE_ADAPTATION.value}),
    )
    policy_decision = evaluate_and_record_policy_gate_decision(policy_request)
    return experiment, adaptation, policy_decision


def test_full_pipeline_stub_candidate_observation_through_promotion(tenant_actor) -> None:
    """Phase 9.8's own named Tests bullet: "full pipeline integration test
    for a stub candidate (observation through promote-or-rollback)"."""
    tenant, actor = tenant_actor
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(tenant, actor)
    assert policy_decision.is_allowed

    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=RULES,
        created_by_user_id=actor.id,
    )
    assert canary.status == CanaryStatus.CONFIGURED.value

    canary = start_canary(tenant.id, canary.id, started_by_user_id=actor.id)
    assert canary.status == CanaryStatus.RUNNING.value
    activated = get_adaptation(tenant.id, adaptation.id)
    assert activated.status == AdaptationStatus.ACTIVE.value

    canary = record_canary_observation(
        tenant.id, canary.id, EvaluationMetrics(error_rate=0.02), recorded_by_user_id=actor.id
    )
    assert canary.status == CanaryStatus.RUNNING.value  # no violation -- unchanged

    canary = conclude_canary_monitoring(tenant.id, canary.id, concluded_by_user_id=actor.id)
    assert canary.status == CanaryStatus.SUCCEEDED.value

    canary = promote_canary(tenant.id, canary.id, promoted_by_user_id=actor.id)
    assert canary.status == CanaryStatus.PROMOTED.value

    entries = list_audit_entries(tenant.id)
    lineage_actions = {e.action for e in entries}
    assert "learning.canary_created" in lineage_actions
    assert "learning.canary_started" in lineage_actions
    assert "learning.canary_observation_recorded" in lineage_actions
    assert "learning.canary_succeeded" in lineage_actions
    assert "learning.canary_promoted" in lineage_actions
    assert "learning.policy_gate_decision" in lineage_actions
    assert "learning.adaptation_activated" in lineage_actions


def test_canary_rolls_back_automatically_on_monitoring_violation(tenant_actor) -> None:
    """Non-vacuous: proven to roll back automatically, not merely
    flagged."""
    tenant, actor = tenant_actor
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(
        tenant, actor, with_previous_version=True
    )

    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=RULES,
        created_by_user_id=actor.id,
    )
    canary = start_canary(tenant.id, canary.id, started_by_user_id=actor.id)
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value

    canary = record_canary_observation(
        tenant.id, canary.id, EvaluationMetrics(error_rate=0.9), recorded_by_user_id=actor.id
    )
    assert canary.status == CanaryStatus.ROLLED_BACK.value
    assert canary.rollback_reason is not None
    assert "error_rate" in canary.rollback_reason

    reverted = get_adaptation(tenant.id, adaptation.id)
    assert reverted.status == AdaptationStatus.ROLLED_BACK.value

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.canary_rolled_back"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"
    observation_entries = [e for e in entries if e.action == "learning.canary_observation_recorded"]
    assert len(observation_entries) == 1
    assert observation_entries[0].outcome == "failure"


def test_manual_rollback_after_success(tenant_actor) -> None:
    tenant, actor = tenant_actor
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(
        tenant, actor, with_previous_version=True
    )
    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=RULES,
        created_by_user_id=actor.id,
    )
    canary = start_canary(tenant.id, canary.id, started_by_user_id=actor.id)
    canary = conclude_canary_monitoring(tenant.id, canary.id, concluded_by_user_id=actor.id)
    assert canary.status == CanaryStatus.SUCCEEDED.value

    canary = rollback_canary(
        tenant.id,
        canary.id,
        rolled_back_by_user_id=actor.id,
        reason="operator decided not to promote",
    )
    assert canary.status == CanaryStatus.ROLLED_BACK.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ROLLED_BACK.value


def test_rollback_failure_is_audited_and_raises(tenant_actor) -> None:
    """The very first version in a lineage has no previous version to
    revert to -- `rollback_adaptation()` itself raises
    `NoPreviousVersionError`. Proves Phase 9.8's own Rollback Strategy:
    "a failed rollback itself produces an audit/operational event, never
    a silent failure"."""
    tenant, actor = tenant_actor
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(tenant, actor)
    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=RULES,
        created_by_user_id=actor.id,
    )
    canary = start_canary(tenant.id, canary.id, started_by_user_id=actor.id)

    with pytest.raises(CanaryRollbackFailedError):
        record_canary_observation(
            tenant.id, canary.id, EvaluationMetrics(error_rate=0.9), recorded_by_user_id=actor.id
        )

    failed = get_canary(tenant.id, canary.id)
    assert failed.status == CanaryStatus.ROLLBACK_FAILED.value

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.canary_rollback_failed"]
    assert len(matching) == 1
    assert matching[0].outcome == "failure"
    # Adaptation itself is untouched (rollback never actually applied) --
    # a failed rollback must never silently claim success.
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value


def test_regression_experiment_blocks_canary_creation_end_to_end(tenant_actor) -> None:
    tenant, actor = tenant_actor
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(
        tenant, actor, comparison_kind="regression"
    )
    assert experiment.evaluation_outcome == "regression"

    with pytest.raises(ExperimentNotEvaluatedForCanaryError):
        create_canary(
            tenant_id=tenant.id,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=policy_decision,
            monitoring_rules=RULES,
            created_by_user_id=actor.id,
        )


def test_cancel_canary_before_start(tenant_actor) -> None:
    tenant, actor = tenant_actor
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(tenant, actor)
    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=RULES,
        created_by_user_id=actor.id,
    )
    canary = cancel_canary(
        tenant.id, canary.id, cancelled_by_user_id=actor.id, reason="no longer needed"
    )
    assert canary.status == CanaryStatus.CANCELLED.value
    # Adaptation was never activated -- cancellation before start has zero
    # production effect.
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.CANDIDATE.value


def test_cancel_running_canary_is_refused(tenant_actor) -> None:
    """A canary that has already activated its Adaptation must go through
    `rollback_canary()`, never a bare cancel -- see `service.py`'s own
    `cancel_canary()` docstring."""
    tenant, actor = tenant_actor
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(tenant, actor)
    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=RULES,
        created_by_user_id=actor.id,
    )
    canary = start_canary(tenant.id, canary.id, started_by_user_id=actor.id)
    with pytest.raises(CanaryNotConfiguredError):
        cancel_canary(tenant.id, canary.id, cancelled_by_user_id=actor.id)


def test_cross_tenant_canary_creation_is_denied(tenant_actor) -> None:
    """Tenant B cannot create a canary using Tenant A's Experiment/
    Adaptation/PolicyGateDecision."""
    tenant_a, actor_a = tenant_actor
    tenant_b = create_tenant(_unique("canary-tenant-b"))
    try:
        experiment, adaptation, policy_decision = _build_ready_canary_inputs(tenant_a, actor_a)
        with pytest.raises(InvalidCanaryCandidateError):
            create_canary(
                tenant_id=tenant_b.id,
                experiment=experiment,
                adaptation=adaptation,
                policy_gate_decision=policy_decision,
                monitoring_rules=RULES,
                created_by_user_id=actor_a.id,
            )
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_b.id)}
            )


def test_tenant_b_cannot_read_tenant_a_canary(tenant_actor) -> None:
    tenant_a, actor_a = tenant_actor
    tenant_b = create_tenant(_unique("canary-tenant-b"))
    try:
        experiment, adaptation, policy_decision = _build_ready_canary_inputs(tenant_a, actor_a)
        canary = create_canary(
            tenant_id=tenant_a.id,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=policy_decision,
            monitoring_rules=RULES,
            created_by_user_id=actor_a.id,
        )
        with pytest.raises(CanaryNotFoundError):
            get_canary(tenant_b.id, canary.id)
    finally:
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_b.id)}
            )


def test_audit_metadata_never_contains_secrets_or_raw_candidate_content(tenant_actor) -> None:
    tenant, actor = tenant_actor
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(tenant, actor)
    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=RULES,
        created_by_user_id=actor.id,
    )
    start_canary(tenant.id, canary.id, started_by_user_id=actor.id)

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action.startswith("learning.canary_")]
    assert matching
    for entry in matching:
        metadata_repr = repr(entry.entry_metadata)
        assert "Be courteous." not in metadata_repr
        assert "safe" not in (entry.entry_metadata or {})
        assert "approved" not in (entry.entry_metadata or {})
