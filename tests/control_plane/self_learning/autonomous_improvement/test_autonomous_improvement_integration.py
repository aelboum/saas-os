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

from control_plane.data_authorization import (
    DataAuthorizationRequest,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    authorize_data_access,
)
from control_plane.self_learning import (
    LearningAuthorizationRequest,
    LearningEvidence,
    TenantLearningPolicy,
    authorize_learning_use,
)
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
    CanaryAuthorizationDeniedError,
    CanaryNotConfiguredError,
    CanaryNotFoundError,
    CanaryRollbackFailedError,
    ExperimentNotEvaluatedForCanaryError,
    InvalidCanaryCandidateError,
    UnauthorizedCanaryPolicyDecisionError,
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
    PolicyGateDecision,
    PolicyGateOutcome,
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


def _learning_authorization_decision(
    tenant_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID,
    allowed_purposes: frozenset[str] = frozenset({"adaptive_prompt_tuning"}),
) -> LearningAuthorizationDecision:
    """CP-02 (Phase J, third pass): `propose_adaptation()`, `create_experiment()`,
    and `evaluate_and_record_policy_gate_decision()` all now require a
    genuine, matching `core.audit_log` provenance record for the
    `LearningAuthorizationDecision` they are given (see
    `control_plane.self_learning.service.verify_learning_authorization_provenance()`).
    A hand-built decision object (this helper's own previous
    implementation) is no longer sufficient -- it must be produced by the
    real `authorize_data_access()` -> `authorize_learning_use()` chain.

    `allowed_purposes` (CP-03, Phase J audit, remediation 2) lets a caller
    produce a genuine, freshly-audited DENY -- e.g. `frozenset({"unrelated_purpose"})`,
    which never includes the fixed `"adaptive_prompt_tuning"` purpose this
    helper's own `LearningAuthorizationRequest` always names -- to simulate
    "current authorization now denies," never a forged/hand-built object."""
    data_decision = authorize_data_access(
        DataAuthorizationRequest(
            tenant_id=tenant_id,
            data_classification="tenant_data",
            purpose="adaptive_prompt_tuning",
            provider="anthropic",
            resource_type="self_learning_autonomous_improvement_fixture",
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
            allowed_purposes=allowed_purposes,
            allowed_models_or_providers=frozenset({"anthropic"}),
            allowed_retentions=frozenset({"30d"}),
        ),
        actor_user_id=actor_user_id,
    )


def _allow_decision(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> LearningAuthorizationDecision:
    return _learning_authorization_decision(tenant_id, actor_user_id=actor_user_id)


def _denied_learning_authorization_decision(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> LearningAuthorizationDecision:
    """CP-03 (Phase J audit, remediation 2): a genuine, freshly-audited
    DENY -- the same real `authorize_data_access()` -> `authorize_learning_use()`
    chain as `_allow_decision()`, just under a policy that no longer
    allows this purpose, simulating "the tenant's current Learning
    Authorization has since changed" without inventing any new storage."""
    decision = _learning_authorization_decision(
        tenant_id, actor_user_id=actor_user_id, allowed_purposes=frozenset({"unrelated_purpose"})
    )
    assert not decision.is_allowed
    return decision


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
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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

    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    assert canary.status == CanaryStatus.RUNNING.value
    activated = get_adaptation(tenant.id, adaptation.id)
    assert activated.status == AdaptationStatus.ACTIVE.value

    canary = record_canary_observation(
        tenant.id,
        canary.id,
        EvaluationMetrics(error_rate=0.02),
        recorded_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value

    canary = record_canary_observation(
        tenant.id,
        canary.id,
        EvaluationMetrics(error_rate=0.9),
        recorded_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    canary = conclude_canary_monitoring(tenant.id, canary.id, concluded_by_user_id=actor.id)
    assert canary.status == CanaryStatus.SUCCEEDED.value

    canary = rollback_canary(
        tenant.id,
        canary.id,
        rolled_back_by_user_id=actor.id,
        reason="operator decided not to promote",
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )

    with pytest.raises(CanaryRollbackFailedError):
        record_canary_observation(
            tenant.id,
            canary.id,
            EvaluationMetrics(error_rate=0.9),
            recorded_by_user_id=actor.id,
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
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
    start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action.startswith("learning.canary_")]
    assert matching
    for entry in matching:
        metadata_repr = repr(entry.entry_metadata)
        assert "Be courteous." not in metadata_repr
        assert "safe" not in (entry.entry_metadata or {})
        assert "approved" not in (entry.entry_metadata or {})


def test_forged_policy_gate_decision_with_fresh_decision_id_is_rejected(tenant_actor) -> None:
    """CP-02 (Phase J, third pass): `create_canary()` must reject a
    plausible, hand-built `PolicyGateDecision` -- correct tenant, action,
    and tier-2 outcome, but a fresh `decision_id` that
    `evaluate_and_record_policy_gate_decision()` never audited. No
    `self_learning.canaries` row may ever be created from it."""
    tenant, actor = tenant_actor
    experiment, adaptation, genuine_policy_decision = _build_ready_canary_inputs(tenant, actor)
    forged = PolicyGateDecision(
        outcome=PolicyGateOutcome.ALLOW,
        tenant_id=genuine_policy_decision.tenant_id,
        requested_action=genuine_policy_decision.requested_action,
        requested_autonomy_tier=genuine_policy_decision.requested_autonomy_tier,
        reason=None,
    )
    assert forged.decision_id != genuine_policy_decision.decision_id

    with pytest.raises(UnauthorizedCanaryPolicyDecisionError):
        create_canary(
            tenant_id=tenant.id,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=forged,
            monitoring_rules=RULES,
            created_by_user_id=actor.id,
        )

    from infra.db.session import tenant_session_scope
    from sqlalchemy import select as sa_select

    from control_plane.self_learning.autonomous_improvement.models import Canary

    with tenant_session_scope(tenant.id) as session:
        rows = session.execute(sa_select(Canary)).scalars().all()
        assert len(rows) == 0


# --------------------------------------------------------------------- #
# CP-03 (Phase J audit, remediation 2): FRESH execution-time Policy Gate
# evaluation -- not a re-check of the original decision's own audit
# provenance (remediation 1, proven insufficient by a Phase-J experiment:
# a stale creation-time ALLOW's audit trail is permanent and never
# expires, so it kept authorizing execution even after a fresh evaluation
# of the exact same action/tenant/scope, right now, would DENY).
# `start_canary()`/`rollback_canary()`/`record_canary_observation()` now
# each require a `learning_authorization_decision` produced by the
# caller's own CURRENT `authorize_learning_use()` call and run a
# genuinely new `evaluate_and_record_policy_gate_decision()` immediately
# before `activate_adaptation()`/`rollback_adaptation()`.
# --------------------------------------------------------------------- #


def test_start_canary_succeeds_with_fresh_current_learning_authorization(tenant_actor) -> None:
    """Point 1 -- fresh allow: a valid CURRENT Learning Authorization
    (evaluated fresh, right now, not merely valid at canary-creation
    time) allows `start_canary()` to activate the `Adaptation`."""
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

    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )

    assert canary.status == CanaryStatus.RUNNING.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value


def test_start_canary_rejects_when_current_learning_authorization_denies(tenant_actor) -> None:
    """Points 2 & 7 -- stale allow / explicit deny: a canary legitimately
    created under a genuine, audited tier-2 ALLOW must still be refused at
    `start_canary()` if the CURRENT Learning Authorization -- evaluated
    fresh, right now, via a real `authorize_learning_use()` call under a
    policy that no longer allows this purpose -- denies. This is the
    exact create-time/execute-time gap the CP-03 experiment demonstrated:
    a stale ALLOW must no longer authorize execution once current
    authorization has changed. The `Adaptation` must never be activated
    and the canary must never leave `CONFIGURED`."""
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

    with pytest.raises(CanaryAuthorizationDeniedError):
        start_canary(
            tenant.id,
            canary.id,
            started_by_user_id=actor.id,
            learning_authorization_decision=_denied_learning_authorization_decision(
                tenant.id, actor_user_id=actor.id
            ),
        )

    assert get_canary(tenant.id, canary.id).status == CanaryStatus.CONFIGURED.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.CANDIDATE.value


def test_rollback_canary_succeeds_with_fresh_current_learning_authorization(tenant_actor) -> None:
    """Point 3 -- fresh rollback allow: a valid CURRENT Learning
    Authorization allows `rollback_canary()` to revert the `Adaptation`."""
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
    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    canary = conclude_canary_monitoring(tenant.id, canary.id, concluded_by_user_id=actor.id)

    canary = rollback_canary(
        tenant.id,
        canary.id,
        rolled_back_by_user_id=actor.id,
        reason="operator decided not to promote",
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )

    assert canary.status == CanaryStatus.ROLLED_BACK.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ROLLED_BACK.value


def test_rollback_canary_rejects_when_current_learning_authorization_denies(tenant_actor) -> None:
    """Points 4 & 7 -- stale rollback authorization / explicit deny: the
    original (creation-time) authorization was valid, but the CURRENT
    Learning Authorization -- evaluated fresh -- denies. `rollback_canary()`
    must not mutate the `Adaptation`, and the canary must stay `RUNNING`
    (an authorization denial, never a failed rollback ATTEMPT, so it must
    never become `ROLLBACK_FAILED`)."""
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
    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    assert canary.status == CanaryStatus.RUNNING.value

    with pytest.raises(CanaryAuthorizationDeniedError):
        rollback_canary(
            tenant.id,
            canary.id,
            rolled_back_by_user_id=actor.id,
            reason="should never reach rollback_adaptation()",
            learning_authorization_decision=_denied_learning_authorization_decision(
                tenant.id, actor_user_id=actor.id
            ),
        )

    assert get_canary(tenant.id, canary.id).status == CanaryStatus.RUNNING.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value


def test_forged_learning_authorization_decision_cannot_start_canary(tenant_actor) -> None:
    """Point 5 -- forged decision (reworked for the new input surface): a
    hand-built `LearningAuthorizationDecision` -- never produced by
    `authorize_learning_use()`, never audited -- claiming `ALLOW` for the
    correct tenant/purpose must not authorize `start_canary()`. CP-02's
    `verify_learning_authorization_provenance()`, run fresh via
    `evaluate_and_record_policy_gate_decision()` at execution time,
    rejects it. This is the new input's own forgery-resistance analogue of
    `test_forged_policy_gate_decision_with_fresh_decision_id_is_rejected`
    above, which continues to cover `create_canary()`'s own, unchanged
    input."""
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

    forged = LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.ALLOW,
        tenant_id=tenant.id,
        purpose="adaptive_prompt_tuning",
        reason=None,
        data_authorization_decision_id=uuid.uuid4(),
    )

    with pytest.raises(CanaryAuthorizationDeniedError):
        start_canary(
            tenant.id,
            canary.id,
            started_by_user_id=actor.id,
            learning_authorization_decision=forged,
        )

    assert get_canary(tenant.id, canary.id).status == CanaryStatus.CONFIGURED.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.CANDIDATE.value


def test_start_canary_cannot_activate_another_tenants_canary(tenant_actor) -> None:
    """Point 6 -- cross-tenant: a canary/adaptation belonging to tenant A
    cannot be started/mutated by calling `start_canary()` under tenant B's
    context -- `get_canary()`'s own RLS-scoped lookup inside
    `start_canary()` never resolves the row at all."""
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
            start_canary(
                tenant_b.id,
                canary.id,
                started_by_user_id=actor_a.id,
                learning_authorization_decision=_allow_decision(
                    tenant_b.id, actor_user_id=actor_a.id
                ),
            )

        assert get_adaptation(tenant_a.id, adaptation.id).status == AdaptationStatus.CANDIDATE.value
    finally:
        # `_allow_decision(tenant_b.id, ...)` above genuinely audits under
        # tenant_b (authorize_data_access()/authorize_learning_use() write
        # real core.audit_log rows) even though start_canary() itself never
        # reaches any canary mutation -- clear those first, mirroring
        # `_admin_cleanup()`'s own ordering, or the FK from audit_log blocks
        # deleting tenant_b.
        engine = build_engine(get_migrations_database_config())
        try:
            factory = build_session_factory(engine)
            with session_scope(session_factory=factory) as session:
                session.execute(
                    text("DELETE FROM core.audit_log WHERE tenant_id = :t"),
                    {"t": str(tenant_b.id)},
                )
        finally:
            engine.dispose()
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_b.id)}
            )


def test_automatic_rollback_denied_by_current_learning_authorization_does_not_bypass_check(
    tenant_actor,
) -> None:
    """Point 9 -- automatic rollback: `record_canary_observation()`'s
    monitoring-triggered rollback threads the SAME fresh-evaluation
    requirement through to `_rollback()`; a denied CURRENT Learning
    Authorization blocks it exactly like the manual path, never silently
    bypassing the check just because no human actor is directly involved.
    The canary stays `RUNNING` (an authorization denial, never a failed
    rollback ATTEMPT, so it must never become `ROLLBACK_FAILED`) and the
    bad `Adaptation` stays `ACTIVE` -- a real, documented residual safety
    tension (see module docstring: rollback, a risk-reduction action, can
    now be blocked by a Learning Authorization denial unrelated to
    safety)."""
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
    canary = start_canary(
        tenant.id,
        canary.id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    assert canary.status == CanaryStatus.RUNNING.value

    with pytest.raises(CanaryAuthorizationDeniedError):
        record_canary_observation(
            tenant.id,
            canary.id,
            EvaluationMetrics(error_rate=0.9),  # violates RULES -- would trigger rollback
            recorded_by_user_id=actor.id,
            learning_authorization_decision=_denied_learning_authorization_decision(
                tenant.id, actor_user_id=actor.id
            ),
        )

    still_running = get_canary(tenant.id, canary.id)
    assert still_running.status == CanaryStatus.RUNNING.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value
