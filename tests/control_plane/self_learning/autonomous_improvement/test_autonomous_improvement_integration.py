"""Integration tests for `saas_os.control_plane.self_learning.autonomous_improvement`
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
from sqlalchemy import text

from lifecycle_callers import PROVISIONING
from saas_os.control_plane.data_authorization import (
    DataAuthorizationRequest,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    authorize_data_access,
)
from saas_os.control_plane.self_learning import (
    LearningAuthorizationRequest,
    LearningEvidence,
    TenantLearningPolicy,
    authorize_learning_use,
)
from saas_os.control_plane.self_learning.adaptive import service as adaptive_service
from saas_os.control_plane.self_learning.adaptive.models import (
    AdaptationScope,
    AdaptationStatus,
    AdaptationSurface,
)
from saas_os.control_plane.self_learning.adaptive.service import (
    activate_adaptation,
    get_adaptation,
    propose_adaptation,
    record_adaptation_evaluation,
    rollback_adaptation,
)
from saas_os.control_plane.self_learning.autonomous_improvement import service as canary_service
from saas_os.control_plane.self_learning.autonomous_improvement.errors import (
    CanaryAuthorizationDeniedError,
    CanaryNotConfiguredError,
    CanaryNotFoundError,
    CanaryRollbackFailedError,
    ExperimentNotEvaluatedForCanaryError,
    InvalidCanaryCandidateError,
    UnauthorizedCanaryPolicyDecisionError,
)
from saas_os.control_plane.self_learning.autonomous_improvement.models import CanaryStatus
from saas_os.control_plane.self_learning.autonomous_improvement.service import (
    cancel_canary,
    conclude_canary_monitoring,
    create_canary,
    get_canary,
    promote_canary,
    record_canary_observation,
    rollback_canary,
    start_canary,
)
from saas_os.control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationMetrics,
    EvaluationOutcome,
    EvaluationRules,
    EvaluationSubjectKind,
    EvaluationSubjectResult,
    MetricDirection,
    MetricThreshold,
)
from saas_os.control_plane.self_learning.evaluation.service import run_evaluation
from saas_os.control_plane.self_learning.experiments.service import (
    create_experiment,
    execute_experiment,
    record_experiment_result,
)
from saas_os.control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)
from saas_os.control_plane.self_learning.policy_gate.models import (
    AutonomyTier,
    PolicyGateDecision,
    PolicyGateOutcome,
    PolicyGateRequest,
    PolicyGateScope,
    RequestedAction,
    Tier2PromotionEvidence,
)
from saas_os.control_plane.self_learning.policy_gate.service import (
    evaluate_and_record_policy_gate_decision,
)
from saas_os.core.audit_log.service import list as list_audit_entries
from saas_os.core.identity.service import create_user
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope
from saas_os.infra.secrets.config import get_secrets_provider


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from sqlalchemy import text

    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine
    from saas_os.infra.db.session import build_session_factory, session_scope

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
            # ADR-0045 Phase C: lifecycle changes also write platform audit
            # rows, which reference the tenant or the acting user and which
            # the runtime role can never delete.
            platform_where = (
                "target_tenant_id::text = ANY(:v)"
                if table == "tenants"
                else "actor_user_id::text = ANY(:v)"
            )
            # A migration test may be cleaning up below the revision that
            # creates the table.
            if session.execute(text("SELECT to_regclass('core.platform_audit_log')")).scalar():
                session.execute(
                    text(f"DELETE FROM core.platform_audit_log WHERE {platform_where}"),  # noqa: S608
                    {"v": values},
                )
    finally:
        engine.dispose()


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
    # S-05 (saas_os/infra/db/config.py): this file's own DB-reachability probe can
    # run after this fixture under pytest's autouse ordering, so
    # ENVIRONMENT=production would otherwise force sslmode=require against
    # this job's plaintext disposable Postgres. Not a real production
    # connection -- opt out explicitly, same fix as the P2.4 backup drill
    # (tests/infra/db/test_backup_restore_drill_integration.py).
    monkeypatch.setenv("DB_REQUIRE_TLS", "false")
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
            _admin_clear_audit_references({"id": str(user_id)}, table="users")
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})
        _admin_clear_audit_references({"id": str(tenant_id)}, table="tenants")
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_id)})


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def tenant_actor():
    tenant = create_tenant(_unique("canary-tenant"), caller=PROVISIONING)
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
    genuine, matching `saas_os.core.audit_log` provenance record for the
    `LearningAuthorizationDecision` they are given (see
    `saas_os.control_plane.self_learning.service.verify_learning_authorization_provenance()`).
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


_COMPARISON_RULES = EvaluationRules(
    thresholds=(
        MetricThreshold(
            metric_name="task_success_rate",
            direction=MetricDirection.HIGHER_IS_BETTER,
            minimum_absolute=0.5,
            maximum_regression=0.1,
        ),
    )
)


def _pass_comparison(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID, baseline_version: str, candidate_version: str
) -> EvaluationComparison:
    """CP-04 (Phase J audit): `record_adaptation_evaluation()`/
    `record_experiment_result()` now require genuine
    `evaluation.service.verify_evaluation_provenance()` -- a hand-built
    `EvaluationComparison` (this helper's own previous implementation) is
    no longer sufficient. Produced by the real `run_evaluation()` so its
    `learning.evaluation_run` audit trail is genuine, exactly like
    `_allow_decision()` above was fixed for CP-02."""
    benchmark = Benchmark(benchmark_id="autonomous-improvement-fixture-benchmark", version="1")
    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version=baseline_version,
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version=candidate_version,
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.95),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    comparison = run_evaluation(baseline, candidate, _COMPARISON_RULES, actor_user_id=actor_user_id)
    assert comparison.outcome is EvaluationOutcome.PASS
    return comparison


def _regression_comparison(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID, baseline_version: str, candidate_version: str
) -> EvaluationComparison:
    """Genuine `REGRESSION` -- same shape the previous hand-built version
    claimed, now actually produced by `run_evaluation()` (CP-04)."""
    benchmark = Benchmark(benchmark_id="autonomous-improvement-fixture-benchmark", version="1")
    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version=baseline_version,
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version=candidate_version,
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.7),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    comparison = run_evaluation(baseline, candidate, _COMPARISON_RULES, actor_user_id=actor_user_id)
    assert comparison.outcome is EvaluationOutcome.REGRESSION
    assert comparison.regressed_metrics == ("task_success_rate",)
    return comparison


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
            tenant.id,
            previous.id,
            _pass_comparison(
                tenant.id,
                actor_user_id=actor.id,
                baseline_version="v-1",
                candidate_version=str(previous.version),
            ),
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
        _pass_comparison(
            tenant.id,
            actor_user_id=actor.id,
            baseline_version="v0",
            candidate_version=str(adaptation.version),
        )
        if comparison_kind == "pass"
        else _regression_comparison(
            tenant.id,
            actor_user_id=actor.id,
            baseline_version="v0",
            candidate_version=str(adaptation.version),
        )
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
    tenant_b = create_tenant(_unique("canary-tenant-b"), caller=PROVISIONING)
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
            _admin_clear_audit_references({"id": str(tenant_b.id)}, table="tenants")
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_b.id)}
            )


def test_tenant_b_cannot_read_tenant_a_canary(tenant_actor) -> None:
    tenant_a, actor_a = tenant_actor
    tenant_b = create_tenant(_unique("canary-tenant-b"), caller=PROVISIONING)
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
            _admin_clear_audit_references({"id": str(tenant_b.id)}, table="tenants")
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

    from sqlalchemy import select as sa_select

    from saas_os.control_plane.self_learning.autonomous_improvement.models import Canary
    from saas_os.infra.db.session import tenant_session_scope

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
    tenant_b = create_tenant(_unique("canary-tenant-b"), caller=PROVISIONING)
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
            _admin_clear_audit_references({"id": str(tenant_b.id)}, table="tenants")
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


# --- Same-transaction audit for production-effect transitions -------------
# (ADR-0031 amendment of 2026-10-30; Phase 9 finding S3,
# docs/architecture/CONTROL-PLANE-AUDIT-DECISION-BRIEF.md option A.) The audit
# write is made to fail for one action; the transition must then leave no
# trace at all: no state change and no audit row for it or its partner.


class _InjectedAuditFailure(RuntimeError):
    pass


def _fail_audit_for(monkeypatch: pytest.MonkeyPatch, action: str) -> None:
    for module in (adaptive_service, canary_service):
        original = module.record_in_transaction

        def failing(session, *, _original=original, **kwargs):
            if kwargs["action"] == action:
                raise _InjectedAuditFailure(action)
            return _original(session, **kwargs)

        monkeypatch.setattr(module, "record_in_transaction", failing)


def _actions(tenant_id: uuid.UUID, *actions: str) -> list[str]:
    return [e.action for e in list_audit_entries(tenant_id) if e.action in actions]


def _configured_canary(tenant, actor, *, with_previous_version: bool = False):
    experiment, adaptation, policy_decision = _build_ready_canary_inputs(
        tenant, actor, with_previous_version=with_previous_version
    )
    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=RULES,
        created_by_user_id=actor.id,
    )
    return canary, adaptation


def _start(tenant, actor, canary_id: uuid.UUID):
    return start_canary(
        tenant.id,
        canary_id,
        started_by_user_id=actor.id,
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )


@pytest.mark.parametrize(
    "failing_action", ["learning.adaptation_activated", "learning.canary_started"]
)
def test_start_canary_audit_failure_leaves_adaptation_and_canary_unchanged(
    tenant_actor, monkeypatch, failing_action
) -> None:
    """Before S3 was fixed, `start_canary` committed the activation first: a
    failure afterwards left the adaptation ACTIVE behind a CONFIGURED canary
    that could never be started again."""
    tenant, actor = tenant_actor
    canary, adaptation = _configured_canary(tenant, actor)
    started = ("learning.adaptation_activated", "learning.canary_started")

    with monkeypatch.context() as patch:
        _fail_audit_for(patch, failing_action)
        with pytest.raises(_InjectedAuditFailure):
            _start(tenant, actor, canary.id)

    assert get_canary(tenant.id, canary.id).status == CanaryStatus.CONFIGURED.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.CANDIDATE.value
    assert _actions(tenant.id, *started) == []

    # Nothing was half-done, so the same canary starts normally afterwards.
    assert _start(tenant, actor, canary.id).status == CanaryStatus.RUNNING.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value
    assert sorted(_actions(tenant.id, *started)) == sorted(started)


def test_start_canary_rechecks_the_canary_inside_its_transaction(tenant_actor, monkeypatch) -> None:
    """A caller holding a stale CONFIGURED snapshot (the first read happens
    before the transaction) is refused by the locked re-read, and nothing is
    activated or audited twice."""
    tenant, actor = tenant_actor
    canary, _ = _configured_canary(tenant, actor)
    stale = get_canary(tenant.id, canary.id)
    _start(tenant, actor, canary.id)

    monkeypatch.setattr(canary_service, "get_canary", lambda *_args: stale)
    with pytest.raises(CanaryNotConfiguredError):
        _start(tenant, actor, canary.id)
    assert _actions(tenant.id, "learning.canary_started") == ["learning.canary_started"]


def test_activate_adaptation_audit_failure_rolls_the_activation_back(
    tenant_actor, monkeypatch
) -> None:
    tenant, actor = tenant_actor
    _, adaptation, _ = _build_ready_canary_inputs(tenant, actor)

    with monkeypatch.context() as patch:
        _fail_audit_for(patch, "learning.adaptation_activated")
        with pytest.raises(_InjectedAuditFailure):
            activate_adaptation(tenant.id, adaptation.id, activated_by_user_id=actor.id)

    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.CANDIDATE.value
    assert _actions(tenant.id, "learning.adaptation_activated") == []


def test_rollback_adaptation_audit_failure_leaves_both_versions_unchanged(
    tenant_actor, monkeypatch
) -> None:
    tenant, actor = tenant_actor
    canary, adaptation = _configured_canary(tenant, actor, with_previous_version=True)
    _start(tenant, actor, canary.id)
    previous_id = get_adaptation(tenant.id, adaptation.id).previous_adaptation_id
    assert previous_id is not None

    with monkeypatch.context() as patch:
        _fail_audit_for(patch, "learning.adaptation_rolled_back")
        with pytest.raises(_InjectedAuditFailure):
            rollback_adaptation(tenant.id, adaptation.id, rolled_back_by_user_id=actor.id)

    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value
    assert get_adaptation(tenant.id, previous_id).status == AdaptationStatus.SUPERSEDED.value
    assert _actions(tenant.id, "learning.adaptation_rolled_back") == []


@pytest.mark.parametrize(
    "failing_action", ["learning.adaptation_rolled_back", "learning.canary_rolled_back"]
)
def test_rollback_canary_audit_failure_leaves_adaptation_and_canary_unchanged(
    tenant_actor, monkeypatch, failing_action
) -> None:
    tenant, actor = tenant_actor
    canary, adaptation = _configured_canary(tenant, actor, with_previous_version=True)
    _start(tenant, actor, canary.id)
    rolled_back = ("learning.adaptation_rolled_back", "learning.canary_rolled_back")

    with monkeypatch.context() as patch:
        _fail_audit_for(patch, failing_action)
        with pytest.raises(_InjectedAuditFailure):
            rollback_canary(
                tenant.id,
                canary.id,
                rolled_back_by_user_id=actor.id,
                reason="operator decided not to promote",
                learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
            )

    assert get_canary(tenant.id, canary.id).status == CanaryStatus.RUNNING.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value
    assert _actions(tenant.id, *rolled_back) == []


def test_rollback_failed_is_not_recorded_without_its_audit_row(tenant_actor, monkeypatch) -> None:
    """The refused rollback (first lineage version, nothing to revert to)
    records ROLLBACK_FAILED only together with its audit row."""
    tenant, actor = tenant_actor
    canary, adaptation = _configured_canary(tenant, actor)
    _start(tenant, actor, canary.id)

    with monkeypatch.context() as patch:
        _fail_audit_for(patch, "learning.canary_rollback_failed")
        with pytest.raises(_InjectedAuditFailure):
            record_canary_observation(
                tenant.id,
                canary.id,
                EvaluationMetrics(error_rate=0.9),
                recorded_by_user_id=actor.id,
                learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
            )

    assert get_canary(tenant.id, canary.id).status == CanaryStatus.RUNNING.value
    assert get_adaptation(tenant.id, adaptation.id).status == AdaptationStatus.ACTIVE.value
    assert _actions(tenant.id, "learning.canary_rollback_failed") == []


def test_production_effect_audit_rows_name_the_attributed_user(tenant_actor) -> None:
    """`record_in_transaction` derives the actor from `UserCaller`: the rows
    still name the same user, as a `user` actor."""
    tenant, actor = tenant_actor
    canary, _ = _configured_canary(tenant, actor)
    _start(tenant, actor, canary.id)
    entries = [
        e
        for e in list_audit_entries(tenant.id)
        if e.action in ("learning.adaptation_activated", "learning.canary_started")
    ]
    assert len(entries) == 2
    assert {(e.actor_type, e.actor_user_id) for e in entries} == {("user", actor.id)}
