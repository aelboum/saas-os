"""Integration tests for `control_plane.self_learning.continuous_loop`
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.9): kill-switch default-deny,
safe no-op when there is no viable outcome yet, seeding the next cycle
from the most recent terminal `Adaptation`/`Canary`, tenant isolation,
duplicate-execution safety, and audit behavior.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/self_learning/continuous_loop/test_continuous_loop_integration.py
"""

from __future__ import annotations

import os
import uuid

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from core.audit_log.service import list as list_audit_entries
from core.feature_flags.errors import DuplicateFeatureFlagKeyError
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from infra.jobs.config import JobsConfig
from infra.jobs.queue import build_worker, enqueue_job, get_redis_pool, register_job
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
    propose_adaptation,
    record_adaptation_evaluation,
    rollback_adaptation,
)
from control_plane.self_learning.autonomous_improvement.models import CanaryStatus
from control_plane.self_learning.autonomous_improvement.service import (
    conclude_canary_monitoring,
    create_canary,
    promote_canary,
    start_canary,
)
from control_plane.self_learning.continuous_loop.models import (
    LoopCycleOutcome,
    LoopObservationSourceKind,
    LoopTrigger,
)
from control_plane.self_learning.continuous_loop.service import (
    _KILL_SWITCH_FLAG_KEY,
    _run_continuous_learning_cycle_job,
    run_continuous_learning_cycle,
)
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationOutcome,
    EvaluationRules,
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
from core.feature_flags import create_flag, set_tenant_override
from core.tenancy import create_tenant
from infra.jobs import TenantJobPayload

pytestmark = [pytest.mark.integration]


@pytest.fixture(autouse=True, scope="module")
def _kill_switch_flag_exists():
    try:
        create_flag(_KILL_SWITCH_FLAG_KEY, enabled_by_default=False)
    except DuplicateFeatureFlagKeyError:
        pass


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
            for table in ("canaries", "experiments", "adaptations"):
                session.execute(
                    text(f"DELETE FROM self_learning.{table} WHERE tenant_id = :t"),
                    {"t": str(tenant_id)},
                )
            session.execute(
                text("DELETE FROM core.feature_flag_tenant_overrides WHERE tenant_id = :t"),
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
    tenant = create_tenant(_unique("loop-tenant"))
    actor = create_user()
    yield tenant, actor
    _admin_cleanup(tenant.id, [actor.id])


def _enable_loop(tenant_id: uuid.UUID) -> None:
    set_tenant_override(tenant_id, _KILL_SWITCH_FLAG_KEY, True)


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


def _activate_a_fresh_adaptation(tenant, actor):
    adaptation = propose_adaptation(
        tenant_id=tenant.id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key=_unique("support_agent.system_prompt"),
        proposed_value="Be courteous.",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(tenant.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-1",
        created_by_user_id=actor.id,
        scope=AdaptationScope.TENANT,
    )
    comparison = EvaluationComparison(
        outcome=EvaluationOutcome.PASS,
        baseline_version="v0",
        candidate_version=str(adaptation.version),
        benchmark=Benchmark(benchmark_id="b", version="1"),
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=(),
    )
    adaptation = record_adaptation_evaluation(tenant.id, adaptation.id, comparison)
    return activate_adaptation(tenant.id, adaptation.id, activated_by_user_id=actor.id), comparison


def _promote_a_fresh_canary(tenant, actor):
    adaptation, comparison = _activate_a_fresh_adaptation(tenant, actor)
    # activate_adaptation() above already made this ACTIVE; create_canary()
    # requires CANDIDATE -- propose a second lineage instead, dedicated to
    # the canary path, so the two seed sources are genuinely independent.
    adaptation = propose_adaptation(
        tenant_id=tenant.id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key=_unique("support_agent.canary_prompt"),
        proposed_value="Be extra courteous.",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(tenant.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-2",
        created_by_user_id=actor.id,
        scope=AdaptationScope.TENANT,
    )
    comparison = EvaluationComparison(
        outcome=EvaluationOutcome.PASS,
        baseline_version="v0",
        candidate_version=str(adaptation.version),
        benchmark=Benchmark(benchmark_id="b", version="1"),
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=(),
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
    policy_decision = evaluate_and_record_policy_gate_decision(
        PolicyGateRequest(
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
                adr_reference="docs/ADR/0020-example.md", reliability_summary="stub"
            ),
            tier2_eligible_actions=frozenset({RequestedAction.ACTIVATE_ADAPTATION.value}),
        )
    )
    canary = create_canary(
        tenant_id=tenant.id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=EvaluationRules(thresholds=()),
        created_by_user_id=actor.id,
    )
    canary = start_canary(tenant.id, canary.id, started_by_user_id=actor.id)
    canary = conclude_canary_monitoring(tenant.id, canary.id, concluded_by_user_id=actor.id)
    canary = promote_canary(tenant.id, canary.id, promoted_by_user_id=actor.id)
    return canary


def test_loop_disabled_by_default_produces_no_seed(tenant_actor) -> None:
    tenant, actor = tenant_actor
    cycle = run_continuous_learning_cycle(
        tenant.id, trigger=LoopTrigger.MANUAL, actor_user_id=actor.id
    )
    assert cycle.outcome is LoopCycleOutcome.DISABLED
    assert cycle.seed is None

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.continuous_loop_cycle_completed"]
    assert len(matching) == 1
    assert matching[0].outcome == "denied"


def test_enabled_but_no_outcome_yet_is_a_safe_no_op(tenant_actor) -> None:
    """Non-vacuous: proven to be a safe no-op, never a forced/degraded
    promotion (Phase 9.9's own Tests bullet)."""
    tenant, actor = tenant_actor
    _enable_loop(tenant.id)
    cycle = run_continuous_learning_cycle(
        tenant.id, trigger=LoopTrigger.MANUAL, actor_user_id=actor.id
    )
    assert cycle.outcome is LoopCycleOutcome.NO_VIABLE_CANDIDATE
    assert cycle.seed is None

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.continuous_loop_cycle_completed"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"


def test_active_adaptation_seeds_the_next_cycle(tenant_actor) -> None:
    tenant, actor = tenant_actor
    _enable_loop(tenant.id)
    adaptation, _ = _activate_a_fresh_adaptation(tenant, actor)

    cycle = run_continuous_learning_cycle(tenant.id, trigger=LoopTrigger.SCHEDULED)
    assert cycle.outcome is LoopCycleOutcome.COMPLETED
    assert cycle.seed is not None
    assert cycle.seed.source_kind is LoopObservationSourceKind.ADAPTATION
    assert cycle.seed.source_id == adaptation.id
    assert cycle.seed.outcome_summary == AdaptationStatus.ACTIVE.value


def test_rollback_outcome_is_a_valid_seed(tenant_actor) -> None:
    """`rollback_adaptation()` updates both the rolled-back row and its
    reactivated-previous row inside the same transaction, so Postgres's
    `now()` (transaction-time, not statement-time) gives both the same
    `updated_at` -- which one wins the "most recent" tie is
    implementation-defined, not something this test asserts a specific
    side of. What matters, and is asserted here: the seed is a real,
    valid outcome from *this* rollback (one of the two rows it touched),
    never a fabricated or unrelated one."""
    tenant, actor = tenant_actor
    _enable_loop(tenant.id)
    v1, _ = _activate_a_fresh_adaptation(tenant, actor)
    v2 = propose_adaptation(
        tenant_id=tenant.id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key=v1.lineage_key,
        proposed_value="Be even more courteous.",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(tenant.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-3",
        created_by_user_id=actor.id,
        scope=AdaptationScope.TENANT,
    )
    v2 = record_adaptation_evaluation(
        tenant.id,
        v2.id,
        EvaluationComparison(
            outcome=EvaluationOutcome.PASS,
            baseline_version="v0",
            candidate_version=str(v2.version),
            benchmark=Benchmark(benchmark_id="b", version="1"),
            invalid_reason=None,
            failed_metrics=(),
            regressed_metrics=(),
        ),
    )
    v2 = activate_adaptation(tenant.id, v2.id, activated_by_user_id=actor.id)
    reactivated = rollback_adaptation(tenant.id, v2.id, rolled_back_by_user_id=actor.id)
    assert reactivated.id == v1.id

    cycle = run_continuous_learning_cycle(tenant.id, trigger=LoopTrigger.MANUAL)
    assert cycle.outcome is LoopCycleOutcome.COMPLETED
    assert cycle.seed is not None
    assert cycle.seed.source_kind is LoopObservationSourceKind.ADAPTATION
    assert cycle.seed.source_id in (v1.id, v2.id)
    assert cycle.seed.outcome_summary in (
        AdaptationStatus.ACTIVE.value,
        AdaptationStatus.ROLLED_BACK.value,
    )


def test_more_recent_canary_outcome_wins_over_older_adaptation(tenant_actor) -> None:
    tenant, actor = tenant_actor
    _enable_loop(tenant.id)
    canary = _promote_a_fresh_canary(
        tenant, actor
    )  # created after, and thus newer than, the adaptation

    cycle = run_continuous_learning_cycle(tenant.id, trigger=LoopTrigger.SCHEDULED)
    assert cycle.outcome is LoopCycleOutcome.COMPLETED
    assert cycle.seed is not None
    assert cycle.seed.source_kind is LoopObservationSourceKind.CANARY
    assert cycle.seed.source_id == canary.id
    assert cycle.seed.outcome_summary == CanaryStatus.PROMOTED.value


def test_cross_tenant_seed_never_leaks(tenant_actor) -> None:
    tenant_a, actor_a = tenant_actor
    _enable_loop(tenant_a.id)
    _activate_a_fresh_adaptation(tenant_a, actor_a)

    tenant_b = create_tenant(_unique("loop-tenant-b"))
    try:
        _enable_loop(tenant_b.id)
        cycle = run_continuous_learning_cycle(tenant_b.id, trigger=LoopTrigger.MANUAL)
        assert cycle.outcome is LoopCycleOutcome.NO_VIABLE_CANDIDATE
        assert cycle.seed is None
    finally:
        _admin_cleanup(tenant_b.id, [])


def test_duplicate_cycle_execution_is_safe(tenant_actor) -> None:
    """Running the same cycle twice (simulating a retried/duplicate job
    delivery) must never duplicate a mutation -- this module performs
    none, so both calls simply reproduce the same read-only seed."""
    tenant, actor = tenant_actor
    _enable_loop(tenant.id)
    adaptation, _ = _activate_a_fresh_adaptation(tenant, actor)

    first = run_continuous_learning_cycle(tenant.id, trigger=LoopTrigger.SCHEDULED)
    second = run_continuous_learning_cycle(tenant.id, trigger=LoopTrigger.SCHEDULED)

    assert first.outcome is second.outcome is LoopCycleOutcome.COMPLETED
    assert first.seed is not None
    assert second.seed is not None
    assert first.seed.source_id == second.seed.source_id == adaptation.id
    assert first.cycle_id != second.cycle_id  # two distinct, independent executions

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.continuous_loop_cycle_completed"]
    assert len(matching) == 2  # two audit entries, zero duplicate adaptations/canaries


def test_audit_metadata_never_contains_raw_candidate_content(tenant_actor) -> None:
    tenant, actor = tenant_actor
    _enable_loop(tenant.id)
    _activate_a_fresh_adaptation(tenant, actor)
    run_continuous_learning_cycle(tenant.id, trigger=LoopTrigger.MANUAL)

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.continuous_loop_cycle_completed"]
    assert matching
    for entry in matching:
        metadata_repr = repr(entry.entry_metadata)
        assert "Be courteous." not in metadata_repr
        assert "safe" not in (entry.entry_metadata or {})
        assert "authorized" not in (entry.entry_metadata or {})


# --------------------------------------------------------------------- #
# Recurring/scheduled execution via a real Redis-backed ARQ job -- Phase
# 9.9's own Security Requirement: "reuses infra/jobs' existing retry/
# dead-letter mechanism." Separately skippable from the database checks
# above: requires REDIS_URL, not just DATABASE_URL.
# --------------------------------------------------------------------- #


@pytest.fixture
def _jobs_config():
    return JobsConfig(
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        max_tries=2,
        retry_backoff_base_seconds=0.01,
    )


@pytest.fixture
def _job_queue_name() -> str:
    return f"continuous-loop-phase99-{uuid.uuid4().hex[:8]}"


@pytest.fixture
async def _require_reachable_redis(_jobs_config) -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(_jobs_config.redis_url))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    try:
        await pool.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}.")
    finally:
        await pool.aclose()


@pytest.mark.anyio
async def test_scheduled_job_delivered_twice_produces_two_independent_cycles(
    tenant_actor, _jobs_config, _job_queue_name, _require_reachable_redis
) -> None:
    """ "Same job delivered twice" (Phase 9.9's own Idempotency/Retry Tests
    requirement), exercised through the real `infra.jobs` ARQ path, not
    just a direct function call: no duplicate mutation results, because
    this module performs none -- see `service.py`'s own docstring."""
    tenant, actor = tenant_actor
    _enable_loop(tenant.id)
    _activate_a_fresh_adaptation(tenant, actor)

    functions = [register_job(_run_continuous_learning_cycle_job, config=_jobs_config)]
    worker = build_worker(functions, config=_jobs_config, burst=True, queue_name=_job_queue_name)
    try:
        pool = await get_redis_pool(_jobs_config)
        try:
            for _ in range(2):  # simulated duplicate delivery
                await enqueue_job(
                    _run_continuous_learning_cycle_job.__name__,
                    TenantJobPayload(tenant_id=str(tenant.id)),
                    pool=pool,
                    queue_name=_job_queue_name,
                )
        finally:
            await pool.aclose()

        await worker.main()
    finally:
        await worker.close()

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.continuous_loop_cycle_completed"]
    assert len(matching) == 2
    assert all(e.outcome == "success" for e in matching)
