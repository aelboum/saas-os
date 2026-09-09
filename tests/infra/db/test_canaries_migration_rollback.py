"""Migration reversibility test for the Phase 9.8 self_learning.canaries
migration (docs/IMPLEMENTATION-ROADMAP.md Phase 9.8; this task's own
Rollback requirement: "if a migration exists: downgrade, verify schema
removed, upgrade, verify schema restored" -- run against real disposable
PostgreSQL, not just inspected).

**Destructive**: this test downgrades past, then re-applies,
`426db78eb60f` (the canaries-table migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`self_learning.canaries`, then recreates it empty. Run this only against
a disposable database, never a shared development or production
database. Marked `integration` and excluded from the default `pytest`
run for exactly this reason, mirroring
`tests/infra/db/test_experiments_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_canaries_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

import core.identity.models  # noqa: F401
import pytest
from alembic import command
from alembic.config import Config
from core.identity.service import create_user
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.adaptive.models import AdaptationScope, AdaptationSurface
from control_plane.self_learning.adaptive.service import (
    propose_adaptation,
    record_adaptation_evaluation,
)
from control_plane.self_learning.autonomous_improvement.service import create_canary
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
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

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CANARIES_REVISION = "426db78eb60f"
_EXPERIMENTS_REVISION = "c0804e84948b"


@pytest.fixture(autouse=True)
def _require_reachable_privileged_database() -> None:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first -- "
            "see this file's module docstring."
        )
    finally:
        probe_engine.dispose()


def _alembic_config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _table_exists(table: str) -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'self_learning' AND table_name = :t)"
                ),
                {"t": table},
            ).scalar_one()
        return bool(row)
    finally:
        engine.dispose()


def _rls_flags(table: str) -> tuple[bool, bool] | None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relname = :t AND relnamespace = 'self_learning'::regnamespace"
                ),
                {"t": table},
            ).one_or_none()
        return (row[0], row[1]) if row is not None else None
    finally:
        engine.dispose()


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


def _seed_canary(tenant_id: uuid.UUID, agent_id: uuid.UUID) -> None:
    """Prove the schema this migration created is genuinely usable, not
    merely structurally present -- create a real Canary through the
    actual service layer."""
    adaptation = propose_adaptation(
        tenant_id=tenant_id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key=f"rollback-check-{uuid.uuid4().hex[:8]}",
        proposed_value="Be courteous.",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(tenant_id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-1",
        created_by_user_id=agent_id,
        scope=AdaptationScope.TENANT,
    )
    comparison = EvaluationComparison(
        outcome=EvaluationOutcome.PASS,
        baseline_version="v0",
        candidate_version=str(adaptation.version),
        benchmark=Benchmark(benchmark_id="rollback-check", version="1"),
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=(),
    )
    adaptation = record_adaptation_evaluation(tenant_id, adaptation.id, comparison)
    experiment = create_experiment(
        tenant_id=tenant_id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(tenant_id),
        evidence_type="tool_output",
        evidence_source_reference="rollback-seed",
        created_by_user_id=agent_id,
        adaptation=adaptation,
    )
    experiment = execute_experiment(tenant_id, experiment.id, executed_by_user_id=agent_id)
    experiment = record_experiment_result(
        tenant_id, experiment.id, comparison, recorded_by_user_id=agent_id
    )

    policy_decision = evaluate_and_record_policy_gate_decision(
        PolicyGateRequest(
            tenant_id=tenant_id,
            actor_user_id=agent_id,
            requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
            requested_autonomy_tier=AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED.value,
            scope=PolicyGateScope(
                authorized=frozenset({adaptation.lineage_key}),
                requested=frozenset({adaptation.lineage_key}),
            ),
            learning_authorization_decision=_allow_decision(tenant_id),
            evaluation_comparison=comparison,
            tier2_promotion_evidence=Tier2PromotionEvidence(
                adr_reference="docs/ADR/0020-example.md", reliability_summary="stub"
            ),
            tier2_eligible_actions=frozenset({RequestedAction.ACTIVATE_ADAPTATION.value}),
        )
    )
    create_canary(
        tenant_id=tenant_id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=EvaluationRules(
            thresholds=(
                MetricThreshold(
                    metric_name="error_rate",
                    direction=MetricDirection.LOWER_IS_BETTER,
                    maximum_absolute=0.1,
                ),
            )
        ),
        created_by_user_id=agent_id,
    )


def test_canaries_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    command.upgrade(cfg, "head")
    assert _table_exists("canaries")
    assert _rls_flags("canaries") == (True, True)
    assert _table_exists("experiments")
    assert _table_exists("adaptations")

    tenant = create_tenant(f"canaries-rollback-{uuid.uuid4().hex[:8]}")
    agent = create_user()
    try:
        _seed_canary(tenant.id, agent.id)

        try:
            command.downgrade(cfg, _EXPERIMENTS_REVISION)
            assert not _table_exists("canaries")
            assert _table_exists("experiments")
            assert _table_exists("adaptations")

            command.upgrade(cfg, _CANARIES_REVISION)
            assert _table_exists("canaries")
            assert _rls_flags("canaries") == (True, True)

            # Usable again post-re-upgrade: a fresh canary succeeds (the
            # old row was dropped with the table, which is expected --
            # this proves the *schema* is usable again, not that data
            # survived a destructive downgrade).
            _seed_canary(tenant.id, agent.id)
        finally:
            command.upgrade(cfg, "head")
    finally:
        admin_engine = build_engine(get_migrations_database_config())
        try:
            admin_factory = build_session_factory(admin_engine)
            with session_scope(session_factory=admin_factory) as session:
                session.execute(
                    text("DELETE FROM self_learning.canaries WHERE tenant_id = :t"),
                    {"t": str(tenant.id)},
                )
                session.execute(
                    text("DELETE FROM self_learning.experiments WHERE tenant_id = :t"),
                    {"t": str(tenant.id)},
                )
                session.execute(
                    text("DELETE FROM self_learning.adaptations WHERE tenant_id = :t"),
                    {"t": str(tenant.id)},
                )
                session.execute(
                    text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant.id)}
                )
        finally:
            admin_engine.dispose()
        with session_scope() as session:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(agent.id)})
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
