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

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

import saas_os.core.identity.models  # noqa: F401
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
from saas_os.control_plane.self_learning.adaptive.models import AdaptationScope, AdaptationSurface
from saas_os.control_plane.self_learning.adaptive.service import (
    propose_adaptation,
    record_adaptation_evaluation,
)
from saas_os.control_plane.self_learning.autonomous_improvement.service import create_canary
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
from saas_os.control_plane.self_learning.models import LearningAuthorizationDecision
from saas_os.control_plane.self_learning.policy_gate.models import (
    AutonomyTier,
    PolicyGateRequest,
    PolicyGateScope,
    RequestedAction,
    Tier2PromotionEvidence,
)
from saas_os.control_plane.self_learning.policy_gate.service import (
    evaluate_and_record_policy_gate_decision,
)
from saas_os.core.identity.service import create_user
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_migrations_database_config
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.session import build_session_factory, session_scope


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


def _allow_decision(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> LearningAuthorizationDecision:
    """CP-02: `propose_adaptation()` and `create_experiment()` require a
    genuine, matching `saas_os.core.audit_log` provenance record for the
    `LearningAuthorizationDecision` they are given
    (`saas_os.control_plane.self_learning.service.verify_learning_authorization_provenance()`).
    A hand-built decision object (this helper's previous implementation)
    is no longer sufficient -- it must come from the real
    `authorize_data_access()` -> `authorize_learning_use()` chain, the
    same fixture the autonomous-improvement integration test builds
    (RA-11-F4)."""
    data_decision = authorize_data_access(
        DataAuthorizationRequest(
            tenant_id=tenant_id,
            data_classification="tenant_data",
            purpose="adaptive_prompt_tuning",
            provider="anthropic",
            resource_type="self_learning_canaries_rollback_fixture",
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
    """CP-04: `record_adaptation_evaluation()`, `record_experiment_result()`
    and the policy gate require genuine
    `evaluation.service.verify_evaluation_provenance()` -- a hand-built
    `EvaluationComparison` (this file's previous fixture) is no longer
    sufficient. Produced by the real `run_evaluation()` so its audit trail
    is genuine, mirroring the autonomous-improvement integration test's own
    `_pass_comparison()` (RA-11-F4)."""
    benchmark = Benchmark(benchmark_id="canaries-rollback-fixture-benchmark", version="1")
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
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=agent_id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-1",
        created_by_user_id=agent_id,
        scope=AdaptationScope.TENANT,
    )
    comparison = _pass_comparison(
        tenant_id,
        actor_user_id=agent_id,
        baseline_version="v0",
        candidate_version=str(adaptation.version),
    )
    adaptation = record_adaptation_evaluation(tenant_id, adaptation.id, comparison)
    experiment = create_experiment(
        tenant_id=tenant_id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=agent_id),
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
            learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=agent_id),
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

    tenant = create_tenant(f"canaries-rollback-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
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

            # --- advance the rest of the way to head before touching the
            # service layer ---
            # `_seed_canary()` runs head's own ORM: `lock_open_tenant()` reads
            # `core.tenants.parent_id`/`inherits_billing` and the audit write
            # fills `saas_os.core.audit_log` columns that later migrations added
            # (`6b4f2d8a91c3`, `9aecff1d1135`, ...) -- none of which
            # exist at `_CANARIES_REVISION`. This test's own job is only to prove
            # `426db78eb60f` itself is reversible, not to freeze those shared
            # tables' shape at that one revision forever: a real rollback is
            # always immediately followed by re-running every migration back
            # to head, never stopped partway (same rationale as
            # tests/infra/db/test_api_keys_migration_rollback.py). Upgrading
            # here first is what keeps the usability proof below meaningful
            # (RA-11-F4).
            command.upgrade(cfg, "head")

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
            _admin_clear_audit_references({"id": str(agent.id)}, table="users")
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(agent.id)})
            _admin_clear_audit_references({"id": str(tenant.id)}, table="tenants")
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
