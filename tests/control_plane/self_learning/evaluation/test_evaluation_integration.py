"""Integration test proving `control_plane.self_learning.evaluation
.service.run_evaluation()` writes exactly one real `core.audit_log`
entry per evaluation run (docs/IMPLEMENTATION-ROADMAP.md Phase 9.3's own
Audit Requirement: `learning.evaluation_run`, "including baseline/
candidate version and pass/fail outcome").

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/self_learning/evaluation/test_evaluation_integration.py
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
from control_plane.self_learning.evaluation import (
    Benchmark,
    EvaluationMetrics,
    EvaluationOutcome,
    EvaluationRules,
    EvaluationSubjectKind,
    EvaluationSubjectResult,
    MetricDirection,
    MetricThreshold,
    run_evaluation,
)
from control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)
from core.tenancy import create_tenant

pytestmark = [pytest.mark.integration]


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
            conn.execute(text("SELECT 1 FROM core.tenants LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.tenants not reachable: {exc}. "
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


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def fx():
    tenant = create_tenant(_unique("evaluation-tenant"))
    actor = create_user()
    yield tenant, actor
    _admin_delete_audit_log_for_tenant(tenant.id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(actor.id)})
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


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


RULES = EvaluationRules(
    thresholds=(
        MetricThreshold(
            metric_name="task_success_rate",
            direction=MetricDirection.HIGHER_IS_BETTER,
            minimum_absolute=0.5,
            maximum_regression=0.05,
        ),
    )
)


def test_pass_evaluation_is_audited(fx) -> None:
    tenant, actor = fx
    benchmark = Benchmark(benchmark_id="support-reply-quality", version="1")
    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version="prompt-v1",
        tenant_id=tenant.id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.8),
        learning_authorization_decision=_allow_decision(tenant.id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="prompt-v2",
        tenant_id=tenant.id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant.id),
    )

    comparison = run_evaluation(baseline, candidate, RULES, actor_user_id=actor.id)
    assert comparison.outcome is EvaluationOutcome.PASS

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.evaluation_run"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"
    assert matching[0].actor_user_id == actor.id
    assert matching[0].resource_id == str(comparison.decision_id)
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["baseline_version"] == "prompt-v1"
    assert matching[0].entry_metadata["candidate_version"] == "prompt-v2"
    assert matching[0].entry_metadata["evaluation_outcome"] == "pass"


def test_invalid_evaluation_benchmark_mismatch_is_audited(fx) -> None:
    tenant, actor = fx
    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version="prompt-v1",
        tenant_id=tenant.id,
        benchmark=Benchmark(benchmark_id="support-reply-quality", version="1"),
        metrics=EvaluationMetrics(task_success_rate=0.8),
        learning_authorization_decision=_allow_decision(tenant.id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="prompt-v2",
        tenant_id=tenant.id,
        benchmark=Benchmark(benchmark_id="support-reply-quality", version="2"),
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant.id),
    )

    comparison = run_evaluation(baseline, candidate, RULES, actor_user_id=actor.id)
    assert comparison.outcome.value == "invalid"

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.evaluation_run"]
    assert len(matching) == 1
    assert matching[0].outcome == "denied"
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["invalid_reason"] == "benchmark_mismatch"


def test_regression_evaluation_is_audited(fx) -> None:
    tenant, actor = fx
    benchmark = Benchmark(benchmark_id="support-reply-quality", version="1")
    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version="prompt-v1",
        tenant_id=tenant.id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant.id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="prompt-v2",
        tenant_id=tenant.id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.7),
        learning_authorization_decision=_allow_decision(tenant.id),
    )

    comparison = run_evaluation(baseline, candidate, RULES, actor_user_id=actor.id)
    assert comparison.outcome is EvaluationOutcome.REGRESSION

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.evaluation_run"]
    assert len(matching) == 1
    assert matching[0].outcome == "failure"
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["regressed_metrics"] == ["task_success_rate"]
    # never raw metric-bearing content beyond the declared numeric fields
    assert "self_reported_success" not in matching[0].entry_metadata
