"""Integration tests for `control_plane.self_learning.experiments`
against a real PostgreSQL instance (docs/IMPLEMENTATION-ROADMAP.md
Phase 9.6).

Covers: the full configure -> execute -> record-result lifecycle (both
COMPLETED and FAILED outcomes), cancellation as Phase 9.6's own Rollback
Strategy, every one of the four audited actions
(`learning.experiment_created` / `.executed` / `.result_recorded` /
`.cancelled`), and a dedicated cross-tenant adversarial check against the
real `self_learning.experiments` table -- mirroring
`tests/control_plane/self_learning/adaptive/test_adaptive_integration.py
.TestCrossTenantAdversarial`'s own discipline.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/self_learning/experiments/test_experiments_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.secrets.config import get_secrets_provider
from sqlalchemy import text

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.adaptive.models import (
    AdaptationSurface,
)
from control_plane.self_learning.adaptive.service import propose_adaptation
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationInvalidReason,
    EvaluationOutcome,
)
from control_plane.self_learning.experiments.errors import (
    ExperimentAlreadyTerminalError,
    ExperimentNotConfiguredError,
    ExperimentNotRunningError,
    ExperimentResultMismatchError,
)
from control_plane.self_learning.experiments.models import Experiment, ExperimentStatus
from control_plane.self_learning.experiments.service import (
    cancel_experiment,
    create_experiment,
    execute_experiment,
    get_experiment,
    record_experiment_result,
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
            conn.execute(text("SELECT 1 FROM self_learning.experiments LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/self_learning.experiments not reachable: {exc}. "
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


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _allow_decision(tenant_id: uuid.UUID) -> LearningAuthorizationDecision:
    data_decision = DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        data_classification="tenant_data",
        purpose="experiment_analysis",
        provider="anthropic",
        reason=None,
    )
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        purpose="experiment_analysis",
        reason=None,
        data_authorization_decision_id=data_decision.decision_id,
    )


def _pass_comparison(
    baseline_version: str = "v0", candidate_version: str = "1"
) -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.PASS,
        baseline_version=baseline_version,
        candidate_version=candidate_version,
        benchmark=Benchmark(benchmark_id="support-reply-quality", version="1"),
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=(),
    )


def _invalid_comparison(
    baseline_version: str = "v0", candidate_version: str = "1"
) -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.INVALID,
        baseline_version=baseline_version,
        candidate_version=candidate_version,
        benchmark=None,
        invalid_reason=EvaluationInvalidReason.BENCHMARK_MISMATCH,
        failed_metrics=(),
        regressed_metrics=(),
    )


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique("experiment-tenant"))
        self.agent = create_user()

    def cleanup(self) -> None:
        _admin_delete_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(self.agent.id)}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


def _adaptation_candidate(fx: _Fixture):
    return propose_adaptation(
        tenant_id=fx.tenant.id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key="support_agent.system_prompt",
        proposed_value="Be courteous.",
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(fx.tenant.id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback-1",
        created_by_user_id=fx.agent.id,
    )


def test_full_lifecycle_configure_execute_record_completed_is_audited(fx: _Fixture) -> None:
    adaptation = _adaptation_candidate(fx)
    experiment = create_experiment(
        tenant_id=fx.tenant.id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(fx.tenant.id),
        evidence_type="tool_output",
        evidence_source_reference="audit-1",
        created_by_user_id=fx.agent.id,
        adaptation=adaptation,
    )
    assert experiment.status == ExperimentStatus.CONFIGURED.value
    assert experiment.candidate_version == str(adaptation.version)

    experiment = execute_experiment(fx.tenant.id, experiment.id, executed_by_user_id=fx.agent.id)
    assert experiment.status == ExperimentStatus.RUNNING.value

    comparison = _pass_comparison(baseline_version="v0", candidate_version=str(adaptation.version))
    experiment = record_experiment_result(
        fx.tenant.id, experiment.id, comparison, recorded_by_user_id=fx.agent.id
    )
    assert experiment.status == ExperimentStatus.COMPLETED.value
    assert experiment.evaluation_outcome == "pass"

    entries = list_audit_entries(fx.tenant.id)
    actions = [e.action for e in entries if e.resource_id == str(experiment.id)]
    assert actions.count("learning.experiment_created") == 1
    assert actions.count("learning.experiment_executed") == 1
    assert actions.count("learning.experiment_result_recorded") == 1


def test_invalid_evaluation_marks_experiment_failed_not_completed(fx: _Fixture) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 9.6's own Tests requirement:
    "a failed/inconclusive experiment never silently proceeds to
    promotion"."""
    adaptation = _adaptation_candidate(fx)
    experiment = create_experiment(
        tenant_id=fx.tenant.id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(fx.tenant.id),
        evidence_type="tool_output",
        evidence_source_reference="audit-2",
        created_by_user_id=fx.agent.id,
        adaptation=adaptation,
    )
    experiment = execute_experiment(fx.tenant.id, experiment.id, executed_by_user_id=fx.agent.id)

    comparison = _invalid_comparison(
        baseline_version="v0", candidate_version=str(adaptation.version)
    )
    experiment = record_experiment_result(
        fx.tenant.id, experiment.id, comparison, recorded_by_user_id=fx.agent.id
    )
    assert experiment.status == ExperimentStatus.FAILED.value
    assert experiment.evaluation_outcome == "invalid"


def test_mismatched_comparison_is_rejected(fx: _Fixture) -> None:
    adaptation = _adaptation_candidate(fx)
    experiment = create_experiment(
        tenant_id=fx.tenant.id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(fx.tenant.id),
        evidence_type="tool_output",
        evidence_source_reference="audit-3",
        created_by_user_id=fx.agent.id,
        adaptation=adaptation,
    )
    experiment = execute_experiment(fx.tenant.id, experiment.id, executed_by_user_id=fx.agent.id)

    wrong_comparison = _pass_comparison(
        baseline_version="some-other-baseline", candidate_version="99"
    )
    with pytest.raises(ExperimentResultMismatchError):
        record_experiment_result(
            fx.tenant.id, experiment.id, wrong_comparison, recorded_by_user_id=fx.agent.id
        )


def test_record_result_before_execution_is_rejected(fx: _Fixture) -> None:
    adaptation = _adaptation_candidate(fx)
    experiment = create_experiment(
        tenant_id=fx.tenant.id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(fx.tenant.id),
        evidence_type="tool_output",
        evidence_source_reference="audit-4",
        created_by_user_id=fx.agent.id,
        adaptation=adaptation,
    )
    comparison = _pass_comparison(baseline_version="v0", candidate_version=str(adaptation.version))
    with pytest.raises(ExperimentNotRunningError):
        record_experiment_result(
            fx.tenant.id, experiment.id, comparison, recorded_by_user_id=fx.agent.id
        )


def test_double_execution_is_rejected(fx: _Fixture) -> None:
    adaptation = _adaptation_candidate(fx)
    experiment = create_experiment(
        tenant_id=fx.tenant.id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(fx.tenant.id),
        evidence_type="tool_output",
        evidence_source_reference="audit-5",
        created_by_user_id=fx.agent.id,
        adaptation=adaptation,
    )
    execute_experiment(fx.tenant.id, experiment.id, executed_by_user_id=fx.agent.id)
    with pytest.raises(ExperimentNotConfiguredError):
        execute_experiment(fx.tenant.id, experiment.id, executed_by_user_id=fx.agent.id)


def test_cancellation_from_configured_is_audited_as_rollback(fx: _Fixture) -> None:
    adaptation = _adaptation_candidate(fx)
    experiment = create_experiment(
        tenant_id=fx.tenant.id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(fx.tenant.id),
        evidence_type="tool_output",
        evidence_source_reference="audit-6",
        created_by_user_id=fx.agent.id,
        adaptation=adaptation,
    )
    cancelled = cancel_experiment(
        fx.tenant.id, experiment.id, cancelled_by_user_id=fx.agent.id, reason="no longer needed"
    )
    assert cancelled.status == ExperimentStatus.CANCELLED.value

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "learning.experiment_cancelled"]
    assert len(matching) == 1
    assert matching[0].entry_metadata is not None
    # never the free-text cancellation reason
    assert "no longer needed" not in str(matching[0].entry_metadata)


def test_cancellation_of_terminal_experiment_is_rejected(fx: _Fixture) -> None:
    adaptation = _adaptation_candidate(fx)
    experiment = create_experiment(
        tenant_id=fx.tenant.id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(fx.tenant.id),
        evidence_type="tool_output",
        evidence_source_reference="audit-7",
        created_by_user_id=fx.agent.id,
        adaptation=adaptation,
    )
    cancel_experiment(fx.tenant.id, experiment.id, cancelled_by_user_id=fx.agent.id)
    with pytest.raises(ExperimentAlreadyTerminalError):
        cancel_experiment(fx.tenant.id, experiment.id, cancelled_by_user_id=fx.agent.id)


class TestCrossTenantAdversarial:
    """The second persisted tenant-owned Self-Learning table (after
    `self_learning.adaptations`, Phase 9.4) -- a dedicated adversarial
    check against the real table, mirroring
    tests/control_plane/self_learning/adaptive/test_adaptive_integration.py
    .TestCrossTenantAdversarial and
    tests/core/tenancy/test_tenant_isolation_integration.py's own
    discipline."""

    def test_force_row_level_security_is_enabled_on_experiments(self, fx: _Fixture) -> None:
        engine = build_engine(get_migrations_database_config())
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                        "WHERE oid = 'self_learning.experiments'::regclass"
                    )
                ).one()
                assert row.relrowsecurity is True
                assert row.relforcerowsecurity is True
        finally:
            engine.dispose()

    def test_tenant_b_cannot_read_tenant_a_experiment(self, fx: _Fixture) -> None:
        tenant_b = create_tenant(_unique("experiment-tenant-b"))
        try:
            adaptation = _adaptation_candidate(fx)
            experiment = create_experiment(
                tenant_id=fx.tenant.id,
                baseline_version="v0",
                learning_authorization_decision=_allow_decision(fx.tenant.id),
                evidence_type="tool_output",
                evidence_source_reference="audit-8",
                created_by_user_id=fx.agent.id,
                adaptation=adaptation,
            )

            with tenant_session_scope(tenant_b.id) as session:
                leaked = session.get(Experiment, experiment.id)
                assert leaked is None

            with tenant_session_scope(tenant_b.id) as session:
                from sqlalchemy import select as sa_select

                rows = session.execute(sa_select(Experiment)).scalars().all()
                assert experiment.id not in {r.id for r in rows}
        finally:
            _admin_delete_for_tenant(tenant_b.id)
            with session_scope() as session:
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_b.id)}
                )

    def test_tenant_b_cannot_influence_or_execute_tenant_a_experiment(self, fx: _Fixture) -> None:
        """Adversarial: even knowing Tenant A's experiment id, Tenant B's
        own tenant-scoped session cannot execute/cancel/read it -- RLS
        makes the row invisible, so the service layer's own
        `ExperimentNotFoundError` (never a leaked "belongs to another
        tenant" distinction) is the only possible outcome."""
        tenant_b = create_tenant(_unique("experiment-tenant-b"))
        try:
            adaptation = _adaptation_candidate(fx)
            experiment = create_experiment(
                tenant_id=fx.tenant.id,
                baseline_version="v0",
                learning_authorization_decision=_allow_decision(fx.tenant.id),
                evidence_type="tool_output",
                evidence_source_reference="audit-9",
                created_by_user_id=fx.agent.id,
                adaptation=adaptation,
            )

            from control_plane.self_learning.experiments.errors import ExperimentNotFoundError

            with pytest.raises(ExperimentNotFoundError):
                execute_experiment(tenant_b.id, experiment.id, executed_by_user_id=fx.agent.id)
            with pytest.raises(ExperimentNotFoundError):
                cancel_experiment(tenant_b.id, experiment.id, cancelled_by_user_id=fx.agent.id)
            with pytest.raises(ExperimentNotFoundError):
                get_experiment(tenant_b.id, experiment.id)

            # Tenant A's own view is untouched by the attempted cross-tenant access.
            still_configured = get_experiment(fx.tenant.id, experiment.id)
            assert still_configured.status == ExperimentStatus.CONFIGURED.value
        finally:
            _admin_delete_for_tenant(tenant_b.id)
            with session_scope() as session:
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_b.id)}
                )

    def test_missing_tenant_context_returns_zero_rows(self, fx: _Fixture) -> None:
        adaptation = _adaptation_candidate(fx)
        create_experiment(
            tenant_id=fx.tenant.id,
            baseline_version="v0",
            learning_authorization_decision=_allow_decision(fx.tenant.id),
            evidence_type="tool_output",
            evidence_source_reference="audit-10",
            created_by_user_id=fx.agent.id,
            adaptation=adaptation,
        )
        with session_scope() as session:
            from sqlalchemy import select as sa_select

            rows = session.execute(sa_select(Experiment)).scalars().all()
            assert len(rows) == 0

    def test_direct_sql_bypass_under_restricted_runtime_role_fails(self, fx: _Fixture) -> None:
        """Application filtering alone is insufficient (Phase 9.6's own
        Tenant-Isolation Requirement) -- prove RLS itself, not just the
        ORM query layer, blocks cross-tenant reads even via raw SQL under
        the restricted `saas_os_app` runtime role with no tenant context
        set."""
        adaptation = _adaptation_candidate(fx)
        create_experiment(
            tenant_id=fx.tenant.id,
            baseline_version="v0",
            learning_authorization_decision=_allow_decision(fx.tenant.id),
            evidence_type="tool_output",
            evidence_source_reference="audit-11",
            created_by_user_id=fx.agent.id,
            adaptation=adaptation,
        )
        app_engine = build_engine(get_database_config())
        try:
            with app_engine.connect() as conn:
                rows = conn.execute(text("SELECT * FROM self_learning.experiments")).fetchall()
                assert len(rows) == 0
        finally:
            app_engine.dispose()
