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
from control_plane.self_learning.evaluation import (
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
    run_evaluation,
    verify_evaluation_provenance,
)
from control_plane.self_learning.models import LearningAuthorizationDecision
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


def _allow_decision(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> LearningAuthorizationDecision:
    """CP-02 (Phase J, third pass): `run_evaluation()` now requires a
    genuine, matching `core.audit_log` provenance record for each
    subject's `LearningAuthorizationDecision` (see
    `control_plane.self_learning.service.verify_learning_authorization_provenance()`,
    invoked from `run_evaluation()` -- `evaluate_candidate()` itself is a
    pure function with no I/O, module docstring). A hand-built decision
    object (this helper's own previous implementation) is no longer
    sufficient -- it must be produced by the real `authorize_data_access()`
    -> `authorize_learning_use()` chain."""
    data_decision = authorize_data_access(
        DataAuthorizationRequest(
            tenant_id=tenant_id,
            data_classification="tenant_data",
            purpose="adaptive_prompt_tuning",
            provider="anthropic",
            resource_type="self_learning_evaluation_fixture",
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
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="prompt-v2",
        tenant_id=tenant.id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="prompt-v2",
        tenant_id=tenant.id,
        benchmark=Benchmark(benchmark_id="support-reply-quality", version="2"),
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="prompt-v2",
        tenant_id=tenant.id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.7),
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
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


def test_forged_learning_authorization_decision_is_rejected(fx) -> None:
    """CP-02 (Phase J, third pass): `run_evaluation()` must reject a
    plausible, hand-built `LearningAuthorizationDecision` on either
    subject -- correct tenant, correct outcome/purpose, but a fresh
    `decision_id` that `authorize_learning_use()` never audited. The
    comparison must downgrade to `INVALID`/`LEARNING_AUTHORIZATION_NOT_PASSED`,
    the same outcome `evaluate_candidate()` itself uses for a missing/
    non-ALLOW decision -- never PASS."""
    tenant, actor = fx
    benchmark = Benchmark(benchmark_id="support-reply-quality", version="1")
    genuine = _allow_decision(tenant.id, actor_user_id=actor.id)
    forged = LearningAuthorizationDecision(
        outcome=genuine.outcome,
        tenant_id=genuine.tenant_id,
        purpose=genuine.purpose,
        reason=None,
        data_authorization_decision_id=genuine.data_authorization_decision_id,
    )
    assert forged.decision_id != genuine.decision_id

    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version="prompt-v1",
        tenant_id=tenant.id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.8),
        learning_authorization_decision=forged,
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version="prompt-v2",
        tenant_id=tenant.id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
    )

    comparison = run_evaluation(baseline, candidate, RULES, actor_user_id=actor.id)
    assert comparison.outcome is EvaluationOutcome.INVALID
    assert comparison.invalid_reason is EvaluationInvalidReason.LEARNING_AUTHORIZATION_NOT_PASSED

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.evaluation_run"]
    assert len(matching) == 1
    assert matching[0].outcome == "denied"
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["invalid_reason"] == "learning_authorization_not_passed"


class TestVerifyEvaluationProvenance:
    """CP-04 (Phase J audit): `verify_evaluation_provenance()` -- the
    provenance check `record_adaptation_evaluation()`/
    `record_experiment_result()` require before trusting a caller-supplied
    `EvaluationComparison`. Mirrors
    `TestCP02ForgedLearningAuthorizationDecision`-style coverage in the
    adaptive/experiments integration suites, at the source."""

    def test_genuine_pass_result_verifies(self, fx) -> None:
        tenant, actor = fx
        benchmark = Benchmark(benchmark_id="support-reply-quality", version="1")
        baseline = EvaluationSubjectResult(
            kind=EvaluationSubjectKind.BASELINE,
            subject_version="prompt-v1",
            tenant_id=tenant.id,
            benchmark=benchmark,
            metrics=EvaluationMetrics(task_success_rate=0.8),
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
        )
        candidate = EvaluationSubjectResult(
            kind=EvaluationSubjectKind.CANDIDATE,
            subject_version="prompt-v2",
            tenant_id=tenant.id,
            benchmark=benchmark,
            metrics=EvaluationMetrics(task_success_rate=0.9),
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
        )
        comparison = run_evaluation(baseline, candidate, RULES, actor_user_id=actor.id)
        assert comparison.outcome is EvaluationOutcome.PASS

        assert verify_evaluation_provenance(comparison, tenant_id=tenant.id) is True

    def test_genuine_invalid_result_also_verifies(self, fx) -> None:
        """Provenance is about authenticity, not "is this a PASS" -- a
        genuinely-audited INVALID/FAIL/REGRESSION must verify too."""
        tenant, actor = fx
        baseline = EvaluationSubjectResult(
            kind=EvaluationSubjectKind.BASELINE,
            subject_version="prompt-v1",
            tenant_id=tenant.id,
            benchmark=Benchmark(benchmark_id="support-reply-quality", version="1"),
            metrics=EvaluationMetrics(task_success_rate=0.8),
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
        )
        candidate = EvaluationSubjectResult(
            kind=EvaluationSubjectKind.CANDIDATE,
            subject_version="prompt-v2",
            tenant_id=tenant.id,
            benchmark=Benchmark(benchmark_id="support-reply-quality", version="2"),
            metrics=EvaluationMetrics(task_success_rate=0.9),
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
        )
        comparison = run_evaluation(baseline, candidate, RULES, actor_user_id=actor.id)
        assert comparison.outcome is EvaluationOutcome.INVALID

        assert verify_evaluation_provenance(comparison, tenant_id=tenant.id) is True

    def test_forged_comparison_never_run_through_evaluator_is_rejected(self, fx) -> None:
        tenant, _actor = fx
        forged = EvaluationComparison(
            outcome=EvaluationOutcome.PASS,
            baseline_version="prompt-v1",
            candidate_version="prompt-v2",
            benchmark=None,
            invalid_reason=None,
            failed_metrics=(),
            regressed_metrics=(),
        )
        assert verify_evaluation_provenance(forged, tenant_id=tenant.id) is False

    def test_wrong_decision_id_is_rejected(self, fx) -> None:
        """A genuine comparison whose `decision_id` is swapped for a
        fresh, never-audited UUID must be rejected exactly like a fully
        hand-built one."""
        tenant, actor = fx
        benchmark = Benchmark(benchmark_id="support-reply-quality", version="1")
        baseline = EvaluationSubjectResult(
            kind=EvaluationSubjectKind.BASELINE,
            subject_version="prompt-v1",
            tenant_id=tenant.id,
            benchmark=benchmark,
            metrics=EvaluationMetrics(task_success_rate=0.8),
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
        )
        candidate = EvaluationSubjectResult(
            kind=EvaluationSubjectKind.CANDIDATE,
            subject_version="prompt-v2",
            tenant_id=tenant.id,
            benchmark=benchmark,
            metrics=EvaluationMetrics(task_success_rate=0.9),
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
        )
        genuine = run_evaluation(baseline, candidate, RULES, actor_user_id=actor.id)
        swapped = EvaluationComparison(
            outcome=genuine.outcome,
            baseline_version=genuine.baseline_version,
            candidate_version=genuine.candidate_version,
            benchmark=genuine.benchmark,
            invalid_reason=genuine.invalid_reason,
            failed_metrics=genuine.failed_metrics,
            regressed_metrics=genuine.regressed_metrics,
            # decision_id omitted -- fresh, never-audited UUID.
        )
        assert swapped.decision_id != genuine.decision_id

        assert verify_evaluation_provenance(swapped, tenant_id=tenant.id) is False

    def test_outcome_swap_on_a_genuine_decision_id_is_rejected(self, fx) -> None:
        """A genuinely-audited INVALID's own `decision_id` reused
        underneath a forged claim of `PASS` must be rejected -- proves
        the check compares the *claimed* outcome against the *specific*
        audited outcome for that exact `decision_id`, not merely "does
        any audit row exist for it"."""
        tenant, actor = fx
        baseline = EvaluationSubjectResult(
            kind=EvaluationSubjectKind.BASELINE,
            subject_version="prompt-v1",
            tenant_id=tenant.id,
            benchmark=Benchmark(benchmark_id="support-reply-quality", version="1"),
            metrics=EvaluationMetrics(task_success_rate=0.8),
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
        )
        candidate = EvaluationSubjectResult(
            kind=EvaluationSubjectKind.CANDIDATE,
            subject_version="prompt-v2",
            tenant_id=tenant.id,
            benchmark=Benchmark(benchmark_id="support-reply-quality", version="2"),
            metrics=EvaluationMetrics(task_success_rate=0.9),
            learning_authorization_decision=_allow_decision(tenant.id, actor_user_id=actor.id),
        )
        genuine_invalid = run_evaluation(baseline, candidate, RULES, actor_user_id=actor.id)
        assert genuine_invalid.outcome is EvaluationOutcome.INVALID

        claimed_pass = EvaluationComparison(
            outcome=EvaluationOutcome.PASS,
            baseline_version=genuine_invalid.baseline_version,
            candidate_version=genuine_invalid.candidate_version,
            benchmark=None,
            invalid_reason=None,
            failed_metrics=(),
            regressed_metrics=(),
            decision_id=genuine_invalid.decision_id,
        )

        assert verify_evaluation_provenance(claimed_pass, tenant_id=tenant.id) is False

    def test_cross_tenant_audit_row_does_not_authorize_another_tenant(self, fx) -> None:
        """An evaluation audit row genuinely produced for tenant A must
        not verify when checked against tenant B's context -- the query
        is tenant-scoped, matching every other CP-02/CP-04 provenance
        check in this codebase."""
        tenant_a, actor_a = fx
        tenant_b = create_tenant(_unique("evaluation-tenant-b"))
        try:
            benchmark = Benchmark(benchmark_id="support-reply-quality", version="1")
            baseline = EvaluationSubjectResult(
                kind=EvaluationSubjectKind.BASELINE,
                subject_version="prompt-v1",
                tenant_id=tenant_a.id,
                benchmark=benchmark,
                metrics=EvaluationMetrics(task_success_rate=0.8),
                learning_authorization_decision=_allow_decision(
                    tenant_a.id, actor_user_id=actor_a.id
                ),
            )
            candidate = EvaluationSubjectResult(
                kind=EvaluationSubjectKind.CANDIDATE,
                subject_version="prompt-v2",
                tenant_id=tenant_a.id,
                benchmark=benchmark,
                metrics=EvaluationMetrics(task_success_rate=0.9),
                learning_authorization_decision=_allow_decision(
                    tenant_a.id, actor_user_id=actor_a.id
                ),
            )
            comparison = run_evaluation(baseline, candidate, RULES, actor_user_id=actor_a.id)
            assert comparison.outcome is EvaluationOutcome.PASS

            assert verify_evaluation_provenance(comparison, tenant_id=tenant_a.id) is True
            assert verify_evaluation_provenance(comparison, tenant_id=tenant_b.id) is False
        finally:
            with session_scope() as session:
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_b.id)}
                )
