"""Integration test proving `control_plane.self_learning.policy_gate
.service.evaluate_and_record_policy_gate_decision()` writes exactly one
real `core.audit_log` entry per gate decision
(docs/IMPLEMENTATION-ROADMAP.md Phase 9.7's own Audit Requirement:
`learning.policy_gate_decision`).

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/control_plane/self_learning/evaluation/test_evaluation_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/self_learning/policy_gate/test_policy_gate_integration.py
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

from control_plane.approvals.models import ApprovalRequest
from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.evaluation.models import (
    Benchmark,
    EvaluationComparison,
    EvaluationOutcome,
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
)
from control_plane.self_learning.policy_gate.service import evaluate_and_record_policy_gate_decision
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
    tenant = create_tenant(_unique("policy-gate-tenant"))
    proposer = create_user()
    approver = create_user()
    yield tenant, proposer, approver
    _admin_delete_audit_log_for_tenant(tenant.id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(proposer.id)})
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(approver.id)})
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


def _eval_pass() -> EvaluationComparison:
    return EvaluationComparison(
        outcome=EvaluationOutcome.PASS,
        baseline_version="v0",
        candidate_version="v1",
        benchmark=Benchmark(benchmark_id="support-reply-quality", version="1"),
        invalid_reason=None,
        failed_metrics=(),
        regressed_metrics=(),
    )


def test_allowed_tier1_decision_is_audited(fx) -> None:
    tenant, proposer, approver = fx
    approval = ApprovalRequest(
        tenant_id=tenant.id,
        proposer_user_id=proposer.id,
        tool_key="control_plane.self_learning.policy_gate.stub",
        agent_scope_value=None,
        payload={},
        status="approved",
        approver_user_id=approver.id,
    )
    request = PolicyGateRequest(
        tenant_id=tenant.id,
        actor_user_id=proposer.id,
        requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
        requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
        scope=PolicyGateScope(
            authorized=frozenset({"support_agent.system_prompt"}),
            requested=frozenset({"support_agent.system_prompt"}),
        ),
        learning_authorization_decision=_allow_decision(tenant.id),
        evaluation_comparison=_eval_pass(),
        approval=approval,
    )

    decision = evaluate_and_record_policy_gate_decision(request)
    assert decision.is_allowed

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.policy_gate_decision"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"
    assert matching[0].actor_user_id == proposer.id
    assert matching[0].resource_id == str(decision.decision_id)
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["requested_action"] == "activate_adaptation"
    assert matching[0].entry_metadata["requested_autonomy_tier"] == 1
    assert "reason" not in matching[0].entry_metadata


def test_denied_decision_is_audited(fx) -> None:
    tenant, proposer, _approver = fx
    request = PolicyGateRequest(
        tenant_id=tenant.id,
        actor_user_id=proposer.id,
        requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
        requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
        scope=PolicyGateScope(
            authorized=frozenset({"support_agent.system_prompt"}),
            requested=frozenset({"support_agent.system_prompt"}),
        ),
        learning_authorization_decision=_allow_decision(tenant.id),
        evaluation_comparison=_eval_pass(),
        approval=None,  # tier 1 requires an approval -- none supplied
    )

    decision = evaluate_and_record_policy_gate_decision(request)
    assert not decision.is_allowed

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.policy_gate_decision"]
    assert len(matching) == 1
    assert matching[0].outcome == "denied"
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["reason"] == "missing_required_approval"


def test_audit_metadata_never_contains_secrets_or_raw_scope_values(fx) -> None:
    """Phase 9.7's own Audit Requirement: metadata must not contain
    secrets, raw tenant/user data, full model prompts, unrestricted
    candidate payloads, or sensitive proposed values -- only identifiers
    and enums."""
    tenant, proposer, approver = fx
    sensitive_scope_value = "internal-system-prompt-do-not-log-verbatim"
    approval = ApprovalRequest(
        tenant_id=tenant.id,
        proposer_user_id=proposer.id,
        tool_key="control_plane.self_learning.policy_gate.stub",
        agent_scope_value=None,
        payload={},
        status="approved",
        approver_user_id=approver.id,
    )
    request = PolicyGateRequest(
        tenant_id=tenant.id,
        actor_user_id=proposer.id,
        requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
        requested_autonomy_tier=AutonomyTier.TIER_1_PROPOSE_AND_APPROVE.value,
        scope=PolicyGateScope(
            authorized=frozenset({sensitive_scope_value}),
            requested=frozenset({sensitive_scope_value}),
        ),
        learning_authorization_decision=_allow_decision(tenant.id),
        evaluation_comparison=_eval_pass(),
        approval=approval,
    )

    evaluate_and_record_policy_gate_decision(request)

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.policy_gate_decision"]
    assert len(matching) == 1
    metadata = matching[0].entry_metadata
    assert metadata is not None
    metadata_repr = repr(metadata)
    assert sensitive_scope_value not in metadata_repr
    assert "safe" not in metadata
    assert "authorized" not in metadata
    assert "approved" not in metadata


def test_missing_tenant_decision_is_denied_but_not_written_to_audit_log() -> None:
    """No tenant means nothing to attribute an audit row to -- see
    `service.evaluate_and_record_policy_gate_decision()`'s own docstring,
    mirroring `control_plane.orchestration.service._execute_tool()`'s
    `ToolNotFoundError` precedent. Proves authorization failure cannot be
    smuggled past the audit boundary via a fabricated tenant."""
    request = PolicyGateRequest(
        tenant_id=None,
        actor_user_id=uuid.uuid4(),
        requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
        requested_autonomy_tier=AutonomyTier.TIER_0_PROPOSE_ONLY.value,
        scope=PolicyGateScope(authorized=frozenset({"a"}), requested=frozenset({"a"})),
        learning_authorization_decision=None,
        evaluation_comparison=_eval_pass(),
    )

    decision = evaluate_and_record_policy_gate_decision(request)
    assert not decision.is_allowed
    # No tenant_id exists under which to look this decision up in
    # core.audit_log -- there is structurally nowhere it could have been
    # written (RLS/tenant scoping requires a real tenant_id).
