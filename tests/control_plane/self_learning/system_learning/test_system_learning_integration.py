"""Integration test proving `control_plane.self_learning.system_learning
.service.propose_system_learning_proposal()` /
`.withdraw_system_learning_proposal()` write exactly one real
`core.audit_log` entry per call (docs/IMPLEMENTATION-ROADMAP.md Phase
9.5's own Audit Requirement: `learning.proposal_created` /
`.proposal_state_changed`), and that no raw evidence content reaches
audit metadata.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/self_learning/system_learning/test_system_learning_integration.py
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from infra.secrets.config import get_secrets_provider
from sqlalchemy import text

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.models import (
    CrossTenantLearningPolicy,
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
    LearningEvidence,
)
from control_plane.self_learning.system_learning.errors import CrossTenantProposalNotAuthorizedError
from control_plane.self_learning.system_learning.models import (
    PlatformWideProposalAuthorization,
    ProblemCategory,
    ProposalScope,
    ProposedChangeTarget,
    RiskLevel,
    SystemLearningObservation,
)
from control_plane.self_learning.system_learning.service import (
    detect_recurrence,
    propose_system_learning_proposal,
    withdraw_system_learning_proposal,
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
    tenant_a = create_tenant(_unique("system-learning-tenant-a"))
    tenant_b = create_tenant(_unique("system-learning-tenant-b"))
    actor = create_user()
    yield tenant_a, tenant_b, actor
    _admin_delete_audit_log_for_tenant(tenant_a.id)
    _admin_delete_audit_log_for_tenant(tenant_b.id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(actor.id)})
        session.execute(
            text("DELETE FROM core.tenants WHERE id IN (:a, :b)"),
            {"a": str(tenant_a.id), "b": str(tenant_b.id)},
        )


def _allow_decision(tenant_id: uuid.UUID) -> LearningAuthorizationDecision:
    data_decision = DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        data_classification="tenant_data",
        purpose="system_learning_analysis",
        provider="anthropic",
        reason=None,
    )
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        purpose="system_learning_analysis",
        reason=None,
        data_authorization_decision_id=data_decision.decision_id,
    )


def _recurrence():
    now = datetime.now(UTC)
    observations = tuple(
        SystemLearningObservation(
            tenant_id=uuid.uuid4(),
            observed_at=now + timedelta(hours=i),
            source_reference=f"ref-{i}",
        )
        for i in range(4)
    )
    return detect_recurrence(observations, window=timedelta(days=7), minimum_occurrences=3)


def test_proposal_creation_is_audited(fx) -> None:
    tenant_a, _tenant_b, actor = fx
    proposal = propose_system_learning_proposal(
        tenant_id=tenant_a.id,
        problem_category=ProblemCategory.LATENCY_PROBLEM,
        problem_description="p95 latency for the checkout agent exceeds 4s repeatedly.",
        evidence=LearningEvidence(evidence_type="tool_output", source_reference="audit-9"),
        learning_authorization_decision=_allow_decision(tenant_a.id),
        data_classification="tenant_data",
        recurrence=_recurrence(),
        proposed_change_target=ProposedChangeTarget.CACHING_STRATEGY,
        proposed_change_description="Cache the catalog lookup for 60s.",
        rationale="4 distinct latency spikes observed in the trailing 7 days.",
        risk_level=RiskLevel.LOW,
        created_by_user_id=actor.id,
    )

    entries = list_audit_entries(tenant_a.id)
    matching = [e for e in entries if e.action == "learning.proposal_created"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"
    assert matching[0].actor_user_id == actor.id
    assert matching[0].resource_id == str(proposal.proposal_id)
    assert matching[0].entry_metadata is not None
    # never the raw problem_description/proposed_change_description content
    assert "p95 latency" not in str(matching[0].entry_metadata)
    assert matching[0].entry_metadata["evidence_source_reference"] == "audit-9"


def test_proposal_creation_with_no_actor_user_is_audited_as_system(fx) -> None:
    tenant_a, _tenant_b, _actor = fx
    proposal = propose_system_learning_proposal(
        tenant_id=tenant_a.id,
        problem_category=ProblemCategory.LATENCY_PROBLEM,
        problem_description="Automated batch analysis detected recurring latency.",
        evidence=LearningEvidence(evidence_type="tool_output", source_reference="audit-10"),
        learning_authorization_decision=_allow_decision(tenant_a.id),
        data_classification="tenant_data",
        recurrence=_recurrence(),
        proposed_change_target=ProposedChangeTarget.CACHING_STRATEGY,
        proposed_change_description="Cache the catalog lookup for 60s.",
        rationale="Automated recurrence detection.",
        risk_level=RiskLevel.LOW,
    )
    entries = list_audit_entries(tenant_a.id)
    matching = [e for e in entries if e.resource_id == str(proposal.proposal_id)]
    assert len(matching) == 1
    assert matching[0].actor_type == "system"
    assert matching[0].actor_user_id is None


def test_withdrawal_is_audited_as_a_state_change(fx) -> None:
    tenant_a, _tenant_b, actor = fx
    proposal = propose_system_learning_proposal(
        tenant_id=tenant_a.id,
        problem_category=ProblemCategory.LATENCY_PROBLEM,
        problem_description="Recurring latency spikes.",
        evidence=LearningEvidence(evidence_type="tool_output", source_reference="audit-11"),
        learning_authorization_decision=_allow_decision(tenant_a.id),
        data_classification="tenant_data",
        recurrence=_recurrence(),
        proposed_change_target=ProposedChangeTarget.CACHING_STRATEGY,
        proposed_change_description="Cache the catalog lookup for 60s.",
        rationale="4 distinct latency spikes.",
        risk_level=RiskLevel.LOW,
        created_by_user_id=actor.id,
    )
    withdraw_system_learning_proposal(proposal, withdrawn_by_user_id=actor.id)

    entries = list_audit_entries(tenant_a.id)
    matching = [e for e in entries if e.action == "learning.proposal_state_changed"]
    assert len(matching) == 1
    assert matching[0].resource_id == str(proposal.proposal_id)
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["new_status"] == "withdrawn"


def test_cross_tenant_proposal_without_policy_is_denied_and_never_audited_as_created(fx) -> None:
    """Adversarial cross-tenant path: no `core.audit_log` entry claims a
    proposal was created naming an unauthorized affected tenant."""
    tenant_a, tenant_b, actor = fx
    with pytest.raises(CrossTenantProposalNotAuthorizedError):
        propose_system_learning_proposal(
            tenant_id=tenant_a.id,
            problem_category=ProblemCategory.LATENCY_PROBLEM,
            problem_description="Recurring latency spikes.",
            evidence=LearningEvidence(evidence_type="tool_output", source_reference="audit-12"),
            learning_authorization_decision=_allow_decision(tenant_a.id),
            data_classification="tenant_data",
            recurrence=_recurrence(),
            proposed_change_target=ProposedChangeTarget.CACHING_STRATEGY,
            proposed_change_description="Cache the catalog lookup for 60s.",
            rationale="4 distinct latency spikes.",
            risk_level=RiskLevel.LOW,
            created_by_user_id=actor.id,
            scope=ProposalScope.PLATFORM_WIDE,
            platform_wide_authorization=PlatformWideProposalAuthorization(
                authorized_purposes=frozenset({"system_learning_analysis"})
            ),
            affected_tenant_ids=frozenset({tenant_a.id, tenant_b.id}),
            cross_tenant_policy=None,
        )

    entries_a = list_audit_entries(tenant_a.id)
    entries_b = list_audit_entries(tenant_b.id)
    assert not [e for e in entries_a if e.action == "learning.proposal_created"]
    assert not [e for e in entries_b if e.action == "learning.proposal_created"]


def test_authorized_cross_tenant_proposal_is_created_and_audited_under_source_tenant(fx) -> None:
    tenant_a, tenant_b, actor = fx
    policy = CrossTenantLearningPolicy(
        source_tenant_id=tenant_a.id,
        target_tenant_id=tenant_b.id,
        approved_purposes=frozenset({"system_learning_analysis"}),
    )
    proposal = propose_system_learning_proposal(
        tenant_id=tenant_a.id,
        problem_category=ProblemCategory.LATENCY_PROBLEM,
        problem_description="Recurring latency spikes affecting both tenants' shared model route.",
        evidence=LearningEvidence(evidence_type="tool_output", source_reference="audit-13"),
        learning_authorization_decision=_allow_decision(tenant_a.id),
        data_classification="tenant_data",
        recurrence=_recurrence(),
        proposed_change_target=ProposedChangeTarget.MODEL_SELECTION_ROUTING,
        proposed_change_description="Switch the shared route to a lower-latency model.",
        rationale="4 distinct latency spikes.",
        risk_level=RiskLevel.MEDIUM,
        created_by_user_id=actor.id,
        scope=ProposalScope.PLATFORM_WIDE,
        platform_wide_authorization=PlatformWideProposalAuthorization(
            authorized_purposes=frozenset({"system_learning_analysis"})
        ),
        affected_tenant_ids=frozenset({tenant_a.id, tenant_b.id}),
        cross_tenant_policy=policy,
    )
    assert proposal.affected_tenant_ids == frozenset({tenant_a.id, tenant_b.id})

    entries_a = list_audit_entries(tenant_a.id)
    matching = [e for e in entries_a if e.action == "learning.proposal_created"]
    assert len(matching) == 1
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["affected_tenant_count"] == 2
