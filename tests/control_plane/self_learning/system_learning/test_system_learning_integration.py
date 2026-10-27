"""Integration test proving `saas_os.control_plane.self_learning.system_learning
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

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta

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
    TenantLearningPolicy,
    authorize_learning_use,
)
from saas_os.control_plane.self_learning.models import (
    CrossTenantLearningPolicy,
    LearningAuthorizationDecision,
    LearningEvidence,
)
from saas_os.control_plane.self_learning.system_learning.errors import (
    CrossTenantProposalNotAuthorizedError,
    UnauthorizedProposalEvidenceError,
    UnrecordedProposalError,
)
from saas_os.control_plane.self_learning.system_learning.models import (
    PlatformWideProposalAuthorization,
    ProblemCategory,
    ProposalScope,
    ProposedChangeTarget,
    RiskLevel,
    SystemLearningObservation,
)
from saas_os.control_plane.self_learning.system_learning.service import (
    build_system_learning_proposal,
    detect_recurrence,
    propose_system_learning_proposal,
    withdraw_system_learning_proposal,
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
    tenant_a = create_tenant(_unique("system-learning-tenant-a"), caller=PROVISIONING)
    tenant_b = create_tenant(_unique("system-learning-tenant-b"), caller=PROVISIONING)
    actor = create_user()
    yield tenant_a, tenant_b, actor
    _admin_delete_audit_log_for_tenant(tenant_a.id)
    _admin_delete_audit_log_for_tenant(tenant_b.id)
    with session_scope() as session:
        _admin_clear_audit_references({"id": str(actor.id)}, table="users")
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(actor.id)})
        _admin_clear_audit_references(
            {"a": str(tenant_a.id), "b": str(tenant_b.id)}, table="tenants"
        )
        session.execute(
            text("DELETE FROM core.tenants WHERE id IN (:a, :b)"),
            {"a": str(tenant_a.id), "b": str(tenant_b.id)},
        )


def _allow_decision(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> LearningAuthorizationDecision:
    """CP-02 (Phase J, third pass): `propose_system_learning_proposal()`
    now requires a genuine, matching `saas_os.core.audit_log` provenance record
    for the `LearningAuthorizationDecision` it is given (see
    `saas_os.control_plane.self_learning.service.verify_learning_authorization_provenance()`).
    A hand-built decision object (this helper's own previous
    implementation) is no longer sufficient -- it must be produced by the
    real `authorize_data_access()` -> `authorize_learning_use()` chain.
    `actor_user_id` is only the actor for *this upstream authorization
    chain* -- independent of whatever `created_by_user_id` (including
    `None`, for the "system" actor tests) is passed to
    `propose_system_learning_proposal()` itself."""
    data_decision = authorize_data_access(
        DataAuthorizationRequest(
            tenant_id=tenant_id,
            data_classification="tenant_data",
            purpose="system_learning_analysis",
            provider="anthropic",
            resource_type="self_learning_system_learning_fixture",
            resource_id="fixture",
        ),
        tenant_policy=TenantAIDataPolicy(
            tenant_id=tenant_id,
            allowed_data_classifications=frozenset({"tenant_data"}),
            allowed_purposes=frozenset({"system_learning_analysis"}),
            allowed_providers=frozenset({"anthropic"}),
        ),
        provider_policy=ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"})),
        actor_user_id=actor_user_id,
    )
    return authorize_learning_use(
        LearningAuthorizationRequest(
            tenant_id=tenant_id,
            purpose="system_learning_analysis",
            target_model_or_provider="anthropic",
            retention="30d",
            evidence=LearningEvidence(
                evidence_type="user_feedback", source_reference="fixture-evidence"
            ),
        ),
        data_authorization_decision=data_decision,
        tenant_learning_policy=TenantLearningPolicy(
            tenant_id=tenant_id,
            allowed_purposes=frozenset({"system_learning_analysis"}),
            allowed_models_or_providers=frozenset({"anthropic"}),
            allowed_retentions=frozenset({"30d"}),
        ),
        actor_user_id=actor_user_id,
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
        learning_authorization_decision=_allow_decision(tenant_a.id, actor_user_id=actor.id),
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
    tenant_a, _tenant_b, actor = fx
    proposal = propose_system_learning_proposal(
        tenant_id=tenant_a.id,
        problem_category=ProblemCategory.LATENCY_PROBLEM,
        problem_description="Automated batch analysis detected recurring latency.",
        evidence=LearningEvidence(evidence_type="tool_output", source_reference="audit-10"),
        learning_authorization_decision=_allow_decision(tenant_a.id, actor_user_id=actor.id),
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
        learning_authorization_decision=_allow_decision(tenant_a.id, actor_user_id=actor.id),
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


def _withdrawal_proposal(tenant_id, actor_id, reference: str, *, record: bool):
    """A proposal for the withdrawal tests: proposed (recorded in the audit
    log) when `record`, otherwise only built in memory."""
    make = propose_system_learning_proposal if record else build_system_learning_proposal
    return make(
        tenant_id=tenant_id,
        problem_category=ProblemCategory.LATENCY_PROBLEM,
        problem_description="Recurring latency spikes.",
        evidence=LearningEvidence(evidence_type="tool_output", source_reference=reference),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_id),
        data_classification="tenant_data",
        recurrence=_recurrence(),
        proposed_change_target=ProposedChangeTarget.CACHING_STRATEGY,
        proposed_change_description="Cache the catalog lookup for 60s.",
        rationale="4 distinct latency spikes.",
        risk_level=RiskLevel.LOW,
        created_by_user_id=actor_id,
    )


def _state_changes(tenant_id) -> list[object]:
    return [
        e for e in list_audit_entries(tenant_id) if e.action == "learning.proposal_state_changed"
    ]


def test_a_proposal_never_proposed_cannot_be_withdrawn(fx) -> None:
    """A proposal built in memory, with no `learning.proposal_created`
    record, writes no state-change row."""
    tenant_a, _tenant_b, actor = fx
    built = _withdrawal_proposal(tenant_a.id, actor.id, "audit-13", record=False)
    with pytest.raises(UnrecordedProposalError):
        withdraw_system_learning_proposal(built, withdrawn_by_user_id=actor.id)
    assert _state_changes(tenant_a.id) == []


def test_a_proposal_is_withdrawn_once(fx) -> None:
    tenant_a, _tenant_b, actor = fx
    proposal = _withdrawal_proposal(tenant_a.id, actor.id, "audit-14", record=True)
    withdraw_system_learning_proposal(proposal, withdrawn_by_user_id=actor.id)
    with pytest.raises(UnrecordedProposalError):
        withdraw_system_learning_proposal(proposal, withdrawn_by_user_id=actor.id)
    assert len(_state_changes(tenant_a.id)) == 1


def test_a_proposal_moved_to_another_tenant_cannot_be_withdrawn_there(fx) -> None:
    """The record is looked up in the proposal's own tenant only: a copy
    naming another tenant finds nothing there and writes nothing."""
    tenant_a, tenant_b, actor = fx
    proposal = _withdrawal_proposal(tenant_a.id, actor.id, "audit-15", record=True)
    moved = dataclasses.replace(
        proposal, tenant_id=tenant_b.id, affected_tenant_ids=frozenset({tenant_b.id})
    )
    with pytest.raises(UnrecordedProposalError):
        withdraw_system_learning_proposal(moved, withdrawn_by_user_id=actor.id)
    assert _state_changes(tenant_b.id) == []
    assert _state_changes(tenant_a.id) == []


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
            learning_authorization_decision=_allow_decision(tenant_a.id, actor_user_id=actor.id),
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
        learning_authorization_decision=_allow_decision(tenant_a.id, actor_user_id=actor.id),
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


def test_forged_learning_authorization_decision_is_rejected(fx) -> None:
    """CP-02 (Phase J, third pass): `propose_system_learning_proposal()`
    must reject a plausible, hand-built `LearningAuthorizationDecision` --
    correct tenant, correct outcome/purpose, but a fresh `decision_id`
    that `authorize_learning_use()` never audited. This check lives in
    the audited wrapper, not `build_system_learning_proposal()` (a pure
    function with no I/O) -- see that module's own docstring."""
    tenant_a, _tenant_b, actor = fx
    genuine = _allow_decision(tenant_a.id, actor_user_id=actor.id)
    forged = LearningAuthorizationDecision(
        outcome=genuine.outcome,
        tenant_id=genuine.tenant_id,
        purpose=genuine.purpose,
        reason=None,
        data_authorization_decision_id=genuine.data_authorization_decision_id,
    )
    assert forged.decision_id != genuine.decision_id

    with pytest.raises(UnauthorizedProposalEvidenceError):
        propose_system_learning_proposal(
            tenant_id=tenant_a.id,
            problem_category=ProblemCategory.LATENCY_PROBLEM,
            problem_description="Recurring latency spikes.",
            evidence=LearningEvidence(evidence_type="tool_output", source_reference="audit-forged"),
            learning_authorization_decision=forged,
            data_classification="tenant_data",
            recurrence=_recurrence(),
            proposed_change_target=ProposedChangeTarget.CACHING_STRATEGY,
            proposed_change_description="Cache the catalog lookup for 60s.",
            rationale="4 distinct latency spikes.",
            risk_level=RiskLevel.LOW,
            created_by_user_id=actor.id,
        )

    entries = list_audit_entries(tenant_a.id)
    assert not [e for e in entries if e.action == "learning.proposal_created"]
