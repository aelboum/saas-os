"""PRIV-03 Phase P5 -- AI Control Plane work drain / fencing, against a
real PostgreSQL instance.

Proves the P5 invariants end to end, through the real gates:

- A: a DELETED / PURGING / PURGED tenant can create no AI work on any of
     the four creator paths (`propose_action`, `propose_adaptation`,
     `create_experiment`, `create_canary`) nor queue a loop cycle.
- B/C: nothing executes for a closed tenant -- an already-APPROVED
     approval, a tier-0 tool, a genuine still-valid Data Authorization
     decision, a RUNNING canary's automatic rollback, a queued loop cycle
     -- and existing artifacts are left inert, never resurrected.
- D: Tool / Data / Learning Authorization and provenance remain required
     on an open tenant exactly as before; the fence is additive.
- E: stale decisions/approvals cannot carry work across the lifecycle
     boundary (execution re-reads tenant state, inside the transaction).
- F: draining tenant A never touches tenant B.
- Races: create-vs-PURGING and execute-vs-PURGING are serialized on the
     `core.tenants` row (FOR SHARE vs FOR UPDATE), so the create/claim
     either commits before the transition or fails closed after it --
     never a row for a tenant that became closed in the same instant.

Every observation of persisted state goes through the privileged
migrations role so RLS cannot hide anything; every action under test runs
as the ordinary application role.

Marked `integration`, excluded from the default `pytest` run, mirroring
`tests/control_plane/approvals/test_approvals_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/control_plane/test_tenant_lifecycle_fencing_integration.py
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from control_plane.approvals.service import (
    approve,
    execute_approved,
    get_approval,
    propose_action,
    reject,
)
from control_plane.data_authorization import (
    DataAuthorizationRequest,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    authorize_data_access,
)
from control_plane.orchestration.errors import (
    DataAuthorizationRequiredError,
    UnauthorizedToolInvocationError,
)
from control_plane.orchestration.service import invoke_tool
from control_plane.orchestration.tools import ToolDefinition, ToolExecutionContext, ToolRegistry
from control_plane.self_learning import (
    LearningAuthorizationRequest,
    LearningEvidence,
    TenantLearningPolicy,
    authorize_learning_use,
)
from control_plane.self_learning.adaptive.models import (
    AdaptationScope,
    AdaptationStatus,
    AdaptationSurface,
)
from control_plane.self_learning.adaptive.service import (
    activate_adaptation,
    get_adaptation,
    propose_adaptation,
    record_adaptation_evaluation,
)
from control_plane.self_learning.autonomous_improvement.models import CanaryStatus
from control_plane.self_learning.autonomous_improvement.service import (
    create_canary,
    get_canary,
    record_canary_observation,
    start_canary,
)
from control_plane.self_learning.continuous_loop.models import LoopCycleOutcome, LoopTrigger
from control_plane.self_learning.continuous_loop.service import (
    _run_continuous_learning_cycle_job,
    run_continuous_learning_cycle,
    trigger_continuous_learning_cycle,
)
from control_plane.self_learning.evaluation.models import (
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
from control_plane.self_learning.evaluation.service import run_evaluation
from control_plane.self_learning.experiments.service import (
    create_experiment,
    execute_experiment,
    record_experiment_result,
)
from control_plane.self_learning.models import LearningAuthorizationDecision
from control_plane.self_learning.policy_gate.models import (
    AutonomyTier,
    PolicyGateRequest,
    PolicyGateScope,
    RequestedAction,
    Tier2PromotionEvidence,
)
from control_plane.self_learning.policy_gate.service import evaluate_and_record_policy_gate_decision
from core.tenancy import (
    Tenant,
    TenantClosedError,
    TenantStatus,
    create_tenant,
    get_tenant,
    purge_tenant,
    transition_tenant_status,
)
from infra.jobs import TenantJobPayload
from infra.secrets import get_secrets_provider

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_CLOSED = [TenantStatus.DELETED, TenantStatus.PURGING, TenantStatus.PURGED]
_AI_TABLES = (
    "control_plane.approval_requests",
    "self_learning.experiments",
    "self_learning.adaptations",
    "self_learning.canaries",
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
        pytest.skip(f"PostgreSQL/self_learning.canaries not reachable: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture(autouse=True)
def _environment_secrets_provider(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_secrets_provider.cache_clear()
    yield
    get_secrets_provider.cache_clear()


@pytest.fixture
def admin() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def _unique(prefix: str) -> str:
    return f"priv03-p5-{prefix}-{uuid.uuid4().hex[:8]}"


def _count(admin: sessionmaker[Session], table: str, tenant_id: uuid.UUID) -> int:
    with session_scope(session_factory=admin) as session:
        return session.execute(
            text(f"SELECT count(*) FROM {table} WHERE tenant_id = :t"),  # noqa: S608 -- fixed names
            {"t": str(tenant_id)},
        ).scalar_one()


def _close(tenant_id: uuid.UUID, status: TenantStatus) -> None:
    """Walk an ACTIVE tenant to `status` through the real lifecycle."""
    transition_tenant_status(tenant_id, TenantStatus.DELETED)
    if status is TenantStatus.PURGING:
        transition_tenant_status(tenant_id, TenantStatus.PURGING)
    elif status is TenantStatus.PURGED:
        purge_tenant(tenant_id)


# --- tools -------------------------------------------------------------------


async def _stub_handler(context: ToolExecutionContext, payload) -> dict[str, object]:
    return {"executed": True}


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            key="p5.tier1.repo",
            description="tier-1, repository-scoped (no RBAC) stub",
            handler=_stub_handler,
            required_scope_type="repository",
            required_scope_value="example/sandbox-repo",
            autonomy_tier=1,
        )
    )
    registry.register(
        ToolDefinition(
            key="p5.tier0.repo",
            description="tier-0, repository-scoped (no RBAC) stub",
            handler=_stub_handler,
            required_scope_type="repository",
            required_scope_value="example/sandbox-repo",
            autonomy_tier=0,
        )
    )
    registry.register(
        ToolDefinition(
            key="p5.tier0.tenant",
            description="tier-0, tenant-scoped (RBAC) stub",
            handler=_stub_handler,
            required_scope_type="tenant",
            required_resource="p5.widget",
            required_action="poke",
            autonomy_tier=0,
        )
    )
    registry.register(
        ToolDefinition(
            key="p5.tier0.data",
            description="tier-0, repository-scoped, needs Data Authorization",
            handler=_stub_handler,
            required_scope_type="repository",
            required_scope_value="example/sandbox-repo",
            autonomy_tier=0,
            requires_data_authorization=True,
        )
    )
    return registry


# --- genuine decisions (real audited chains, never hand-built) ---------------


def _data_decision(tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID):
    return authorize_data_access(
        DataAuthorizationRequest(
            tenant_id=tenant_id,
            data_classification="tenant_data",
            purpose="adaptive_prompt_tuning",
            provider="anthropic",
            resource_type="p5_fixture",
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


def _allow_decision(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> LearningAuthorizationDecision:
    return authorize_learning_use(
        LearningAuthorizationRequest(
            tenant_id=tenant_id,
            purpose="adaptive_prompt_tuning",
            target_model_or_provider="anthropic",
            retention="30d",
            evidence=LearningEvidence(evidence_type="user_feedback", source_reference="fixture"),
        ),
        data_authorization_decision=_data_decision(tenant_id, actor_user_id=actor_user_id),
        tenant_learning_policy=TenantLearningPolicy(
            tenant_id=tenant_id,
            allowed_purposes=frozenset({"adaptive_prompt_tuning"}),
            allowed_models_or_providers=frozenset({"anthropic"}),
            allowed_retentions=frozenset({"30d"}),
        ),
        actor_user_id=actor_user_id,
    )


_RULES = EvaluationRules(
    thresholds=(
        MetricThreshold(
            metric_name="task_success_rate",
            direction=MetricDirection.HIGHER_IS_BETTER,
            minimum_absolute=0.5,
        ),
    )
)
_MONITORING_RULES = EvaluationRules(
    thresholds=(
        MetricThreshold(
            metric_name="error_rate",
            direction=MetricDirection.LOWER_IS_BETTER,
            maximum_absolute=0.1,
        ),
    )
)


def _pass_comparison(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID, baseline_version: str, candidate_version: str
) -> EvaluationComparison:
    benchmark = Benchmark(benchmark_id="p5-benchmark", version="1")
    baseline = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.BASELINE,
        subject_version=baseline_version,
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.8),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    candidate = EvaluationSubjectResult(
        kind=EvaluationSubjectKind.CANDIDATE,
        subject_version=candidate_version,
        tenant_id=tenant_id,
        benchmark=benchmark,
        metrics=EvaluationMetrics(task_success_rate=0.9),
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
    )
    comparison = run_evaluation(baseline, candidate, _RULES, actor_user_id=actor_user_id)
    assert comparison.outcome is EvaluationOutcome.PASS
    return comparison


def _propose(tenant_id: uuid.UUID, actor_user_id: uuid.UUID, lineage_key: str, value: str):
    return propose_adaptation(
        tenant_id=tenant_id,
        surface=AdaptationSurface.PROMPT_INSTRUCTION,
        lineage_key=lineage_key,
        proposed_value=value,
        learning_purpose="adaptive_prompt_tuning",
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
        evidence_type="user_feedback",
        evidence_source_reference="feedback",
        created_by_user_id=actor_user_id,
        scope=AdaptationScope.TENANT,
    )


def _ready_canary_inputs(tenant_id: uuid.UUID, actor_user_id: uuid.UUID):
    """A real, PASS-evaluated Adaptation (with an already-ACTIVE previous
    version so rollback is possible) + COMPLETED Experiment + tier-2 ALLOW
    PolicyGateDecision -- everything `create_canary()` requires."""
    lineage = _unique("lineage")
    previous = _propose(tenant_id, actor_user_id, lineage, "Be polite.")
    record_adaptation_evaluation(
        tenant_id,
        previous.id,
        _pass_comparison(
            tenant_id,
            actor_user_id=actor_user_id,
            baseline_version="v-1",
            candidate_version=str(previous.version),
        ),
    )
    activate_adaptation(tenant_id, previous.id, activated_by_user_id=actor_user_id)

    adaptation = _propose(tenant_id, actor_user_id, lineage, "Be courteous.")
    comparison = _pass_comparison(
        tenant_id,
        actor_user_id=actor_user_id,
        baseline_version="v0",
        candidate_version=str(adaptation.version),
    )
    adaptation = record_adaptation_evaluation(tenant_id, adaptation.id, comparison)
    experiment = create_experiment(
        tenant_id=tenant_id,
        baseline_version="v0",
        learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
        evidence_type="tool_output",
        evidence_source_reference="experiment-seed",
        created_by_user_id=actor_user_id,
        adaptation=adaptation,
    )
    experiment = execute_experiment(tenant_id, experiment.id, executed_by_user_id=actor_user_id)
    experiment = record_experiment_result(
        tenant_id, experiment.id, comparison, recorded_by_user_id=actor_user_id
    )
    policy_decision = evaluate_and_record_policy_gate_decision(
        PolicyGateRequest(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            requested_action=RequestedAction.ACTIVATE_ADAPTATION.value,
            requested_autonomy_tier=AutonomyTier.TIER_2_AUTO_EXECUTE_AUDITED.value,
            scope=PolicyGateScope(authorized=frozenset({lineage}), requested=frozenset({lineage})),
            learning_authorization_decision=_allow_decision(tenant_id, actor_user_id=actor_user_id),
            evaluation_comparison=comparison,
            tier2_promotion_evidence=Tier2PromotionEvidence(
                adr_reference="docs/ADR/0020-example.md",
                reliability_summary="stub demonstrated reliability",
            ),
            tier2_eligible_actions=frozenset({RequestedAction.ACTIVATE_ADAPTATION.value}),
        )
    )
    return experiment, adaptation, policy_decision


# --- rig ----------------------------------------------------------------------


@dataclass
class Rig:
    tenant_id: uuid.UUID
    actor_id: uuid.UUID
    approver_id: uuid.UUID
    registry: ToolRegistry
    user_ids: list[uuid.UUID] = field(default_factory=list)


def _build_rig() -> Rig:
    tenant = create_tenant(_unique("tenant"))
    transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
    actor = create_user()
    approver = create_user()
    add_tenant_membership(tenant.id, actor.id)
    add_tenant_membership(tenant.id, approver.id)
    return Rig(
        tenant_id=tenant.id,
        actor_id=actor.id,
        approver_id=approver.id,
        registry=_registry(),
        user_ids=[actor.id, approver.id],
    )


def _teardown(admin: sessionmaker[Session], rigs: list[Rig]) -> None:
    tables = (
        "core.audit_log",
        "self_learning.canaries",
        "self_learning.experiments",
        "self_learning.adaptations",
        "control_plane.approval_requests",
        "core.feature_flag_tenant_overrides",
        "core.membership_roles",
        "core.role_permissions",
        "core.roles",
        "core.tenant_memberships",
    )
    with session_scope(session_factory=admin) as session:
        for rig in rigs:
            for table in tables:
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :t"), {"t": str(rig.tenant_id)}
                )  # noqa: S608
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(rig.tenant_id)}
            )
            for uid in rig.user_ids:
                session.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": str(uid)})


@pytest.fixture
def rig(admin: sessionmaker[Session]) -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(admin, [built])


@pytest.fixture
def other(admin: sessionmaker[Session]) -> Iterator[Rig]:
    built = _build_rig()
    try:
        yield built
    finally:
        _teardown(admin, [built])


# --- Invariant A: no new AI work for closed tenants ---------------------------


def test_open_tenant_can_create_ai_work(rig: Rig, admin: sessionmaker[Session]) -> None:
    propose_action(
        rig.tenant_id, rig.actor_id, "p5.tier1.repo", agent_scope_value="example/sandbox-repo"
    )
    _propose(rig.tenant_id, rig.actor_id, _unique("lineage"), "Be polite.")
    assert _count(admin, "control_plane.approval_requests", rig.tenant_id) == 1
    assert _count(admin, "self_learning.adaptations", rig.tenant_id) == 1


@pytest.mark.parametrize("status", _CLOSED)
def test_closed_tenant_cannot_create_ai_work_on_any_creator_path(
    status: TenantStatus, rig: Rig, admin: sessionmaker[Session]
) -> None:
    # Everything a creator could legitimately need is minted while open;
    # the lifecycle fence alone must reject each creation afterwards.
    experiment, adaptation, policy_decision = _ready_canary_inputs(rig.tenant_id, rig.actor_id)
    learning = _allow_decision(rig.tenant_id, actor_user_id=rig.actor_id)
    before = {t: _count(admin, t, rig.tenant_id) for t in _AI_TABLES}
    _close(rig.tenant_id, status)

    with pytest.raises(TenantClosedError):
        propose_action(rig.tenant_id, rig.actor_id, "p5.tier1.repo")
    with pytest.raises(TenantClosedError):
        propose_adaptation(
            tenant_id=rig.tenant_id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key=_unique("lineage"),
            proposed_value="late",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=learning,
            evidence_type="user_feedback",
            evidence_source_reference="feedback",
            created_by_user_id=rig.actor_id,
        )
    with pytest.raises(TenantClosedError):
        create_experiment(
            tenant_id=rig.tenant_id,
            baseline_version="v0",
            learning_authorization_decision=learning,
            evidence_type="tool_output",
            evidence_source_reference="late",
            created_by_user_id=rig.actor_id,
            adaptation=adaptation,
        )
    with pytest.raises(TenantClosedError):
        create_canary(
            tenant_id=rig.tenant_id,
            experiment=experiment,
            adaptation=adaptation,
            policy_gate_decision=policy_decision,
            monitoring_rules=_MONITORING_RULES,
            created_by_user_id=rig.actor_id,
        )
    with pytest.raises(TenantClosedError):
        asyncio.run(trigger_continuous_learning_cycle(rig.tenant_id))

    assert {t: _count(admin, t, rig.tenant_id) for t in _AI_TABLES} == before
    assert get_tenant(rig.tenant_id).status == status.value


# --- Invariants B/C/E: nothing executes for a closed tenant -------------------


@pytest.mark.parametrize("status", _CLOSED)
async def test_approved_action_cannot_execute_once_the_tenant_is_closed(
    status: TenantStatus, rig: Rig
) -> None:
    approval = propose_action(
        rig.tenant_id, rig.actor_id, "p5.tier1.repo", agent_scope_value="example/sandbox-repo"
    )
    approve(rig.tenant_id, approval.id, rig.approver_id)
    _close(rig.tenant_id, status)
    with pytest.raises(TenantClosedError):
        await execute_approved(rig.tenant_id, approval.id, registry=rig.registry)
    # The claim was refused inside its own transaction: never "executing",
    # never "executed" -- the approval is untouched and inert.
    assert get_approval(rig.tenant_id, approval.id).status == "approved"


@pytest.mark.parametrize("status", _CLOSED)
async def test_tier0_invocation_is_refused_and_audited_as_a_lifecycle_denial(
    status: TenantStatus, rig: Rig
) -> None:
    _close(rig.tenant_id, status)
    with pytest.raises(TenantClosedError):
        await invoke_tool(
            "p5.tier0.repo",
            agent_user_id=rig.actor_id,
            tenant_id=rig.tenant_id,
            agent_scope_value="example/sandbox-repo",
            registry=rig.registry,
        )
    denials = [
        e
        for e in list_audit_entries(rig.tenant_id, resource_type="control_plane_tool", limit=50)
        if e.outcome == "denied"
        and (e.entry_metadata or {}).get("denied_gate") == "tenant_lifecycle"
    ]
    assert len(denials) == 1


async def test_a_genuine_still_valid_data_authorization_cannot_override_the_fence(rig: Rig) -> None:
    decision = _data_decision(
        rig.tenant_id, actor_user_id=rig.actor_id
    )  # ALLOW, audited, provenanced
    result = await invoke_tool(
        "p5.tier0.data",
        agent_user_id=rig.actor_id,
        tenant_id=rig.tenant_id,
        agent_scope_value="example/sandbox-repo",
        registry=rig.registry,
        data_authorization_decision=decision,
    )
    assert result.output == {"executed": True}  # sanity: it worked while open
    _close(rig.tenant_id, TenantStatus.DELETED)
    with pytest.raises(TenantClosedError):
        await invoke_tool(
            "p5.tier0.data",
            agent_user_id=rig.actor_id,
            tenant_id=rig.tenant_id,
            agent_scope_value="example/sandbox-repo",
            registry=rig.registry,
            data_authorization_decision=decision,
        )


def test_pending_approval_cannot_be_decided_once_closed(rig: Rig) -> None:
    approval = propose_action(rig.tenant_id, rig.actor_id, "p5.tier1.repo")
    _close(rig.tenant_id, TenantStatus.DELETED)
    with pytest.raises(TenantClosedError):
        approve(rig.tenant_id, approval.id, rig.approver_id)
    with pytest.raises(TenantClosedError):
        reject(rig.tenant_id, approval.id, rig.approver_id)
    assert get_approval(rig.tenant_id, approval.id).status == "pending"


# --- Invariant D: authorization is still required on an open tenant ----------


async def test_tool_and_data_authorization_remain_required_on_an_open_tenant(rig: Rig) -> None:
    with pytest.raises(UnauthorizedToolInvocationError):  # RBAC: no role grants p5.widget:poke
        await invoke_tool(
            "p5.tier0.tenant",
            agent_user_id=rig.actor_id,
            tenant_id=rig.tenant_id,
            registry=rig.registry,
        )
    with pytest.raises(DataAuthorizationRequiredError):  # no Data Authorization decision
        await invoke_tool(
            "p5.tier0.data",
            agent_user_id=rig.actor_id,
            tenant_id=rig.tenant_id,
            agent_scope_value="example/sandbox-repo",
            registry=rig.registry,
        )


# --- Automatic rollback vs PURGING/PURGED (Race 5) ----------------------------


@pytest.mark.parametrize("status", [TenantStatus.PURGING, TenantStatus.PURGED])
def test_running_canary_is_left_inert_and_automatic_rollback_fails_closed(
    status: TenantStatus, rig: Rig
) -> None:
    experiment, adaptation, policy_decision = _ready_canary_inputs(rig.tenant_id, rig.actor_id)
    canary = create_canary(
        tenant_id=rig.tenant_id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=_MONITORING_RULES,
        created_by_user_id=rig.actor_id,
    )
    canary = start_canary(
        rig.tenant_id,
        canary.id,
        started_by_user_id=rig.actor_id,
        learning_authorization_decision=_allow_decision(rig.tenant_id, actor_user_id=rig.actor_id),
    )
    assert canary.status == CanaryStatus.RUNNING.value
    assert get_adaptation(rig.tenant_id, adaptation.id).status == AdaptationStatus.ACTIVE.value
    fresh = _allow_decision(rig.tenant_id, actor_user_id=rig.actor_id)  # minted while still open

    _close(rig.tenant_id, status)

    with pytest.raises(TenantClosedError):
        record_canary_observation(
            rig.tenant_id,
            canary.id,
            EvaluationMetrics(error_rate=0.9),  # violates the rule -> would auto-roll-back
            recorded_by_user_id=rig.actor_id,
            learning_authorization_decision=fresh,
        )
    # Nothing moved: the canary and its adaptation are retained, inert.
    assert get_canary(rig.tenant_id, canary.id).status == CanaryStatus.RUNNING.value
    assert get_adaptation(rig.tenant_id, adaptation.id).status == AdaptationStatus.ACTIVE.value


def test_configured_canary_cannot_start_once_closed(rig: Rig) -> None:
    experiment, adaptation, policy_decision = _ready_canary_inputs(rig.tenant_id, rig.actor_id)
    canary = create_canary(
        tenant_id=rig.tenant_id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=_MONITORING_RULES,
        created_by_user_id=rig.actor_id,
    )
    fresh = _allow_decision(rig.tenant_id, actor_user_id=rig.actor_id)
    _close(rig.tenant_id, TenantStatus.DELETED)
    with pytest.raises(TenantClosedError):
        start_canary(
            rig.tenant_id,
            canary.id,
            started_by_user_id=rig.actor_id,
            learning_authorization_decision=fresh,
        )
    assert get_canary(rig.tenant_id, canary.id).status == CanaryStatus.CONFIGURED.value
    assert get_adaptation(rig.tenant_id, adaptation.id).status == AdaptationStatus.CANDIDATE.value


# --- Queued work: the continuous loop job (retry vs PURGING) ------------------


@pytest.mark.parametrize("status", _CLOSED)
async def test_queued_loop_cycle_for_a_closed_tenant_is_a_no_op_not_a_retry(
    status: TenantStatus, rig: Rig
) -> None:
    _close(rig.tenant_id, status)
    payload = TenantJobPayload(tenant_id=str(rig.tenant_id))
    await _run_continuous_learning_cycle_job(payload)  # must not raise -> no retry, no dead-letter
    await _run_continuous_learning_cycle_job(payload)  # idempotent
    cycle = run_continuous_learning_cycle(rig.tenant_id, trigger=LoopTrigger.SCHEDULED)
    assert cycle.outcome is LoopCycleOutcome.TENANT_CLOSED
    assert cycle.seed is None
    cycles = list_audit_entries(
        rig.tenant_id, resource_type="self_learning_continuous_loop_cycle", limit=50
    )
    assert len(cycles) == 3
    assert all(e.outcome == "denied" for e in cycles)


# --- Races 1 & 2: serialized on the core.tenants row ---------------------------


def _hold_tenant_row_then_close(
    tenant_id: uuid.UUID, ready: threading.Event, release: threading.Event
) -> None:
    """Simulate a lifecycle transition that is *in progress*: hold the
    tenant row FOR UPDATE, let the racing caller start, then write PURGING
    and commit."""
    with session_scope() as session:
        row = session.get(Tenant, tenant_id, with_for_update=True)
        assert row is not None
        ready.set()
        release.wait(timeout=10)
        row.status = TenantStatus.PURGING.value
        session.flush()


def test_create_racing_a_purging_transition_fails_closed(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)  # graph: only DELETED -> PURGING
    ready, release = threading.Event(), threading.Event()
    errors: list[BaseException] = []
    holder = threading.Thread(
        target=_hold_tenant_row_then_close, args=(rig.tenant_id, ready, release)
    )
    holder.start()
    assert ready.wait(timeout=10)

    def _create() -> None:
        try:
            propose_action(rig.tenant_id, rig.actor_id, "p5.tier1.repo")
        except BaseException as exc:  # noqa: BLE001 -- asserted below
            errors.append(exc)

    creator = threading.Thread(target=_create)
    creator.start()
    creator.join(timeout=2)
    assert creator.is_alive(), "the create must block on the row the transition holds"
    release.set()
    holder.join(timeout=10)
    creator.join(timeout=10)
    assert len(errors) == 1 and isinstance(errors[0], TenantClosedError)
    assert _count(admin, "control_plane.approval_requests", rig.tenant_id) == 0
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGING.value


def test_execution_racing_a_purging_transition_fails_closed(rig: Rig) -> None:
    approval = propose_action(
        rig.tenant_id, rig.actor_id, "p5.tier1.repo", agent_scope_value="example/sandbox-repo"
    )
    approve(rig.tenant_id, approval.id, rig.approver_id)
    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    ready, release = threading.Event(), threading.Event()
    errors: list[BaseException] = []
    holder = threading.Thread(
        target=_hold_tenant_row_then_close, args=(rig.tenant_id, ready, release)
    )
    holder.start()
    assert ready.wait(timeout=10)

    def _execute() -> None:
        try:
            asyncio.run(execute_approved(rig.tenant_id, approval.id, registry=rig.registry))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    executor = threading.Thread(target=_execute)
    executor.start()
    executor.join(timeout=2)
    assert executor.is_alive(), "the claim must block on the row the transition holds"
    release.set()
    holder.join(timeout=10)
    executor.join(timeout=10)
    assert len(errors) == 1 and isinstance(errors[0], TenantClosedError)
    assert get_approval(rig.tenant_id, approval.id).status == "approved"


# --- Invariant F: isolation ----------------------------------------------------


def test_draining_tenant_a_does_not_touch_tenant_b(
    rig: Rig, other: Rig, admin: sessionmaker[Session]
) -> None:
    propose_action(other.tenant_id, other.actor_id, "p5.tier1.repo")
    _close(rig.tenant_id, TenantStatus.PURGING)
    propose_action(other.tenant_id, other.actor_id, "p5.tier1.repo")  # B keeps working
    assert _count(admin, "control_plane.approval_requests", other.tenant_id) == 2
    assert get_tenant(other.tenant_id).status == TenantStatus.ACTIVE.value


# --- Purge: artifacts retained and inert, evidence intact -----------------------


async def test_purge_retains_ai_artifacts_inert_and_keeps_their_audit_evidence(
    rig: Rig, admin: sessionmaker[Session]
) -> None:
    experiment, adaptation, policy_decision = _ready_canary_inputs(rig.tenant_id, rig.actor_id)
    create_canary(
        tenant_id=rig.tenant_id,
        experiment=experiment,
        adaptation=adaptation,
        policy_gate_decision=policy_decision,
        monitoring_rules=_MONITORING_RULES,
        created_by_user_id=rig.actor_id,
    )
    approval = propose_action(
        rig.tenant_id, rig.actor_id, "p5.tier1.repo", agent_scope_value="example/sandbox-repo"
    )
    approve(rig.tenant_id, approval.id, rig.approver_id)
    before = {t: _count(admin, t, rig.tenant_id) for t in _AI_TABLES}
    ai_audit_before = _count(admin, "core.audit_log", rig.tenant_id)

    transition_tenant_status(rig.tenant_id, TenantStatus.DELETED)
    result = purge_tenant(rig.tenant_id)
    assert get_tenant(rig.tenant_id).status == TenantStatus.PURGED.value
    assert not result.already_purged

    assert {
        t: _count(admin, t, rig.tenant_id) for t in _AI_TABLES
    } == before  # DEFERRED_POLICY: retained
    assert _count(admin, "core.audit_log", rig.tenant_id) >= ai_audit_before  # evidence intact
    with pytest.raises(TenantClosedError):  # ...and inert forever
        await execute_approved(rig.tenant_id, approval.id, registry=rig.registry)
    assert get_approval(rig.tenant_id, approval.id).status == "approved"
