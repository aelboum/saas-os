"""P1.1 -- Data Authorization wired into AI Control Plane tool execution,
against a real PostgreSQL instance.

Proves `docs/AI-CONTROL-PLANE.md` section 2.1's two gates (Tool
Authorization, `control_plane.orchestration`; Data Authorization,
`control_plane.data_authorization`) are wired together at the one point
docs/AI-CONTROL-PLANE.md section 2.1 requires -- before a tool declaring
`requires_data_authorization=True` reaches its own handler -- while
remaining independent decisions: passing RBAC/tier/approval never implies
Data Authorization passes, and vice versa.

The critical invariant under test throughout: `DataAuthorizationOutcome
.DENY` (or no decision at all) => the tool handler's own "provider" call
count is 0. A test that only checks the returned/raised exception is not
enough on its own -- every denial scenario below also asserts the fake
provider was never actually reached.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/orchestration/test_data_authorization_wiring_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_user, get_membership
from core.rbac.service import assign_role, create_role, grant_permission, register_permission
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from infra.secrets.config import get_secrets_provider
from sqlalchemy import text

from control_plane.approvals.service import approve, execute_approved, get_approval, propose_action
from control_plane.data_authorization import (
    DataAuthorizationDecision,
    DataAuthorizationOutcome,
    DataAuthorizationRequest,
    DataDenialReason,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    authorize_data_access,
)
from control_plane.orchestration.errors import DataAuthorizationRequiredError
from control_plane.orchestration.service import invoke_tool
from control_plane.orchestration.tools import ToolDefinition, ToolExecutionContext, ToolRegistry
from core.tenancy import create_tenant

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


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
            conn.execute(text("SELECT 1 FROM core.membership_roles LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.membership_roles not reachable: {exc}. "
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


class _FakeProvider:
    """A local, in-memory call counter -- no network access, no
    credential -- standing in for an external AI/LLM provider exactly as
    `control_plane.development.provider.FakePullRequestProvider` stands in
    for a real PR provider. Not production code: this phase adds no new
    AI/LLM provider abstraction, only proves the wiring using a throwaway
    test double."""

    def __init__(self) -> None:
        self.call_count = 0
        self.calls: list[dict[str, object]] = []

    def send(self, *, prompt: str) -> str:
        self.call_count += 1
        self.calls.append({"prompt": prompt})
        return "fake-provider-response"


async def _stub_handler(context: ToolExecutionContext, payload) -> dict[str, object]:
    return {"echo": payload.get("value")}


def _build_external_handler(provider: _FakeProvider):
    async def handler(context: ToolExecutionContext, payload) -> dict[str, object]:
        response = provider.send(prompt=str(payload.get("prompt", "")))
        return {"provider_response": response}

    return handler


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique("data-auth-wiring-tenant"))
        self.agent = create_user()
        add_tenant_membership(self.tenant.id, self.agent.id)

        self.resource = _unique("control_plane.stub_tool")
        self.role = create_role(self.tenant.id, _unique("stub-tool-role"))
        permission = register_permission(self.resource, "invoke")
        grant_permission(self.tenant.id, self.role.id, permission.id)

        membership = get_membership(self.tenant.id, self.agent.id)
        assert membership is not None
        self.membership = membership
        assign_role(self.tenant.id, self.membership.id, self.role.id)

        self.provider = _FakeProvider()
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                key="safe_tool",
                description="A stub tool that never touches an external provider.",
                handler=_stub_handler,
                required_scope_type="tenant",
                required_resource=self.resource,
                required_action="invoke",
                autonomy_tier=0,
                requires_data_authorization=False,
            )
        )
        self.registry.register(
            ToolDefinition(
                key="external_tool",
                description="A stub tool that hands data to an external AI provider.",
                handler=_build_external_handler(self.provider),
                required_scope_type="tenant",
                required_resource=self.resource,
                required_action="invoke",
                autonomy_tier=0,
                data_classification="tenant_data",
                requires_data_authorization=True,
            )
        )
        self.registry.register(
            ToolDefinition(
                key="external_tier1_tool",
                description="A tier-1 stub tool that hands data to an external AI provider.",
                handler=_build_external_handler(self.provider),
                required_scope_type="tenant",
                required_resource=self.resource,
                required_action="invoke",
                autonomy_tier=1,
                data_classification="tenant_data",
                requires_data_authorization=True,
            )
        )

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM control_plane.approval_requests WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.membership_roles WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.role_permissions WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(self.tenant.id)}
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(self.agent.id)}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )

    def allow_decision(self) -> DataAuthorizationDecision:
        policy = TenantAIDataPolicy(
            tenant_id=self.tenant.id,
            allowed_data_classifications=frozenset({"tenant_data"}),
            allowed_purposes=frozenset({"support_response_drafting"}),
            allowed_providers=frozenset({"anthropic"}),
        )
        provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
        request = DataAuthorizationRequest(
            tenant_id=self.tenant.id,
            data_classification="tenant_data",
            purpose="support_response_drafting",
            provider="anthropic",
            resource_type="support_ticket",
            resource_id="ticket-1",
        )
        return authorize_data_access(
            request,
            tenant_policy=policy,
            provider_policy=provider_policy,
            actor_user_id=self.agent.id,
        )

    def deny_decision(
        self, *, tenant_policy: TenantAIDataPolicy | None = None
    ) -> DataAuthorizationDecision:
        provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
        request = DataAuthorizationRequest(
            tenant_id=self.tenant.id,
            data_classification="tenant_data",
            purpose="support_response_drafting",
            provider="anthropic",
            resource_type="support_ticket",
            resource_id="ticket-1",
        )
        return authorize_data_access(
            request,
            tenant_policy=tenant_policy,
            provider_policy=provider_policy,
            actor_user_id=self.agent.id,
        )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


# --- Existing non-external tools: unaffected --------------------------------


async def test_non_external_tool_unaffected_and_data_authorization_never_invoked(
    fx: _Fixture,
) -> None:
    result = await invoke_tool(
        "safe_tool",
        agent_user_id=fx.agent.id,
        tenant_id=fx.tenant.id,
        payload={"value": 1},
        registry=fx.registry,
    )
    assert result.output == {"echo": 1}

    entries = list_audit_entries(fx.tenant.id)
    assert not any(e.action.startswith("ai_control_plane.data_access_") for e in entries)
    matching = [e for e in entries if e.action == "control_plane.tool_invocation"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"


# --- External-provider tool: ALLOW / DENY -----------------------------------


async def test_allow_decision_lets_the_provider_execute(fx: _Fixture) -> None:
    decision = fx.allow_decision()
    assert decision.outcome is DataAuthorizationOutcome.ALLOW

    result = await invoke_tool(
        "external_tool",
        agent_user_id=fx.agent.id,
        tenant_id=fx.tenant.id,
        payload={"prompt": "draft a reply"},
        registry=fx.registry,
        data_authorization_decision=decision,
    )
    assert result.output == {"provider_response": "fake-provider-response"}
    assert fx.provider.call_count == 1


async def test_deny_decision_blocks_the_provider(fx: _Fixture) -> None:
    decision = fx.deny_decision(tenant_policy=None)  # NO_TENANT_POLICY -> DENY
    assert decision.outcome is DataAuthorizationOutcome.DENY

    with pytest.raises(DataAuthorizationRequiredError):
        await invoke_tool(
            "external_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"prompt": "draft a reply"},
            registry=fx.registry,
            data_authorization_decision=decision,
        )
    assert fx.provider.call_count == 0


async def test_missing_decision_blocks_the_provider(fx: _Fixture) -> None:
    with pytest.raises(DataAuthorizationRequiredError):
        await invoke_tool(
            "external_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"prompt": "draft a reply"},
            registry=fx.registry,
        )
    assert fx.provider.call_count == 0


async def test_wrong_tenant_decision_blocks_the_provider(fx: _Fixture) -> None:
    other_tenant = create_tenant(_unique("data-auth-wiring-other-tenant"))
    try:
        foreign_decision = DataAuthorizationDecision(
            outcome=DataAuthorizationOutcome.ALLOW,
            tenant_id=other_tenant.id,
            data_classification="tenant_data",
            purpose="support_response_drafting",
            provider="anthropic",
            reason=None,
        )
        with pytest.raises(DataAuthorizationRequiredError):
            await invoke_tool(
                "external_tool",
                agent_user_id=fx.agent.id,
                tenant_id=fx.tenant.id,
                payload={"prompt": "draft a reply"},
                registry=fx.registry,
                data_authorization_decision=foreign_decision,
            )
        assert fx.provider.call_count == 0
    finally:
        _admin_delete_audit_log_for_tenant(other_tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(other_tenant.id)}
            )


async def test_unauthorized_provider_denied(fx: _Fixture) -> None:
    """The tenant's own policy does not permit the requested provider --
    `evaluate_data_authorization()`'s own `PROVIDER_NOT_PERMITTED` branch."""
    policy = TenantAIDataPolicy(
        tenant_id=fx.tenant.id,
        allowed_data_classifications=frozenset({"tenant_data"}),
        allowed_purposes=frozenset({"support_response_drafting"}),
        allowed_providers=frozenset(),  # anthropic not permitted for this tenant
    )
    provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
    request = DataAuthorizationRequest(
        tenant_id=fx.tenant.id,
        data_classification="tenant_data",
        purpose="support_response_drafting",
        provider="anthropic",
        resource_type="support_ticket",
        resource_id="ticket-1",
    )
    decision = authorize_data_access(
        request, tenant_policy=policy, provider_policy=provider_policy, actor_user_id=fx.agent.id
    )
    assert decision.reason is DataDenialReason.PROVIDER_NOT_PERMITTED

    with pytest.raises(DataAuthorizationRequiredError):
        await invoke_tool(
            "external_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"prompt": "draft a reply"},
            registry=fx.registry,
            data_authorization_decision=decision,
        )
    assert fx.provider.call_count == 0


async def test_unauthorized_purpose_denied(fx: _Fixture) -> None:
    """`evaluate_data_authorization()`'s own `PURPOSE_NOT_PERMITTED` branch."""
    policy = TenantAIDataPolicy(
        tenant_id=fx.tenant.id,
        allowed_data_classifications=frozenset({"tenant_data"}),
        allowed_purposes=frozenset(),  # no purpose permitted for this tenant
        allowed_providers=frozenset({"anthropic"}),
    )
    provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
    request = DataAuthorizationRequest(
        tenant_id=fx.tenant.id,
        data_classification="tenant_data",
        purpose="support_response_drafting",
        provider="anthropic",
        resource_type="support_ticket",
        resource_id="ticket-1",
    )
    decision = authorize_data_access(
        request, tenant_policy=policy, provider_policy=provider_policy, actor_user_id=fx.agent.id
    )
    assert decision.reason is DataDenialReason.PURPOSE_NOT_PERMITTED

    with pytest.raises(DataAuthorizationRequiredError):
        await invoke_tool(
            "external_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"prompt": "draft a reply"},
            registry=fx.registry,
            data_authorization_decision=decision,
        )
    assert fx.provider.call_count == 0


async def test_malformed_unclassified_data_denied(fx: _Fixture) -> None:
    """`evaluate_data_authorization()`'s own `UNCLASSIFIED_DATA` branch --
    an empty/unknown `data_classification` is default-deny, never silently
    allowed."""
    provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
    request = DataAuthorizationRequest(
        tenant_id=fx.tenant.id,
        data_classification="",
        purpose="support_response_drafting",
        provider="anthropic",
        resource_type="support_ticket",
        resource_id="ticket-1",
    )
    decision = authorize_data_access(
        request, tenant_policy=None, provider_policy=provider_policy, actor_user_id=fx.agent.id
    )
    assert decision.reason is DataDenialReason.UNCLASSIFIED_DATA

    with pytest.raises(DataAuthorizationRequiredError):
        await invoke_tool(
            "external_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"prompt": "draft a reply"},
            registry=fx.registry,
            data_authorization_decision=decision,
        )
    assert fx.provider.call_count == 0


# --- Adversarial -------------------------------------------------------


async def test_forged_allow_for_another_tenant_does_not_permit_execution(fx: _Fixture) -> None:
    """A hand-constructed `DataAuthorizationDecision` -- never produced by
    `authorize_data_access()` -- claiming ALLOW for a *different* tenant
    must not authorize this tenant's invocation. Distinct from
    `test_wrong_tenant_decision_blocks_the_provider` only in that this
    decision was never audited/computed by the real service at all,
    proving the tenant check is not merely incidental to that code path."""
    forged = DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=uuid.uuid4(),  # an arbitrary, unrelated tenant id -- never created
        data_classification="tenant_data",
        purpose="support_response_drafting",
        provider="anthropic",
        reason=None,
    )
    with pytest.raises(DataAuthorizationRequiredError):
        await invoke_tool(
            "external_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"prompt": "draft a reply"},
            registry=fx.registry,
            data_authorization_decision=forged,
        )
    assert fx.provider.call_count == 0


async def test_denial_after_rbac_and_approval_success_still_blocks_provider(
    fx: _Fixture,
) -> None:
    """RBAC passes and the tier-1 tool is fully approved (separation of
    duties honored) -- Data Authorization is still the final, independent
    gate: its own denial still blocks the provider, proving approval
    success never implies Data Authorization success."""
    approver = create_user()
    add_tenant_membership(fx.tenant.id, approver.id)
    try:
        approval = propose_action(
            fx.tenant.id,
            fx.agent.id,
            "external_tier1_tool",
            payload={"prompt": "draft a reply"},
        )
        approve(fx.tenant.id, approval.id, approver.id)

        deny_decision = fx.deny_decision(tenant_policy=None)
        with pytest.raises(DataAuthorizationRequiredError):
            await execute_approved(
                fx.tenant.id,
                approval.id,
                registry=fx.registry,
                data_authorization_decision=deny_decision,
            )
        assert fx.provider.call_count == 0

        # the approval itself is untouched by the Data Authorization denial --
        # it remains "approved", never silently marked "executed".
        refreshed = get_approval(fx.tenant.id, approval.id)
        assert refreshed.status == "approved"
    finally:
        # `approve()` audits with actor_user_id=approver.id, and the
        # approval row itself FK-references approver.id -- delete both the
        # tenant's audit log and its approval requests first so those
        # FK-referenced rows don't block deleting the user below
        # (fx.cleanup()'s own later calls to the same deletes are then a
        # no-op).
        _admin_delete_audit_log_for_tenant(fx.tenant.id)
        with tenant_session_scope(fx.tenant.id) as session:
            session.execute(
                text("DELETE FROM control_plane.approval_requests WHERE tenant_id = :t"),
                {"t": str(fx.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE user_id = :u"),
                {"u": str(approver.id)},
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(approver.id)})


async def test_approved_allow_decision_lets_the_provider_execute(fx: _Fixture) -> None:
    """Full RBAC -> approval -> Data Authorization -> handler chain, this
    time ending in ALLOW: the provider is reached exactly once."""
    approver = create_user()
    add_tenant_membership(fx.tenant.id, approver.id)
    try:
        approval = propose_action(
            fx.tenant.id,
            fx.agent.id,
            "external_tier1_tool",
            payload={"prompt": "draft a reply"},
        )
        approve(fx.tenant.id, approval.id, approver.id)

        allow_decision = fx.allow_decision()
        executed = await execute_approved(
            fx.tenant.id,
            approval.id,
            registry=fx.registry,
            data_authorization_decision=allow_decision,
        )
        assert executed.status == "executed"
        assert fx.provider.call_count == 1
    finally:
        # `approve()` audits with actor_user_id=approver.id, and the
        # approval row itself FK-references approver.id -- delete both the
        # tenant's audit log and its approval requests first so those
        # FK-referenced rows don't block deleting the user below
        # (fx.cleanup()'s own later calls to the same deletes are then a
        # no-op).
        _admin_delete_audit_log_for_tenant(fx.tenant.id)
        with tenant_session_scope(fx.tenant.id) as session:
            session.execute(
                text("DELETE FROM control_plane.approval_requests WHERE tenant_id = :t"),
                {"t": str(fx.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE user_id = :u"),
                {"u": str(approver.id)},
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(approver.id)})


# --- Audit ---------------------------------------------------------------


async def test_allow_decision_audit_has_no_duplicate_and_no_raw_data(fx: _Fixture) -> None:
    decision = fx.allow_decision()
    await invoke_tool(
        "external_tool",
        agent_user_id=fx.agent.id,
        tenant_id=fx.tenant.id,
        payload={"prompt": "the customer's raw ticket body should never be in an audit row"},
        registry=fx.registry,
        data_authorization_decision=decision,
    )

    entries = list_audit_entries(fx.tenant.id)

    approved = [e for e in entries if e.action == "ai_control_plane.data_access_approved"]
    assert len(approved) == 1  # exactly one -- orchestration never re-invokes authorize_data_access
    assert approved[0].outcome == "success"

    invocations = [e for e in entries if e.action == "control_plane.tool_invocation"]
    assert len(invocations) == 1
    assert invocations[0].outcome == "success"

    for entry in entries:
        metadata_str = str(entry.entry_metadata)
        assert "the customer's raw ticket body" not in metadata_str


async def test_deny_decision_audit_has_no_duplicate_and_no_raw_data(fx: _Fixture) -> None:
    decision = fx.deny_decision(tenant_policy=None)
    with pytest.raises(DataAuthorizationRequiredError):
        await invoke_tool(
            "external_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"prompt": "the customer's raw ticket body should never be in an audit row"},
            registry=fx.registry,
            data_authorization_decision=decision,
        )

    entries = list_audit_entries(fx.tenant.id)

    denied = [e for e in entries if e.action == "ai_control_plane.data_access_denied"]
    assert len(denied) == 1  # exactly one -- orchestration never re-invokes authorize_data_access
    assert denied[0].outcome == "denied"
    assert denied[0].entry_metadata is not None
    assert denied[0].entry_metadata["denial_reason"] == "no_tenant_policy"

    invocations = [e for e in entries if e.action == "control_plane.tool_invocation"]
    assert len(invocations) == 1
    assert invocations[0].outcome == "denied"
    assert invocations[0].entry_metadata is not None
    assert invocations[0].entry_metadata["denied_gate"] == "data_authorization"

    for entry in entries:
        metadata_str = str(entry.entry_metadata)
        assert "the customer's raw ticket body" not in metadata_str


async def test_missing_decision_denial_is_audited_exactly_once(fx: _Fixture) -> None:
    with pytest.raises(DataAuthorizationRequiredError):
        await invoke_tool(
            "external_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            payload={"prompt": "draft a reply"},
            registry=fx.registry,
        )

    entries = list_audit_entries(fx.tenant.id)
    # no authorize_data_access() call ever happened for this invocation --
    # there is no real decision to have audited in the first place.
    assert not any(e.action.startswith("ai_control_plane.data_access_") for e in entries)

    invocations = [e for e in entries if e.action == "control_plane.tool_invocation"]
    assert len(invocations) == 1
    assert invocations[0].outcome == "denied"
