"""Tool invocation integration tests against a real PostgreSQL instance
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.1's own Tests requirement: "a
stub tool registers, is invoked, and its invocation is denied when the
invoking agent identity lacks the required RBAC permission; a stub tool
declaring a named secret receives that secret's value in its execution
context while the invoking agent's returned output/transcript contains
no secret value; an attempt to request a secret not declared by the
invoking tool is rejected").

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/control_plane/orchestration/test_orchestration_integration.py
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

from control_plane.orchestration.errors import (
    TierRequiresApprovalError,
    ToolNotFoundError,
    UnauthorizedToolInvocationError,
    UndeclaredSecretError,
)
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


async def _stub_handler(context: ToolExecutionContext, payload) -> dict[str, object]:
    return {"echo": payload.get("value"), "correlation_id": context.correlation_id}


async def _secret_handler(context: ToolExecutionContext, payload) -> dict[str, object]:
    secret_value = context.get_secret("STUB_TOOL_SECRET")
    assert secret_value == "shh-do-not-leak"
    return {"used_secret": True}  # the returned output never contains the secret value itself


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique("orch-tenant"))
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

        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                key="stub_tool",
                description="A stub tool for Phase 7.1 integration tests.",
                handler=_stub_handler,
                required_scope_type="tenant",
                required_resource=self.resource,
                required_action="invoke",
                autonomy_tier=0,
            )
        )
        self.registry.register(
            ToolDefinition(
                key="secret_tool",
                description="A stub tool declaring one secret.",
                handler=_secret_handler,
                required_scope_type="tenant",
                required_resource=self.resource,
                required_action="invoke",
                autonomy_tier=0,
                declared_secrets=frozenset({"STUB_TOOL_SECRET"}),
            )
        )
        self.registry.register(
            ToolDefinition(
                key="tier1_tool",
                description="A stub tier-1 tool.",
                handler=_stub_handler,
                required_scope_type="tenant",
                required_resource=self.resource,
                required_action="invoke",
                autonomy_tier=1,
            )
        )
        self.registry.register(
            ToolDefinition(
                key="repo_tool",
                description="A stub repository-scoped tool.",
                handler=_stub_handler,
                required_scope_type="repository",
                required_scope_value="example/sandbox-repo",
                autonomy_tier=0,
            )
        )

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
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


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


# --- Allowed invocation, tenant-scoped RBAC ---------------------------------


async def test_authorized_invocation_succeeds_and_is_audited(fx: _Fixture) -> None:
    result = await invoke_tool(
        "stub_tool",
        agent_user_id=fx.agent.id,
        tenant_id=fx.tenant.id,
        payload={"value": 42},
        registry=fx.registry,
    )
    assert result.output == {"echo": 42, "correlation_id": result.correlation_id}

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "control_plane.tool_invocation"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"
    assert matching[0].actor_user_id == fx.agent.id
    assert matching[0].correlation_id == result.correlation_id


# --- Denied invocation: agent lacks the required RBAC permission -----------


async def test_invocation_denied_without_permission_is_audited(fx: _Fixture) -> None:
    other_user = create_user()
    add_tenant_membership(fx.tenant.id, other_user.id)  # member, but no role/permission grant
    try:
        with pytest.raises(UnauthorizedToolInvocationError):
            await invoke_tool(
                "stub_tool",
                agent_user_id=other_user.id,
                tenant_id=fx.tenant.id,
                registry=fx.registry,
            )

        entries = list_audit_entries(fx.tenant.id)
        matching = [
            e
            for e in entries
            if e.action == "control_plane.tool_invocation" and e.actor_user_id == other_user.id
        ]
        assert len(matching) == 1
        assert matching[0].outcome == "denied"
    finally:
        _admin_delete_audit_log_for_tenant(fx.tenant.id)
        with tenant_session_scope(fx.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE user_id = :u"),
                {"u": str(other_user.id)},
            )
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(other_user.id)}
            )


async def test_invocation_denied_for_wrong_tenant(fx: _Fixture) -> None:
    """The agent has the required permission in `fx.tenant`, but not in a
    second, unrelated tenant it has no membership in at all."""
    other_tenant = create_tenant(_unique("orch-other-tenant"))
    try:
        with pytest.raises(UnauthorizedToolInvocationError):
            await invoke_tool(
                "stub_tool",
                agent_user_id=fx.agent.id,
                tenant_id=other_tenant.id,
                registry=fx.registry,
            )
    finally:
        _admin_delete_audit_log_for_tenant(other_tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(other_tenant.id)}
            )


async def test_unknown_tool_raises_not_found(fx: _Fixture) -> None:
    with pytest.raises(ToolNotFoundError):
        await invoke_tool(
            "does_not_exist",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            registry=fx.registry,
        )


# --- Tool secrets access -----------------------------------------------


async def test_declared_secret_reaches_the_handler_but_never_the_output(
    fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STUB_TOOL_SECRET", "shh-do-not-leak")
    result = await invoke_tool(
        "secret_tool", agent_user_id=fx.agent.id, tenant_id=fx.tenant.id, registry=fx.registry
    )
    assert result.output == {"used_secret": True}
    assert "shh-do-not-leak" not in str(result.output)


async def test_requesting_an_undeclared_secret_is_rejected(fx: _Fixture) -> None:
    async def _handler(context: ToolExecutionContext, payload) -> dict[str, object]:
        return {"value": context.get_secret("NOT_DECLARED_SECRET")}

    fx.registry.register(
        ToolDefinition(
            key="bad_secret_tool",
            description="Requests an undeclared secret.",
            handler=_handler,
            required_scope_type="tenant",
            required_resource=fx.resource,
            required_action="invoke",
            autonomy_tier=0,
            declared_secrets=frozenset({"STUB_TOOL_SECRET"}),
        )
    )
    with pytest.raises(Exception) as excinfo:
        await invoke_tool(
            "bad_secret_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            registry=fx.registry,
        )
    # ToolExecutionError wraps the handler's own UndeclaredSecretError --
    # confirm the *cause* is the undeclared-secret rejection, not merely
    # any failure.
    assert isinstance(excinfo.value.__cause__, UndeclaredSecretError)


async def test_audit_entries_never_carry_a_secret_value(
    fx: _Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STUB_TOOL_SECRET", "shh-do-not-leak")
    await invoke_tool(
        "secret_tool", agent_user_id=fx.agent.id, tenant_id=fx.tenant.id, registry=fx.registry
    )
    entries = list_audit_entries(fx.tenant.id)
    for entry in entries:
        assert "shh-do-not-leak" not in str(entry.entry_metadata)


# --- Autonomy tier enforcement -------------------------------------------


async def test_tier_1_tool_cannot_be_invoked_directly(fx: _Fixture) -> None:
    with pytest.raises(TierRequiresApprovalError):
        await invoke_tool(
            "tier1_tool", agent_user_id=fx.agent.id, tenant_id=fx.tenant.id, registry=fx.registry
        )


# --- Environment/repository scope matching --------------------------------


async def test_repository_scoped_tool_denied_for_wrong_agent_scope(fx: _Fixture) -> None:
    with pytest.raises(UnauthorizedToolInvocationError):
        await invoke_tool(
            "repo_tool",
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            agent_scope_value="example/some-other-repo",
            registry=fx.registry,
        )


async def test_repository_scoped_tool_allowed_for_matching_agent_scope(fx: _Fixture) -> None:
    result = await invoke_tool(
        "repo_tool",
        agent_user_id=fx.agent.id,
        tenant_id=fx.tenant.id,
        agent_scope_value="example/sandbox-repo",
        registry=fx.registry,
    )
    assert result.tool_key == "repo_tool"


async def test_repository_scoped_tool_denied_with_no_agent_scope(fx: _Fixture) -> None:
    with pytest.raises(UnauthorizedToolInvocationError):
        await invoke_tool(
            "repo_tool", agent_user_id=fx.agent.id, tenant_id=fx.tenant.id, registry=fx.registry
        )
