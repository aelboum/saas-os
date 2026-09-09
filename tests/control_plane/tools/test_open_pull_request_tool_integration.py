"""End-to-end integration test for the first real AI Control Plane tool
(docs/IMPLEMENTATION-ROADMAP.md Phase 7.3's own Acceptance Criteria:
"agent proposes a change via the normal PR mechanism; normal
branch-protection/review rules still apply; every proposal is
audit-logged") against a real PostgreSQL instance, exercising the full
`control_plane.orchestration` + `control_plane.approvals` +
`control_plane.tools.open_pull_request` stack together, using
`FakePullRequestProvider` -- no live GitHub network access needed (see
`tests/control_plane/development/test_development_github_integration.py`
for the one test that exercises the real provider, skipping cleanly
without a token).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/control_plane/tools/test_open_pull_request_tool_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import add_tenant_membership, create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text

from control_plane.approvals.service import approve, execute_approved, propose_action
from control_plane.development.errors import RepositoryScopeMismatchError
from control_plane.development.provider import FakePullRequestProvider
from control_plane.orchestration.errors import (
    TierRequiresApprovalError,
    ToolExecutionError,
    UnauthorizedToolInvocationError,
)
from control_plane.orchestration.service import invoke_tool
from control_plane.orchestration.tools import ToolRegistry
from control_plane.tools.open_pull_request import TOOL_KEY, build_open_pull_request_tool
from core.tenancy import create_tenant

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_SANDBOX_REPOSITORY = "example/sandbox-repo"


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
            conn.execute(text("SELECT 1 FROM control_plane.approval_requests LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/control_plane.approval_requests not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


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


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique("dev-tool-tenant"))
        self.agent = create_user()  # the development-agent identity
        self.approver = create_user()
        add_tenant_membership(self.tenant.id, self.agent.id)
        add_tenant_membership(self.tenant.id, self.approver.id)

        self.provider = FakePullRequestProvider()
        self.registry = ToolRegistry()
        self.registry.register(
            build_open_pull_request_tool(_SANDBOX_REPOSITORY, provider=self.provider)
        )

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM control_plane.approval_requests WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.users WHERE id IN (:a, :b)"),
                {"a": str(self.agent.id), "b": str(self.approver.id)},
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


def _payload() -> dict:
    return {
        "repository": _SANDBOX_REPOSITORY,
        "base_branch": "main",
        "branch_name": f"agent/proposed-change-{uuid.uuid4().hex[:8]}",
        "title": "Fix a typo",
        "body": "Proposed by the development agent.",
        "file_changes": [{"path": "README.md", "content": "fixed content"}],
    }


# --- The tool is tier 1: cannot be invoked directly -------------------------


async def test_tool_cannot_be_invoked_directly(fx: _Fixture) -> None:
    with pytest.raises(TierRequiresApprovalError):
        await invoke_tool(
            TOOL_KEY,
            agent_user_id=fx.agent.id,
            tenant_id=fx.tenant.id,
            agent_scope_value=_SANDBOX_REPOSITORY,
            payload=_payload(),
            registry=fx.registry,
        )
    assert fx.provider.opened_pull_requests == {}


# --- Full propose -> approve -> execute cycle opens a PR via the fake ------


async def test_full_cycle_opens_a_pull_request_via_the_provider(fx: _Fixture) -> None:
    approval = propose_action(
        fx.tenant.id,
        fx.agent.id,
        TOOL_KEY,
        agent_scope_value=_SANDBOX_REPOSITORY,
        payload=_payload(),
    )
    approve(fx.tenant.id, approval.id, fx.approver.id)
    executed = await execute_approved(fx.tenant.id, approval.id, registry=fx.registry)

    assert executed.status == "executed"
    assert len(fx.provider.opened_pull_requests) == 1
    recorded = next(iter(fx.provider.opened_pull_requests.values()))
    assert recorded["repository"] == _SANDBOX_REPOSITORY

    entries = list_audit_entries(fx.tenant.id)
    assert any(e.action == "control_plane.action_proposed" for e in entries)
    assert any(e.action == "control_plane.action_approved" for e in entries)
    assert any(
        e.action == "control_plane.tool_invocation" and e.outcome == "success" for e in entries
    )


# --- Repository scope mismatch is rejected (defense in depth) --------------


async def test_repository_scope_mismatch_is_rejected(fx: _Fixture) -> None:
    """The agent's declared scope matches the tool's own
    `required_scope_value` (so orchestration's authorization check
    passes), but the *payload* itself names a different repository --
    the handler's own defense-in-depth check must still reject this."""
    approval = propose_action(
        fx.tenant.id,
        fx.agent.id,
        TOOL_KEY,
        agent_scope_value=_SANDBOX_REPOSITORY,
        payload={**_payload(), "repository": "example/a-completely-different-repo"},
    )
    approve(fx.tenant.id, approval.id, fx.approver.id)

    with pytest.raises(ToolExecutionError) as excinfo:
        await execute_approved(fx.tenant.id, approval.id, registry=fx.registry)
    assert isinstance(excinfo.value.__cause__, RepositoryScopeMismatchError)
    assert fx.provider.opened_pull_requests == {}


async def test_wrong_agent_scope_is_denied_at_the_orchestration_layer(fx: _Fixture) -> None:
    """A proposal whose declared `agent_scope_value` does not match the
    tool's own `required_scope_value` is denied before the handler ever
    runs -- proven by proposing under the wrong scope and confirming
    execution raises `UnauthorizedToolInvocationError`, never opening a
    PR."""
    approval = propose_action(
        fx.tenant.id,
        fx.agent.id,
        TOOL_KEY,
        agent_scope_value="example/a-repo-this-agent-is-not-scoped-to",
        payload=_payload(),
    )
    approve(fx.tenant.id, approval.id, fx.approver.id)

    with pytest.raises(UnauthorizedToolInvocationError):
        await execute_approved(fx.tenant.id, approval.id, registry=fx.registry)
    assert fx.provider.opened_pull_requests == {}
