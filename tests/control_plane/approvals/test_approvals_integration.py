"""Propose -> approve -> execute / reject workflow integration tests
against a real PostgreSQL instance (docs/IMPLEMENTATION-ROADMAP.md Phase
7.2's own Tests/Acceptance Criteria: "a staged action requires approval
before execution; an approval is itself audit-logged with the approving
human's identity"; "full propose -> approve -> execute cycle works for a
stub action; a rejected proposal never executes"; Security Requirement:
"an approval cannot be self-granted by the same identity that proposed
the action").

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/control_plane/approvals/test_approvals_integration.py
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
from sqlalchemy.exc import IntegrityError

from control_plane.approvals.errors import (
    ApprovalNotPendingError,
    SelfApprovalNotAllowedError,
)
from control_plane.approvals.service import (
    approve,
    execute_approved,
    get_approval,
    list_approvals,
    propose_action,
    reject,
)
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


async def _stub_handler(context: ToolExecutionContext, payload) -> dict[str, object]:
    return {"executed": True}


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(_unique("appr-tenant"))
        self.proposer = create_user()
        self.approver = create_user()
        add_tenant_membership(self.tenant.id, self.proposer.id)
        add_tenant_membership(self.tenant.id, self.approver.id)

        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                key="tier1_stub_tool",
                description="A stub tier-1 tool.",
                handler=_stub_handler,
                required_scope_type="repository",
                required_scope_value="example/sandbox-repo",
                autonomy_tier=1,
            )
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
                {"a": str(self.proposer.id), "b": str(self.approver.id)},
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


# --- Propose ---------------------------------------------------------------


async def test_propose_action_creates_a_pending_request_and_is_audited(fx: _Fixture) -> None:
    approval = propose_action(
        fx.tenant.id,
        fx.proposer.id,
        "tier1_stub_tool",
        agent_scope_value="example/sandbox-repo",
        payload={"repository": "example/sandbox-repo"},
    )
    assert approval.status == "pending"

    fetched = get_approval(fx.tenant.id, approval.id)
    assert fetched.id == approval.id

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "control_plane.action_proposed"]
    assert len(matching) == 1
    assert matching[0].actor_user_id == fx.proposer.id


# --- Full propose -> approve -> execute cycle ------------------------------


async def test_full_propose_approve_execute_cycle(fx: _Fixture) -> None:
    approval = propose_action(
        fx.tenant.id,
        fx.proposer.id,
        "tier1_stub_tool",
        agent_scope_value="example/sandbox-repo",
        payload={"repository": "example/sandbox-repo"},
    )

    approved = approve(fx.tenant.id, approval.id, fx.approver.id)
    assert approved.status == "approved"
    assert approved.approver_user_id == fx.approver.id
    assert approved.decided_at is not None

    executed = await execute_approved(fx.tenant.id, approval.id, registry=fx.registry)
    assert executed.status == "executed"

    entries = list_audit_entries(fx.tenant.id)
    assert any(e.action == "control_plane.action_approved" for e in entries)
    assert any(
        e.action == "control_plane.tool_invocation" and e.outcome == "success" for e in entries
    )


# --- Rejected proposal never executes --------------------------------------


async def test_rejected_proposal_never_executes(fx: _Fixture) -> None:
    approval = propose_action(
        fx.tenant.id,
        fx.proposer.id,
        "tier1_stub_tool",
        agent_scope_value="example/sandbox-repo",
        payload={"repository": "example/sandbox-repo"},
    )
    rejected = reject(fx.tenant.id, approval.id, fx.approver.id)
    assert rejected.status == "rejected"

    with pytest.raises(ApprovalNotPendingError):
        await execute_approved(fx.tenant.id, approval.id, registry=fx.registry)

    fetched = get_approval(fx.tenant.id, approval.id)
    assert fetched.status == "rejected"  # never transitions to "executed"

    entries = list_audit_entries(fx.tenant.id)
    assert any(e.action == "control_plane.action_rejected" for e in entries)
    assert not any(e.action == "control_plane.tool_invocation" for e in entries)


# --- Separation of duties: self-approval is rejected -----------------------


async def test_self_approval_is_rejected_at_the_application_layer(fx: _Fixture) -> None:
    approval = propose_action(fx.tenant.id, fx.proposer.id, "tier1_stub_tool")
    with pytest.raises(SelfApprovalNotAllowedError):
        approve(fx.tenant.id, approval.id, fx.proposer.id)

    fetched = get_approval(fx.tenant.id, approval.id)
    assert fetched.status == "pending"  # the self-approval attempt never took effect


async def test_self_approval_denial_is_audited(fx: _Fixture) -> None:
    approval = propose_action(fx.tenant.id, fx.proposer.id, "tier1_stub_tool")
    with pytest.raises(SelfApprovalNotAllowedError):
        approve(fx.tenant.id, approval.id, fx.proposer.id)

    entries = list_audit_entries(fx.tenant.id)
    matching = [
        e for e in entries if e.action == "control_plane.action_approved" and e.outcome == "denied"
    ]
    assert len(matching) == 1


async def test_self_approval_is_rejected_at_the_database_level_non_vacuously(fx: _Fixture) -> None:
    """Non-vacuous proof that the CHECK constraint
    (`ck_approval_requests_no_self_approval`) is a real, independent
    guarantee -- bypass the application-layer `approve()` check entirely
    and attempt the same self-approval directly via raw SQL."""
    approval = propose_action(fx.tenant.id, fx.proposer.id, "tier1_stub_tool")
    with pytest.raises(IntegrityError, match="ck_approval_requests_no_self_approval"):
        with tenant_session_scope(fx.tenant.id) as session:
            session.execute(
                text(
                    "UPDATE control_plane.approval_requests "
                    "SET status = 'approved', approver_user_id = :approver "
                    "WHERE id = :id"
                ),
                {"approver": str(fx.proposer.id), "id": str(approval.id)},
            )


# --- Decided-once semantics --------------------------------------------


async def test_approving_an_already_decided_request_is_rejected(fx: _Fixture) -> None:
    approval = propose_action(fx.tenant.id, fx.proposer.id, "tier1_stub_tool")
    approve(fx.tenant.id, approval.id, fx.approver.id)
    with pytest.raises(ApprovalNotPendingError):
        approve(fx.tenant.id, approval.id, fx.approver.id)


async def test_rejecting_an_already_approved_request_is_rejected(fx: _Fixture) -> None:
    approval = propose_action(fx.tenant.id, fx.proposer.id, "tier1_stub_tool")
    approve(fx.tenant.id, approval.id, fx.approver.id)
    with pytest.raises(ApprovalNotPendingError):
        reject(fx.tenant.id, approval.id, fx.approver.id)


# --- Listing -----------------------------------------------------------


async def test_list_approvals_filters_by_status(fx: _Fixture) -> None:
    a1 = propose_action(fx.tenant.id, fx.proposer.id, "tier1_stub_tool")
    a2 = propose_action(fx.tenant.id, fx.proposer.id, "tier1_stub_tool")
    reject(fx.tenant.id, a2.id, fx.approver.id)

    pending = list_approvals(fx.tenant.id, status="pending")
    assert {a.id for a in pending} == {a1.id}

    rejected = list_approvals(fx.tenant.id, status="rejected")
    assert {a.id for a in rejected} == {a2.id}
