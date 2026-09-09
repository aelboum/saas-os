"""Cross-tenant isolation integration tests for
`control_plane.approval_requests` against a real PostgreSQL instance
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.1's standing rule: "No phase
touching tenant data may merge without the cross-tenant isolation suite
... passing against the new code"; this task's own Rule 12: "If Phase 7
introduces tenant-owned data, the complete Phase 3.1 isolation
methodology is mandatory").

Mirrors tests/core/usage/test_usage_isolation_integration.py's structure
and discipline (real `saas_os_app` runtime role, not a manufactured
test-only role).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/control_plane/approvals/test_approvals_isolation_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from control_plane.approvals.errors import ApprovalRequestNotFoundError
from control_plane.approvals.models import ApprovalRequest
from control_plane.approvals.service import get_approval, list_approvals
from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_approval_requests_table() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.approval_requests LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"control_plane.approval_requests does not exist yet -- "
            f"run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


class _TenantRig:
    def __init__(self, label: str) -> None:
        self.tenant = create_tenant(f"appr-tenant-{label}-{uuid.uuid4().hex[:8]}")
        self.proposer = create_user()
        with tenant_session_scope(self.tenant.id) as session:
            approval = ApprovalRequest(
                tenant_id=self.tenant.id,
                proposer_user_id=self.proposer.id,
                tool_key="tier1_stub_tool",
                agent_scope_value="example/sandbox-repo",
                payload={"repository": "example/sandbox-repo"},
                status="pending",
            )
            session.add(approval)
            session.flush()
            session.refresh(approval)
            session.expunge(approval)
        self.approval = approval


@pytest.fixture
def rig_a():
    return _TenantRig("a")


@pytest.fixture
def rig_b():
    return _TenantRig("b")


def _cleanup(rig: _TenantRig) -> None:
    with tenant_session_scope(rig.tenant.id) as session:
        session.execute(
            text("DELETE FROM control_plane.approval_requests WHERE tenant_id = :t"),
            {"t": str(rig.tenant.id)},
        )
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(rig.proposer.id)})
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(rig.tenant.id)})


@pytest.fixture(autouse=True)
def _cleanup_rigs(rig_a: _TenantRig, rig_b: _TenantRig):
    yield
    _cleanup(rig_a)
    _cleanup(rig_b)


# --- Setup correctness -----------------------------------------------------


def test_approval_requests_has_force_row_level_security(rig_a: _TenantRig) -> None:
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'approval_requests'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True


# --- Cross-tenant: A cannot read/write/delete B's approval requests --------


def test_tenant_a_read_own_approval_passes(rig_a: _TenantRig) -> None:
    fetched = get_approval(rig_a.tenant.id, rig_a.approval.id)
    assert fetched.id == rig_a.approval.id


def test_tenant_a_cannot_read_tenant_bs_approval(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    with pytest.raises(ApprovalRequestNotFoundError):
        get_approval(rig_a.tenant.id, rig_b.approval.id)


def test_tenant_a_list_does_not_include_tenant_bs_approval(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    ids = {a.id for a in list_approvals(rig_a.tenant.id)}
    assert rig_b.approval.id not in ids


def test_tenant_a_cannot_modify_tenant_bs_approval_via_raw_sql(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        result = session.execute(
            text("UPDATE control_plane.approval_requests SET status = 'rejected' WHERE id = :id"),
            {"id": str(rig_b.approval.id)},
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]

    still = get_approval(rig_b.tenant.id, rig_b.approval.id)
    assert still.status == "pending"


def test_tenant_a_cannot_delete_tenant_bs_approval_via_raw_sql(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        result = session.execute(
            text("DELETE FROM control_plane.approval_requests WHERE id = :id"),
            {"id": str(rig_b.approval.id)},
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]

    still = get_approval(rig_b.tenant.id, rig_b.approval.id)
    assert still.id == rig_b.approval.id


# --- Non-vacuous DB-boundary proof ------------------------------------------


def test_rls_alone_blocks_cross_tenant_read_with_no_application_filter(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        tenant_ids = {
            row[0]
            for row in session.execute(
                text("SELECT tenant_id FROM control_plane.approval_requests")
            ).all()
        }
    assert tenant_ids == {rig_a.tenant.id}


def test_missing_tenant_context_sees_zero_approval_rows(rig_a: _TenantRig) -> None:
    with session_scope() as session:
        rows = session.execute(text("SELECT id FROM control_plane.approval_requests")).all()
    assert rows == []


def test_manually_forged_session_setting_cannot_grant_extra_access(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with session_scope() as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(uuid.uuid4())}
        )
        rows = session.execute(text("SELECT id FROM control_plane.approval_requests")).all()
    assert rows == []


def test_tenant_a_cannot_read_tenant_bs_approval_payload(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        rows = session.execute(
            text("SELECT payload FROM control_plane.approval_requests WHERE id = :id"),
            {"id": str(rig_b.approval.id)},
        ).all()
    assert rows == []
