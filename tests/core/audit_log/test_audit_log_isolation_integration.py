"""Cross-tenant isolation integration tests for `core.audit_log` against a
real PostgreSQL instance with the Phase 3.4 table actually migrated
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 sections 15-16).

Mirrors `tests/core/rbac/test_rbac_isolation_integration.py`'s structure
and discipline (real `saas_os_app` runtime role, not a manufactured
test-only role) -- exercises the real, migrated `core.audit_log` table
directly.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/audit_log/test_audit_log_isolation_integration.py
"""

from __future__ import annotations

import uuid

# Registers core.users on the shared declarative Base.metadata -- this
# file never otherwise imports core.identity, but
# AuditLogEntry.actor_user_id's ForeignKey("core.users.id") needs that
# table's mapping present for INSERT to resolve it (a test-file-only
# concern -- core/audit_log itself never imports core.identity, see
# core/audit_log/models.py's docstring).
import core.identity.models  # noqa: F401
import pytest
from core.audit_log.models import ActorType, AuditOutcome
from core.audit_log.service import list as list_audit_entries
from core.audit_log.service import record
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_audit_log_table() -> None:
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
            conn.execute(text("SELECT 1 FROM core.audit_log LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(f"core.audit_log does not exist yet -- run `alembic upgrade head` first: {exc}")
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


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _cleanup(tenant_ids: list[uuid.UUID]) -> None:
    admin_engine = build_engine(get_migrations_database_config())
    try:
        admin_factory = build_session_factory(admin_engine)
        with session_scope(session_factory=admin_factory) as session:
            for tenant_id in tenant_ids:
                session.execute(
                    text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
                )
    finally:
        admin_engine.dispose()
    with session_scope() as session:
        for tenant_id in tenant_ids:
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


@pytest.fixture
def tenant_a():
    return create_tenant(_unique_name("tenant-a"))


@pytest.fixture
def tenant_b():
    return create_tenant(_unique_name("tenant-b"))


@pytest.fixture(autouse=True)
def _cleanup_tenants(tenant_a, tenant_b):
    yield
    _cleanup([tenant_a.id, tenant_b.id])


def _record_for(tenant_id: uuid.UUID, action: str) -> uuid.UUID:
    entry = record(
        tenant_id=tenant_id,
        actor_type=ActorType.SYSTEM,
        action=action,
        resource_type="probe",
        outcome=AuditOutcome.SUCCESS,
    )
    return entry.id


# --- Setup correctness -----------------------------------------------------


def test_force_row_level_security_is_actually_enabled() -> None:
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'audit_log'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True


def test_runtime_role_has_no_update_or_delete_privilege() -> None:
    with _admin_session() as session:
        rows = session.execute(
            text(
                "SELECT privilege_type FROM information_schema.role_table_grants "
                "WHERE grantee = 'saas_os_app' AND table_schema = 'core' "
                "AND table_name = 'audit_log'"
            )
        ).all()
    privileges = {r[0] for r in rows}
    assert privileges == {"SELECT", "INSERT"}


# --- Core isolation: A sees A, B sees B, neither sees the other ------------


def test_tenant_a_cannot_read_tenant_b_entries(tenant_a, tenant_b) -> None:
    _record_for(tenant_a.id, "a-action")
    _record_for(tenant_b.id, "b-action")

    visible_from_a = list_audit_entries(tenant_a.id)
    assert {e.action for e in visible_from_a} == {"a-action"}


def test_tenant_b_cannot_read_tenant_a_entries(tenant_a, tenant_b) -> None:
    _record_for(tenant_a.id, "a-action")
    _record_for(tenant_b.id, "b-action")

    visible_from_b = list_audit_entries(tenant_b.id)
    assert {e.action for e in visible_from_b} == {"b-action"}


def test_tenant_a_cannot_enumerate_tenant_b_entries_via_raw_query(tenant_a, tenant_b) -> None:
    """Enumerate: try to read every row in the table (no filter beyond
    tenant context) from tenant A's session and confirm tenant B's rows
    never appear, even via a bare unfiltered SELECT."""
    _record_for(tenant_a.id, "a-action")
    _record_for(tenant_b.id, "b-action")

    with tenant_session_scope(tenant_a.id) as session:
        rows = session.execute(text("SELECT tenant_id, action FROM core.audit_log")).all()
    assert all(row[0] == tenant_a.id for row in rows)
    assert "b-action" not in {row[1] for row in rows}


def test_tenant_a_cannot_create_an_audit_record_for_tenant_b(tenant_a, tenant_b) -> None:
    """`record(tenant_id=tenant_b.id, ...)` sets the session's own tenant
    context to tenant_b for that call -- this test instead simulates the
    adversarial shape: a caller *authenticated as* tenant A's context
    attempting to smuggle a tenant_b-labeled row in via raw SQL."""
    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        with tenant_session_scope(tenant_a.id) as session:
            session.execute(
                text(
                    "INSERT INTO core.audit_log "
                    "(id, tenant_id, actor_type, action, resource_type, outcome) "
                    "VALUES (:id, :tid, 'system', 'smuggled', 'probe', 'success')"
                ),
                {"id": str(uuid.uuid4()), "tid": str(tenant_b.id)},
            )
    assert "row-level security" in str(excinfo.value).lower()

    # Confirm nothing was smuggled into tenant B's own view either.
    visible_from_b = list_audit_entries(tenant_b.id)
    assert "smuggled" not in {e.action for e in visible_from_b}


def test_tenant_a_cannot_manipulate_tenant_b_identifiers(tenant_a, tenant_b) -> None:
    """An UPDATE attempting to re-label a tenant A row as tenant B's (or
    vice versa) -- rejected at the privilege level before RLS is even
    reached (UPDATE is REVOKEd entirely), proven directly."""
    entry_id = _record_for(tenant_a.id, "a-action")

    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        with tenant_session_scope(tenant_a.id) as session:
            session.execute(
                text("UPDATE core.audit_log SET tenant_id = :tid WHERE id = :id"),
                {"tid": str(tenant_b.id), "id": entry_id},
            )
    assert "permission denied" in str(excinfo.value).lower()


# --- Missing / adversarial context ------------------------------------------


def test_missing_tenant_context_sees_zero_audit_rows(tenant_a) -> None:
    _record_for(tenant_a.id, "a-action")

    with session_scope() as session:
        rows = session.execute(text("SELECT id FROM core.audit_log")).all()
    assert rows == []


def test_manually_forged_session_setting_cannot_grant_extra_access(tenant_a) -> None:
    _record_for(tenant_a.id, "a-action")
    forged_tenant_id = uuid.uuid4()

    with session_scope() as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(forged_tenant_id)}
        )
        rows = session.execute(text("SELECT id FROM core.audit_log")).all()
    assert rows == []


def test_injection_shaped_tenant_identifier_is_rejected_not_executed(tenant_a) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 15: "injection-shaped
    tenant identifiers fail safely." `tenant_session_scope()` requires a
    real `uuid.UUID` object (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1) --
    a string, injection-shaped or not, is rejected by a type check before
    ever reaching SQL, exactly the same protection Phase 3.1's own suite
    already proves for every other tenant-owned table.
    """
    with pytest.raises(TypeError):
        with tenant_session_scope("'; DROP TABLE core.audit_log; --"):  # type: ignore[arg-type]
            pass

    # The table must still exist and be queryable afterward.
    with tenant_session_scope(tenant_a.id) as session:
        session.execute(text("SELECT 1 FROM core.audit_log LIMIT 1"))


# --- Pooled connection reuse -------------------------------------------


def test_tenant_context_does_not_leak_across_sequential_pooled_sessions(tenant_a, tenant_b) -> None:
    _record_for(tenant_a.id, "a-action")
    _record_for(tenant_b.id, "b-action")

    for _ in range(10):
        assert {e.action for e in list_audit_entries(tenant_a.id)} == {"a-action"}
        assert {e.action for e in list_audit_entries(tenant_b.id)} == {"b-action"}
        with session_scope() as session:
            assert session.execute(text("SELECT id FROM core.audit_log")).all() == []


# --- Non-vacuous regression: proves RLS itself, not the app filter ---------
# (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 16 -- mandatory)


def test_zero_predicate_query_is_still_isolated_by_rls_alone(tenant_a, tenant_b) -> None:
    """Deliberately issue `SELECT tenant_id FROM core.audit_log` -- no
    `WHERE` clause at all, i.e. exactly what removing the application-level
    tenant predicate from the code would still produce -- under tenant A's
    session, and confirm the result contains only tenant A's rows. This
    passes because of RLS alone: if `core/audit_log/service.py`'s own
    `tenant_id ==` filters were deleted entirely, this test's assertion
    would be completely unaffected, since it never calls `list()` or
    `record()` -- it talks to the table directly. If RLS itself were
    removed (or FORCE dropped, or the runtime role gained BYPASSRLS), this
    test would fail.
    """
    _record_for(tenant_a.id, "a-action")
    _record_for(tenant_a.id, "a-action-2")
    _record_for(tenant_b.id, "b-action")

    with tenant_session_scope(tenant_a.id) as session:
        tenant_ids = {
            row[0] for row in session.execute(text("SELECT tenant_id FROM core.audit_log")).all()
        }
    assert tenant_ids == {tenant_a.id}
