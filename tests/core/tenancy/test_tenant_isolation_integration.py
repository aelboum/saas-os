"""Cross-tenant data isolation integration test against a real PostgreSQL
instance (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1 -- the platform's
primary security boundary, docs/SECURITY.md section 5).

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/infra/test_db_integration.py` (Phase 2.1).

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/tenancy/test_tenant_isolation_integration.py

**Security correction (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1)**:
PostgreSQL never applies Row-Level Security to a superuser or a role with
BYPASSRLS -- there is no override, `FORCE ROW LEVEL SECURITY` included.
An earlier version of this file created a throwaway, per-test restricted
role for the isolation assertions while `DATABASE_URL` (what the real
application actually connects as) remained the Postgres superuser
bootstrap role -- every assertion would have passed while providing zero
real protection. The fix was architectural, not just a test fix: the
application now runs as a dedicated, `NOSUPERUSER NOBYPASSRLS` role
(`APP_DB_USER`/`saas_os_app`, created by
`infra/db/init/01-create-app-role.sh`), separate from the bootstrap/
migration role (`POSTGRES_USER`/`saas_os`, `MIGRATIONS_DATABASE_URL`).
Every isolation assertion below therefore uses the *default*
`session_scope()`/`tenant_session_scope()` (i.e. whatever `DATABASE_URL`
actually is) -- the same connection the real application uses -- not a
separate role manufactured only for this test file. `admin_session_factory`
(built from `MIGRATIONS_DATABASE_URL`) is used only for scratch-table
setup/teardown, exactly mirroring what a real migration does for a real
tenant-owned table.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.rls import tenant_rls_statements
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

pytestmark = pytest.mark.integration

_APP_ROLE = os.environ.get("APP_DB_USER", "saas_os_app")


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
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
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


@pytest.fixture
def admin_session_factory() -> Iterator[sessionmaker[Session]]:
    """The privileged bootstrap/migration connection -- used *only* to set
    up (and tear down) the scratch tenant-owned table, exactly mirroring
    what a real migration does for a real tenant-owned table. Every
    isolation assertion in this file uses the default, application-role
    `session_scope()`/`tenant_session_scope()` instead (see module
    docstring) -- this fixture is deliberately not used for those.
    """
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def scratch_table(admin_session_factory: sessionmaker[Session]) -> Iterator[str]:
    table = f"phase31_rls_probe_{uuid.uuid4().hex[:8]}"
    with session_scope(session_factory=admin_session_factory) as session:
        session.execute(
            text(f"CREATE TABLE {table} (id UUID PRIMARY KEY, tenant_id UUID NOT NULL, data TEXT)")
        )
        # Mirrors what a real migration grants the runtime app role on a
        # real tenant-owned table (see the core.tenants migration).
        session.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO "{_APP_ROLE}"'))
        for statement in tenant_rls_statements(table):
            session.execute(text(statement))
    try:
        yield table
    finally:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(text(f"DROP TABLE IF EXISTS {table}"))


def _insert(table: str, tenant_id: uuid.UUID, data: str) -> uuid.UUID:
    row_id = uuid.uuid4()
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text(f"INSERT INTO {table} (id, tenant_id, data) VALUES (:id, :tenant_id, :data)"),
            {"id": str(row_id), "tenant_id": str(tenant_id), "data": data},
        )
    return row_id


def _select_all_data(table: str, session: Session) -> list[str]:
    rows = session.execute(text(f"SELECT data FROM {table} ORDER BY data")).all()
    return [r[0] for r in rows]


# --- Setup correctness (proves the fixture/mechanism itself is real) -------


def test_force_row_level_security_is_actually_enabled(
    scratch_table: str, admin_session_factory: sessionmaker[Session]
) -> None:
    """Non-vacuous proof that infra.db.rls's FORCE clause is not a no-op
    statement -- query Postgres's own catalog, don't just trust the DDL
    text.
    """
    with session_scope(session_factory=admin_session_factory) as session:
        row = session.execute(
            text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = :t"),
            {"t": scratch_table},
        ).one()
    assert row[0] is True  # relrowsecurity
    assert row[1] is True  # relforcerowsecurity


def test_the_real_runtime_role_is_not_superuser_or_bypassrls() -> None:
    """THE regression test for this phase's security correction (section 8
    of the correction task): if `DATABASE_URL` is ever pointed back at a
    superuser or BYPASSRLS role, this fails -- and every isolation
    assertion below would otherwise become silently vacuous again. Uses
    the *default* session_scope(), i.e. whatever the real application
    actually connects as -- not a role manufactured only for this test.
    """
    with session_scope() as session:
        row = session.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
    assert row[0] is False, "the application runtime role must not be a Postgres superuser"
    assert row[1] is False, "the application runtime role must not have BYPASSRLS"


def test_bootstrap_and_runtime_roles_are_actually_distinct(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """Role separation (section 13 Q11 of the correction task): proves
    `DATABASE_URL` and `MIGRATIONS_DATABASE_URL` are genuinely two
    different PostgreSQL roles, not the same credential under two names.
    """
    with session_scope() as session:
        runtime_user = session.execute(text("SELECT current_user")).scalar_one()
    with session_scope(session_factory=admin_session_factory) as session:
        bootstrap_user = session.execute(text("SELECT current_user")).scalar_one()

    assert runtime_user != bootstrap_user


def test_bootstrap_role_is_the_table_owner_not_the_runtime_role(
    scratch_table: str, admin_session_factory: sessionmaker[Session]
) -> None:
    """Least-privilege ownership: the runtime app role has only GRANTed
    DML, never table ownership -- so it cannot ALTER/DROP the table or
    otherwise manage it, regardless of FORCE RLS (docs/IMPLEMENTATION-
    ROADMAP.md Phase 3.1 correction section 4).
    """
    with session_scope(session_factory=admin_session_factory) as session:
        owner = session.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = :t"), {"t": scratch_table}
        ).scalar_one()
    assert owner != _APP_ROLE


def test_runtime_role_cannot_alter_or_drop_the_table(scratch_table: str) -> None:
    with session_scope() as session, pytest.raises(Exception):  # noqa: PT011, B017
        session.execute(text(f"ALTER TABLE {scratch_table} DISABLE ROW LEVEL SECURITY"))


# --- Core isolation: A sees A, B sees B, neither sees the other ------------


def test_tenant_a_can_read_its_own_data(scratch_table: str) -> None:
    tenant_a = uuid.uuid4()
    _insert(scratch_table, tenant_a, "a-data")

    with tenant_session_scope(tenant_a) as session:
        assert _select_all_data(scratch_table, session) == ["a-data"]


def test_tenant_b_can_read_its_own_data(scratch_table: str) -> None:
    tenant_b = uuid.uuid4()
    _insert(scratch_table, tenant_b, "b-data")

    with tenant_session_scope(tenant_b) as session:
        assert _select_all_data(scratch_table, session) == ["b-data"]


def test_tenant_a_cannot_read_tenant_b_data(scratch_table: str) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    _insert(scratch_table, tenant_a, "a-data")
    _insert(scratch_table, tenant_b, "b-data")

    with tenant_session_scope(tenant_a) as session:
        assert _select_all_data(scratch_table, session) == ["a-data"]


def test_tenant_b_cannot_read_tenant_a_data(scratch_table: str) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    _insert(scratch_table, tenant_a, "a-data")
    _insert(scratch_table, tenant_b, "b-data")

    with tenant_session_scope(tenant_b) as session:
        assert _select_all_data(scratch_table, session) == ["b-data"]


# --- Missing / adversarial context ------------------------------------------


def test_missing_tenant_context_returns_zero_rows_not_all_rows(scratch_table: str) -> None:
    """The chokepoint's deny-by-default guarantee: a session that never
    called tenant_session_scope() (e.g. a bug that forgot to set tenant
    context) must see NOTHING from a tenant-owned table -- not an error,
    not every tenant's data.
    """
    tenant_a = uuid.uuid4()
    _insert(scratch_table, tenant_a, "a-data")

    with session_scope() as session:
        assert _select_all_data(scratch_table, session) == []


def test_bare_session_scope_cannot_be_used_to_bypass_isolation(scratch_table: str) -> None:
    """Adversarial: even going through the sanctioned infra/db chokepoint
    (not some raw psycopg connection), simply omitting tenant context is
    not a viable bypass.
    """
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    _insert(scratch_table, tenant_a, "a-data")
    _insert(scratch_table, tenant_b, "b-data")

    with session_scope() as session:
        assert _select_all_data(scratch_table, session) == []


def test_tenant_session_scope_rejects_non_uuid_context(scratch_table: str) -> None:
    with pytest.raises(TypeError):
        with tenant_session_scope("'; SELECT * FROM " + scratch_table + "; --"):  # type: ignore[arg-type]
            pass


def test_manually_forged_session_setting_cannot_grant_extra_access(scratch_table: str) -> None:
    """Adversarial: even if a caller reaches past tenant_session_scope()
    and calls set_config() directly (bypassing the UUID type check), the
    runtime role still cannot see another tenant's row that way -- the
    RLS policy itself, not the type check, is the real boundary. Uses a
    syntactically-valid but never-inserted tenant_id, so this only proves
    "forging a setting doesn't grant access to real data," not a false
    positive from matching zero rows regardless.
    """
    tenant_a = uuid.uuid4()
    _insert(scratch_table, tenant_a, "a-data")
    forged_tenant_id = uuid.uuid4()

    with session_scope() as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"),
            {"tid": str(forged_tenant_id)},
        )
        assert _select_all_data(scratch_table, session) == []


# --- Writes cannot cross tenant boundaries ----------------------------------


def test_cross_tenant_insert_is_rejected(scratch_table: str) -> None:
    """Tenant A's session attempts to insert a row *labeled* as tenant
    B's -- the RLS policy's implicit WITH CHECK (derived from USING, since
    no dedicated FOR INSERT policy overrides it) must reject this, not
    silently accept a mislabeled row.
    """
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    row_id = uuid.uuid4()

    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        with tenant_session_scope(tenant_a) as session:
            session.execute(
                text(f"INSERT INTO {scratch_table} (id, tenant_id, data) VALUES (:id, :tid, :d)"),
                {"id": str(row_id), "tid": str(tenant_b), "d": "smuggled"},
            )
    assert "row-level security" in str(excinfo.value).lower()

    # Confirm nothing was smuggled in under B's identity either.
    with tenant_session_scope(tenant_b) as session:
        assert _select_all_data(scratch_table, session) == []


def test_cross_tenant_update_affects_zero_rows(scratch_table: str) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    row_id = _insert(scratch_table, tenant_b, "b-original")

    with tenant_session_scope(tenant_a) as session:
        result = session.execute(
            text(f"UPDATE {scratch_table} SET data = :d WHERE id = :id"),
            {"d": "tampered-by-a", "id": str(row_id)},
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]

    with tenant_session_scope(tenant_b) as session:
        assert _select_all_data(scratch_table, session) == ["b-original"]


def test_cross_tenant_delete_affects_zero_rows(scratch_table: str) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    row_id = _insert(scratch_table, tenant_b, "b-original")

    with tenant_session_scope(tenant_a) as session:
        result = session.execute(
            text(f"DELETE FROM {scratch_table} WHERE id = :id"), {"id": str(row_id)}
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]

    with tenant_session_scope(tenant_b) as session:
        assert _select_all_data(scratch_table, session) == ["b-original"]


# --- Connection-pool reuse cannot leak tenant context -----------------------


def test_tenant_context_does_not_leak_across_sequential_pooled_sessions(scratch_table: str) -> None:
    """`tenant_session_scope` uses `set_config(..., is_local=true)`, reset
    by PostgreSQL at each transaction's end -- even though the underlying
    connection is pooled and reused. Run enough sequential scoped sessions
    on the small default pool to make connection reuse likely, and confirm
    each one only ever sees its own tenant's data.
    """
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    _insert(scratch_table, tenant_a, "a-data")
    _insert(scratch_table, tenant_b, "b-data")

    for _ in range(10):
        with tenant_session_scope(tenant_a) as session:
            assert _select_all_data(scratch_table, session) == ["a-data"]
        with tenant_session_scope(tenant_b) as session:
            assert _select_all_data(scratch_table, session) == ["b-data"]
        with session_scope() as session:
            assert _select_all_data(scratch_table, session) == []
