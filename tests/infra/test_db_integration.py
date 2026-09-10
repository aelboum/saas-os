"""infra/db integration test against a real PostgreSQL instance
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.1: "a query executed through
infra/db succeeds against a real test database").

Marked `integration` and excluded from the default `pytest` run
(pyproject.toml `[tool.pytest.ini_options] addopts`) -- the normal
validation pipeline (`scripts/check-backend.sh`, CI's `backend`/`security`
jobs) must not depend on an external database being available
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.1 task 10).

How to run this test locally:

    docker compose up -d db
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/test_db_integration.py

(host `localhost`, not `db` -- outside the Compose network, the published
host port from docker-compose.yml is what's reachable; `.env`'s
`DATABASE_URL` uses `db` because that's for the `backend` container,
which *is* on the Compose network.)

Since Phase 3.1's security correction, `DATABASE_URL` is the restricted
application runtime role (`NOSUPERUSER NOBYPASSRLS`, and -- as of
PostgreSQL 15 -- no `CREATE` on the `public` schema by default either).
The ad hoc scratch tables these tests create are a testing convenience,
not something the real application does, so they're created through
`MIGRATIONS_DATABASE_URL` (the privileged bootstrap/migration role)
instead of the default `session_scope()`.

If PostgreSQL is not reachable, the test skips with a clear message
rather than failing with a raw connection traceback.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001 -- turned into a clear skip, not a failure
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    # A short, explicit connect timeout for this reachability probe only
    # (not the real engine get_engine() builds -- production connection
    # behavior is unaffected). Without one, connecting to a host that
    # isn't listening can hang for the OS's default TCP timeout (tens of
    # seconds on Windows) instead of skipping promptly -- found empirically
    # while validating this fixture, docs/IMPLEMENTATION-ROADMAP.md Phase 2.1.
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


@pytest.fixture
def admin_session_factory() -> Iterator[sessionmaker[Session]]:
    """The privileged bootstrap/migration connection -- these tests' ad
    hoc scratch tables need `CREATE` privilege the restricted runtime role
    (`DATABASE_URL`) deliberately does not have (docs/IMPLEMENTATION-
    ROADMAP.md Phase 3.1 security correction).
    """
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")
    engine = build_engine(config)
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def test_query_succeeds_through_infra_db() -> None:
    with session_scope() as session:
        result = session.execute(text("SELECT 1 AS value")).one()
    assert result.value == 1


def test_session_scope_transaction_is_real(admin_session_factory: sessionmaker[Session]) -> None:
    """Non-vacuous: prove session_scope() is a real, working transaction
    against real PostgreSQL, not merely a passthrough -- create a table
    (uniquely named to avoid colliding with a concurrent test run),
    insert through one session_scope() call, read it back through a
    second (proving the commit was durable across connections, not just
    visible within one transaction), then drop the table.
    """
    table = f"infra_db_phase21_probe_{uuid.uuid4().hex[:8]}"
    try:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(text(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, value TEXT)"))
            session.execute(text(f"INSERT INTO {table} (id, value) VALUES (1, 'phase-2.1')"))

        with session_scope(session_factory=admin_session_factory) as session:
            row = session.execute(text(f"SELECT value FROM {table} WHERE id = 1")).one()
        assert row.value == "phase-2.1"
    finally:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(text(f"DROP TABLE IF EXISTS {table}"))


def test_session_scope_rolls_back_on_exception(
    admin_session_factory: sessionmaker[Session],
) -> None:
    table = f"infra_db_phase21_rollback_{uuid.uuid4().hex[:8]}"
    try:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(text(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)"))

        with pytest.raises(RuntimeError):
            with session_scope(session_factory=admin_session_factory) as session:
                session.execute(text(f"INSERT INTO {table} (id) VALUES (1)"))
                raise RuntimeError("simulated failure mid-transaction")

        with session_scope(session_factory=admin_session_factory) as session:
            count = session.execute(text(f"SELECT COUNT(*) AS n FROM {table}")).one()
        assert count.n == 0
    finally:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(text(f"DROP TABLE IF EXISTS {table}"))


def test_no_raw_connection_is_available_outside_the_chokepoint() -> None:
    """docs/MULTI-TENANCY.md section 3 / Acceptance Criteria: 'no other
    module can obtain a raw connection' -- infra/db exposes get_engine()
    and session_scope() (and, since Phase 3.1, tenant_session_scope()) as
    its only session/connection entrypoints; the ORM/RLS additions
    (Base, mixins, Mapped/mapped_column/String, tenant_rls_statements) are
    schema-definition and DDL-generation helpers, not connection escape
    hatches -- nothing here hands out a bare, unmanaged connection for ad
    hoc use. `validate_application_role`/`ApplicationRoleValidation`/
    `UnsafeDatabaseRoleError` (P1.2) are the same shape: a startup-time
    safety check that *consumes* an existing engine, never a new way to
    obtain a raw connection. `acquire_tenant_advisory_lock` (P1.9) is the
    same shape again: a named, narrowly-scoped wrapper around the one
    raw-SQL statement (`pg_advisory_xact_lock`) that has no ORM
    equivalent, never a generic `text()`/raw-connection escape hatch
    (see its own docstring, `infra/db/session.py`). `Session` (P1.11) is
    exported purely as a *type* -- `core.idempotency.service.run_idempotent()`
    needs it to annotate the session its `business_fn` callback receives
    (already threaded through `tenant_session_scope()`'s own type
    signature); it is never a second way to construct or obtain a
    session/connection, only a name for the one `tenant_session_scope()`
    already yields. `run_core_migrations` (SaaS OS packaging implementation
    phase, docs/ADR/0016-...) is the same shape once more: it *invokes*
    SaaS OS's own Alembic migration environment (`infra.db.migration_runner`)
    via `alembic.command`, which resolves its own connection internally
    through `get_migrations_database_config()` -- it hands the caller no
    connection or engine of any kind.
    """
    import infra.db as infra_db

    assert set(infra_db.__all__) == {
        "DatabaseConfig",
        "DatabaseConfigurationError",
        "get_database_config",
        "get_migrations_database_config",
        "run_core_migrations",
        "build_engine",
        "get_engine",
        "build_session_factory",
        "get_session_factory",
        "session_scope",
        "tenant_session_scope",
        "acquire_tenant_advisory_lock",
        "Session",
        "Base",
        "UUIDPrimaryKeyMixin",
        "TimestampMixin",
        "Mapped",
        "mapped_column",
        "String",
        "Text",
        "Integer",
        "Numeric",
        "Boolean",
        "DateTime",
        "ForeignKey",
        "ForeignKeyConstraint",
        "UniqueConstraint",
        "CheckConstraint",
        "Index",
        "JSON",
        "func",
        "select",
        "IntegrityError",
        "OperationalError",
        "tenant_rls_statements",
        "validate_application_role",
        "ApplicationRoleValidation",
        "UnsafeDatabaseRoleError",
    }
