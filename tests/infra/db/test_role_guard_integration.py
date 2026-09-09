"""Real-PostgreSQL integration tests for `infra.db.role_guard
.validate_application_role` (P1.2). Proves the actual `pg_roles` semantics
this guard depends on -- not just the pure decision logic (see
`tests/infra/db/test_role_guard_unit.py` for that) -- using real,
throwaway PostgreSQL roles created via the privileged
`MIGRATIONS_DATABASE_URL` connection, mirroring how `tests/core/tenancy
/test_tenant_isolation_integration.py` uses `admin_session_factory` only
for privileged setup/teardown while every actual assertion runs against
the role under test.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_role_guard_integration.py
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from infra.db.config import DatabaseConfig, get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.role_guard import (
    ApplicationRoleValidation,
    UnsafeDatabaseRoleError,
    validate_application_role,
)
from sqlalchemy import text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import OperationalError

pytestmark = pytest.mark.integration


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


def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.fixture
def admin_engine() -> Iterator[Engine]:
    """The privileged bootstrap/migration connection -- used only to
    create/drop the throwaway roles under test, exactly mirroring how the
    Phase 3.1 isolation suite's `admin_session_factory` is used only for
    privileged fixture setup, never for the assertions themselves."""
    engine = build_engine(get_migrations_database_config())
    try:
        yield engine
    finally:
        engine.dispose()


def _role_engine(role: str, password: str) -> Engine:
    """A real Engine authenticating as `role` -- built from the same host/
    port/database `MIGRATIONS_DATABASE_URL` already points at, with only
    the credential swapped, so this exercises a real network round-trip
    to the same real database instance every other test in this file
    uses."""
    base_url = make_url(get_migrations_database_config().url)
    role_url = base_url.set(username=role, password=password)
    # `str(URL)` masks the password (`render_as_string(hide_password=True)`,
    # SQLAlchemy's default) -- render it unmasked here, the one place this
    # engine's real credential must actually be usable to connect.
    return build_engine(
        DatabaseConfig(url=role_url.render_as_string(hide_password=False)),
        connect_args={"connect_timeout": 5},
    )


@pytest.fixture
def throwaway_role(admin_engine: Engine):
    """Yields a factory: `throwaway_role(sql_attributes) -> (role, password)`
    that creates a real, throwaway, LOGIN-capable role with the given
    PostgreSQL role-attribute clause (e.g. `"SUPERUSER"`, `"BYPASSRLS"`)
    and drops it on teardown. Role name and password are both locally
    generated (`uuid4().hex` -- alphanumeric only), never external input,
    so building the DDL by f-string here mirrors this repository's own
    established convention for trusted, non-user-supplied SQL identifiers
    (`infra/db/rls.py`'s own docstring)."""
    created: list[str] = []

    def _create(attributes: str) -> tuple[str, str]:
        role = _unique("p12_test_role")
        password = uuid.uuid4().hex
        with admin_engine.connect() as conn:
            conn.execute(text(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' {attributes}"))
            dbname = base_dbname(admin_engine)
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{dbname}" TO "{role}"'))
            conn.commit()
        created.append(role)
        return role, password

    yield _create

    with admin_engine.connect() as conn:
        for role in created:
            # The explicit GRANT CONNECT above leaves the role owning a
            # database-level privilege -- DROP ROLE refuses to drop a role
            # with dependent privileges, so revoke everything it was
            # granted before dropping it.
            conn.execute(text(f'DROP OWNED BY "{role}"'))
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        conn.commit()


def base_dbname(engine: Engine) -> str:
    return engine.url.database or ""


# --- The real application runtime role -------------------------------------


def test_the_real_application_runtime_role_passes() -> None:
    """Non-vacuous baseline: the actual `DATABASE_URL` role this
    repository ships (`saas_os_app`, `NOSUPERUSER NOBYPASSRLS`, `infra/db
    /init/01-create-app-role.sh`) passes the guard using the same
    process-wide engine the real application would use."""
    result = validate_application_role(get_engine())
    assert isinstance(result, ApplicationRoleValidation)
    assert result.role_name


# --- Real superuser / BYPASSRLS roles are rejected --------------------------


def test_a_real_superuser_role_is_rejected(throwaway_role) -> None:
    role, password = throwaway_role("SUPERUSER NOBYPASSRLS")
    engine = _role_engine(role, password)
    try:
        with pytest.raises(UnsafeDatabaseRoleError, match="superuser"):
            validate_application_role(engine)
    finally:
        engine.dispose()


def test_a_real_bypassrls_role_is_rejected(throwaway_role) -> None:
    role, password = throwaway_role("NOSUPERUSER BYPASSRLS")
    engine = _role_engine(role, password)
    try:
        with pytest.raises(UnsafeDatabaseRoleError, match="BYPASSRLS"):
            validate_application_role(engine)
    finally:
        engine.dispose()


def test_a_real_superuser_bypassrls_role_is_rejected(throwaway_role) -> None:
    role, password = throwaway_role("SUPERUSER BYPASSRLS")
    engine = _role_engine(role, password)
    try:
        with pytest.raises(UnsafeDatabaseRoleError):
            validate_application_role(engine)
    finally:
        engine.dispose()


def test_a_real_safe_role_passes(throwaway_role) -> None:
    """A freshly created, ordinary `NOSUPERUSER NOBYPASSRLS` role -- not
    the shipped `saas_os_app` role -- also passes, proving the guard
    checks the role's actual attributes, not a hardcoded role name."""
    role, password = throwaway_role("NOSUPERUSER NOBYPASSRLS")
    engine = _role_engine(role, password)
    try:
        result = validate_application_role(engine)
        assert result.role_name == role
    finally:
        engine.dispose()


# --- Unreachable database fails closed ---------------------------------


def test_unreachable_database_fails_closed() -> None:
    base_url = make_url(get_migrations_database_config().url)
    unreachable_url = base_url.set(host=base_url.host, port=1)  # port 1: connection refused, fast
    config = DatabaseConfig(url=str(unreachable_url))
    engine = build_engine(config, connect_args={"connect_timeout": 2})
    try:
        with pytest.raises(UnsafeDatabaseRoleError, match="not reachable"):
            validate_application_role(engine)
    finally:
        engine.dispose()


def test_unreachable_database_error_never_contains_the_connection_string() -> None:
    base_url = make_url(get_migrations_database_config().url)
    unreachable_url = base_url.set(host=base_url.host, port=1)
    config = DatabaseConfig(url=str(unreachable_url))
    engine = build_engine(config, connect_args={"connect_timeout": 2})
    try:
        with pytest.raises(UnsafeDatabaseRoleError) as excinfo:
            validate_application_role(engine)
        message = str(excinfo.value)
        assert str(unreachable_url) not in message
        assert (base_url.password or "") not in message if base_url.password else True
    finally:
        engine.dispose()
