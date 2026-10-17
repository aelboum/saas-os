"""The platform-configuration database boundary, proven against real
PostgreSQL (docs/ADR/0056-platform-configuration-database-identity.md).

- The application role (`DATABASE_URL`) cannot `INSERT`, `UPDATE`, `DELETE`
  or `TRUNCATE` any protected AI configuration table, whatever
  `app.tenant_id` holds, and can still read them.
- The platform-configuration role (`PLATFORM_CONFIG_DATABASE_URL`) can insert
  and update them, cannot delete or truncate them, and cannot write anything
  else: no tenant table, no platform grant, operator or user, no audit row
  beyond inserting one. It can lock the authorization rows `FOR SHARE`.
- `validate_application_role()` and `validate_platform_config_role()` refuse
  a drifted grant, a role membership and a role of the wrong kind.

Every statement that would change data runs in a transaction that is rolled
back, so a broken boundary is reported without destroying anything.
Throwaway roles are created through `MIGRATIONS_DATABASE_URL` and dropped.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import DBAPIError, OperationalError

from saas_os.infra.db.config import (
    DatabaseConfig,
    get_database_config,
    get_migrations_database_config,
)
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.platform_config import (
    get_platform_config_database_config,
    validate_platform_config_role,
)
from saas_os.infra.db.role_guard import (
    PROTECTED_TABLES,
    UnsafeDatabaseRoleError,
    validate_application_role,
)

pytestmark = pytest.mark.integration

_INSUFFICIENT_PRIVILEGE = "42501"
# Unset, empty, a random tenant, and the all-zero id a platform tenant might use.
_TENANT_SETTINGS = (None, "", str(uuid.uuid4()), "00000000-0000-0000-0000-000000000000")


@pytest.fixture(autouse=True)
def _require_reachable_database(platform_config_database: None) -> None:
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.ai_providers LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    finally:
        probe.dispose()


def _engine(config: DatabaseConfig) -> Iterator[Engine]:
    engine = build_engine(config, connect_args={"connect_timeout": 5})
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def app_engine() -> Iterator[Engine]:
    yield from _engine(get_database_config())


@pytest.fixture
def config_engine() -> Iterator[Engine]:
    yield from _engine(get_platform_config_database_config())


@pytest.fixture
def admin_engine() -> Iterator[Engine]:
    yield from _engine(get_migrations_database_config())


def _role_of(engine: Engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("SELECT current_user")).scalar_one()


def _attempt(engine: Engine, statement: str, *, tenant: str | None = None) -> None:
    """Run `statement` in a transaction that is always rolled back."""
    with engine.connect() as conn:
        transaction = conn.begin()
        try:
            if tenant is not None:
                conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant})
            conn.execute(text(statement))
        finally:
            transaction.rollback()


def _denied(engine: Engine, statement: str, *, tenant: str | None = None) -> str:
    with pytest.raises(DBAPIError) as caught:
        _attempt(engine, statement, tenant=tenant)
    sqlstate = getattr(caught.value.orig, "sqlstate", None)
    assert sqlstate == _INSUFFICIENT_PRIVILEGE, (statement, sqlstate, str(caught.value.orig))
    return str(caught.value.orig)


def _writes(table: str) -> tuple[str, ...]:
    return (
        f"INSERT INTO {table} (id) VALUES (gen_random_uuid())",
        # No column is read, so only the UPDATE privilege decides.
        f"UPDATE {table} SET id = gen_random_uuid() WHERE false",
        f"DELETE FROM {table} WHERE false",
        f"TRUNCATE {table}",
    )


# --- the application role -------------------------------------------------------------


@pytest.mark.parametrize("tenant", _TENANT_SETTINGS)
@pytest.mark.parametrize("table", PROTECTED_TABLES)
def test_the_application_role_cannot_write_a_protected_table(
    app_engine: Engine, table: str, tenant: str | None
) -> None:
    for statement in _writes(table):
        message = _denied(app_engine, statement, tenant=tenant)
        assert "permission denied" in message


@pytest.mark.parametrize("table", PROTECTED_TABLES)
def test_the_application_role_still_reads_a_protected_table(app_engine: Engine, table: str) -> None:
    for tenant in _TENANT_SETTINGS:
        _attempt(app_engine, f"SELECT count(*) FROM {table}", tenant=tenant)


def test_the_real_application_role_passes_the_startup_guard(app_engine: Engine) -> None:
    assert validate_application_role(app_engine).role_name == _role_of(app_engine)


def test_a_drifted_write_grant_stops_the_application_role(
    app_engine: Engine, admin_engine: Engine
) -> None:
    role = _role_of(app_engine)
    with admin_engine.begin() as conn:
        conn.execute(text(f'GRANT INSERT ON control_plane.ai_aliases TO "{role}"'))
    try:
        with pytest.raises(UnsafeDatabaseRoleError, match=r"control_plane\.ai_aliases"):
            validate_application_role(app_engine)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f'REVOKE INSERT ON control_plane.ai_aliases FROM "{role}"'))
    validate_application_role(app_engine)


@pytest.fixture
def throwaway_login(admin_engine: Engine) -> Iterator[tuple[str, Engine]]:
    role = f"adr56_{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    database = make_url(get_migrations_database_config().url).database
    with admin_engine.begin() as conn:
        conn.execute(text(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'"))
        conn.execute(text(f'GRANT CONNECT ON DATABASE "{database}" TO "{role}"'))
    url = make_url(get_migrations_database_config().url).set(username=role, password=password)
    engine = build_engine(
        DatabaseConfig(url=url.render_as_string(hide_password=False)),
        connect_args={"connect_timeout": 5},
    )
    try:
        yield role, engine
    finally:
        engine.dispose()
        with admin_engine.begin() as conn:
            conn.execute(text(f'DROP OWNED BY "{role}"'))
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))


def test_membership_in_the_platform_configuration_role_stops_an_application_role(
    throwaway_login: tuple[str, Engine], config_engine: Engine, admin_engine: Engine
) -> None:
    role, engine = throwaway_login
    config_role = _role_of(config_engine)
    with admin_engine.begin() as conn:
        conn.execute(text(f'GRANT "{config_role}" TO "{role}"'))
    try:
        with pytest.raises(UnsafeDatabaseRoleError, match="can write"):
            validate_application_role(engine)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f'REVOKE "{config_role}" FROM "{role}"'))


# --- the platform-configuration role ---------------------------------------------------


def test_the_platform_configuration_role_is_distinct_and_passes_its_check(
    config_engine: Engine, app_engine: Engine
) -> None:
    name = validate_platform_config_role(config_engine)
    assert name == _role_of(config_engine)
    assert name != _role_of(app_engine)


def test_the_platform_configuration_role_inserts_and_updates_configuration(
    config_engine: Engine,
) -> None:
    alias_id = uuid.uuid4()
    with config_engine.connect() as conn:
        transaction = conn.begin()
        try:
            conn.execute(
                text(
                    "INSERT INTO control_plane.ai_aliases (id, alias, status) "
                    "VALUES (:id, :alias, 'disabled')"
                ),
                {"id": alias_id, "alias": f"adr56-{alias_id.hex[:8]}"},
            )
            updated = conn.execute(
                text("UPDATE control_plane.ai_aliases SET status = 'active' WHERE id = :id"),
                {"id": alias_id},
            ).rowcount
            assert updated == 1
        finally:
            transaction.rollback()


@pytest.mark.parametrize("table", PROTECTED_TABLES)
def test_the_platform_configuration_role_cannot_delete_or_truncate(
    config_engine: Engine, table: str
) -> None:
    _denied(config_engine, f"DELETE FROM {table} WHERE false")
    _denied(config_engine, f"TRUNCATE {table}")


@pytest.mark.parametrize(
    "table",
    [
        "core.tenants",
        "core.tenant_memberships",
        "core.audit_log",
        "core.platform_operators",
        "core.platform_grants",
        "control_plane.ai_tenant_policies",
        "control_plane.ai_tenant_use_case_grants",
        "control_plane.ai_tenant_destination_grants",
        "control_plane.ai_inference_attempts",
    ],
)
def test_the_platform_configuration_role_cannot_write_unrelated_tables(
    config_engine: Engine, table: str
) -> None:
    for statement in _writes(table):
        _denied(config_engine, statement)


@pytest.mark.parametrize(
    ("table", "assignment", "refused_by"),
    [
        ("core.users", "updated_at = now()", "trigger"),
        ("core.users", "is_active = false", "grant"),
        ("core.platform_operators", "updated_at = now()", "trigger"),
        ("core.platform_operators", "status = 'revoked'", "grant"),
        ("core.platform_grants", "granted_at = now()", "trigger"),
        ("core.platform_grants", "revoked_at = now()", "grant"),
    ],
)
def test_the_platform_configuration_role_never_updates_authorization_rows(
    config_engine: Engine, table: str, assignment: str, refused_by: str
) -> None:
    # The lock column (UPDATE granted for FOR SHARE) is refused by the
    # statement trigger, which fires even when no row matches; every other
    # column by the grant. No column is read, so nothing else can refuse it.
    message = _denied(config_engine, f"UPDATE {table} SET {assignment} WHERE false")
    if refused_by == "trigger":
        assert "platform-configuration role may not update" in message
    else:
        assert "permission denied" in message


def test_the_platform_configuration_role_appends_audit_rows_only(config_engine: Engine) -> None:
    _denied(config_engine, "UPDATE core.platform_audit_log SET reason = 'x' WHERE false")
    _denied(config_engine, "DELETE FROM core.platform_audit_log WHERE false")
    _denied(config_engine, "TRUNCATE core.platform_audit_log")


def test_the_platform_configuration_role_reads_no_user_data(config_engine: Engine) -> None:
    _denied(config_engine, "SELECT created_at FROM core.users LIMIT 1")
    _denied(config_engine, "SELECT * FROM core.external_identities LIMIT 1")
    _denied(config_engine, "SELECT * FROM core.tenants LIMIT 1")
    _denied(config_engine, "SELECT reason FROM core.platform_audit_log LIMIT 1")


def test_the_platform_configuration_role_can_lock_authorization_rows(
    config_engine: Engine,
) -> None:
    for statement in (
        "SELECT id, is_active FROM core.users LIMIT 1 FOR SHARE",
        "SELECT id, status FROM core.platform_operators LIMIT 1 FOR SHARE",
        "SELECT id, permission FROM core.platform_grants LIMIT 1 FOR SHARE",
    ):
        _attempt(config_engine, statement)


def test_the_application_role_is_not_a_platform_configuration_role(app_engine: Engine) -> None:
    with pytest.raises(UnsafeDatabaseRoleError):
        validate_platform_config_role(app_engine)


def test_the_migrations_role_is_not_a_platform_configuration_role(admin_engine: Engine) -> None:
    with pytest.raises(UnsafeDatabaseRoleError):
        validate_platform_config_role(admin_engine)


def test_a_platform_configuration_role_with_memberships_is_refused(
    throwaway_login: tuple[str, Engine], config_engine: Engine, admin_engine: Engine
) -> None:
    role, engine = throwaway_login
    config_role = _role_of(config_engine)
    with admin_engine.begin() as conn:
        conn.execute(text(f'GRANT "{config_role}" TO "{role}"'))
    try:
        with pytest.raises(UnsafeDatabaseRoleError, match="member of another role"):
            validate_platform_config_role(engine)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f'REVOKE "{config_role}" FROM "{role}"'))


def test_a_role_without_configuration_privileges_is_refused(
    throwaway_login: tuple[str, Engine],
) -> None:
    _, engine = throwaway_login
    with pytest.raises(UnsafeDatabaseRoleError, match="cannot write the AI configuration"):
        validate_platform_config_role(engine)
