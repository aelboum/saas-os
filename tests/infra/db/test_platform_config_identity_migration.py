"""Migration test for `f6a2c8e4b1d9` (ADR-0056): the platform-configuration
database identity.

At head: the application role only reads the six global AI configuration
tables; the platform-configuration role reads, inserts and updates them,
never deletes; its three authorization-lock triggers exist and their
function is not `SECURITY DEFINER`. A downgrade restores the application
role's earlier grants and removes every privilege, trigger and the function
it added, and keeps the role; upgrading again restores everything. An
upgrade creates a missing role `NOLOGIN` and refuses an unsafe existing one.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "f6a2c8e4b1d9"  # pragma: allowlist secret
_PREVIOUS = "c5d7e9f1a2b4"  # pragma: allowlist secret
_TABLES = (
    "control_plane.ai_providers",
    "control_plane.ai_models",
    "control_plane.ai_aliases",
    "control_plane.ai_endpoint_trust",
    "control_plane.ai_destination_policy",
    "control_plane.ai_model_prices",
)
_TRIGGERS = {
    ("users", "trg_users_refuse_platform_config_update"),
    ("platform_operators", "trg_platform_operators_refuse_platform_config_update"),
    ("platform_grants", "trg_platform_grants_refuse_platform_config_update"),
}
_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")


@pytest.fixture(scope="module")
def admin() -> Iterator[Engine]:
    get_migrations_database_config.cache_clear()
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.ai_providers LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def _at_head_afterwards(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield
    monkeypatch.delenv("PLATFORM_CONFIG_DB_USER", raising=False)
    command.upgrade(_config(), "head")


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _app_role() -> str:
    return make_url(get_database_config().url).username or "saas_os_app"


def _config_role() -> str:
    return "saas_os_platform_config"


def _privileges(admin: Engine, role: str) -> dict[str, set[str]]:
    with admin.connect() as conn:
        return {
            table: {
                p
                for p in _PRIVILEGES
                if conn.execute(
                    text("SELECT has_table_privilege(:r, CAST(:t AS regclass), :p)"),
                    {"r": role, "t": table, "p": p},
                ).scalar_one()
            }
            for table in _TABLES
        }


def _column_privileges(admin: Engine, role: str) -> set[tuple[str, str, str]]:
    with admin.connect() as conn:
        return {
            (row.table_name, row.column_name, row.privilege_type)
            for row in conn.execute(
                text(
                    "SELECT table_name, column_name, privilege_type "
                    "FROM information_schema.column_privileges "
                    "WHERE grantee = :r AND table_schema = 'core'"
                ),
                {"r": role},
            )
        }


def _triggers(admin: Engine) -> set[tuple[str, str]]:
    with admin.connect() as conn:
        return {
            (row.relname, row.tgname)
            for row in conn.execute(
                text(
                    "SELECT c.relname, t.tgname FROM pg_trigger t "
                    "JOIN pg_class c ON c.oid = t.tgrelid "
                    "WHERE t.tgname LIKE 'trg_%_refuse_platform_config_update'"
                )
            )
        }


def _function_security(admin: Engine) -> list[bool]:
    with admin.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT p.prosecdef FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'core' "
                    "AND p.proname = 'refuse_platform_config_role_update'"
                )
            ).scalars()
        )


def _role_exists(admin: Engine, role: str) -> bool:
    with admin.connect() as conn:
        return (
            conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}
            ).scalar_one_or_none()
            is not None
        )


def test_the_grants_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    assert _privileges(admin, _app_role()) == {table: {"SELECT"} for table in _TABLES}
    assert _privileges(admin, _config_role()) == {
        table: {"SELECT", "INSERT", "UPDATE"} for table in _TABLES
    }
    assert _column_privileges(admin, _config_role()) >= {
        ("users", "is_active", "SELECT"),
        ("users", "updated_at", "UPDATE"),
        ("platform_operators", "status", "SELECT"),
        ("platform_operators", "updated_at", "UPDATE"),
        ("platform_grants", "permission", "SELECT"),
        ("platform_grants", "granted_at", "UPDATE"),
        ("platform_audit_log", "created_at", "SELECT"),
        ("platform_audit_log", "actor_user_id", "INSERT"),
    }
    assert _triggers(admin) == _TRIGGERS
    assert _function_security(admin) == [False]


def test_downgrade_restores_the_previous_grants_then_upgrade_reapplies(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    command.downgrade(_config(), _PREVIOUS)
    assert _privileges(admin, _app_role()) == {
        table: {"SELECT", "INSERT", "UPDATE"} for table in _TABLES
    }
    assert _privileges(admin, _config_role()) == {table: set() for table in _TABLES}
    assert _column_privileges(admin, _config_role()) == set()
    assert _triggers(admin) == set()
    assert _function_security(admin) == []
    assert _role_exists(admin, _config_role())

    command.upgrade(_config(), _REVISION)
    assert _privileges(admin, _app_role()) == {table: {"SELECT"} for table in _TABLES}
    assert _triggers(admin) == _TRIGGERS


def test_an_upgrade_creates_a_missing_role_without_login(
    admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    fresh = f"adr56_fresh_{uuid.uuid4().hex[:8]}"
    command.upgrade(_config(), "head")
    command.downgrade(_config(), _PREVIOUS)
    monkeypatch.setenv("PLATFORM_CONFIG_DB_USER", fresh)
    try:
        command.upgrade(_config(), _REVISION)
        with admin.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole "
                    "FROM pg_roles WHERE rolname = :r"
                ),
                {"r": fresh},
            ).one()
        assert tuple(row) == (False, False, False, False)
        assert _privileges(admin, fresh) == {
            table: {"SELECT", "INSERT", "UPDATE"} for table in _TABLES
        }
        command.downgrade(_config(), _PREVIOUS)
    finally:
        monkeypatch.delenv("PLATFORM_CONFIG_DB_USER")
        with admin.begin() as conn:
            if _role_exists(admin, fresh):
                conn.execute(text(f'DROP OWNED BY "{fresh}"'))
                conn.execute(text(f'DROP ROLE "{fresh}"'))


@pytest.mark.parametrize("attribute", ["BYPASSRLS", "CREATEROLE"])
def test_an_upgrade_refuses_an_unsafe_existing_role(
    admin: Engine, monkeypatch: pytest.MonkeyPatch, attribute: str
) -> None:
    unsafe = f"adr56_unsafe_{uuid.uuid4().hex[:8]}"
    with admin.begin() as conn:
        conn.execute(text(f'CREATE ROLE "{unsafe}" NOLOGIN {attribute}'))
    command.upgrade(_config(), "head")
    command.downgrade(_config(), _PREVIOUS)
    monkeypatch.setenv("PLATFORM_CONFIG_DB_USER", unsafe)
    try:
        with pytest.raises(RuntimeError, match="must be none of these"):
            command.upgrade(_config(), _REVISION)
    finally:
        monkeypatch.delenv("PLATFORM_CONFIG_DB_USER")
        with admin.begin() as conn:
            conn.execute(text(f'DROP OWNED BY "{unsafe}"'))
            conn.execute(text(f'DROP ROLE "{unsafe}"'))


def test_an_upgrade_refuses_a_role_in_a_membership_with_the_application_role(
    admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    member = f"adr56_member_{uuid.uuid4().hex[:8]}"
    with admin.begin() as conn:
        conn.execute(text(f'CREATE ROLE "{member}" NOLOGIN'))
        conn.execute(text(f'GRANT "{_app_role()}" TO "{member}"'))
    command.upgrade(_config(), "head")
    command.downgrade(_config(), _PREVIOUS)
    monkeypatch.setenv("PLATFORM_CONFIG_DB_USER", member)
    try:
        with pytest.raises(RuntimeError, match="membership"):
            command.upgrade(_config(), _REVISION)
    finally:
        monkeypatch.delenv("PLATFORM_CONFIG_DB_USER")
        with admin.begin() as conn:
            conn.execute(text(f'REVOKE "{_app_role()}" FROM "{member}"'))
            conn.execute(text(f'DROP OWNED BY "{member}"'))
            conn.execute(text(f'DROP ROLE "{member}"'))
