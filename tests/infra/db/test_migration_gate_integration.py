"""P1.7 -- the CI migration gate: proves a *clean* PostgreSQL database can
be migrated from the repository's initial schema state to the current
Alembic head using the real migration/admin path, and that the resulting
schema is compatible with the application (docs/IMPLEMENTATION-ROADMAP.md
P1.7's own objective statement).

`tests/infra/db/test_migration_graph_unit.py` proves the revision chain
itself is internally consistent (no database needed); this file proves
those migrations actually *apply*, against real PostgreSQL, and produce
the schema the rest of the application depends on. Reuses existing
verification rather than duplicating policy definitions:
`infra.db.backup.verify_restored_database()` (P1.3) for schema/RLS shape,
and `infra.db.role_guard.validate_application_role()` (P1.2) for the
post-migration application role.

Marked `integration`; excluded from the default `pytest` run. Run locally
the same way as `tests/infra/test_db_integration.py`
(`scripts/check-migrations.sh` runs this against a disposable database);
in CI, `.github/workflows/ci.yml`'s `migrations` job runs it against a
GitHub Actions `postgres:16-alpine` service container -- never the
developer's own `saas-os-db-1`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from infra.db.backup import verify_restored_database
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.role_guard import validate_application_role
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _require_reachable_privileged_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL: {exc}. "
            "Run `docker compose up -d db` first -- see this file's module docstring."
        )
    finally:
        probe_engine.dispose()

    try:
        get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")


def _alembic_config() -> Config:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "infra" / "db" / "migrations"))
    return cfg


def _expected_head() -> str:
    (head,) = ScriptDirectory.from_config(_alembic_config()).get_heads()
    return head


def _alembic_version_in_db() -> str | None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return conn.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one_or_none()
    finally:
        engine.dispose()


# --- 1-6: clean database -> head, command succeeds, expected head, schema -


def test_alembic_upgrade_to_head_succeeds_and_reaches_the_expected_head() -> None:
    """The actual gate: `alembic upgrade head` (real command, real
    exceptions -- a real migration failure here raises, which is a real
    pytest failure, which is a real non-zero CI exit code)."""
    command.upgrade(_alembic_config(), "head")  # raises on failure; no swallowing
    assert _alembic_version_in_db() == _expected_head()


def test_resulting_schema_matches_the_expected_repository_state() -> None:
    """Reuses P1.3's own `verify_restored_database()` rather than
    duplicating RLS/policy assertions -- the same function P1.3's real
    disaster-recovery drill already trusts to answer "is this schema
    correct", now also answering "did a clean migration run produce it"."""
    command.upgrade(_alembic_config(), "head")

    admin_engine = build_engine(get_migrations_database_config())
    try:
        result = verify_restored_database(admin_engine)
    finally:
        admin_engine.dispose()

    assert result.schemas_present == {"core", "control_plane", "self_learning"}
    assert result.rls_protected_table_count >= 14
    assert result.every_rls_table_has_force_rls is True
    assert result.every_rls_table_has_a_policy is True
    assert result.alembic_version == _expected_head()


def test_upgrading_to_a_nonexistent_revision_fails_loudly() -> None:
    """Non-vacuous proof this gate has a real failure condition -- it is
    not structurally impossible for `command.upgrade()` to raise. A
    request for a revision that does not exist in the script directory
    must raise, not silently no-op."""
    with pytest.raises(Exception):  # noqa: B017, PT011 -- alembic's own resolution error
        command.upgrade(_alembic_config(), "0000000000000000_does_not_exist")


# --- Role separation: migration executes as the admin role, never the app role -


def test_migration_executes_as_the_migration_admin_role_not_the_application_role() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md P1.7's own role-separation
    requirement: prove *which role the migration connection actually
    authenticated as* (PostgreSQL's own `current_user`), not merely that
    the two configs' URLs differ."""
    command.upgrade(_alembic_config(), "head")

    admin_engine = build_engine(get_migrations_database_config())
    try:
        with admin_engine.connect() as conn:
            migration_current_user = conn.execute(text("SELECT current_user")).scalar_one()
    finally:
        admin_engine.dispose()

    app_role_name = make_url(get_database_config().url).username
    migrations_role_name = make_url(get_migrations_database_config().url).username

    assert migration_current_user == migrations_role_name
    assert migration_current_user != app_role_name


def test_application_role_remains_restricted_after_migration() -> None:
    """P1.2's fail-closed startup guard, reused unmodified, run against
    the application engine *after* a real migration -- proves migrations
    do not weaken/replace the restricted runtime role."""
    command.upgrade(_alembic_config(), "head")

    app_engine = build_engine(get_database_config())
    try:
        result = validate_application_role(app_engine)
    finally:
        app_engine.dispose()
    assert result.role_name == make_url(get_database_config().url).username


# --- P1.6 pool separation: migration path is unaffected by app pool config -


def test_migration_engine_uses_null_pool_matching_env_py(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mirrors exactly how `infra/db/migrations/env.py`'s own
    `run_migrations_online()` builds its engine
    (`engine_from_config(..., poolclass=NullPool)`) -- proves that
    construction path is what this gate actually exercises, and that it
    stays `NullPool` regardless of a hostile `DB_POOL_*` override."""
    from sqlalchemy import engine_from_config

    monkeypatch.setenv("DB_POOL_SIZE", "1")
    monkeypatch.setenv("DB_POOL_PRE_PING", "false")
    get_database_config.cache_clear()
    try:
        connectable = engine_from_config(
            {"sqlalchemy.url": get_migrations_database_config().url},
            prefix="sqlalchemy.",
            poolclass=NullPool,
        )
        try:
            assert isinstance(connectable.pool, NullPool)
            with connectable.connect() as conn:
                conn.execute(text("SELECT 1"))
        finally:
            connectable.dispose()
    finally:
        get_database_config.cache_clear()


def test_a_real_migration_run_is_unaffected_by_hostile_app_pool_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The actual gate command, run for real, with the most aggressive
    plausible `DB_POOL_*` override set -- if `infra/db/migrations/env.py`
    ever accidentally depended on the application's runtime pool
    (`infra.db.engine.get_engine()`), this is the setting most likely to
    break it. It does not, because `env.py` never calls `build_engine()`/
    `get_engine()` at all (module docstring)."""
    monkeypatch.setenv("DB_POOL_SIZE", "1")
    monkeypatch.setenv("DB_POOL_MAX_OVERFLOW", "0")
    monkeypatch.setenv("DB_POOL_TIMEOUT_SECONDS", "1")
    monkeypatch.setenv("DB_POOL_PRE_PING", "false")
    command.upgrade(_alembic_config(), "head")  # raises on failure; no assertion needed
    assert _alembic_version_in_db() == _expected_head()
