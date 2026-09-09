"""Migration reversibility test for the Phase 3.2 identity migration
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 section 16: "upgrade -> verify ->
downgrade -> verify removal/restoration -> upgrade again -> verify", run
against real disposable PostgreSQL, not just inspected).

**Destructive**: this test downgrades past, then re-applies,
`770fe52b8468` (the identity-tables migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`core.users`/`core.external_identities`/`core.sessions`/`core.tenant_memberships`
and any data in them, then recreates the empty tables. Run this only
against a disposable database (e.g. `docker run --rm postgres:16-alpine`),
never a shared development or production database. Marked `integration`
and excluded from the default `pytest` run for exactly this reason, on top
of the usual "no external DB in the default run" rule.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_identity_migration_rollback.py
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_IDENTITY_REVISION = "770fe52b8468"
_TENANCY_REVISION = "e99c76057719"


@pytest.fixture(autouse=True)
def _require_reachable_privileged_database() -> None:
    get_migrations_database_config.cache_clear()
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
            f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    finally:
        probe_engine.dispose()


def _alembic_config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _table_exists(table: str) -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'core' AND table_name = :t)"
                ),
                {"t": table},
            ).scalar_one()
        return bool(row)
    finally:
        engine.dispose()


def _rls_flags(table: str) -> tuple[bool, bool] | None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = :t"),
                {"t": table},
            ).one_or_none()
        return (row[0], row[1]) if row is not None else None
    finally:
        engine.dispose()


def test_identity_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("users")
    assert _table_exists("external_identities")
    assert _table_exists("sessions")
    assert _table_exists("tenant_memberships")
    assert _rls_flags("tenant_memberships") == (True, True)

    try:
        # --- downgrade past the identity migration ---
        command.downgrade(cfg, _TENANCY_REVISION)
        assert not _table_exists("users")
        assert not _table_exists("external_identities")
        assert not _table_exists("sessions")
        assert not _table_exists("tenant_memberships")
        # The tenancy migration's own table must be untouched by this
        # downgrade -- proves the reverse migration only removes what it
        # itself created, not a broader "drop everything in core" shortcut.
        assert _table_exists("tenants")

        # --- re-apply the identity migration ---
        command.upgrade(cfg, _IDENTITY_REVISION)
        assert _table_exists("users")
        assert _table_exists("external_identities")
        assert _table_exists("sessions")
        assert _table_exists("tenant_memberships")
        assert _rls_flags("tenant_memberships") == (True, True)
    finally:
        # Restore to head regardless of outcome, so this test never leaves
        # the disposable database in a half-migrated state for a
        # subsequent test run.
        command.upgrade(cfg, "head")
