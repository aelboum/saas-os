"""Migration reversibility test for the P2.2 login-transactions migration
(`4c1e9a7b2d55`): upgrade -> verify -> downgrade -> verify removal and
that nothing else was touched -> upgrade again -> verify, against real
disposable PostgreSQL (mirrors `test_identity_migration_rollback.py`).

**Destructive**: temporarily drops `core.login_transactions` (and any
in-flight login rows) on whatever database `MIGRATIONS_DATABASE_URL`
points at. Run only against a disposable database. Marked `integration`.

How to run locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_login_transactions_migration_rollback.py
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
_LOGIN_TRANSACTIONS_REVISION = "4c1e9a7b2d55"
_PREVIOUS_REVISION = "3fb4e3e2f8de"


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
        pytest.skip(f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL: {exc}")
    finally:
        probe_engine.dispose()


def _alembic_config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _query_one(sql: str, params: dict[str, object]) -> object:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            return session.execute(text(sql), params).scalar_one()
    finally:
        engine.dispose()


def _table_exists(table: str) -> bool:
    return bool(
        _query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'core' AND table_name = :t)",
            {"t": table},
        )
    )


def _state_is_unique() -> bool:
    return bool(
        _query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'core' "
            "AND tablename = 'login_transactions' AND indexdef ILIKE 'CREATE UNIQUE INDEX%' "
            "AND indexdef ILIKE '%(state)%')",
            {},
        )
    )


def _rls_enabled(table: str) -> bool:
    return bool(
        _query_one(
            "SELECT relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'core' AND c.relname = :t",
            {"t": table},
        )
    )


def test_login_transactions_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    command.upgrade(cfg, "head")
    assert _table_exists("login_transactions")
    assert _state_is_unique()
    # Global table, deliberately not RLS-scoped (mirrors core.sessions).
    assert _rls_enabled("login_transactions") is False
    # A sibling identity table is still RLS-protected -- this migration
    # changed nothing about the existing identity posture.
    assert _rls_enabled("tenant_memberships") is True

    try:
        command.downgrade(cfg, _PREVIOUS_REVISION)
        assert not _table_exists("login_transactions")
        # Existing identity data/tables are untouched by this downgrade.
        assert _table_exists("users")
        assert _table_exists("external_identities")
        assert _table_exists("sessions")
        assert _table_exists("tenant_memberships")
        assert _table_exists("idempotency_records")

        command.upgrade(cfg, _LOGIN_TRANSACTIONS_REVISION)
        assert _table_exists("login_transactions")
        assert _state_is_unique()
    finally:
        command.upgrade(cfg, "head")
