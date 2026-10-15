"""Migration test for `a8c3e5f1d204` (ADR-0048): the global
`core.billing_provider_events` ledger.

Asserts the table's exact columns at head (no payload column, no
`tenant_id`), its uniqueness and status constraints, that it has no RLS
(global by design), that the application role can insert, update and
delete (the retention job runs as that role), and that a downgrade
removes the table and an upgrade restores it empty.

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
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "a8c3e5f1d204"  # pragma: allowlist secret
_PREVIOUS = "3654bebb24c7"  # pragma: allowlist secret
_COLUMNS = {
    "id": ("uuid", "NO"),
    "provider": ("character varying", "NO"),
    "event_id": ("character varying", "NO"),
    "event_type": ("character varying", "NO"),
    "provider_account_ref": ("character varying", "YES"),
    "status": ("character varying", "NO"),
    "attempts": ("integer", "NO"),
    "outcome": ("character varying", "YES"),
    "last_error_code": ("character varying", "YES"),
    "processed_at": ("timestamp with time zone", "YES"),
    "created_at": ("timestamp with time zone", "NO"),
    "updated_at": ("timestamp with time zone", "NO"),
}


@pytest.fixture(scope="module")
def admin() -> Iterator[Engine]:
    get_migrations_database_config.cache_clear()
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_migrations_database_config()
        get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.tenants LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def app_engine() -> Iterator[Engine]:
    engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _columns(admin: Engine) -> dict[str, tuple[str, str]]:
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = 'core' AND table_name = 'billing_provider_events'"
            )
        ).all()
    return {row[0]: (row[1], row[2]) for row in rows}


def _insert(conn, event_id: str, status: str = "received") -> None:  # type: ignore[no-untyped-def]
    conn.execute(
        text(
            "INSERT INTO core.billing_provider_events "
            "(id, provider, event_id, event_type, status) "
            "VALUES (:id, 'migration-test', :e, 't', :s)"
        ),
        {"id": uuid.uuid4(), "e": event_id, "s": status},
    )


def test_the_table_has_exactly_the_documented_columns_and_no_rls(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    assert _columns(admin) == _COLUMNS
    with admin.connect() as conn:
        rls = conn.execute(
            text(
                "SELECT relrowsecurity FROM pg_class "
                "WHERE oid = 'core.billing_provider_events'::regclass"
            )
        ).scalar_one()
    assert rls is False


def test_the_application_role_records_updates_and_prunes(app_engine: Engine) -> None:
    command.upgrade(_config(), "head")
    event_id = f"evt-{uuid.uuid4().hex}"
    with app_engine.begin() as conn:
        _insert(conn, event_id)
        conn.execute(
            text(
                "UPDATE core.billing_provider_events SET status = 'processed' "
                "WHERE provider = 'migration-test' AND event_id = :e"
            ),
            {"e": event_id},
        )
        deleted = conn.execute(
            text(
                "DELETE FROM core.billing_provider_events "
                "WHERE provider = 'migration-test' AND event_id = :e"
            ),
            {"e": event_id},
        ).rowcount
    assert deleted == 1


def test_one_row_per_provider_event(app_engine: Engine) -> None:
    event_id = f"evt-{uuid.uuid4().hex}"
    try:
        with app_engine.begin() as conn:
            _insert(conn, event_id)
        with pytest.raises(IntegrityError), app_engine.begin() as conn:
            _insert(conn, event_id)
    finally:
        with app_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM core.billing_provider_events WHERE event_id = :e"),
                {"e": event_id},
            )


def test_an_unknown_status_is_refused(app_engine: Engine) -> None:
    with pytest.raises(IntegrityError), app_engine.begin() as conn:
        _insert(conn, f"evt-{uuid.uuid4().hex}", status="done")


def test_downgrade_removes_the_table_and_upgrade_restores_it(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _columns(admin) == {}
        command.upgrade(cfg, _REVISION)
        assert _columns(admin) == _COLUMNS
    finally:
        command.upgrade(cfg, "head")
