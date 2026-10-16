"""Migration test for `d3e9a1c47b20` (ADR-0053): `core.audit_digests`.

Additive only. The test asserts the table at head (columns, forced
row-level security with the tenant-context exclusion policy), that its
checks refuse a malformed row, and that a downgrade removes exactly this
table while every other `core` table stays.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
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
_REVISION = "d3e9a1c47b20"  # pragma: allowlist secret
_PREVIOUS = "b5d2f7a9c3e1"  # pragma: allowlist secret


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
            conn.execute(text("SELECT 1 FROM core.audit_log LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _core_tables(admin: Engine) -> set[str]:
    with admin.connect() as conn:
        return set(
            conn.execute(
                text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'core'")
            ).scalars()
        )


def test_the_table_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        columns = {
            row[0]: (row[1], row[2])
            for row in conn.execute(
                text(
                    "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                    "WHERE table_schema = 'core' AND table_name = 'audit_digests'"
                )
            )
        }
        rls = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = 'core.audit_digests'::regclass"
            )
        ).one()
        policies = conn.execute(
            text(
                "SELECT count(*) FROM pg_policies "
                "WHERE schemaname = 'core' AND tablename = 'audit_digests'"
            )
        ).scalar_one()
    assert columns == {
        "window_start": ("timestamp with time zone", "NO"),
        "window_end": ("timestamp with time zone", "NO"),
        "digest": ("character varying", "NO"),
        "record": ("text", "NO"),
        "created_at": ("timestamp with time zone", "NO"),
    }
    assert tuple(rls) == (True, True)
    assert policies >= 1


@pytest.mark.parametrize(
    ("length", "digest"),
    [
        (timedelta(0), "a" * 64),  # an empty window
        (timedelta(hours=1), "A" * 64),  # not lowercase hex
        (timedelta(hours=1), "a" * 63),  # too short
    ],
)
def test_the_checks_refuse_a_malformed_row(admin: Engine, length: timedelta, digest: str) -> None:
    command.upgrade(_config(), "head")
    start = datetime(1980, 1, 1, tzinfo=UTC)
    with admin.connect() as conn:
        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    "INSERT INTO core.audit_digests (window_start, window_end, digest, record) "
                    "VALUES (:s, :e, :d, '{}')"
                ),
                {"s": start, "e": start + length, "d": digest},
            )
        conn.rollback()


def test_downgrade_and_upgrade_change_only_this_table(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    tables = _core_tables(admin)
    assert "audit_digests" in tables
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _core_tables(admin) == tables - {"audit_digests"}
        command.upgrade(cfg, _REVISION)
        assert _core_tables(admin) == tables
    finally:
        command.upgrade(cfg, "head")
