"""Migration test for `d7e4b2a91c36` (ADR-0045 Phase C): the partial index
on `core.api_keys (user_id)`.

Additive only. The test asserts the index definition at head, that a
downgrade removes exactly that index and nothing else of the table, that
the upgrade finds an index created beforehand in place, and that no row is
touched in either direction.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

from saas_os.infra.db.config import get_migrations_database_config
from saas_os.infra.db.engine import build_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "d7e4b2a91c36"  # pragma: allowlist secret
_PREVIOUS = "c4a9e1f07b52"  # pragma: allowlist secret
_INDEX = "ix_api_keys_user_id"
_CREATE = f"CREATE INDEX {_INDEX} ON core.api_keys (user_id) WHERE user_id IS NOT NULL"
_PROBE = "EXPLAIN SELECT id FROM core.api_keys WHERE user_id = :u AND revoked_at IS NULL"


@pytest.fixture(scope="module")
def admin() -> Iterator[Engine]:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.api_keys LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _index_definition(admin: Engine) -> str | None:
    with admin.connect() as conn:
        return conn.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE schemaname = :s AND tablename = :t AND indexname = :i"
            ),
            {"s": "core", "t": "api_keys", "i": _INDEX},
        ).scalar_one_or_none()


def _table_shape(admin: Engine) -> tuple[list[tuple[str, str]], list[str], int]:
    """Columns, constraints and row count of `core.api_keys`: everything
    the migration must leave alone."""
    with admin.connect() as conn:
        columns = conn.execute(
            text(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = :s AND table_name = :t ORDER BY column_name"
            ),
            {"s": "core", "t": "api_keys"},
        ).all()
        constraints = (
            conn.execute(
                text(
                    "SELECT conname FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
                    "JOIN pg_namespace n ON n.oid = t.relnamespace "
                    "WHERE n.nspname = :s AND t.relname = :t ORDER BY conname"
                ),
                {"s": "core", "t": "api_keys"},
            )
            .scalars()
            .all()
        )
        rows = conn.execute(text("SELECT count(*) FROM core.api_keys")).scalar_one()
    return [(row[0], row[1]) for row in columns], list(constraints), rows


def test_the_index_is_partial_on_user_id_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    definition = _index_definition(admin)
    assert definition is not None
    assert "(user_id)" in definition
    assert "WHERE (user_id IS NOT NULL)" in definition
    assert "UNIQUE" not in definition


def test_downgrade_and_upgrade_change_only_the_index(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    before = _table_shape(admin)
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _index_definition(admin) is None
        assert _table_shape(admin) == before  # no column, constraint or row changed
        # An operator may have built the index beforehand, concurrently: the
        # migration then finds it in place.
        with admin.begin() as conn:
            conn.execute(text(_CREATE))
        command.upgrade(cfg, _REVISION)
        assert _index_definition(admin) is not None
        assert _table_shape(admin) == before
    finally:
        command.upgrade(cfg, "head")


def test_the_revocation_statement_can_use_the_index(admin: Engine) -> None:
    """The statement the index exists for. With sequential scans disabled
    the planner must be able to answer it from the index: proof that the
    index matches the predicate, not a claim about the plan at any size."""
    command.upgrade(_config(), "head")
    with admin.begin() as conn:
        conn.execute(text("SET LOCAL enable_seqscan = off"))
        plan = "\n".join(
            row[0]
            for row in conn.execute(text(_PROBE), {"u": "00000000-0000-0000-0000-000000000001"})
        )
    assert _INDEX in plan
