"""Migration test for `d2f7a9c4e6b8` (ADR-0054 amendment of 2026-11-09, Gap
20a): the nullable `preference_rank` column, its non-negative check and its
partial unique index on `control_plane.ai_tenant_destination_grants`.

Additive only. The test asserts the column, check and index at head (smallint,
nullable, no default; unique per tenant and use case over non-NULL ranks
only), that a downgrade removes exactly those three and nothing else of the
table (the other columns, constraints, the unique grant key, the row-level
security policy, the privileges and the rows), that the upgrade restores them
with every rank NULL, and that the table keeps its tenant RLS policy.

**Destructive to schema state for its duration**: downgrades one revision and
re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
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
_REVISION = "d2f7a9c4e6b8"  # pragma: allowlist secret
_PREVIOUS = "b3d6f8a1c5e7"  # pragma: allowlist secret
_TABLE = "ai_tenant_destination_grants"
_COLUMN = "preference_rank"
_CHECK = "ck_ai_tenant_destination_grants_rank"
_INDEX = "ux_ai_tenant_destination_grants_rank"


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
            conn.execute(text(f"SELECT 1 FROM control_plane.{_TABLE} LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _column(admin: Engine) -> tuple[str, str, str | None] | None:
    with admin.connect() as conn:
        row = conn.execute(
            text(
                "SELECT data_type, is_nullable, column_default FROM information_schema.columns "
                "WHERE table_schema = 'control_plane' AND table_name = :t AND column_name = :c"
            ),
            {"t": _TABLE, "c": _COLUMN},
        ).one_or_none()
    return tuple(row) if row is not None else None  # type: ignore[return-value]


def _index(admin: Engine) -> str | None:
    with admin.connect() as conn:
        return conn.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE schemaname = 'control_plane' AND tablename = :t AND indexname = :i"
            ),
            {"t": _TABLE, "i": _INDEX},
        ).scalar_one_or_none()


def _check(admin: Engine) -> str | None:
    with admin.connect() as conn:
        return conn.execute(
            text(
                "SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c "
                "JOIN pg_class t ON t.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                "WHERE n.nspname = 'control_plane' AND t.relname = :t AND c.conname = :n"
            ),
            {"t": _TABLE, "n": _CHECK},
        ).scalar_one_or_none()


def _table_shape(admin: Engine) -> dict[str, object]:
    """Everything of the table the migration must leave alone."""
    with admin.connect() as conn:
        columns = conn.execute(
            text(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = 'control_plane' AND table_name = :t "
                f"AND column_name <> '{_COLUMN}' ORDER BY column_name"
            ),
            {"t": _TABLE},
        ).all()
        constraints = conn.execute(
            text(
                "SELECT conname FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                f"WHERE n.nspname = 'control_plane' AND t.relname = :t AND conname <> '{_CHECK}' "
                "ORDER BY conname"
            ),
            {"t": _TABLE},
        ).all()
        indexes = conn.execute(
            text(
                "SELECT indexname FROM pg_indexes WHERE schemaname = 'control_plane' "
                f"AND tablename = :t AND indexname <> '{_INDEX}' ORDER BY indexname"
            ),
            {"t": _TABLE},
        ).all()
        policies = conn.execute(
            text(
                "SELECT policyname, cmd, qual FROM pg_policies "
                "WHERE schemaname = 'control_plane' AND tablename = :t ORDER BY policyname"
            ),
            {"t": _TABLE},
        ).all()
        privileges = conn.execute(
            text(
                "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                "WHERE table_schema = 'control_plane' AND table_name = :t "
                "ORDER BY grantee, privilege_type"
            ),
            {"t": _TABLE},
        ).all()
        rls = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'control_plane' AND c.relname = :t"
            ),
            {"t": _TABLE},
        ).one()
        rows = conn.execute(text(f"SELECT count(*) FROM control_plane.{_TABLE}")).scalar_one()
    return {
        "columns": [tuple(r) for r in columns],
        "constraints": [r[0] for r in constraints],
        "indexes": [r[0] for r in indexes],
        "policies": [tuple(r) for r in policies],
        "privileges": [tuple(r) for r in privileges],
        "rls": tuple(rls),
        "rows": rows,
    }


def test_the_column_check_and_index_are_as_designed_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    assert _column(admin) == ("smallint", "YES", None)
    check = _check(admin)
    assert check is not None and "preference_rank >= 0" in check
    definition = _index(admin)
    assert definition is not None
    assert "UNIQUE" in definition and "(tenant_id, use_case, preference_rank)" in definition
    assert "WHERE (preference_rank IS NOT NULL)" in definition


def test_downgrade_removes_only_the_rank_and_upgrade_restores_it_null(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    before = _table_shape(admin)
    assert before["rls"][0] is True  # type: ignore[index]  # tenant RLS stays on
    assert before["policies"]  # and its policy exists
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _column(admin) is None and _check(admin) is None and _index(admin) is None
        # nothing else changed: the columns, constraints (including the unique
        # grant key), indexes, the RLS policy, the privileges and the rows
        assert _table_shape(admin) == before
        command.upgrade(cfg, _REVISION)
        assert _column(admin) == ("smallint", "YES", None)
        assert _check(admin) is not None and _index(admin) is not None
        assert _table_shape(admin) == before
        with admin.connect() as conn:
            ranked = conn.execute(
                text(f"SELECT count(*) FROM control_plane.{_TABLE} WHERE {_COLUMN} IS NOT NULL")
            ).scalar_one()
        assert ranked == 0  # no backfill: every pre-existing grant is unranked
    finally:
        command.upgrade(cfg, "head")


def test_the_upgrade_finds_a_column_and_index_added_by_hand(admin: Engine) -> None:
    """`ADD COLUMN IF NOT EXISTS` and `CREATE UNIQUE INDEX IF NOT EXISTS`: an
    operator who added them beforehand finds them in place."""
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        with admin.begin() as conn:
            conn.execute(text(f"ALTER TABLE control_plane.{_TABLE} ADD COLUMN {_COLUMN} smallint"))
            conn.execute(
                text(
                    f"CREATE UNIQUE INDEX {_INDEX} ON control_plane.{_TABLE} "
                    f"(tenant_id, use_case, {_COLUMN}) WHERE {_COLUMN} IS NOT NULL"
                )
            )
        command.upgrade(cfg, _REVISION)
        assert _column(admin) == ("smallint", "YES", None)
        assert _check(admin) is not None and _index(admin) is not None
    finally:
        command.upgrade(cfg, "head")
