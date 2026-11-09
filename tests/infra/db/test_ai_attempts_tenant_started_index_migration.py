"""Migration test for `b3d6f8a1c5e7` (ADR-0054 amendment of 2026-11-09, Gap
22a): the index on `control_plane.ai_inference_attempts (tenant_id,
started_at)`.

Additive only. The test asserts the index definition at head, that a downgrade
removes exactly that index and nothing else of the table (the other index, the
columns, the constraints, the row-level security policy, the privileges and the
rows), that the upgrade finds an index created beforehand in place, and that
the tenant usage window read can be answered from it.

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
_REVISION = "b3d6f8a1c5e7"  # pragma: allowlist secret
_PREVIOUS = "c8e5a2f7d1b3"  # pragma: allowlist secret
_INDEX = "ix_ai_inference_attempts_tenant_started"
_OTHER_INDEX = "ix_ai_inference_attempts_tenant_state_started"
_CREATE = f"CREATE INDEX {_INDEX} ON control_plane.ai_inference_attempts (tenant_id, started_at)"
_PROBE = (
    "EXPLAIN SELECT 1 FROM control_plane.ai_inference_attempts "
    "WHERE tenant_id = :t AND started_at >= :a AND started_at < :b"
)


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
            conn.execute(text("SELECT 1 FROM control_plane.ai_inference_attempts LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _index_definition(admin: Engine, name: str = _INDEX) -> str | None:
    with admin.connect() as conn:
        return conn.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE schemaname = :s AND tablename = :t AND indexname = :i"
            ),
            {"s": "control_plane", "t": "ai_inference_attempts", "i": name},
        ).scalar_one_or_none()


def _table_shape(admin: Engine) -> dict[str, object]:
    """Everything of the table the migration must leave alone."""
    with admin.connect() as conn:
        columns = conn.execute(
            text(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = :s AND table_name = :t ORDER BY column_name"
            ),
            {"s": "control_plane", "t": "ai_inference_attempts"},
        ).all()
        constraints = conn.execute(
            text(
                "SELECT conname FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace "
                "WHERE n.nspname = :s AND t.relname = :t ORDER BY conname"
            ),
            {"s": "control_plane", "t": "ai_inference_attempts"},
        ).all()
        policies = conn.execute(
            text(
                "SELECT policyname, cmd, qual FROM pg_policies "
                "WHERE schemaname = :s AND tablename = :t ORDER BY policyname"
            ),
            {"s": "control_plane", "t": "ai_inference_attempts"},
        ).all()
        privileges = conn.execute(
            text(
                "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                "WHERE table_schema = :s AND table_name = :t ORDER BY grantee, privilege_type"
            ),
            {"s": "control_plane", "t": "ai_inference_attempts"},
        ).all()
        rows = conn.execute(
            text("SELECT count(*) FROM control_plane.ai_inference_attempts")
        ).scalar_one()
        other = _index_definition(admin, _OTHER_INDEX)
    return {
        "columns": [tuple(r) for r in columns],
        "constraints": [r[0] for r in constraints],
        "policies": [tuple(r) for r in policies],
        "privileges": [tuple(r) for r in privileges],
        "rows": rows,
        "other_index": other,
    }


def test_the_index_is_on_tenant_and_started_at_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    definition = _index_definition(admin)
    assert definition is not None
    assert "(tenant_id, started_at)" in definition
    assert "UNIQUE" not in definition
    assert "WHERE" not in definition


def test_downgrade_and_upgrade_change_only_the_index(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    before = _table_shape(admin)
    assert before["other_index"] is not None
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _index_definition(admin) is None
        # nothing else of the table changed: the other index, columns, constraints,
        # the row-level security policy, the privileges and the rows
        assert _table_shape(admin) == before
        # An operator may have built the index beforehand, concurrently: the
        # migration then finds it in place.
        with admin.begin() as conn:
            conn.execute(text(_CREATE))
        command.upgrade(cfg, _REVISION)
        assert _index_definition(admin) is not None
        assert _table_shape(admin) == before
    finally:
        command.upgrade(cfg, "head")


def test_the_usage_window_read_can_use_the_index(admin: Engine) -> None:
    """The read the index exists for: one tenant, a `started_at` window, no
    state. With sequential scans disabled the planner must answer it from this
    index (proof that the index matches the predicate, not a claim about the
    plan at any size)."""
    command.upgrade(_config(), "head")
    with admin.begin() as conn:
        conn.execute(text("SET LOCAL enable_seqscan = off"))
        plan = "\n".join(
            row[0]
            for row in conn.execute(
                text(_PROBE),
                {
                    "t": "00000000-0000-0000-0000-000000000001",
                    "a": "2026-03-01T00:00:00+00:00",
                    "b": "2026-04-01T00:00:00+00:00",
                },
            )
        )
    assert _INDEX in plan
