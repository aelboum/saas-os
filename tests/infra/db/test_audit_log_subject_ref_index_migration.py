"""Migration test for `d4f8b2e6a9c1` (audit identity phase P3b, migration
M2): the two partial expression indexes on `core.audit_log` for the tenant
audit subject reference keys, built `CONCURRENTLY`.

- at head both indexes exist, are valid, and have the planned definition;
- a downgrade removes exactly those two indexes and nothing else of the
  table, and the upgrade restores them;
- an index built beforehand by an operator is found in place;
- an INVALID index left by a failed concurrent build is dropped and
  rebuilt;
- a valid index of that name with another definition makes the upgrade
  fail naming it, and is not dropped;
- the record-bound lookups can be answered from the indexes.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
One case marks an index invalid through `pg_index`, which needs the
migrations role to be a superuser (it is, in CI and in the local scripts).
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
_REVISION = "d4f8b2e6a9c1"  # pragma: allowlist secret
_PREVIOUS = "c7e3a9f2b4d8"  # pragma: allowlist secret
_INITIATED = "ix_audit_log_initiated_by_subject_ref"
_OWNER = "ix_audit_log_owner_user_subject_ref"
_PREBUILD = {
    _INITIATED: (
        f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_INITIATED} ON core.audit_log "
        "(tenant_id, ((metadata -> 'initiated_by') ->> 'subject_ref')) "
        "WHERE (metadata -> 'initiated_by') ->> 'subject_ref' IS NOT NULL"
    ),
    _OWNER: (
        f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_OWNER} ON core.audit_log "
        "(tenant_id, (metadata ->> 'owner_user_subject_ref')) "
        "WHERE metadata ->> 'owner_user_subject_ref' IS NOT NULL"
    ),
}
_TENANT = "00000000-0000-0000-0000-000000000001"
_REFERENCE = "00000000-0000-0000-0000-000000000002"


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
            conn.execute(text("SELECT 1 FROM core.audit_log LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _autocommit(admin: Engine, statement: str) -> None:
    with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(statement))


def _index(admin: Engine, name: str) -> tuple[bool, str] | None:
    """(valid, definition) of `core.<name>`, or None."""
    with admin.connect() as conn:
        row = conn.execute(
            text(
                "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) FROM pg_index i "
                "WHERE i.indexrelid = to_regclass(:n)"
            ),
            {"n": f"core.{name}"},
        ).one_or_none()
    return None if row is None else (row[0], row[1])


def _oid(admin: Engine, name: str) -> int | None:
    with admin.connect() as conn:
        return conn.execute(text("SELECT to_regclass(:n)::oid"), {"n": f"core.{name}"}).scalar_one()


def _table_shape(admin: Engine) -> tuple[list[str], list[str], list[str], int]:
    """Indexes, columns, constraints and row count of `core.audit_log`."""
    with admin.connect() as conn:
        indexes = (
            conn.execute(
                text(
                    "SELECT indexname FROM pg_indexes WHERE schemaname = 'core' "
                    "AND tablename = 'audit_log' ORDER BY indexname"
                )
            )
            .scalars()
            .all()
        )
        columns = (
            conn.execute(
                text(
                    "SELECT column_name || ':' || data_type FROM information_schema.columns "
                    "WHERE table_schema = 'core' AND table_name = 'audit_log' "
                    "ORDER BY column_name"
                )
            )
            .scalars()
            .all()
        )
        constraints = (
            conn.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conrelid = 'core.audit_log'::regclass ORDER BY conname"
                )
            )
            .scalars()
            .all()
        )
        rows = conn.execute(text("SELECT count(*) FROM core.audit_log")).scalar_one()
    return list(indexes), list(columns), list(constraints), rows


def _stamped(admin: Engine) -> str:
    with admin.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version_saas_os")).scalar_one()


def test_both_indexes_are_valid_and_partial_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    initiated = _index(admin, _INITIATED)
    owner = _index(admin, _OWNER)
    assert initiated is not None and owner is not None
    assert initiated[0] is True and owner[0] is True
    expression = "((metadata -> 'initiated_by'::text) ->> 'subject_ref'::text)"
    assert f"(tenant_id, ({expression}))" in initiated[1]
    assert f"WHERE ({expression} IS NOT NULL)" in initiated[1]
    assert "(tenant_id, ((metadata ->> 'owner_user_subject_ref'::text)))" in owner[1]
    assert "WHERE ((metadata ->> 'owner_user_subject_ref'::text) IS NOT NULL)" in owner[1]
    assert "UNIQUE" not in initiated[1] and "UNIQUE" not in owner[1]


def test_downgrade_and_upgrade_change_only_the_two_indexes(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    indexes, columns, constraints, rows = _table_shape(admin)
    assert {_INITIATED, _OWNER} <= set(indexes)
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _stamped(admin) == _PREVIOUS
        assert _table_shape(admin) == (
            [i for i in indexes if i not in (_INITIATED, _OWNER)],
            columns,
            constraints,
            rows,
        )
        command.upgrade(cfg, _REVISION)
        assert _stamped(admin) == _REVISION
        assert _table_shape(admin) == (indexes, columns, constraints, rows)
    finally:
        command.upgrade(cfg, "head")


def test_an_index_built_beforehand_is_found_in_place(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        # An operator builds the indexes during a quiet period.
        for statement in _PREBUILD.values():
            _autocommit(admin, statement)
        before = {name: _oid(admin, name) for name in _PREBUILD}
        command.upgrade(cfg, _REVISION)
        assert {name: _oid(admin, name) for name in _PREBUILD} == before  # found, not rebuilt
        assert all(_index(admin, name) is not None for name in _PREBUILD)
    finally:
        command.upgrade(cfg, "head")


def test_an_invalid_leftover_index_is_dropped_and_rebuilt(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        # What a failed concurrent build leaves behind: an INVALID index of
        # that name, which `IF NOT EXISTS` alone would accept as it is.
        _autocommit(admin, _PREBUILD[_OWNER])
        with admin.begin() as conn:
            conn.execute(
                text("UPDATE pg_index SET indisvalid = false WHERE indexrelid = to_regclass(:n)"),
                {"n": f"core.{_OWNER}"},
            )
        leftover = _index(admin, _OWNER)
        assert leftover is not None and leftover[0] is False
        stale = _oid(admin, _OWNER)
        command.upgrade(cfg, _REVISION)
        rebuilt = _index(admin, _OWNER)
        assert rebuilt is not None and rebuilt[0] is True
        assert _oid(admin, _OWNER) != stale  # dropped and built again
    finally:
        command.upgrade(cfg, "head")


def test_an_index_of_that_name_with_another_definition_fails_and_is_kept(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        _autocommit(admin, f"CREATE INDEX {_INITIATED} ON core.audit_log (tenant_id)")
        with pytest.raises(RuntimeError, match=f"core.{_INITIATED} exists with another"):
            command.upgrade(cfg, _REVISION)
        kept = _index(admin, _INITIATED)
        assert kept is not None and kept[0] is True
        assert "(tenant_id)" in kept[1] and "'subject_ref'" not in kept[1]
        # The revision is not stamped: the database stays at the previous one.
        assert _stamped(admin) == _PREVIOUS
    finally:
        _autocommit(admin, f"DROP INDEX IF EXISTS core.{_INITIATED}")
        command.upgrade(cfg, "head")


@pytest.mark.parametrize(
    ("index", "predicate"),
    [
        (_INITIATED, "(metadata -> 'initiated_by') ->> 'subject_ref' = :r"),
        (_OWNER, "metadata ->> 'owner_user_subject_ref' = :r"),
    ],
)
def test_the_record_bound_lookup_can_use_the_index(
    admin: Engine, index: str, predicate: str
) -> None:
    """The lookup the indexes exist for (P3c's expiry record bound): the
    newest row of one tenant carrying one reference. With sequential scans
    disabled the planner must be able to answer it from the index: proof
    that the expression and the predicate match, not a claim about the plan
    at any size."""
    command.upgrade(_config(), "head")
    with admin.begin() as conn:
        conn.execute(text("SET LOCAL enable_seqscan = off"))
        plan = "\n".join(
            row[0]
            for row in conn.execute(
                text(
                    "EXPLAIN SELECT max(created_at) FROM core.audit_log "  # noqa: S608
                    f"WHERE tenant_id = CAST(:t AS uuid) AND {predicate}"
                ),
                {"t": _TENANT, "r": _REFERENCE},
            )
        )
    assert index in plan, plan
