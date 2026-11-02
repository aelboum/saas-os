"""Migration test for `a9c3e5f7b1d4` (owner policy of 2026-11-02: legal holds
on the permission grant ledger), against real PostgreSQL.

- `core.permission_grant_ledger_holds` is global with the tenant-context
  exclusion policy (ENABLE + FORCE), its CHECKs refuse a reference that is
  not identifier-shaped and a half-released hold, and at most one active
  hold per (tenant, reference) exists;
- the runtime role may SELECT and INSERT, UPDATE only the two release
  columns, and never DELETE or TRUNCATE;
- the migration does not alter the ledger table;
- a release is one-way: a released hold can never change again, whichever
  role tries;
- its downgrade refuses while any hold exists (and changes nothing); on an
  empty table it drops the holds table only (the ledger and its rows
  stay), and re-upgrade recreates it empty.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`. Everything it creates is
removed in `finally` blocks.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import (
    DataError,
    DBAPIError,
    IntegrityError,
    OperationalError,
    ProgrammingError,
)

# Imported for its tables: `core.audit_log` has foreign keys onto RBAC tables,
# and `create_tenant` writes audit rows.
import saas_os.core.rbac  # noqa: F401
from lifecycle_callers import PROVISIONING
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_HOLDS = "a9c3e5f7b1d4"  # pragma: allowlist secret
_LEDGER = "e8f3b1d5a2c7"  # pragma: allowlist secret
_TABLE = "core.permission_grant_ledger_holds"


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
            conn.execute(text("SELECT 1 FROM core.platform_grants LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def runtime() -> Iterator[Engine]:
    engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _exists(admin: Engine, table: str) -> bool:
    with admin.connect() as conn:
        return conn.execute(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": table}).scalar_one()


def _tenant() -> uuid.UUID:
    return create_tenant(f"grt-hold-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id


def _drop_tenant(admin: Engine, tenant_id: uuid.UUID) -> None:
    with admin.begin() as conn:
        params = {"t": tenant_id}
        if _exists(admin, _TABLE):
            conn.execute(text(f"DELETE FROM {_TABLE} WHERE target_tenant_id = :t"), params)  # noqa: S608
        conn.execute(
            text("DELETE FROM core.permission_grant_applications WHERE tenant_id = :t"), params
        )
        conn.execute(
            text("DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t"),
            params,
        )
        conn.execute(text("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t"), params)
        conn.execute(
            text("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t"), params
        )
        conn.execute(text("DELETE FROM core.tenants WHERE id = :t"), params)


def _hold(conn: Connection, tenant_id: uuid.UUID, reference: str = "LEGAL-1") -> uuid.UUID:
    hold_id = uuid.uuid4()
    conn.execute(
        text(
            f"INSERT INTO {_TABLE} (id, target_tenant_id, reference, placed_by_platform_audit_id) "  # noqa: S608
            "VALUES (:i, :t, :r, :a)"
        ),
        {"i": hold_id, "t": tenant_id, "r": reference, "a": uuid.uuid4()},
    )
    return hold_id


def _ledger_definition(admin: Engine) -> list[tuple[object, ...]]:
    with admin.connect() as conn:
        columns = conn.execute(
            text(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = 'core' AND table_name = 'permission_grant_applications' "
                "ORDER BY column_name"
            )
        ).all()
        constraints = conn.execute(
            text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'core.permission_grant_applications'::regclass ORDER BY conname"
            )
        ).all()
    return [tuple(row) for row in columns] + [tuple(row) for row in constraints]


def test_the_holds_table_is_global_excluded_from_tenant_scope_and_never_deletable(
    admin: Engine, runtime: Engine
) -> None:
    command.upgrade(_config(), "head")
    role = runtime.url.username
    with admin.connect() as conn:
        flags = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = CAST(:t AS regclass)"
            ),
            {"t": _TABLE},
        ).one()
        assert tuple(flags) == (True, True)
        policy = conn.execute(
            text(
                "SELECT qual FROM pg_policies WHERE schemaname = 'core' "
                "AND tablename = 'permission_grant_ledger_holds'"
            )
        ).scalar_one()
        assert "app.tenant_id" in policy and "IS NULL" in policy
        table_privileges = {
            privilege: conn.execute(
                text("SELECT has_table_privilege(:r, :t, :p)"),
                {"r": role, "t": _TABLE, "p": privilege},
            ).scalar_one()
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
        }
        column_update = {
            column: conn.execute(
                text("SELECT has_column_privilege(:r, :t, :c, 'UPDATE')"),
                {"r": role, "t": _TABLE, "c": column},
            ).scalar_one()
            for column in (
                "id",
                "target_tenant_id",
                "reference",
                "placed_at",
                "placed_by_platform_audit_id",
                "released_at",
                "released_by_platform_audit_id",
            )
        }
        fk = conn.execute(
            text(
                "SELECT confdeltype FROM pg_constraint "
                "WHERE conname = 'fk_permission_grant_ledger_holds_target_tenant_id'"
            )
        ).scalar_one()
    assert table_privileges == {
        "SELECT": True,
        "INSERT": True,
        "UPDATE": False,
        "DELETE": False,
        "TRUNCATE": False,
    }
    assert column_update == {
        "id": False,
        "target_tenant_id": False,
        "reference": False,
        "placed_at": False,
        "placed_by_platform_audit_id": False,
        "released_at": True,
        "released_by_platform_audit_id": True,
    }
    assert fk == "a"  # NO ACTION: a hold keeps its tenant's tombstone

    tenant_id = _tenant()
    try:
        with admin.connect() as conn:
            trans = conn.begin()
            try:
                _hold(conn, tenant_id)
                with pytest.raises(IntegrityError), conn.begin_nested():
                    _hold(conn, tenant_id)  # one active hold per (tenant, reference)
                _hold(conn, tenant_id, "LEGAL-2")
                # A name, empty, a leading separator, too long, a slash.
                for bad in ("John Smith", "", "-leading", "x" * 101, "a/b"):
                    with pytest.raises((IntegrityError, DataError)), conn.begin_nested():
                        _hold(conn, tenant_id, bad)
                with pytest.raises(IntegrityError), conn.begin_nested():
                    conn.execute(
                        text(f"UPDATE {_TABLE} SET released_at = now() WHERE reference = 'LEGAL-1'")  # noqa: S608
                    )  # half released
                with pytest.raises(IntegrityError), conn.begin_nested():
                    _hold(conn, uuid.uuid4())  # no such tenant
                # A release is one-way, even for the owner role.
                conn.execute(
                    text(
                        f"UPDATE {_TABLE} SET released_at = now(), "  # noqa: S608
                        "released_by_platform_audit_id = :a WHERE reference = 'LEGAL-1'"
                    ),
                    {"a": uuid.uuid4()},
                )
                for change in (
                    "released_at = NULL, released_by_platform_audit_id = NULL",
                    "released_at = now() + interval '1 day'",
                    "released_by_platform_audit_id = gen_random_uuid()",
                    "reference = 'LEGAL-9'",
                ):
                    with pytest.raises(IntegrityError, match="never changed"), conn.begin_nested():
                        conn.execute(
                            text(f"UPDATE {_TABLE} SET {change} WHERE reference = 'LEGAL-1'")  # noqa: S608
                        )
            finally:
                trans.rollback()
    finally:
        _drop_tenant(admin, tenant_id)


def test_downgrade_refuses_while_a_hold_exists_then_drops_only_the_holds(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    before = _ledger_definition(admin)
    tenant_id = _tenant()
    try:
        with admin.begin() as conn:
            _hold(conn, tenant_id)
            conn.execute(
                text(
                    "INSERT INTO core.permission_grant_applications (id, tenant_id, namespace, "
                    "migration_id, content_digest, outcome, grants_added, "
                    "applied_by_platform_audit_id) VALUES (:i, :t, 'grt_app', 'm-1', :d, "
                    "'applied', 1, :r)"
                ),
                {"i": uuid.uuid4(), "t": tenant_id, "d": "a" * 64, "r": uuid.uuid4()},
            )
        try:
            # A hold exists: the downgrade refuses and nothing changes.
            with pytest.raises(DBAPIError, match="legal holds"):
                command.downgrade(cfg, _LEDGER)
            assert _exists(admin, _TABLE)
            with admin.connect() as conn:
                assert conn.execute(text(f"SELECT count(*) FROM {_TABLE}")).scalar_one() == 1  # noqa: S608
            # The separately approved manual step (docs/RUNBOOKS.md), then
            # the downgrade of the empty table works.
            with admin.begin() as conn:
                conn.execute(
                    text(f"DELETE FROM {_TABLE} WHERE target_tenant_id = :t"),  # noqa: S608
                    {"t": tenant_id},
                )
            command.downgrade(cfg, _LEDGER)
            assert not _exists(admin, _TABLE)
            # The ledger is not altered by this migration: same definition,
            # same rows, before and after its downgrade.
            assert _ledger_definition(admin) == before
            with admin.connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT count(*) FROM core.permission_grant_applications "
                        "WHERE tenant_id = :t"
                    ),
                    {"t": tenant_id},
                ).scalar_one()
            assert rows == 1
            command.upgrade(cfg, _HOLDS)
            assert _exists(admin, _TABLE)
            with admin.connect() as conn:
                assert conn.execute(text(f"SELECT count(*) FROM {_TABLE}")).scalar_one() == 0  # noqa: S608
            assert _ledger_definition(admin) == before
        finally:
            command.upgrade(cfg, "head")
    finally:
        _drop_tenant(admin, tenant_id)


# --- the retention permissions (owner decision A of 2026-11-02) --------------------

_RETENTION = ("platform.security_retention:report", "platform.security_retention_hold:manage")


def _seed_operator(conn: Connection, permission: str) -> uuid.UUID:
    user_id, operator_id = uuid.uuid4(), uuid.uuid4()
    conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user_id})
    conn.execute(
        text("INSERT INTO core.platform_operators (id, user_id, status) VALUES (:o, :u, 'active')"),
        {"o": operator_id, "u": user_id},
    )
    conn.execute(
        text("INSERT INTO core.platform_grants (id, operator_id, permission) VALUES (:g, :o, :p)"),
        {"g": uuid.uuid4(), "o": operator_id, "p": permission},
    )
    return operator_id


def _remove_operator(admin: Engine, operator_id: uuid.UUID) -> None:
    with admin.begin() as conn:
        conn.execute(
            text("DELETE FROM core.platform_grants WHERE operator_id = :o"), {"o": operator_id}
        )
        user_id = conn.execute(
            text("DELETE FROM core.platform_operators WHERE id = :o RETURNING user_id"),
            {"o": operator_id},
        ).scalar_one()
        conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user_id})


def _check_definition(admin: Engine) -> str:
    with admin.connect() as conn:
        return conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'ck_platform_grants_permission'"
            )
        ).scalar_one()


def test_the_check_admits_both_retention_permissions_and_their_grants_block_the_downgrade(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    definition = _check_definition(admin)
    assert all(permission in definition for permission in _RETENTION)
    with admin.connect() as conn:
        lingering = conn.execute(
            text("SELECT count(*) FROM core.platform_grants WHERE permission = ANY(:p)"),
            {"p": list(_RETENTION)},
        ).scalar_one()
    assert lingering == 0, "a previous test left a retention permission grant behind"
    try:
        for permission in _RETENTION:
            with admin.begin() as conn:
                operator_id = _seed_operator(conn, permission)
            try:
                with pytest.raises(DBAPIError, match="security retention permission"):
                    command.downgrade(cfg, _LEDGER)
                # One transaction: the table and the wide CHECK are still there.
                assert _exists(admin, _TABLE)
                assert permission in _check_definition(admin)
            finally:
                _remove_operator(admin, operator_id)
        # An unknown permission is still refused at head.
        with admin.connect() as conn:
            trans = conn.begin()
            try:
                with pytest.raises(IntegrityError):
                    _seed_operator(conn, "platform.security_retention:manage_hold")
            finally:
                trans.rollback()
        # Without such a grant (and without holds) the downgrade restores
        # d7e2a9c4f1b6's twenty-six-permission CHECK exactly.
        command.downgrade(cfg, _LEDGER)
        narrowed = _check_definition(admin)
        assert "security_retention" not in narrowed
        assert "platform.permission_grant:apply" in narrowed
        assert "platform.authority:manage" in narrowed
        command.upgrade(cfg, _HOLDS)
        assert all(permission in _check_definition(admin) for permission in _RETENTION)
    finally:
        command.upgrade(cfg, "head")
