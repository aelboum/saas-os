"""Migration tests for ADR 0060 (permission grant migrations), against real
PostgreSQL:

- `d7e2a9c4f1b6`: `ck_platform_grants_permission` accepts
  `platform.permission_grant:apply` at head and still refuses an unknown
  permission; a downgrade refuses while a grant of it exists (by design,
  nothing is deleted), and once none exists restores the
  twenty-five-permission CHECK of `c5e8a1d3f7b2` (PR #192), on which it is
  stacked.
- `e8f3b1d5a2c7`: `core.permission_grant_applications` is tenant-owned with
  the canonical policy, ENABLE + FORCE, unique per (tenant, namespace,
  migration id), readable and insertable by the runtime role and nothing
  more; its downgrade drops it (the grants it recorded are not touched);
  re-upgrade recreates it empty.

**Destructive to schema state for its duration**: downgrades two revisions
and re-applies them on whatever database `MIGRATIONS_DATABASE_URL` points
at. Disposable databases only. Marked `integration`. Everything it creates
is removed in `finally` blocks.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError, ProgrammingError

# Imported for its tables: `core.audit_log` has foreign keys onto RBAC tables,
# and `create_tenant` writes audit rows.
import saas_os.core.rbac  # noqa: F401
from lifecycle_callers import PROVISIONING
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_LEDGER = "e8f3b1d5a2c7"  # pragma: allowlist secret
_PERMISSION_REVISION = "d7e2a9c4f1b6"  # pragma: allowlist secret
_PREVIOUS = "c5e8a1d3f7b2"  # pragma: allowlist secret
_PERMISSION = "platform.permission_grant:apply"
_DIGEST = "a" * 64


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


def _seed_operator(conn: Connection) -> uuid.UUID:
    user_id, operator_id = uuid.uuid4(), uuid.uuid4()
    conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user_id})
    conn.execute(
        text("INSERT INTO core.platform_operators (id, user_id, status) VALUES (:o, :u, 'active')"),
        {"o": operator_id, "u": user_id},
    )
    return operator_id


def _grant(conn: Connection, operator_id: uuid.UUID, permission: str) -> None:
    conn.execute(
        text("INSERT INTO core.platform_grants (id, operator_id, permission) VALUES (:g, :o, :p)"),
        {"g": uuid.uuid4(), "o": operator_id, "p": permission},
    )


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


def _definition(admin: Engine) -> str:
    with admin.connect() as conn:
        return conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'ck_platform_grants_permission'"
            )
        ).scalar_one()


def _ledger_exists(admin: Engine) -> bool:
    with admin.connect() as conn:
        return conn.execute(
            text("SELECT to_regclass('core.permission_grant_applications') IS NOT NULL")
        ).scalar_one()


def _tenant(admin: Engine) -> uuid.UUID:
    del admin
    return create_tenant(f"grt-mig-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id


def _drop_tenant(admin: Engine, tenant_id: uuid.UUID) -> None:
    with admin.begin() as conn:
        params = {"t": tenant_id}
        if _ledger_exists(admin):
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


def _ledger_row(conn: Connection, tenant_id: uuid.UUID, migration_id: str = "m-1") -> None:
    conn.execute(
        text(
            "INSERT INTO core.permission_grant_applications (id, tenant_id, namespace, "
            "migration_id, content_digest, outcome, grants_added, applied_by_platform_audit_id) "
            "VALUES (:i, :t, 'grt_app', :m, :d, 'applied', 1, :r)"
        ),
        {"i": uuid.uuid4(), "t": tenant_id, "m": migration_id, "d": _DIGEST, "r": uuid.uuid4()},
    )


def test_the_check_accepts_the_new_permission_and_refuses_an_unknown_one(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            operator_id = _seed_operator(conn)
            _grant(conn, operator_id, _PERMISSION)
            with pytest.raises(IntegrityError), conn.begin_nested():
                _grant(conn, operator_id, "platform.permission_grant:revoke")
        finally:
            trans.rollback()


def test_the_ledger_is_tenant_owned_forced_rls_unique_and_append_only(
    admin: Engine, runtime: Engine
) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        flags = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = 'core.permission_grant_applications'::regclass"
            )
        ).one()
        assert tuple(flags) == (True, True)
        policies = conn.execute(
            text(
                "SELECT count(*) FROM pg_policies "
                "WHERE schemaname = 'core' AND tablename = 'permission_grant_applications'"
            )
        ).scalar_one()
        assert policies >= 1
        role = runtime.url.username
        privileges = {
            privilege: conn.execute(
                text("SELECT has_table_privilege(:r, 'core.permission_grant_applications', :p)"),
                {"r": role, "p": privilege},
            ).scalar_one()
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
        }
    assert privileges == {
        "SELECT": True,
        "INSERT": True,
        "UPDATE": False,
        "DELETE": False,
        "TRUNCATE": False,
    }

    tenant_id = _tenant(admin)
    try:
        with admin.connect() as conn:
            trans = conn.begin()
            try:
                _ledger_row(conn, tenant_id)
                with pytest.raises(IntegrityError), conn.begin_nested():
                    _ledger_row(conn, tenant_id)  # unique per (tenant, namespace, migration)
                with pytest.raises(IntegrityError), conn.begin_nested():
                    conn.execute(
                        text(
                            "UPDATE core.permission_grant_applications SET outcome = 'revoked' "
                            "WHERE tenant_id = :t"
                        ),
                        {"t": tenant_id},
                    )
                with pytest.raises(IntegrityError), conn.begin_nested():
                    conn.execute(
                        text(
                            "UPDATE core.permission_grant_applications SET content_digest = :d "
                            "WHERE tenant_id = :t"
                        ),
                        {"t": tenant_id, "d": "Z" * 64},
                    )
            finally:
                trans.rollback()
    finally:
        _drop_tenant(admin, tenant_id)


def test_downgrade_refuses_while_a_grant_exists_then_drops_the_ledger_and_restores_the_check(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    with admin.connect() as conn:
        lingering = conn.execute(
            text("SELECT count(*) FROM core.platform_grants WHERE permission = :p"),
            {"p": _PERMISSION},
        ).scalar_one()
    assert lingering == 0, "a previous test left a platform.permission_grant:apply grant behind"

    tenant_id = _tenant(admin)
    try:
        with admin.begin() as conn:
            _ledger_row(conn, tenant_id)
            operator_id = _seed_operator(conn)
            _grant(conn, operator_id, _PERMISSION)
        try:
            with pytest.raises(DBAPIError):
                command.downgrade(cfg, _PREVIOUS)
            # One transaction: nothing changed, the ledger is still there.
            assert _PERMISSION in _definition(admin) and _ledger_exists(admin)
            with admin.connect() as conn:
                kept = conn.execute(
                    text("SELECT count(*) FROM core.platform_grants WHERE operator_id = :o"),
                    {"o": operator_id},
                ).scalar_one()
                rows = conn.execute(
                    text(
                        "SELECT count(*) FROM core.permission_grant_applications "
                        "WHERE tenant_id = :t"
                    ),
                    {"t": tenant_id},
                ).scalar_one()
            assert (kept, rows) == (1, 1)
        finally:
            _remove_operator(admin, operator_id)

        try:
            command.downgrade(cfg, _PERMISSION_REVISION)
            assert not _ledger_exists(admin)  # the ledger, its row with it
            assert _PERMISSION in _definition(admin)
            command.downgrade(cfg, _PREVIOUS)
            definition = _definition(admin)
            assert "permission_grant" not in definition
            assert "platform.outbox:replay" in definition
            assert "platform.webhook_secret:reencrypt" in definition  # pragma: allowlist secret
            assert "platform.authority:manage" in definition
            command.upgrade(cfg, _LEDGER)
            assert _PERMISSION in _definition(admin) and _ledger_exists(admin)
            with admin.connect() as conn:
                assert (
                    conn.execute(
                        text("SELECT count(*) FROM core.permission_grant_applications")
                    ).scalar_one()
                    == 0
                )
        finally:
            command.upgrade(cfg, "head")
    finally:
        _drop_tenant(admin, tenant_id)
