"""Migration test for `c8e5a2f7d1b3` (ADR-0054 amendment of 2026-11-09, the
platform hold on one tenant's AI): `ck_platform_grants_permission` accepts
`platform.ai_tenant_hold:manage` at head and still refuses an unknown
permission; `control_plane.ai_tenant_holds` exists with its constraints, its
unique tenant reference, the application role's SELECT only, the
platform-configuration role's SELECT, INSERT and UPDATE (no DELETE), and a
trigger that refuses a write made in a tenant-scoped transaction; a
downgrade refuses while a hold row or a grant of the new permission exists
(by design, nothing is deleted), and once neither exists drops the table and
the function and restores the twenty-eight-permission CHECK; upgrade restores everything.

**Destructive to schema state for its duration**: downgrades one revision and
re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "c8e5a2f7d1b3"  # pragma: allowlist secret
_PREVIOUS = "e2b7c4d9a1f6"  # pragma: allowlist secret
_PERMISSION = "platform.ai_tenant_hold:manage"


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


def _seed_tenant(conn: Connection) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    conn.execute(
        text("INSERT INTO core.tenants (id, name, status) VALUES (:t, :n, 'active')"),
        {"t": tenant_id, "n": f"hold-migration-{tenant_id.hex[:8]}"},
    )
    return tenant_id


def _insert_hold(conn: Connection, tenant_id: uuid.UUID, reason: str = "security") -> None:
    conn.execute(
        text(
            "INSERT INTO control_plane.ai_tenant_holds "
            "(id, target_tenant_id, reason, active, held_at) "
            "VALUES (:i, :t, :r, true, now())"
        ),
        {"i": uuid.uuid4(), "t": tenant_id, "r": reason},
    )


def _remove_tenant(admin: Engine, tenant_id: uuid.UUID) -> None:
    with admin.begin() as conn:
        conn.execute(
            text("DELETE FROM control_plane.ai_tenant_holds WHERE target_tenant_id = :t"),
            {"t": tenant_id},
        )
        conn.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": tenant_id})


def test_the_check_accepts_the_hold_permission_and_refuses_an_unknown_one(
    admin: Engine,
) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            operator_id = _seed_operator(conn)
            _grant(conn, operator_id, _PERMISSION)
            with pytest.raises(IntegrityError), conn.begin_nested():
                _grant(conn, operator_id, "platform.ai_tenant_hold:purge")
        finally:
            trans.rollback()


def test_the_table_enforces_its_constraints(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            tenant_id = _seed_tenant(conn)
            _insert_hold(conn, tenant_id)
            with pytest.raises(IntegrityError), conn.begin_nested():
                _insert_hold(conn, tenant_id)  # one row per tenant
            with pytest.raises(IntegrityError), conn.begin_nested():
                _insert_hold(conn, uuid.uuid4())  # a tenant that does not exist
            other = _seed_tenant(conn)
            with pytest.raises(IntegrityError), conn.begin_nested():
                _insert_hold(conn, other, reason="because")  # closed reason set
            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(  # active must agree with released_at
                    text(
                        "UPDATE control_plane.ai_tenant_holds SET active = false "
                        "WHERE target_tenant_id = :t"
                    ),
                    {"t": tenant_id},
                )
        finally:
            trans.rollback()


def test_the_application_role_only_reads_and_the_configuration_role_writes_without_delete(
    admin: Engine,
) -> None:
    command.upgrade(_config(), "head")
    app_role = os.environ.get("APP_DB_USER", "saas_os_app")
    config_role = os.environ.get("PLATFORM_CONFIG_DB_USER", "saas_os_platform_config")

    def granted(role: str) -> set[str]:
        with admin.connect() as conn:
            return {
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT privilege_type FROM information_schema.role_table_grants "
                        "WHERE table_schema = 'control_plane' "
                        "AND table_name = 'ai_tenant_holds' AND grantee = :r"
                    ),
                    {"r": role},
                )
            }

    assert granted(app_role) == {"SELECT"}
    assert granted(config_role) == {"SELECT", "INSERT", "UPDATE"}


def test_the_trigger_refuses_a_write_in_a_tenant_scoped_transaction(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            tenant_id = _seed_tenant(conn)
            _insert_hold(conn, tenant_id)  # no tenant bound: allowed
            conn.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)}
            )
            with pytest.raises(DBAPIError, match="tenant-scoped"), conn.begin_nested():
                conn.execute(
                    text(
                        "UPDATE control_plane.ai_tenant_holds SET reason = 'operator' "
                        "WHERE target_tenant_id = :t"
                    ),
                    {"t": tenant_id},
                )
            with pytest.raises(DBAPIError, match="tenant-scoped"), conn.begin_nested():
                _insert_hold(conn, _seed_tenant(conn))
            # reading stays possible: governed inference reads it in a tenant transaction
            assert (
                conn.execute(
                    text("SELECT count(*) FROM control_plane.ai_tenant_holds")
                ).scalar_one()
                >= 1
            )
        finally:
            trans.rollback()


def test_downgrade_refuses_while_a_hold_or_a_grant_exists_then_restores_the_previous_check(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    with admin.connect() as conn:
        lingering = conn.execute(
            text("SELECT count(*) FROM core.platform_grants WHERE permission = :p"),
            {"p": _PERMISSION},
        ).scalar_one()
        held = conn.execute(text("SELECT count(*) FROM control_plane.ai_tenant_holds")).scalar_one()
    assert lingering == 0, "a previous test left a platform.ai_tenant_hold:manage grant behind"
    assert held == 0, "a previous test left a tenant AI hold behind"

    # a hold row refuses the downgrade
    with admin.begin() as conn:
        tenant_id = _seed_tenant(conn)
        _insert_hold(conn, tenant_id)
    try:
        with pytest.raises(DBAPIError):
            command.downgrade(cfg, _PREVIOUS)
        with admin.connect() as conn:
            kept = conn.execute(
                text("SELECT count(*) FROM control_plane.ai_tenant_holds")
            ).scalar_one()
        assert kept == 1 and _PERMISSION in _definition(admin)
    finally:
        _remove_tenant(admin, tenant_id)

    # a grant of the new permission refuses it too
    with admin.begin() as conn:
        operator_id = _seed_operator(conn)
        _grant(conn, operator_id, _PERMISSION)
    try:
        with pytest.raises(DBAPIError):
            command.downgrade(cfg, _PREVIOUS)
        assert _PERMISSION in _definition(admin)  # one transaction: nothing changed
    finally:
        _remove_operator(admin, operator_id)

    try:
        command.downgrade(cfg, _PREVIOUS)
        definition = _definition(admin)
        assert _PERMISSION not in definition and "platform.ai_policy:manage" in definition
        assert "platform.security_retention_hold:manage" in definition
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT to_regclass('control_plane.ai_tenant_holds')")
                ).scalar_one()
                is None
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = "
                        "p.pronamespace WHERE n.nspname = 'control_plane' "
                        "AND p.proname = 'ai_tenant_holds_refuse_tenant_context'"
                    )
                ).scalar_one()
                == 0
            )
        command.upgrade(cfg, _REVISION)
        assert _PERMISSION in _definition(admin)
    finally:
        command.upgrade(cfg, "head")
