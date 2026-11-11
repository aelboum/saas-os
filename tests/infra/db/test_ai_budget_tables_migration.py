"""Migration test for `f1b9d3e7a5c2` (ADR-0054 amendment of 2026-11-10, Gap
21b: the monetary AI budget). At head: `ck_platform_grants_permission`
accepts `platform.ai_budget:manage` and still refuses an unknown permission;
the five tables exist with their constraints; the two platform tables give
the application role SELECT only and the platform-configuration role exactly
SELECT and INSERT (plan budgets) or SELECT, INSERT and UPDATE (overrides),
and refuse a write in a tenant-scoped transaction; the three tenant tables
give the application role SELECT, INSERT and UPDATE (never DELETE) and carry
the canonical tenant policy, ENABLE and FORCE. A downgrade refuses while any
budget row or a grant of the new permission exists (nothing is deleted), and
otherwise drops the tables and the function and restores the
twenty-nine-permission CHECK; upgrade restores everything.

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
_REVISION = "f1b9d3e7a5c2"  # pragma: allowlist secret
_PREVIOUS = "a4c8e1f3b7d5"  # pragma: allowlist secret
_PERMISSION = "platform.ai_budget:manage"
_PLATFORM_TABLES = ("ai_plan_budgets", "ai_budget_overrides")
_TENANT_TABLES = ("ai_tenant_budgets", "ai_budget_periods", "ai_budget_reservations")


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
        {"t": tenant_id, "n": f"budget-migration-{tenant_id.hex[:8]}"},
    )
    return tenant_id


def _seed_plan(conn: Connection) -> uuid.UUID:
    plan_id = uuid.uuid4()
    conn.execute(
        text("INSERT INTO core.billing_plans (id, key, name) VALUES (:p, :k, 'budget migration')"),
        {"p": plan_id, "k": f"budget-{plan_id.hex[:8]}"},
    )
    return plan_id


def _insert_plan_budget(
    conn: Connection,
    plan_id: uuid.UUID,
    *,
    version: str = "b1",
    currency: str | None = "USD",
    amount: str | None = "10",
) -> None:
    conn.execute(
        text(
            "INSERT INTO control_plane.ai_plan_budgets "
            "(id, plan_id, budget_version, currency, monthly_amount, effective_from) "
            "VALUES (:i, :p, :v, :c, CAST(:a AS numeric), now())"
        ),
        {"i": uuid.uuid4(), "p": plan_id, "v": version, "c": currency, "a": amount},
    )


def _insert_period(
    conn: Connection, tenant_id: uuid.UUID, *, start: str = "2026-11-01T00:00:00+00:00"
) -> None:
    conn.execute(
        text(
            "INSERT INTO control_plane.ai_budget_periods (id, tenant_id, period_start, currency) "
            "VALUES (:i, :t, CAST(:s AS timestamptz), 'USD')"
        ),
        {"i": uuid.uuid4(), "t": tenant_id, "s": start},
    )


def _granted(admin: Engine, table: str, role: str) -> set[str]:
    with admin.connect() as conn:
        return {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'control_plane' AND table_name = :t AND grantee = :r"
                ),
                {"t": table, "r": role},
            )
        }


def test_the_check_accepts_the_budget_permission_and_refuses_an_unknown_one(
    admin: Engine,
) -> None:
    command.upgrade(_config(), "head")
    definition = _definition(admin)
    assert _PERMISSION in definition and "platform.ai_budget:spend" not in definition


def test_the_grants_and_policies_are_exactly_the_reviewed_ones(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    app_role = os.environ.get("APP_DB_USER", "saas_os_app")
    config_role = os.environ.get("PLATFORM_CONFIG_DB_USER", "saas_os_platform_config")
    for table in _PLATFORM_TABLES:
        assert _granted(admin, table, app_role) == {"SELECT"}, table
    assert _granted(admin, "ai_plan_budgets", config_role) == {"SELECT", "INSERT"}
    assert _granted(admin, "ai_budget_overrides", config_role) == {"SELECT", "INSERT", "UPDATE"}
    for table in _TENANT_TABLES:
        assert _granted(admin, table, app_role) == {"SELECT", "INSERT", "UPDATE"}, table
        assert _granted(admin, table, config_role) == set(), table
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
                "(SELECT count(*) FROM pg_policies p WHERE p.schemaname = 'control_plane' "
                "AND p.tablename = c.relname) FROM pg_class c JOIN pg_namespace n "
                "ON n.oid = c.relnamespace WHERE n.nspname = 'control_plane' "
                "AND c.relname = ANY(:t)"
            ),
            {"t": [*_TENANT_TABLES, *_PLATFORM_TABLES]},
        ).all()
    state = {name: (rls, force, policies) for name, rls, force, policies in rows}
    for table in _TENANT_TABLES:
        assert state[table] == (True, True, 1), table
    for table in _PLATFORM_TABLES:
        assert state[table] == (False, False, 0), table


def test_the_tables_enforce_their_constraints(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            plan_id = _seed_plan(conn)
            _insert_plan_budget(conn, plan_id)
            _insert_plan_budget(conn, plan_id, version="b2", currency=None, amount=None)
            for bad in (
                {"version": "b1"},  # a version is unique per plan
                {"version": "b3", "currency": "usd"},  # ISO-4217 upper case
                {"version": "b4", "amount": "-1"},  # never negative
                {"version": "b5", "currency": None},  # currency and amount together
            ):
                with pytest.raises(IntegrityError), conn.begin_nested():
                    _insert_plan_budget(conn, plan_id, **bad)  # type: ignore[arg-type]
            with pytest.raises(IntegrityError), conn.begin_nested():
                _insert_plan_budget(conn, uuid.uuid4())  # an unknown plan
            tenant_id = _seed_tenant(conn)
            _insert_period(conn, tenant_id)
            with pytest.raises(IntegrityError), conn.begin_nested():
                _insert_period(conn, tenant_id)  # one period per tenant and month
            with pytest.raises(IntegrityError), conn.begin_nested():
                _insert_period(conn, tenant_id, start="2026-11-02T00:00:00+00:00")  # not a month
            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(
                    text(
                        "UPDATE control_plane.ai_budget_periods SET reserved = -1 "
                        "WHERE tenant_id = :t"
                    ),
                    {"t": tenant_id},
                )
            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO control_plane.ai_budget_overrides (id, target_tenant_id, "
                        "currency, amount, reason, active, expires_at, set_at) VALUES "
                        "(:i, :t, 'USD', 1, 'because', true, now() + interval '1 day', now())"
                    ),
                    {"i": uuid.uuid4(), "t": tenant_id},
                )
            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(  # an override must end after it was set
                    text(
                        "INSERT INTO control_plane.ai_budget_overrides (id, target_tenant_id, "
                        "currency, amount, reason, active, expires_at, set_at) VALUES "
                        "(:i, :t, 'USD', 1, 'support', true, now() - interval '1 day', now())"
                    ),
                    {"i": uuid.uuid4(), "t": tenant_id},
                )
        finally:
            trans.rollback()


def test_the_platform_tables_refuse_a_write_in_a_tenant_scoped_transaction(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            plan_id = _seed_plan(conn)
            tenant_id = _seed_tenant(conn)
            conn.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)}
            )
            with pytest.raises(DBAPIError, match="tenant-scoped"), conn.begin_nested():
                _insert_plan_budget(conn, plan_id)
            with pytest.raises(DBAPIError, match="tenant-scoped"), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO control_plane.ai_budget_overrides (id, target_tenant_id, "
                        "currency, amount, reason, active, expires_at, set_at) VALUES "
                        "(:i, :t, 'USD', 1, 'support', true, now() + interval '1 day', now())"
                    ),
                    {"i": uuid.uuid4(), "t": tenant_id},
                )
        finally:
            trans.rollback()


def test_downgrade_refuses_while_a_budget_row_or_a_grant_exists_then_restores_the_check(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    with admin.connect() as conn:
        for table in (*_TENANT_TABLES, *_PLATFORM_TABLES):
            left = conn.execute(
                text(f"SELECT count(*) FROM control_plane.{table}")  # noqa: S608 -- fixed names
            ).scalar_one()
            assert left == 0, f"a previous test left a row in {table}"

    # a budget row refuses the downgrade
    with admin.begin() as conn:
        tenant_id = _seed_tenant(conn)
        _insert_period(conn, tenant_id)
    try:
        with pytest.raises(DBAPIError):
            command.downgrade(cfg, _PREVIOUS)
        assert _PERMISSION in _definition(admin)  # one transaction: nothing changed
    finally:
        with admin.begin() as conn:
            conn.execute(
                text("DELETE FROM control_plane.ai_budget_periods WHERE tenant_id = :t"),
                {"t": tenant_id},
            )
            conn.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": tenant_id})

    # a grant of the new permission refuses it too
    with admin.begin() as conn:
        user_id, operator_id = uuid.uuid4(), uuid.uuid4()
        conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user_id})
        conn.execute(
            text(
                "INSERT INTO core.platform_operators (id, user_id, status) "
                "VALUES (:o, :u, 'active')"
            ),
            {"o": operator_id, "u": user_id},
        )
        conn.execute(
            text(
                "INSERT INTO core.platform_grants (id, operator_id, permission) VALUES (:g, :o, :p)"
            ),
            {"g": uuid.uuid4(), "o": operator_id, "p": _PERMISSION},
        )
    try:
        with pytest.raises(DBAPIError):
            command.downgrade(cfg, _PREVIOUS)
        assert _PERMISSION in _definition(admin)
    finally:
        with admin.begin() as conn:
            conn.execute(
                text("DELETE FROM core.platform_grants WHERE operator_id = :o"), {"o": operator_id}
            )
            conn.execute(
                text("DELETE FROM core.platform_operators WHERE id = :o"), {"o": operator_id}
            )
            conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user_id})

    try:
        command.downgrade(cfg, _PREVIOUS)
        definition = _definition(admin)
        assert _PERMISSION not in definition and "platform.ai_tenant_hold:manage" in definition
        with admin.connect() as conn:
            for table in (*_TENANT_TABLES, *_PLATFORM_TABLES):
                assert (
                    conn.execute(
                        text("SELECT to_regclass(:t)"), {"t": f"control_plane.{table}"}
                    ).scalar_one()
                    is None
                ), table
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = "
                        "p.pronamespace WHERE n.nspname = 'control_plane' "
                        "AND p.proname = 'ai_budget_config_refuse_tenant_context'"
                    )
                ).scalar_one()
                == 0
            )
        command.upgrade(cfg, _REVISION)
        assert _PERMISSION in _definition(admin)
    finally:
        command.upgrade(cfg, "head")
