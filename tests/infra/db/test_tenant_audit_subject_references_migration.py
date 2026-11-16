"""Migration test for `c7e3a9f2b4d8` (audit identity phase P3a: the tenant
audit subject reference tables), against real PostgreSQL.

- the three tables are tenant-owned under the canonical tenant policy
  (ENABLE + FORCE);
- the runtime role may SELECT and INSERT, may UPDATE only the three unlink
  columns of a link and the two release columns of a hold, and never DELETE
  (ADR-0063 option A);
- both triggers are SECURITY INVOKER with a pinned `search_path`;
- the downgrade refuses while any of the three tables holds a row -- also
  when the row is visible only under its tenant (FORCE RLS binds a
  non-superuser owner, so the downgrade lifts RLS inside its own
  transaction before it counts) -- and changes nothing; with the tables
  empty it drops them, and a re-upgrade recreates them.

**Destructive to schema state for its duration**: downgrades two
revisions (to `b6d2f8a4c1e7`) and re-applies them on whatever database
`MIGRATIONS_DATABASE_URL` points at.
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
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PREVIOUS = "b6d2f8a4c1e7"  # pragma: allowlist secret
_LINKS = "core.audit_subject_links"
_ERASURES = "core.audit_subject_erasures"
_HOLDS = "core.audit_identity_holds"
_TABLES = (_LINKS, _ERASURES, _HOLDS)


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
            conn.execute(text(f"SELECT 1 FROM {_LINKS} LIMIT 1"))  # noqa: S608
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _exists(admin: Engine, table: str) -> bool:
    with admin.connect() as conn:
        return conn.execute(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": table}).scalar_one()


def _stamp(admin: Engine) -> str:
    with admin.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version_saas_os")).scalar_one()


def _app_role() -> str:
    engine = build_engine(get_database_config())
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT current_user")).scalar_one()
    finally:
        engine.dispose()


def test_the_tables_are_tenant_owned_with_forced_rls_and_narrow_grants(admin: Engine) -> None:
    role = _app_role()
    with admin.connect() as conn:
        for table in _TABLES:
            rls, forced = conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid = to_regclass(:t)"
                ),
                {"t": table},
            ).one()
            assert (rls, forced) == (True, True), table
            policy = conn.execute(
                text("SELECT qual FROM pg_policies WHERE schemaname = 'core' AND tablename = :t"),
                {"t": table.split(".")[1]},
            ).scalar_one()
            assert "app.tenant_id" in policy and "tenant_id" in policy, table
            for privilege, expected in (
                ("SELECT", True),
                ("INSERT", True),
                ("UPDATE", False),
                ("DELETE", False),
            ):
                assert (
                    conn.execute(
                        text("SELECT has_table_privilege(:r, :t, :p)"),
                        {"r": role, "t": table, "p": privilege},
                    ).scalar_one()
                    is expected
                ), (table, privilege)

        def column_update(table: str, column: str) -> bool:
            return conn.execute(
                text("SELECT has_column_privilege(:r, :t, :c, 'UPDATE')"),
                {"r": role, "t": table, "c": column},
            ).scalar_one()

        for column in ("user_id", "unlinked_at", "unlink_reason"):
            assert column_update(_LINKS, column)
        for column in ("subject_ref", "tenant_id", "subject_day", "created_at"):
            assert not column_update(_LINKS, column)
        for column in ("released_at", "released_by_platform_audit_id"):
            assert column_update(_HOLDS, column)
        assert not column_update(_HOLDS, "subject_ref")
        assert not column_update(_ERASURES, "erased_at")

        functions = conn.execute(
            text(
                "SELECT p.proname, p.prosecdef, p.proconfig FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'core' "
                "AND p.proname IN ('audit_subject_links_one_way', "
                "'audit_identity_holds_release_once')"
            )
        ).all()
        assert len(functions) == 2
        for name, definer, config in functions:
            assert definer is False, name
            assert config == ["search_path=pg_catalog"], name


def test_the_downgrade_refuses_a_row_visible_only_under_its_tenant(admin: Engine) -> None:
    tenant = create_tenant(f"p3a-mig-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id
    user = uuid.uuid4()
    try:
        with admin.begin() as conn:
            conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user})
            conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant)})
            conn.execute(
                text(
                    f"INSERT INTO {_LINKS} (tenant_id, user_id, subject_day) "  # noqa: S608
                    "VALUES (:t, :u, DATE '2026-11-15')"
                ),
                {"t": tenant, "u": user},
            )
        head = _stamp(admin)
        with pytest.raises(DBAPIError, match="refusing to drop it"):
            command.downgrade(_config(), _PREVIOUS)
        # Nothing changed: still at head, the row still there, the
        # downgrade's lift of RLS rolled back with it, and the indexes of the
        # later revision `d4f8b2e6a9c1` (whose downgrade ran first, in the
        # same transaction) are still there.
        assert all(_exists(admin, table) for table in _TABLES)
        assert _exists(admin, "core.ix_audit_log_initiated_by_subject_ref")
        assert _exists(admin, "core.ix_audit_log_owner_user_subject_ref")
        assert _stamp(admin) == head
        with admin.begin() as conn:
            conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant)})
            assert conn.execute(text(f"SELECT count(*) FROM {_LINKS}")).scalar_one() == 1  # noqa: S608
            forced = conn.execute(
                text(
                    "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                    "WHERE oid = to_regclass(:t)"
                ),
                {"t": _LINKS},
            ).scalar_one()
            assert forced is True

        # Empty: the downgrade drops the tables, and the upgrade restores them.
        with admin.begin() as conn:
            conn.execute(text("TRUNCATE " + ", ".join(_TABLES)))
        command.downgrade(_config(), _PREVIOUS)
        assert not any(_exists(admin, table) for table in _TABLES)
        command.upgrade(_config(), "head")
        assert all(_exists(admin, table) for table in _TABLES)
    finally:
        if not _exists(admin, _LINKS):
            command.upgrade(_config(), "head")
        with admin.begin() as conn:
            conn.execute(text("TRUNCATE " + ", ".join(_TABLES)))
            conn.execute(text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": tenant})
            conn.execute(
                text("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t"),
                {"t": tenant},
            )
            conn.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": tenant})
            conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user})
