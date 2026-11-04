"""Migration test for `c3f9e1a7b5d2` (owner decisions of 2026-11-03: the
ledger deletion approval records and the approver eligibility register),
against real PostgreSQL.

- the four tables are global, with the tenant-context exclusion policy
  enabled and forced; the runtime role holds SELECT and INSERT, UPDATE only
  of the invalidate pair on approvals and authorisations, never DELETE;
- the downgrade refuses while any of the four holds a row and changes
  nothing; on empty tables it drops exactly the four (and their functions),
  and the upgrade recreates them.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on the database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`. Every row it creates is
removed in a `finally` block.
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

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_APPROVALS = "c3f9e1a7b5d2"  # pragma: allowlist secret
_HOLDS = "a9c3e5f7b1d4"  # pragma: allowlist secret
_TABLES = (
    "permission_grant_ledger_approver_register",
    "permission_grant_ledger_deletion_requests",
    "permission_grant_ledger_deletion_approvals",
    "permission_grant_ledger_deletion_execution_authorizations",
)


@pytest.fixture(scope="module")
def admin() -> Iterator[Engine]:
    get_migrations_database_config.cache_clear()
    get_database_config.cache_clear()
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


def _present(admin: Engine) -> set[str]:
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'core' AND c.relkind = 'r' AND c.relname = ANY(:t)"
            ),
            {"t": list(_TABLES)},
        ).scalars()
        return set(rows)


def _app_role() -> str:
    from sqlalchemy.engine import make_url

    name = make_url(get_database_config().url).username
    assert name is not None
    return name


def test_the_tables_are_global_excluded_from_tenant_scope_and_never_deletable(
    admin: Engine,
) -> None:
    command.upgrade(_config(), "head")
    assert _present(admin) == set(_TABLES)
    role = _app_role()
    with admin.connect() as conn:
        for table in _TABLES:
            enabled, forced = conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid = CAST(:t AS regclass)"
                ),
                {"t": f"core.{table}"},
            ).one()
            assert (enabled, forced) == (True, True), table
            privileges = {
                p
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
                if conn.execute(
                    text("SELECT has_table_privilege(:r, CAST(:t AS regclass), :p)"),
                    {"r": role, "t": f"core.{table}", "p": p},
                ).scalar_one()
            }
            assert privileges == {"SELECT", "INSERT"}, (table, privileges)
            columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.column_privileges "
                        "WHERE grantee = :r AND table_schema = 'core' AND table_name = :t "
                        "AND privilege_type = 'UPDATE'"
                    ),
                    {"r": role, "t": table},
                ).scalars()
            )
            expected = (
                {"invalidated_at", "invalidated_by_platform_audit_id"}
                if table.endswith(("approvals", "authorizations"))
                else set()
            )
            assert columns == expected, (table, columns)


def test_downgrade_refuses_while_a_row_exists_then_drops_only_the_four(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    user_id = uuid.uuid4()
    entry_id = uuid.uuid4()
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user_id})
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(
            text(
                "INSERT INTO core.permission_grant_ledger_approver_register (id, entry_type, "
                "subject_user_id, recorded_by_user_id, designation_ref, ticket_ref, valid_until, "
                "proposal_expires_at, recorded_at, recorded_by_platform_audit_id) VALUES "
                "(:i, 'representative_designation_proposal', :u, :u, 'D-1', 'T-1', "
                "now() + interval '1 month', now() + interval '1 day', now(), :a)"
            ),
            {"i": entry_id, "u": user_id, "a": uuid.uuid4()},
        )
    try:
        with pytest.raises(DBAPIError, match="holds rows; refusing to drop it"):
            command.downgrade(cfg, _HOLDS)
        assert _present(admin) == set(_TABLES)
    finally:
        with admin.begin() as conn:
            conn.execute(text("SET LOCAL session_replication_role = replica"))
            conn.execute(
                text("DELETE FROM core.permission_grant_ledger_approver_register WHERE id = :i"),
                {"i": entry_id},
            )
            conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user_id})
    try:
        command.downgrade(cfg, _HOLDS)
        assert _present(admin) == set()
        with admin.connect() as conn:
            left = conn.execute(
                text(
                    "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'core' AND p.proname LIKE 'pgl\\_%'"
                )
            ).scalar_one()
            assert left == 0
            # The holds table of the previous revision is untouched.
            assert conn.execute(
                text("SELECT to_regclass('core.permission_grant_ledger_holds') IS NOT NULL")
            ).scalar_one()
        command.upgrade(cfg, _APPROVALS)
        assert _present(admin) == set(_TABLES)
    finally:
        command.upgrade(cfg, "head")
