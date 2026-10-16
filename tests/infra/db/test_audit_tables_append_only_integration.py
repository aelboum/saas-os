"""ADR-0051 -- the runtime role can only append to the two audit tables.

`core.audit_log` and `core.platform_audit_log` are evidence: the restricted
application role may `SELECT` and `INSERT` them and nothing else. The same
holds for `core.audit_digests`, the digest job's cursor (ADR-0053). This test
asks PostgreSQL directly, for every privilege that could change or remove a
row, and then tries each one as that role.

Marked `integration`.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_TABLES = ("core.audit_log", "core.platform_audit_log", "core.audit_digests")
# A column each table has, for the UPDATE attempts.
_COLUMN = {
    "core.audit_log": "action",
    "core.platform_audit_log": "action",
    "core.audit_digests": "digest",
}
_FORBIDDEN = ("UPDATE", "DELETE", "TRUNCATE")


@pytest.fixture(scope="module")
def app_engine() -> Iterator[Engine]:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.platform_audit_log LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


@pytest.mark.parametrize("table", _TABLES)
def test_the_runtime_role_holds_only_select_and_insert(app_engine: Engine, table: str) -> None:
    with app_engine.connect() as conn:
        held = {
            privilege: conn.execute(
                text("SELECT has_table_privilege(current_user, :t, :p)"),
                {"t": table, "p": privilege},
            ).scalar_one()
            for privilege in ("SELECT", "INSERT", *_FORBIDDEN)
        }
        # A column-level grant would not show in the table-level check.
        column_update = conn.execute(
            text("SELECT has_any_column_privilege(current_user, :t, 'UPDATE')"),
            {"t": table},
        ).scalar_one()
    assert column_update is False
    assert held == {
        "SELECT": True,
        "INSERT": True,
        "UPDATE": False,
        "DELETE": False,
        "TRUNCATE": False,
    }


@pytest.mark.parametrize("table", _TABLES)
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE {table} SET {column} = {column} WHERE false",
        "UPDATE {table} SET created_at = created_at WHERE false",
        "DELETE FROM {table} WHERE false",
        "TRUNCATE {table}",
    ],
)
def test_changing_or_removing_rows_is_refused(
    app_engine: Engine, table: str, statement: str
) -> None:
    # `connect()`, never `begin()`: if a statement were ever permitted, closing
    # the connection rolls it back instead of committing it.
    with app_engine.connect() as conn:
        with pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text(statement.format(table=table, column=_COLUMN[table])))
        conn.rollback()
