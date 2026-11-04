"""A transaction on the migrations database role, for one manual
maintenance procedure (owner decision B of 2026-11-02: deleting expired
permission grant ledger rows; ADR-0045 amendment of 2026-11-02).

The application role (`DATABASE_URL`) never holds `DELETE` on the ledger,
and no new database role or `SECURITY DEFINER` function was approved for
it. The deletion therefore runs as the migrations role
(`MIGRATIONS_DATABASE_URL`), the privileged role that owns the schema, in
an operator-run process. This module is the only place that connection is
opened for application code:

- `validate_migrations_role(engine, owned_table=...)` checks, on the
  engine's own connection, the role it authenticated as (`current_user`,
  never a name read from configuration): it must own `owned_table` (or be
  a member of its owner; a superuser is), hold `DELETE` on it, and must not
  be the application role (the user name of `DATABASE_URL`, when that is
  configured). Anything that cannot be established is refused
  (`UnsafeDatabaseRoleError`), fail closed. The application role never
  owns a table, so pointing `MIGRATIONS_DATABASE_URL` at the application
  credential is refused even where `DATABASE_URL` is not set.
- `migrations_role_session_scope(owned_table=...)` is the transaction:
  commit on success, rollback on error, always close; its engine is built
  for the one call and disposed afterwards. There is no fallback to
  `DATABASE_URL`.

It is not exported by `saas_os.infra.db`; its only importer is
`saas_os.core.permission_grants.expiry`
(`tests/architecture/test_migrations_role_boundary.py`). Error messages
name a variable, a role or a table, never a URL.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError, OperationalError
from sqlalchemy.orm import Session

from saas_os.infra.db.config import (
    DatabaseConfigurationError,
    get_database_config,
    get_migrations_database_config,
)
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.role_guard import UnsafeDatabaseRoleError
from saas_os.infra.db.session import build_session_factory, session_scope

MIGRATIONS_URL_VARIABLE = "MIGRATIONS_DATABASE_URL"

_ROLE_QUERY = (
    "SELECT r.rolname, "
    "pg_has_role(current_user, c.relowner, 'MEMBER') AS owns, "
    "has_table_privilege(c.oid, 'DELETE') AS may_delete "
    "FROM pg_roles r CROSS JOIN pg_class c "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE r.rolname = current_user AND n.nspname || '.' || c.relname = :table"
)


def _unsafe(reason: str) -> UnsafeDatabaseRoleError:
    return UnsafeDatabaseRoleError(
        f"{MIGRATIONS_URL_VARIABLE} does not reach the migrations role: {reason}. "
        "Refusing to use it."
    )


def _application_role_name() -> str | None:
    """The user name of `DATABASE_URL`, or `None` when it is not configured
    (the operator's shell need not hold the application credential)."""
    try:
        url = get_database_config().url
    except DatabaseConfigurationError:
        return None
    try:
        return make_url(url).username
    except ArgumentError:
        return None


def validate_migrations_role(engine: Engine, *, owned_table: str) -> str:
    """The role `engine` authenticates as, if it is the migrations role for
    `owned_table` (module docstring); `UnsafeDatabaseRoleError` otherwise."""
    try:
        with engine.connect() as connection:
            row = connection.execute(text(_ROLE_QUERY), {"table": owned_table}).one_or_none()
    except OperationalError as exc:
        raise _unsafe("the database was not reachable") from exc
    if row is None:
        raise _unsafe(f"no role or no table {owned_table}")
    role, owns, may_delete = row
    if not isinstance(role, str) or owns is not True or may_delete is not True:
        raise _unsafe(f"role {role!r} does not own {owned_table} or cannot delete from it")
    application_role = _application_role_name()
    if application_role is not None and application_role == role:
        raise _unsafe(f"role {role!r} is the application role (DATABASE_URL)")
    return role


@contextmanager
def migrations_role_session_scope(*, owned_table: str) -> Iterator[Session]:
    """One transaction on the migrations role, checked first (module
    docstring). Never tenant-bound unless the caller binds a scope."""
    engine = build_engine(get_migrations_database_config())
    try:
        validate_migrations_role(engine, owned_table=owned_table)
        with session_scope(session_factory=build_session_factory(engine)) as session:
            yield session
    finally:
        engine.dispose()
