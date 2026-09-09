"""P1.2 -- the application-runtime RLS role-misconfiguration startup guard.

PostgreSQL never applies Row-Level Security to a superuser or a role with
`BYPASSRLS` -- there is no override, `FORCE ROW LEVEL SECURITY` included
(`infra/db/rls.py`'s own docstring; the regression test this module
protects, `tests/core/tenancy/test_tenant_isolation_integration.py
::test_the_real_runtime_role_is_not_superuser_or_bypassrls`). That test
only runs when someone remembers to run the Phase 3.1 integration suite.
This module makes the same property a startup-time, fail-closed
precondition of the running application itself: if the role
`infra.db.get_database_config()`/`get_engine()` actually connects as can
bypass RLS, the application must never become ready.

`_evaluate_role_safety()` is a pure decision function -- same input
always produces the same result, no I/O, mirroring
`control_plane.data_authorization.service.evaluate_data_authorization()`'s
own "default deny must be structurally obvious in the code" discipline:
every branch that is not the one explicit safe case raises
`UnsafeDatabaseRoleError`. `validate_application_role()` is the one I/O
wrapper around it -- it queries PostgreSQL's own authoritative role
catalog (`pg_roles`, keyed on `current_user`, the same query
`test_the_real_runtime_role_is_not_superuser_or_bypassrls` already uses)
for the role the given engine's connection actually authenticated as, not
a role name read from configuration -- a role can be renamed, and
`current_user` is the one source PostgreSQL itself uses to decide
whether RLS applies.

This is defense-in-depth around the existing RLS boundary, not a
replacement for it: this module runs no tenant-scoped query, applies no
policy, and grants no access -- it only refuses to let the application
start if the boundary it depends on (a non-superuser, non-BYPASSRLS
runtime role) does not actually hold. It never receives or requests a
credential itself -- `validate_application_role()` takes an already
-constructed `Engine` (normally `infra.db.engine.get_engine()`, itself
built from `infra.db.config.get_database_config()` -- the existing
`infra.secrets`-sourced configuration path); this module introduces no
new secret-reading mechanism.

`UnsafeDatabaseRoleError` messages carry only a role name (explicitly
acceptable diagnostic information, never a credential) and a fixed,
non-parameterized reason string -- never the engine's URL, connection
string, or any value that could embed a password.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError


class UnsafeDatabaseRoleError(RuntimeError):
    """Raised when the application's configured PostgreSQL runtime role
    can bypass Row-Level Security, or when that property cannot be
    established at all (fail closed -- see module docstring). Never
    includes a password, connection string, or `DATABASE_URL` value."""


@dataclass(frozen=True)
class ApplicationRoleValidation:
    """Returned only once every safety check in `_evaluate_role_safety()`
    has explicitly passed."""

    role_name: str


def _evaluate_role_safety(row: tuple[object, object, object] | None) -> ApplicationRoleValidation:
    """Pure decision function -- no I/O. `row` is the
    `(rolname, rolsuper, rolbypassrls)` tuple `validate_application_role()`
    fetched from `pg_roles`, or `None` if no such row was found. Every
    `raise` below is a DENY (fail closed); the final line is the one and
    only safe-role path, reached only once every prior check has passed
    explicitly."""
    if row is None:
        raise UnsafeDatabaseRoleError(
            "Unable to establish PostgreSQL role safety for the application "
            "database connection: no matching pg_roles entry for the "
            "connected role. Refusing to start."
        )

    role_name, is_superuser, bypasses_rls = row
    if (
        not isinstance(role_name, str)
        or not isinstance(is_superuser, bool)
        or not isinstance(bypasses_rls, bool)
    ):
        raise UnsafeDatabaseRoleError(
            "Unable to establish PostgreSQL role safety for the application "
            "database connection: role attributes could not be determined. "
            "Refusing to start."
        )

    if is_superuser:
        raise UnsafeDatabaseRoleError(
            f"Application database role {role_name!r} is a PostgreSQL superuser "
            "-- Row-Level Security is never applied to a superuser. Refusing to start."
        )
    if bypasses_rls:
        raise UnsafeDatabaseRoleError(
            f"Application database role {role_name!r} has BYPASSRLS -- Row-Level "
            "Security would be silently bypassed. Refusing to start."
        )

    return ApplicationRoleValidation(role_name=role_name)


def validate_application_role(engine: Engine) -> ApplicationRoleValidation:
    """Fail-closed startup guard: establishes a connection on `engine`
    (the application's normal runtime DB engine -- see module docstring),
    queries PostgreSQL's own authoritative `pg_roles` catalog for the
    role that connection actually authenticated as, and raises
    `UnsafeDatabaseRoleError` unless that role is demonstrably neither a
    superuser nor BYPASSRLS. Any failure to establish the connection or
    run the query itself is also treated as unsafe -- this function never
    returns a "success" result by default when the property it exists to
    prove could not actually be checked.
    """
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                    "WHERE rolname = current_user"
                )
            ).one_or_none()
    except OperationalError as exc:
        raise UnsafeDatabaseRoleError(
            "Unable to establish PostgreSQL role safety for the application "
            "database connection: the database was not reachable. Refusing to start."
        ) from exc

    return _evaluate_role_safety(tuple(row) if row is not None else None)
