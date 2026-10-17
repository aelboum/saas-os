"""The platform-configuration database identity
(docs/ADR/0056-platform-configuration-database-identity.md).

The global AI configuration tables (`PROTECTED_TABLES`) are written by one
PostgreSQL role only, the platform-configuration role, reached through
`PLATFORM_CONFIG_DATABASE_URL`. The application role (`DATABASE_URL`) may
only read them. This module is the only place that connection is built:

`PROTECTED_TABLES` is declared in `role_guard`, which checks at startup that
the application role cannot write them.

- `get_platform_config_database_config()` reads the URL through
  `SecretsProvider`. A missing value is `DatabaseConfigurationError`. There is
  no fallback to `DATABASE_URL`, and nothing falls back to this URL.
- `get_platform_config_engine()` checks the connected role
  (`validate_platform_config_role()`) before it first returns the engine.
- `platform_config_session_scope()` is the transaction. Its only importer is
  `saas_os.core.platform_authority.transactions`
  (tests/architecture/test_platform_config_boundary.py); it is not exported by
  `saas_os.infra.db`.
- `assert_no_platform_config_credential()` is what the API and the worker run
  at startup: a long-running process that serves tenants never holds the
  credential.

Error messages name a variable, a role or a table, never a URL.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from saas_os.infra.db.config import (
    DatabaseConfig,
    DatabaseConfigurationError,
    _apply_tls_requirement,
    _require_tls_default,
)
from saas_os.infra.db.engine import build_engine
from saas_os.infra.db.role_guard import PROTECTED_TABLES, UnsafeDatabaseRoleError
from saas_os.infra.db.session import build_session_factory, session_scope
from saas_os.infra.secrets import get_secrets_provider

PLATFORM_CONFIG_URL_VARIABLE = "PLATFORM_CONFIG_DATABASE_URL"

# The complete set of table-level write privileges the role may hold
# (ADR-0056 D2). Its column-level `UPDATE` on three timestamp columns, for
# `FOR SHARE`, is refused by triggers and is not a table-level privilege.
ALLOWED_WRITES: Mapping[str, frozenset[str]] = {
    **{table: frozenset({"INSERT", "UPDATE"}) for table in PROTECTED_TABLES},
    "core.platform_audit_log": frozenset({"INSERT"}),
}

_WRITE_PRIVILEGES = ("INSERT", "UPDATE", "DELETE", "TRUNCATE")

# The URL, and the role's password as the local init script reads it
# (`02-create-platform-config-role.sh`), in either form.
_SECRET_NAMES = (PLATFORM_CONFIG_URL_VARIABLE, "PLATFORM_CONFIG_DB_PASSWORD")
_CREDENTIAL_VARIABLES = (*_SECRET_NAMES, *(f"{name}_FILE" for name in _SECRET_NAMES))


class PlatformConfigCredentialExposedError(RuntimeError):
    """The platform-configuration credential is visible to a process that
    must never hold it (the API, the worker). Names the variable only."""


def assert_no_platform_config_credential() -> None:
    """Refuse to start if `PLATFORM_CONFIG_DATABASE_URL` or
    `PLATFORM_CONFIG_DB_PASSWORD`, or either `_FILE` form, is in this
    process's environment or resolves through `SecretsProvider` (which also
    reads the development `.env` file)."""
    if any(os.environ.get(name) for name in _CREDENTIAL_VARIABLES) or any(
        get_secrets_provider().get(name) for name in _SECRET_NAMES
    ):
        raise PlatformConfigCredentialExposedError(
            "The platform-configuration credential (PLATFORM_CONFIG_DATABASE_URL or "
            "PLATFORM_CONFIG_DB_PASSWORD) is visible to this process. Only the "
            "`saas-os-operator ai-*` invocation that changes AI configuration may hold it "
            "(docs/ADR/0056-platform-configuration-database-identity.md). Refusing to start."
        )


@lru_cache
def get_platform_config_database_config() -> DatabaseConfig:
    url = get_secrets_provider().get(PLATFORM_CONFIG_URL_VARIABLE)
    if not url:
        raise DatabaseConfigurationError(
            f"{PLATFORM_CONFIG_URL_VARIABLE} is not set. AI configuration changes need the "
            "platform-configuration role "
            "(docs/ADR/0056-platform-configuration-database-identity.md)."
        )
    require_tls = _require_tls_default()
    url = _apply_tls_requirement(
        url, require_tls=require_tls, var_name=PLATFORM_CONFIG_URL_VARIABLE
    )
    # One change per command; a second connection only covers a reconnect.
    return DatabaseConfig(url=url, pool_size=1, max_overflow=1, require_tls=require_tls)


def _unsafe(reason: str) -> UnsafeDatabaseRoleError:
    return UnsafeDatabaseRoleError(
        f"{PLATFORM_CONFIG_URL_VARIABLE} does not reach a safe platform-configuration role: "
        f"{reason}. Refusing to use it."
    )


def validate_platform_config_role(engine: Engine) -> str:
    """Check, on `engine`'s own connection, that the role it authenticates
    as is a safe platform-configuration role (ADR-0056 D3); return its name.
    Fails closed: anything that cannot be established raises
    `UnsafeDatabaseRoleError`."""
    try:
        with engine.connect() as connection:
            role = connection.execute(
                text(
                    "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, "
                    "EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) "
                    "AS has_memberships "
                    "FROM pg_roles r WHERE rolname = current_user"
                )
            ).one_or_none()
            if role is None:
                raise _unsafe("no pg_roles entry for the connected role")
            if role.rolsuper or role.rolbypassrls or role.rolcreaterole:
                raise _unsafe(f"role {role.rolname!r} is a superuser, BYPASSRLS or CREATEROLE")
            if role.has_memberships:
                raise _unsafe(f"role {role.rolname!r} is a member of another role")
            owner = connection.execute(
                text(
                    "SELECT bool_or(pg_has_role(current_user, c.relowner, 'MEMBER')) "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname || '.' || c.relname = ANY(CAST(:tables AS text[]))"
                ),
                {"tables": list(PROTECTED_TABLES)},
            ).scalar_one()
            if owner:
                raise _unsafe(f"role {role.rolname!r} owns the AI configuration tables")
            writes = connection.execute(
                text(
                    "SELECT n.nspname || '.' || c.relname AS name, p.privilege "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "CROSS JOIN unnest(CAST(:privileges AS text[])) AS p(privilege) "
                    "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') "
                    "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
                    "AND n.nspname NOT LIKE 'pg\\_%' "
                    "AND has_table_privilege(c.oid, p.privilege)"
                ),
                {"privileges": list(_WRITE_PRIVILEGES)},
            ).all()
    except OperationalError as exc:
        raise _unsafe("the database was not reachable") from exc

    held: dict[str, set[str]] = {}
    for name, privilege in writes:
        held.setdefault(name, set()).add(privilege)
    for name, privileges in sorted(held.items()):
        if not privileges <= ALLOWED_WRITES.get(name, frozenset()):
            raise _unsafe(f"role {role.rolname!r} may write {name} beyond its declared privileges")
    if held.get("control_plane.ai_providers") != {"INSERT", "UPDATE"}:
        raise _unsafe(f"role {role.rolname!r} cannot write the AI configuration tables")
    return role.rolname


@lru_cache
def get_platform_config_engine() -> Engine:
    """The process's platform-configuration engine, checked before it is
    first returned. A failed check disposes it and is not cached."""
    engine = build_engine(get_platform_config_database_config())
    try:
        validate_platform_config_role(engine)
    except BaseException:
        engine.dispose()
        raise
    return engine


@lru_cache
def get_platform_config_session_factory() -> sessionmaker[Session]:
    return build_session_factory(get_platform_config_engine())


@contextmanager
def platform_config_session_scope() -> Iterator[Session]:
    """`session_scope()` on the platform-configuration connection: commit
    on success, rollback on error, always close. Never tenant-bound."""
    with session_scope(session_factory=get_platform_config_session_factory()) as session:
        yield session


def reset_platform_config_connection() -> None:
    """Dispose the cached engine and forget the configuration (tests, and a
    credential rotation inside a long-lived process)."""
    if get_platform_config_engine.cache_info().currsize:
        get_platform_config_engine().dispose()
    get_platform_config_session_factory.cache_clear()
    get_platform_config_engine.cache_clear()
    get_platform_config_database_config.cache_clear()
