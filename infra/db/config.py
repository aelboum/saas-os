"""Database configuration (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1, secret
sourcing migrated to `infra/secrets` in Phase 2.3 per that phase's own
Security Requirement for this module -- see docs/ADR/0012-secrets-management.md;
connection-pool tuning added in P1.6).

`DATABASE_URL` is a credential (it commonly embeds a password), so it is
retrieved through `infra.secrets.get_secrets_provider()` -- the
provider-agnostic `SecretsProvider` abstraction -- rather than read
directly from `os.environ`. `infra/db` does not import `core.config`;
`infra/secrets` is itself `infra`, so this stays within the "Infrastructure
depends on nothing above it" rule (docs/ARCHITECTURE.md section 2).

Two distinct connection configs, since Phase 3.1's security correction
(docs/IMPLEMENTATION-ROADMAP.md, docs/MULTI-TENANCY.md section 2):
`get_database_config()` (`DATABASE_URL`) is the restricted application
runtime role's connection -- what `session_scope()`/`tenant_session_scope()`
use, and what Row-Level Security enforcement depends on being non-superuser.
`get_migrations_database_config()` (`MIGRATIONS_DATABASE_URL`) is the
separate, privileged bootstrap/migration role's connection -- used only by
Alembic (`infra/db/migrations/env.py`) and by tests that need to set up a
fixture requiring elevated privileges (e.g. a scratch table), mirroring
what a real migration does. PostgreSQL never applies Row-Level Security to
a superuser or a role with BYPASSRLS -- there is no override -- so these
two roles must never be the same one in any environment where RLS is
expected to actually protect data.

**P1.6 connection-pool fields** (`pool_size`/`max_overflow`/`pool_timeout`/
`pool_recycle`/`pool_pre_ping`): apply to the *application* runtime engine
only (`infra.db.engine.build_engine()` passes them straight to
`sqlalchemy.create_engine()`). `get_migrations_database_config()` below
deliberately never reads the `DB_POOL_*` environment variables this module
introduces -- `infra/db/migrations/env.py` builds its own one-shot engine
via `sqlalchemy.engine_from_config(..., poolclass=pool.NullPool)` and reads
only this dataclass's `.url` field, so migrations remain structurally
unaffected by application pool tuning regardless (a one-shot `alembic
upgrade` run has no use for a connection pool at all). Defaults are chosen
for this repository's actual deployment model (docs/ADR/0010-deployment-
target.md: Docker Compose + VPS, one application instance, one PostgreSQL
instance, no connection-pooling proxy like PgBouncer in front of it) --
conservative and bounded, not values picked because they are common
elsewhere:
  - `pool_size=5`, `max_overflow=10` -- SQLAlchemy's own defaults, already
    a sensible ceiling (15 connections at absolute peak) for a single
    application instance against PostgreSQL's own default
    `max_connections=100` (`docker-compose.yml`'s `db` service uses the
    stock `postgres:16-alpine` image, unmodified).
  - `pool_timeout=30` -- bounded wait for a pooled connection before
    raising, rather than blocking a request indefinitely when the pool is
    exhausted.
  - `pool_recycle=1800` (30 minutes) -- this stack has no intermediary
    (load balancer, PgBouncer) that might otherwise silently drop an
    idle connection, but a stock Postgres/Docker-network idle connection
    can still go stale over a long enough window; recycling well under any
    plausible idle-connection timeout avoids ever handing out one that has
    quietly died.
  - `pool_pre_ping=True` -- the actual fix for this phase's audit finding
    ("stale/dead connection handling"): SQLAlchemy ships this `False` by
    default; a lightweight liveness check before handing out a pooled
    connection, transparently reconnecting if it is dead, is the
    single highest-value change here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from infra.secrets import get_secrets_provider

_DEFAULT_POOL_SIZE = 5
_DEFAULT_MAX_OVERFLOW = 10
_DEFAULT_POOL_TIMEOUT_SECONDS = 30
_DEFAULT_POOL_RECYCLE_SECONDS = 1800
_DEFAULT_POOL_PRE_PING = True

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class DatabaseConfigurationError(ValueError):
    """Raised when `DATABASE_URL` is missing/malformed, or when a
    `DB_POOL_*` value is invalid. Never includes the raw `DATABASE_URL`
    value in its message -- it may contain a credential (docs/SECURITY.md:
    no secret value may appear in an exception). Pool tunables are plain
    integers/booleans, never secrets, so they may appear in these messages
    freely.
    """


@dataclass(frozen=True)
class DatabaseConfig:
    url: str
    pool_size: int = _DEFAULT_POOL_SIZE
    max_overflow: int = _DEFAULT_MAX_OVERFLOW
    pool_timeout: int = _DEFAULT_POOL_TIMEOUT_SECONDS
    pool_recycle: int = _DEFAULT_POOL_RECYCLE_SECONDS
    pool_pre_ping: bool = _DEFAULT_POOL_PRE_PING

    def __post_init__(self) -> None:
        if self.pool_size < 1:
            raise DatabaseConfigurationError(f"DB_POOL_SIZE must be >= 1, got: {self.pool_size}")
        if self.max_overflow < 0:
            raise DatabaseConfigurationError(
                f"DB_POOL_MAX_OVERFLOW must be >= 0, got: {self.max_overflow}"
            )
        if self.pool_timeout < 1:
            raise DatabaseConfigurationError(
                f"DB_POOL_TIMEOUT_SECONDS must be >= 1, got: {self.pool_timeout}"
            )
        # -1 is SQLAlchemy's own sentinel for "never recycle"; any other
        # non-positive value is nonsensical (docs/IMPLEMENTATION-ROADMAP.md
        # P1.6's own "invalid recycle values" example).
        if self.pool_recycle != -1 and self.pool_recycle < 1:
            raise DatabaseConfigurationError(
                "DB_POOL_RECYCLE_SECONDS must be >= 1, or exactly -1 to disable "
                f"recycling, got: {self.pool_recycle}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise DatabaseConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise DatabaseConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


def _database_config_from_env() -> DatabaseConfig:
    """`DB_POOL_*` parsing lives only here -- see module docstring for why
    `_migrations_database_config_from_env()` below never reads these."""
    url = get_secrets_provider().get("DATABASE_URL")
    if not url:
        raise DatabaseConfigurationError(
            "DATABASE_URL is not set. Copy .env.example to .env and set a value "
            "(see docs/ADR/0012-secrets-management.md)."
        )

    pool_size_raw = os.environ.get("DB_POOL_SIZE")
    max_overflow_raw = os.environ.get("DB_POOL_MAX_OVERFLOW")
    pool_timeout_raw = os.environ.get("DB_POOL_TIMEOUT_SECONDS")
    pool_recycle_raw = os.environ.get("DB_POOL_RECYCLE_SECONDS")
    pool_pre_ping_raw = os.environ.get("DB_POOL_PRE_PING")

    return DatabaseConfig(
        url=url,
        pool_size=(
            _parse_int("DB_POOL_SIZE", pool_size_raw)
            if pool_size_raw is not None
            else _DEFAULT_POOL_SIZE
        ),
        max_overflow=(
            _parse_int("DB_POOL_MAX_OVERFLOW", max_overflow_raw)
            if max_overflow_raw is not None
            else _DEFAULT_MAX_OVERFLOW
        ),
        pool_timeout=(
            _parse_int("DB_POOL_TIMEOUT_SECONDS", pool_timeout_raw)
            if pool_timeout_raw is not None
            else _DEFAULT_POOL_TIMEOUT_SECONDS
        ),
        pool_recycle=(
            _parse_int("DB_POOL_RECYCLE_SECONDS", pool_recycle_raw)
            if pool_recycle_raw is not None
            else _DEFAULT_POOL_RECYCLE_SECONDS
        ),
        pool_pre_ping=(
            _parse_bool("DB_POOL_PRE_PING", pool_pre_ping_raw)
            if pool_pre_ping_raw is not None
            else _DEFAULT_POOL_PRE_PING
        ),
    )


@lru_cache
def get_database_config() -> DatabaseConfig:
    """Cached configuration singleton, read once from the environment.
    Tests that need a different `DATABASE_URL` should call
    `get_database_config.cache_clear()` after `monkeypatch.setenv(...)`.
    """
    return _database_config_from_env()


def _migrations_database_config_from_env() -> DatabaseConfig:
    url = get_secrets_provider().get("MIGRATIONS_DATABASE_URL")
    if not url:
        raise DatabaseConfigurationError(
            "MIGRATIONS_DATABASE_URL is not set. Copy .env.example to .env and set a value "
            "(see docs/ADR/0012-secrets-management.md)."
        )
    return DatabaseConfig(url=url)


@lru_cache
def get_migrations_database_config() -> DatabaseConfig:
    """Cached configuration singleton for the privileged bootstrap/
    migration connection (see module docstring) -- distinct from
    `get_database_config()`'s restricted runtime role.
    """
    return _migrations_database_config_from_env()
