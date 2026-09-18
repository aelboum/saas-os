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

**`connect_timeout_seconds` (CP-07 J-INFRA-03)**: bounds how long
opening a *new* physical connection may take -- `pool_pre_ping` only
protects a connection already sitting in the pool (it reconnects a dead
one on checkout, but that reconnect attempt is itself a new connection
with no bound of its own). `infra/health/readiness.py`'s own DB probe
already documented and fixed this exact risk for itself ("an unreachable
host with no `connect_timeout` can hang for the OS's default TCP
timeout -- tens of seconds on Windows") but the shared application
engine every real tenant request depends on (`get_engine()`) previously
had no such bound at all. `build_engine()` threads this through
`connect_args` as `{"connect_timeout": ...}` -- psycopg's own
recognized libpq parameter -- merged under any caller-supplied
`connect_args` (never overriding an explicit caller choice, e.g.
`readiness.py`'s own tighter 2-second probe timeout).

**S-05 (BANK-SEC-01/05, `docs/ADR/0021-database-redis-transport-encryption.md`)**:
`DATABASE_URL`/`MIGRATIONS_DATABASE_URL` are both required to carry an
encrypting `sslmode` (`require` or stronger) whenever TLS is required
-- `ENVIRONMENT=production` by default, or `DB_REQUIRE_TLS` explicitly
either way. `_apply_tls_requirement()` fails closed on an explicit
downgrade (`sslmode=disable`/`allow`/`prefer`) or an unrecognized value,
and adds `sslmode=require` when none is present -- never relies on
psycopg's own implicit default (`prefer`, which silently accepts
plaintext). This establishes transport encryption only, not certificate
verification -- see that function's own docstring and the ADR for the
exact boundary and why this repository's current reference deployment
(network-isolated Postgres/Redis, no CA infrastructure) does not enable
this by default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from infra.secrets import get_secrets_provider

_DEFAULT_POOL_SIZE = 5
_DEFAULT_MAX_OVERFLOW = 10
_DEFAULT_POOL_TIMEOUT_SECONDS = 30
_DEFAULT_POOL_RECYCLE_SECONDS = 1800
_DEFAULT_POOL_PRE_PING = True
_DEFAULT_CONNECT_TIMEOUT_SECONDS = 10

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})

# S-05 (BANK-SEC-01/05): PostgreSQL's own `sslmode` values, classified by
# whether they actually require an encrypted transport. `disable` never
# encrypts; `allow`/`prefer` both *try* plaintext first (or fall back to
# it) -- neither is "encrypted", both are a silent-downgrade risk this
# phase exists to close. `require`/`verify-ca`/`verify-full` all refuse a
# plaintext connection; they differ only in certificate verification
# (out of this phase's scope -- see `_apply_tls_requirement()`'s own
# docstring), not in whether the wire is encrypted.
_WEAK_SSLMODES = frozenset({"disable", "allow", "prefer"})
_STRONG_SSLMODES = frozenset({"require", "verify-ca", "verify-full"})
_VALID_SSLMODES = _WEAK_SSLMODES | _STRONG_SSLMODES
_REQUIRED_SSLMODE_DEFAULT = "require"


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
    connect_timeout_seconds: int = _DEFAULT_CONNECT_TIMEOUT_SECONDS
    # S-05: whether `url` was required (and, if necessary, adjusted) to
    # specify an encrypting `sslmode` -- exposed for tests/introspection,
    # never itself read by `infra.db.engine.build_engine()` (which only
    # ever needs `url`, already carrying the final, enforced value).
    require_tls: bool = False

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
        if self.connect_timeout_seconds < 1:
            raise DatabaseConfigurationError(
                f"DB_CONNECT_TIMEOUT_SECONDS must be >= 1, got: {self.connect_timeout_seconds}"
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


def _require_tls_default() -> bool:
    """S-05: production requires TLS unless `DB_REQUIRE_TLS` explicitly
    overrides it -- the same "read `ENVIRONMENT` directly, independently"
    convention `infra/secrets/config.py`'s own docstring establishes and
    explains (`infra` submodules deliberately never import each other for
    this). An unset/non-`production` `ENVIRONMENT` defaults to not
    requiring TLS, preserving the existing local development/test
    workflow exactly -- this module's own `_database_config_from_env()`
    already fails closed if `ENVIRONMENT` were needed and absent
    elsewhere in the stack (`infra/secrets/config.py`'s own guard); this
    function does not re-require it, since a missing `ENVIRONMENT` here
    simply means "not known to be production," the same conservative
    default a fresh clone's `.env.example` already implies.
    """
    override = os.environ.get("DB_REQUIRE_TLS")
    if override is not None:
        return _parse_bool("DB_REQUIRE_TLS", override)
    return os.environ.get("ENVIRONMENT") == "production"


def _apply_tls_requirement(url: str, *, require_tls: bool, var_name: str) -> str:
    """S-05: enforce (or leave alone) `url`'s `sslmode`, fitting the
    distinction this phase's own directive draws -- this function
    establishes only that **transport encryption is required**
    (`sslmode=require` or stronger), never certificate verification,
    a CA bundle, or hostname verification (`verify-ca`/`verify-full`,
    which this repository's current deployment has no CA infrastructure
    to support -- documented as a residual limitation, not silently
    claimed). Never logs or includes `url` in any exception message (it
    may embed a credential, same discipline as every other error in this
    module).

    - `require_tls=False`: `url` is returned completely unchanged -- the
      existing development/test workflow (plaintext `postgres:16-alpine`
      over a Docker network, or `localhost`) is unaffected.
    - `require_tls=True` and `url` already names a strong `sslmode`
      (`require`/`verify-ca`/`verify-full`): returned unchanged --
      an operator's own, possibly stricter, explicit choice is never
      weakened.
    - `require_tls=True` and `url` names a weak `sslmode`
      (`disable`/`allow`/`prefer`) or an unrecognized value: raises
      `DatabaseConfigurationError` -- fails closed on an explicit
      downgrade attempt or a typo, rather than silently accepting
      either.
    - `require_tls=True` and `url` has no `sslmode` at all: `sslmode=require`
      is added -- the strongest explicit setting this phase's own
      directive asks for ("use the strongest appropriate explicit
      setting rather than relying on implicit driver defaults"; psycopg's
      own unstated default is `prefer`, which silently accepts
      plaintext).
    """
    if not require_tls:
        return url

    parts = urlsplit(url)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    existing_sslmode = next((value for key, value in query_pairs if key == "sslmode"), None)

    if existing_sslmode is not None:
        if existing_sslmode not in _VALID_SSLMODES:
            raise DatabaseConfigurationError(
                f"{var_name} sslmode={existing_sslmode!r} is not a recognized PostgreSQL "
                f"sslmode ({sorted(_VALID_SSLMODES)})."
            )
        if existing_sslmode in _WEAK_SSLMODES:
            raise DatabaseConfigurationError(
                f"DB_REQUIRE_TLS is enabled but {var_name}'s sslmode={existing_sslmode!r} does "
                "not require an encrypted connection -- this repository never silently "
                "downgrades a production connection to plaintext. Use sslmode=require (or "
                "stronger) or explicitly set DB_REQUIRE_TLS=false if this connection is "
                "intentionally over a trusted, isolated network."
            )
        return url

    new_query = urlencode([*query_pairs, ("sslmode", _REQUIRED_SSLMODE_DEFAULT)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _database_config_from_env() -> DatabaseConfig:
    """`DB_POOL_*` parsing lives only here -- see module docstring for why
    `_migrations_database_config_from_env()` below never reads these."""
    url = get_secrets_provider().get("DATABASE_URL")
    if not url:
        raise DatabaseConfigurationError(
            "DATABASE_URL is not set. Copy .env.example to .env and set a value "
            "(see docs/ADR/0012-secrets-management.md)."
        )
    require_tls = _require_tls_default()
    url = _apply_tls_requirement(url, require_tls=require_tls, var_name="DATABASE_URL")

    pool_size_raw = os.environ.get("DB_POOL_SIZE")
    max_overflow_raw = os.environ.get("DB_POOL_MAX_OVERFLOW")
    pool_timeout_raw = os.environ.get("DB_POOL_TIMEOUT_SECONDS")
    pool_recycle_raw = os.environ.get("DB_POOL_RECYCLE_SECONDS")
    pool_pre_ping_raw = os.environ.get("DB_POOL_PRE_PING")
    connect_timeout_raw = os.environ.get("DB_CONNECT_TIMEOUT_SECONDS")

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
        connect_timeout_seconds=(
            _parse_int("DB_CONNECT_TIMEOUT_SECONDS", connect_timeout_raw)
            if connect_timeout_raw is not None
            else _DEFAULT_CONNECT_TIMEOUT_SECONDS
        ),
        require_tls=require_tls,
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
    # S-05: the same `DB_REQUIRE_TLS` decision as `_database_config_from_env()`
    # -- the migrations role connects to the same physical PostgreSQL
    # server over the same network path as the application role, so the
    # transport-encryption requirement is identical; only the pool
    # tunables above are deliberately application-role-only (module
    # docstring).
    require_tls = _require_tls_default()
    url = _apply_tls_requirement(url, require_tls=require_tls, var_name="MIGRATIONS_DATABASE_URL")
    return DatabaseConfig(url=url, require_tls=require_tls)


@lru_cache
def get_migrations_database_config() -> DatabaseConfig:
    """Cached configuration singleton for the privileged bootstrap/
    migration connection (see module docstring) -- distinct from
    `get_database_config()`'s restricted runtime role.
    """
    return _migrations_database_config_from_env()
