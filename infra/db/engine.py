"""SQLAlchemy engine construction (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1;
connection-pool tuning added in P1.6).

One engine per process, built from `infra.db.config.DatabaseConfig` --
never constructed anywhere else (docs/MULTI-TENANCY.md section 3:
`infra/db` is the single database-access chokepoint; no other module may
obtain a raw connection). `create_engine()` itself is lazy -- constructing
an `Engine` opens no connection; the first connection happens on first use
(the pool connects lazily too).

P1.6: `config`'s `pool_size`/`max_overflow`/`pool_timeout`/`pool_recycle`/
`pool_pre_ping` fields are always passed through to `create_engine()` here
-- there is exactly one engine-construction function, so there is no
second code path that could apply a different (or no) pool policy. This
is harmless for every existing caller of `build_engine()`, including
`infra/health/readiness.py`'s short-lived reachability probe (disposed
immediately after one connection -- an idle QueuePool sized for 5
never opens more than the one connection actually used) and
`infra.db.migrations.env.py` (which does not call `build_engine()` at
all -- it constructs its own one-shot `NullPool` engine directly via
`sqlalchemy.engine_from_config()`, `infra/db/config.py`'s own docstring).

CP-07 J-INFRA-03: `config.connect_timeout_seconds` is always folded into
`connect_args` as `connect_timeout` (psycopg's own recognized libpq
parameter) -- previously only `readiness.py`'s own one-off probe passed
a `connect_timeout` explicitly, so `get_engine()`'s real, pooled,
process-wide engine (every tenant request's own connection) had no
bound on how long establishing a *new* physical connection could take.
`pool_pre_ping` does not cover this: it only reconnects a connection
already sitting in the pool once found dead, and that reconnect is
itself a fresh, otherwise-unbounded connection attempt. A caller-supplied
`connect_args` entry always wins over this default (dict unpacking order
below) -- `readiness.py`'s own tighter, purpose-specific timeout is
unaffected.
"""

from __future__ import annotations

from functools import lru_cache

from sqlalchemy import Engine, create_engine

from infra.db.config import DatabaseConfig, get_database_config


def build_engine(
    config: DatabaseConfig, *, connect_args: dict[str, object] | None = None
) -> Engine:
    """Construct a new Engine from an explicit config. Exposed for tests
    that need an engine pointed at something other than the process-wide
    `DATABASE_URL` (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1 task 10).

    `connect_args` is passed straight through to `create_engine` -- e.g. a
    short `connect_timeout` for a reachability probe, without affecting
    `get_engine()`'s real, process-wide connection behavior. Pool
    settings (P1.6) always come from `config` itself, never from a
    caller-supplied override -- one canonical source of pool policy per
    `DatabaseConfig`, matching how `connect_args` is the one caller-level
    override this function has ever exposed. `config.connect_timeout_seconds`
    (CP-07 J-INFRA-03) seeds a default `connect_timeout` entry that a
    caller-supplied `connect_args` value of the same name always overrides.

    `hide_parameters=True` (PRIV-03 Phase P14, privacy re-audit RA-10
    finding F1): SQLAlchemy otherwise renders every bound parameter of a
    failing statement into the exception's own text (`[SQL: ...]
    [parameters: {...}]`) -- a notification's subject and body, a webhook's
    plaintext signing secret, an invited e-mail address, a PKCE verifier.
    Every module already wraps such failures in typed errors that carry
    only identifiers and type names, but a traceback printed by
    `logger.exception()` (the API middleware's unhandled path, the arq
    worker's job-failure line) or recorded by `span.record_exception()`
    walks `__cause__` and prints the SQLAlchemy message underneath. With
    parameters hidden, the SQL statement is still rendered for diagnosis;
    the bound values never enter any exception text. Not configurable:
    there is no environment in which echoing customer content into logs
    is the right default.
    """
    merged_connect_args: dict[str, object] = {
        "connect_timeout": config.connect_timeout_seconds,
        **(connect_args or {}),
    }
    return create_engine(
        config.url,
        connect_args=merged_connect_args,
        pool_size=config.pool_size,
        max_overflow=config.max_overflow,
        pool_timeout=config.pool_timeout,
        pool_recycle=config.pool_recycle,
        pool_pre_ping=config.pool_pre_ping,
        hide_parameters=True,
    )


@lru_cache
def get_engine() -> Engine:
    """Cached engine singleton for the process, built from the environment
    (`infra.db.config.get_database_config`). Tests that need a different
    engine should call `get_engine.cache_clear()` after
    `infra.db.config.get_database_config.cache_clear()`."""
    return build_engine(get_database_config())
