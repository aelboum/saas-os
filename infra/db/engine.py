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
    override this function has ever exposed.
    """
    return create_engine(
        config.url,
        connect_args=connect_args or {},
        pool_size=config.pool_size,
        max_overflow=config.max_overflow,
        pool_timeout=config.pool_timeout,
        pool_recycle=config.pool_recycle,
        pool_pre_ping=config.pool_pre_ping,
    )


@lru_cache
def get_engine() -> Engine:
    """Cached engine singleton for the process, built from the environment
    (`infra.db.config.get_database_config`). Tests that need a different
    engine should call `get_engine.cache_clear()` after
    `infra.db.config.get_database_config.cache_clear()`."""
    return build_engine(get_database_config())
