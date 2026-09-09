"""infra/db engine construction tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.1)."""

from __future__ import annotations

import socket
from typing import cast

import pytest
from infra.db.config import DatabaseConfig, get_database_config
from infra.db.engine import build_engine, get_engine
from sqlalchemy import Engine
from sqlalchemy.pool import QueuePool


def test_build_engine_returns_an_engine_bound_to_the_given_url() -> None:
    engine = build_engine(DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db"))
    assert isinstance(engine, Engine)
    assert engine.url.database == "db"


def test_engine_construction_makes_no_network_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-vacuous (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1 task 17-style
    proof, matching the discipline established in earlier phases):
    SQLAlchemy's create_engine() is lazy -- constructing an Engine must
    not open a connection. Block outbound connections, then build one.
    """

    def _forbidden_connection(*args: object, **kwargs: object) -> None:
        raise AssertionError("build_engine() attempted an outbound network connection")

    monkeypatch.setattr(socket, "create_connection", _forbidden_connection)

    engine = build_engine(DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db"))
    assert isinstance(engine, Engine)


def test_get_engine_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        first = get_engine()
        second = get_engine()
        assert first is second
    finally:
        get_engine.cache_clear()
        get_database_config.cache_clear()


# --- P1.6: the engine actually receives the config's pool settings --------
# Not merely testing that DatabaseConfig holds the right constants (that's
# test_db_pool_config_unit.py's job) -- these inspect the real, constructed
# sqlalchemy.Engine's own QueuePool object, proving build_engine() actually
# wires the values through to create_engine() rather than silently dropping
# them. create_engine() is lazy (no network I/O), so this needs no database.


def _queue_pool(engine: Engine) -> QueuePool:
    """`Engine.pool` is statically typed as the base `Pool` -- the
    concrete `QueuePool` attributes these tests inspect (`.size()`, the
    otherwise-private `_max_overflow`/`_timeout`/`_recycle`/`_pre_ping`,
    for which SQLAlchemy exposes no public accessor) only exist on the
    real object every application engine actually gets
    (`test_engine_uses_a_real_bounded_queue_pool_not_an_unbounded_or_null_pool`
    below proves that non-vacuously)."""
    return cast("QueuePool", engine.pool)


def test_engine_receives_the_configured_pool_size() -> None:
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", pool_size=3)
    engine = build_engine(config)
    assert _queue_pool(engine).size() == 3


def test_engine_receives_the_configured_max_overflow() -> None:
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", max_overflow=7)
    engine = build_engine(config)
    assert _queue_pool(engine)._max_overflow == 7  # noqa: SLF001 -- no public accessor exists


def test_engine_receives_the_configured_pool_timeout() -> None:
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", pool_timeout=12)
    engine = build_engine(config)
    assert _queue_pool(engine)._timeout == 12  # noqa: SLF001


def test_engine_receives_the_configured_pool_recycle() -> None:
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", pool_recycle=900)
    engine = build_engine(config)
    assert _queue_pool(engine)._recycle == 900  # noqa: SLF001


@pytest.mark.parametrize("pre_ping", [True, False])
def test_engine_receives_the_configured_pre_ping(pre_ping: bool) -> None:
    config = DatabaseConfig(
        url="postgresql+psycopg://u:p@localhost:5432/db", pool_pre_ping=pre_ping
    )
    engine = build_engine(config)
    assert _queue_pool(engine)._pre_ping is pre_ping  # noqa: SLF001


def test_engine_uses_a_real_bounded_queue_pool_not_an_unbounded_or_null_pool() -> None:
    """Bounded pool behavior (docs/IMPLEMENTATION-ROADMAP.md P1.6): the
    application engine must use SQLAlchemy's own `QueuePool` -- never
    `NullPool` (no pooling at all -- that is deliberately what the
    *migration* engine uses, `infra/db/migrations/env.py`) and never
    something unbounded."""
    engine = build_engine(DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db"))
    assert isinstance(engine.pool, QueuePool)


def test_default_engine_matches_the_documented_production_defaults() -> None:
    """Non-vacuous end-to-end proof that the *default* `DatabaseConfig()`
    -- the one every real deployment gets when no `DB_POOL_*` override is
    set -- actually produces the exact pool this phase's own config
    docstring documents."""
    engine = build_engine(DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db"))
    pool = _queue_pool(engine)
    assert pool.size() == 5
    assert pool._max_overflow == 10  # noqa: SLF001
    assert pool._timeout == 30  # noqa: SLF001
    assert pool._recycle == 1800  # noqa: SLF001
    assert pool._pre_ping is True  # noqa: SLF001


def test_connect_args_and_pool_settings_are_independent() -> None:
    """`connect_args` (a per-call override, e.g. a short reachability-probe
    timeout) must not interfere with `config`'s own pool settings -- the
    two are orthogonal `create_engine()` keyword groups."""
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", pool_size=2)
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    assert _queue_pool(engine).size() == 2
