"""P1.6 -- database connection-pool hardening tests against a real
PostgreSQL instance (docs/IMPLEMENTATION-ROADMAP.md P1.6).

`tests/infra/test_db_engine.py` and `tests/infra/db/test_db_pool_config_unit.py`
cover configuration/engine-construction in isolation, with no database;
this file proves the pool actually *behaves* the way it is configured to
-- deterministic exhaustion/timeout, `pool_pre_ping` transparently
recovering a server-killed connection, and the migration engine's
`NullPool` staying completely unaffected -- against a real, throwaway
PostgreSQL instance (never the developer's own `saas-os-db-1`).

Marked `integration`; excluded from the default `pytest` run. Run locally
the same way as `tests/infra/test_db_integration.py` (same module
docstring's invocation).
"""

from __future__ import annotations

import threading
import time
import uuid

import pytest
from infra.db.config import DatabaseConfig, get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.role_guard import validate_application_role
from infra.db.session import build_session_factory, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as SATimeoutError
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at the configured DATABASE_URL: {exc}.")
    finally:
        probe_engine.dispose()


def _app_config(**overrides: object) -> DatabaseConfig:
    base = get_database_config()
    return DatabaseConfig(
        url=base.url,
        pool_size=overrides.get("pool_size", base.pool_size),  # type: ignore[arg-type]
        max_overflow=overrides.get("max_overflow", base.max_overflow),  # type: ignore[arg-type]
        pool_timeout=overrides.get("pool_timeout", base.pool_timeout),  # type: ignore[arg-type]
        pool_recycle=overrides.get("pool_recycle", base.pool_recycle),  # type: ignore[arg-type]
        pool_pre_ping=overrides.get("pool_pre_ping", base.pool_pre_ping),  # type: ignore[arg-type]
    )


# --- Deterministic pool exhaustion / acquisition timeout --------------------


def test_pool_exhaustion_raises_a_bounded_timeout_not_a_hang() -> None:
    """`pool_size=1`, `max_overflow=0`, a short `pool_timeout` -- this
    *always* exhausts (no race: exactly one checked-out connection is
    held for the whole test), so the second acquisition is guaranteed to
    time out, not merely likely to. Bounded and deterministic, not a
    flaky timing test (docs/IMPLEMENTATION-ROADMAP.md P1.6's own "Do NOT
    rely on flaky timing-based tests where avoidable")."""
    config = _app_config(pool_size=1, max_overflow=0, pool_timeout=1)
    engine = build_engine(config)
    try:
        held_connection = engine.connect()
        try:
            started = time.monotonic()
            with pytest.raises(SATimeoutError):
                engine.connect()
            elapsed = time.monotonic() - started
            # Bounded: raised at ~pool_timeout, never hung indefinitely.
            assert elapsed < 5
        finally:
            held_connection.close()
    finally:
        engine.dispose()


def test_pool_recovers_once_the_held_connection_is_released() -> None:
    """Not a permanent trip -- once the one connection is returned to the
    pool, a new acquisition succeeds immediately."""
    config = _app_config(pool_size=1, max_overflow=0, pool_timeout=1)
    engine = build_engine(config)
    try:
        held_connection = engine.connect()
        with pytest.raises(SATimeoutError):
            engine.connect()
        held_connection.close()

        recovered_connection = engine.connect()
        try:
            recovered_connection.execute(text("SELECT 1"))
        finally:
            recovered_connection.close()
    finally:
        engine.dispose()


def test_max_overflow_provides_real_burst_capacity_above_pool_size() -> None:
    """`pool_size=1` with `max_overflow=1` must allow exactly 2
    simultaneous connections, not 1 -- proves `max_overflow` is genuinely
    wired through, not silently ignored."""
    config = _app_config(pool_size=1, max_overflow=1, pool_timeout=2)
    engine = build_engine(config)
    try:
        first = engine.connect()
        second = engine.connect()  # the overflow connection -- must succeed
        try:
            first.execute(text("SELECT 1"))
            second.execute(text("SELECT 1"))

            # a third, beyond pool_size(1) + max_overflow(1) = 2, must be
            # bounded -- both slots are still held at this point.
            with pytest.raises(SATimeoutError):
                engine.connect()
        finally:
            first.close()
            second.close()
    finally:
        engine.dispose()


# --- pool_pre_ping actually detects and recovers from a dead connection ----


def _kill_backend(pid: int) -> None:
    """Kill a PostgreSQL backend process by pid, from a separate admin
    connection -- simulating exactly the "idle pooled connection goes
    stale" failure mode `pool_pre_ping` exists to guard against (a
    network blip, a DBA-initiated `pg_terminate_backend`, a server-side
    idle timeout). Called only *after* the connection being killed has
    already been cleanly returned to its own pool -- killing it while
    still checked out would make that connection's own graceful
    close/rollback raise, which is not the scenario being tested here."""
    admin_engine = build_engine(get_migrations_database_config())
    try:
        with admin_engine.connect() as admin_conn:
            admin_conn.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
            admin_conn.commit()
    finally:
        admin_engine.dispose()


def test_pre_ping_transparently_recovers_a_server_killed_connection() -> None:
    """The actual property `pool_pre_ping=True` exists to guarantee: a
    pooled connection that has died server-side (here, forcibly) is
    detected and silently replaced -- the caller never sees the stale
    connection's error."""
    config = _app_config(pool_size=1, max_overflow=0, pool_pre_ping=True)
    engine = build_engine(config)
    try:
        with engine.connect() as conn:
            backend_pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
        # the connection above is now idle in the pool, still alive.

        _kill_backend(backend_pid)
        time.sleep(0.5)  # give Postgres a moment to fully tear down the backend

        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar_one()
        assert result == 1
    finally:
        engine.dispose()


def test_without_pre_ping_a_server_killed_connection_surfaces_an_error() -> None:
    """Contrast case, proving the test above is non-vacuous: with
    `pool_pre_ping=False`, the exact same server-side kill *does* surface
    to the caller (SQLAlchemy has no other way to discover a dead pooled
    connection without pinging it first)."""
    config = _app_config(pool_size=1, max_overflow=0, pool_pre_ping=False)
    engine = build_engine(config)
    try:
        with engine.connect() as conn:
            backend_pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()

        _kill_backend(backend_pid)
        time.sleep(0.5)

        with pytest.raises(OperationalError):
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
    finally:
        engine.dispose()


# --- pool_recycle is genuinely active on the constructed engine ------------


def test_pool_recycle_forces_a_fresh_connection_past_its_age(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real, deterministic (not timing-flaky) proof: `pool_recycle=1`
    means any connection checked back in and re-acquired more than one
    second later is discarded and replaced -- observable as a different
    backend PID, without needing to actually kill anything server-side."""
    config = _app_config(pool_size=1, max_overflow=0, pool_recycle=1)
    engine = build_engine(config)
    try:
        with engine.connect() as conn:
            first_pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()

        time.sleep(1.5)  # older than pool_recycle=1

        with engine.connect() as conn:
            second_pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()

        assert second_pid != first_pid
    finally:
        engine.dispose()


# --- Concurrency: pool exhaustion under real concurrent load ---------------


def test_concurrent_acquisitions_beyond_capacity_all_fail_closed_deterministically() -> None:
    """Many real threads competing for a deliberately tiny pool -- proves
    the bounded-timeout behavior holds under genuine concurrency, not
    just from a single caller."""
    config = _app_config(pool_size=1, max_overflow=0, pool_timeout=1)
    engine = build_engine(config)
    results: list[str] = []
    lock = threading.Lock()

    def _hold_and_release() -> None:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                time.sleep(0.3)
            with lock:
                results.append("ok")
        except SATimeoutError:
            with lock:
                results.append("timeout")

    try:
        threads = [threading.Thread(target=_hold_and_release) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(results) == 5
        assert "ok" in results  # at least the pool's one slot succeeded
        # Every outcome is one of the two well-defined states -- never an
        # unhandled exception, never a hang (join() above would have
        # timed out this test's own thread join otherwise).
        assert set(results) <= {"ok", "timeout"}
    finally:
        engine.dispose()


# --- Migration engine separation is unaffected -------------------------------


def test_migration_style_engine_still_uses_null_pool_regardless_of_app_pool_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mirrors exactly how `infra/db/migrations/env.py` builds its own
    engine (`engine_from_config(..., poolclass=NullPool)`) -- proves that
    construction path, and `get_migrations_database_config()`'s own
    values, are completely unaffected by application `DB_POOL_*` tuning."""
    from sqlalchemy import engine_from_config

    monkeypatch.setenv("DB_POOL_SIZE", "1")
    monkeypatch.setenv("DB_POOL_PRE_PING", "false")
    get_database_config.cache_clear()
    try:
        migrations_config = get_migrations_database_config()
        connectable = engine_from_config(
            {"sqlalchemy.url": migrations_config.url},
            prefix="sqlalchemy.",
            poolclass=NullPool,
        )
        try:
            assert isinstance(connectable.pool, NullPool)
            with connectable.connect() as conn:
                result = conn.execute(text("SELECT 1")).scalar_one()
            assert result == 1
        finally:
            connectable.dispose()
    finally:
        get_database_config.cache_clear()


def test_a_real_migration_run_succeeds_unaffected_by_app_pool_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runs `alembic upgrade head` for real (idempotent -- the throwaway
    database this suite runs against is already migrated) with an
    aggressive, deliberately-hostile `DB_POOL_*` override set -- if
    migrations ever accidentally depended on the application's runtime
    pool, an absurd `DB_POOL_SIZE=1`/`pool_pre_ping=false` would be the
    value most likely to break something; it does not, because
    `infra/db/migrations/env.py` never reads these variables at all."""
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    monkeypatch.setenv("DB_POOL_SIZE", "1")
    monkeypatch.setenv("DB_POOL_MAX_OVERFLOW", "0")
    monkeypatch.setenv("DB_POOL_PRE_PING", "false")

    repo_root = Path(__file__).resolve().parents[3]
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "infra" / "db" / "migrations"))
    command.upgrade(cfg, "head")  # raises on failure; no assertion needed


# --- Existing invariants: role guard + RLS still hold on the new engine ----


def test_role_guard_still_passes_against_the_pool_hardened_engine() -> None:
    """P1.2's fail-closed startup guard must remain fully enforced against
    an engine built with the new pool settings -- pool tuning is
    orthogonal to which role the connection authenticates as."""
    config = _app_config(pool_size=2, max_overflow=3, pool_pre_ping=True)
    engine = build_engine(config)
    try:
        result = validate_application_role(engine)
        assert result.role_name == "saas_os_app"
    finally:
        engine.dispose()


def test_tenant_session_scope_still_works_normally_on_the_new_engine() -> None:
    """Smoke proof that ordinary tenant-scoped session usage -- the
    actual thing the pool serves -- is unaffected: `tenant_session_scope()`
    still runs, commits, and returns real rows through an engine built
    with explicit P1.6 pool settings."""
    config = _app_config(pool_size=2, max_overflow=2)
    engine = build_engine(config)
    try:
        factory = build_session_factory(engine)
        fake_tenant_id = uuid.uuid4()
        with tenant_session_scope(fake_tenant_id, session_factory=factory) as session:
            value = session.execute(text("SELECT 1")).scalar_one()
        assert value == 1
    finally:
        engine.dispose()
