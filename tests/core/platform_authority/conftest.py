"""Fixtures for the platform-authority integration tests (ADR-0045 Phase B).
See `platform_helpers.py` for what they provide and why every test starts
from empty platform tables. Nothing is autouse."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from platform_helpers import CLEAR, Gate, PlatformWorld
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.platform_authority.service as service_module
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine


@pytest.fixture
def admin() -> Iterator[Engine]:
    """The privileged (migrations) role: test setup, inspection and
    cleanup only. Never the role the code under test runs as."""
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
        get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL / MIGRATIONS_DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.platform_operators LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated to head: {exc}")
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def platform(admin: Engine) -> Iterator[PlatformWorld]:
    world = PlatformWorld(admin)
    world.execute(CLEAR)
    try:
        yield world
    finally:
        world.cleanup()


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str], Gate]]:
    """Install a pause gate at `record_platform_event_in_transaction()` --
    after an operation's change is flushed in its transaction, before its
    audit row and COMMIT. `install(thread_name)` returns the gate for the
    transaction running on that thread."""
    gates: list[Gate] = []
    real = service_module.record_platform_event_in_transaction

    def gated(session: Any, *args: Any, **kwargs: Any) -> Any:
        for installed in gates:
            installed.checkpoint(session)
        return real(session, *args, **kwargs)

    monkeypatch.setattr(service_module, "record_platform_event_in_transaction", gated)

    def install(thread_name: str) -> Gate:
        installed = Gate(thread_name)
        gates.append(installed)
        return installed

    yield install
    for installed in gates:
        installed.release.set()
