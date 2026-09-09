"""infra/health integration test against real PostgreSQL and Redis
instances (docs/IMPLEMENTATION-ROADMAP.md Phase 2.5 acceptance criteria:
"/health (or equivalent) returns correct status under both conditions").

Marked `integration` and excluded from the default `pytest` run
(pyproject.toml `[tool.pytest.ini_options] addopts`), mirroring
`tests/infra/test_db_integration.py` (Phase 2.1) and
`tests/infra/jobs/test_jobs_integration.py` (Phase 2.4).

How to run this test locally:

    docker compose up -d db redis
    DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/infra/health/test_health_integration.py

If either dependency is not reachable, the affected tests skip with a
clear message rather than failing with a raw connection traceback.

The "dependency taken down" tests don't stop a shared container (which
could interfere with other tests using the same Postgres/Redis instance)
-- they point a real `DatabaseConfig`/`JobsConfig` at a genuinely
unreachable endpoint instead, which is operationally equivalent (a real
socket-level connection failure) and safe to run in parallel with
anything else using the real, still-running services.
"""

from __future__ import annotations

import os

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from infra.db.config import DatabaseConfig
from infra.db.engine import build_engine
from infra.health.readiness import _check_database, _check_redis, check_readiness
from infra.health.results import HealthStatus
from infra.jobs.config import JobsConfig
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os"
)
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# A real, routable-but-refusing address -- fast, deterministic "down"
# simulation without touching any shared service.
_UNREACHABLE_DATABASE_URL = "postgresql+psycopg://u:p@127.0.0.1:1/nonexistent"
_UNREACHABLE_REDIS_URL = "redis://127.0.0.1:1/0"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    config = DatabaseConfig(url=_DATABASE_URL)
    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({_DATABASE_URL.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture(autouse=True)
async def _require_reachable_redis() -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(_REDIS_URL))
    except Exception as exc:  # noqa: BLE001 -- turned into a clear skip, not a failure
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    try:
        await pool.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Redis not reachable at the configured REDIS_URL "
            f"({_REDIS_URL.split('@')[-1]}): {exc}. Run `docker compose up -d redis` first "
            "-- see this file's module docstring."
        )
    finally:
        await pool.aclose()


async def test_database_check_is_healthy_against_a_real_database() -> None:
    result = _check_database(config=DatabaseConfig(url=_DATABASE_URL))
    assert result.status == HealthStatus.HEALTHY
    assert result.detail is None


async def test_database_check_is_unhealthy_against_an_unreachable_database() -> None:
    result = _check_database(config=DatabaseConfig(url=_UNREACHABLE_DATABASE_URL))
    assert result.status == HealthStatus.UNHEALTHY
    assert result.detail is not None
    assert result.detail.isidentifier()  # a bare exception type name, never a raw message/DSN
    assert _UNREACHABLE_DATABASE_URL not in result.detail


async def test_redis_check_is_healthy_against_a_real_redis() -> None:
    result = await _check_redis(config=JobsConfig(redis_url=_REDIS_URL))
    assert result.status == HealthStatus.HEALTHY
    assert result.detail is None


async def test_redis_check_is_unhealthy_against_an_unreachable_redis() -> None:
    result = await _check_redis(config=JobsConfig(redis_url=_UNREACHABLE_REDIS_URL))
    assert result.status == HealthStatus.UNHEALTHY
    assert result.detail is not None
    assert result.detail.isidentifier()  # a bare exception type name, never a raw message/DSN
    assert _UNREACHABLE_REDIS_URL not in result.detail


async def test_readiness_is_healthy_when_both_real_dependencies_are_up() -> None:
    report = await check_readiness()
    assert report.status == HealthStatus.HEALTHY
    assert all(check.status == HealthStatus.HEALTHY for check in report.checks)
