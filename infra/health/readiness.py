"""Readiness aggregation (docs/IMPLEMENTATION-ROADMAP.md Phase 2.5,
docs/DEPLOYMENT-ARCHITECTURE.md section 7: "infra/health owns the generic
liveness/readiness endpoint mechanism and dependency-health aggregation
(DB reachable, queue reachable, etc.)").

Reuses `infra/db`'s and `infra/jobs`'s own sanctioned connection
primitives -- `infra.db.engine.build_engine` and
`infra.jobs.queue.get_redis_pool` -- rather than opening a second
connection mechanism. Configuration (including `REDIS_URL`/`DATABASE_URL`,
sourced through `infra.secrets`) is reused from `infra/db` and
`infra/jobs` unchanged; nothing here reads a secret or builds a connection
string itself.

A short `connect_timeout` is applied to the database probe specifically:
`infra/db`'s own Phase 2.1 integration test already documented that an
unreachable host with no `connect_timeout` can hang for the OS's default
TCP timeout (tens of seconds on Windows) -- exactly the failure mode a
readiness check must not have. Redis's client already applies a bounded
default connect timeout/retry policy
(`arq.connections.RedisSettings`'s `conn_timeout`/`conn_retries`
defaults), so no additional timeout is added there -- reusing existing
bounded behavior rather than inventing a second one.
"""

from __future__ import annotations

import asyncio
import logging

from arq import ArqRedis
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from infra.db.config import DatabaseConfig, DatabaseConfigurationError, get_database_config
from infra.db.engine import build_engine
from infra.health.results import CheckResult, HealthStatus, ReadinessReport
from infra.jobs.config import JobsConfig
from infra.jobs.queue import get_redis_pool

logger = logging.getLogger(__name__)

_DB_CHECK_CONNECT_TIMEOUT_SECONDS = 2


def _check_database(
    *, engine: Engine | None = None, config: DatabaseConfig | None = None
) -> CheckResult:
    """Smallest meaningful DB connectivity check: `SELECT 1` through a
    real connection. `engine`/`config` are override hooks for tests only
    -- the real path always builds from `get_database_config()`.
    """
    owns_engine = engine is None
    active_engine: Engine | None = None
    try:
        active_engine = engine or build_engine(
            config or get_database_config(),
            connect_args={"connect_timeout": _DB_CHECK_CONNECT_TIMEOUT_SECONDS},
        )
        with active_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return CheckResult(name="database", status=HealthStatus.HEALTHY)
    except (DatabaseConfigurationError, SQLAlchemyError, OSError) as exc:
        logger.warning("database readiness check failed: %s", type(exc).__name__)
        return CheckResult(
            name="database", status=HealthStatus.UNHEALTHY, detail=type(exc).__name__
        )
    finally:
        if owns_engine and active_engine is not None:
            active_engine.dispose()


async def _check_redis(
    *, pool: ArqRedis | None = None, config: JobsConfig | None = None
) -> CheckResult:
    """Smallest meaningful Redis connectivity check: `PING`. `pool`/
    `config` are override hooks for tests only -- the real path always
    builds from `get_jobs_config()`.
    """
    owns_pool = pool is None
    active_pool: ArqRedis | None = None
    try:
        active_pool = pool or await get_redis_pool(config)
        await active_pool.ping()
        return CheckResult(name="redis", status=HealthStatus.HEALTHY)
    except Exception as exc:  # noqa: BLE001 -- any connection/config failure becomes a
        # failed check, never an uncaught exception through the health API (section 11).
        logger.warning("redis readiness check failed: %s", type(exc).__name__)
        return CheckResult(name="redis", status=HealthStatus.UNHEALTHY, detail=type(exc).__name__)
    finally:
        if owns_pool and active_pool is not None:
            await active_pool.aclose()


async def check_readiness() -> ReadinessReport:
    """Aggregate DB + Redis reachability (docs/DEPLOYMENT-ARCHITECTURE.md
    section 7). Overall status is healthy only if every check is healthy;
    one dependency being down never crashes the aggregator or silently
    reports success for the others.
    """
    db_result, redis_result = await asyncio.gather(
        asyncio.to_thread(_check_database), _check_redis()
    )
    checks = (db_result, redis_result)
    overall = (
        HealthStatus.HEALTHY
        if all(check.status == HealthStatus.HEALTHY for check in checks)
        else HealthStatus.UNHEALTHY
    )
    return ReadinessReport(status=overall, checks=checks)
