"""infra/jobs integration test against a real Redis instance
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.4 acceptance criteria: "sample job
completes; sample failing job retries per policy then dead-letters").

Marked `integration` and excluded from the default `pytest` run
(pyproject.toml `[tool.pytest.ini_options] addopts`) -- the normal
validation pipeline must not depend on an external Redis being available,
mirroring `tests/infra/test_db_integration.py` (Phase 2.1).

How to run this test locally:

    docker compose up -d redis
    REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/infra/jobs/test_jobs_integration.py

If Redis is not reachable, the test skips with a clear message rather than
failing with a raw connection traceback.

Every test uses a uuid-namespaced arq queue name and dead-letter key
(never the default queue/key), so this is safe to run against a Redis
instance shared with unrelated data -- and cleans its own keys up
afterward.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job
from infra.jobs.config import JobsConfig
from infra.jobs.dead_letter import count_dead_letters, list_dead_letters
from infra.jobs.payload import TenantJobPayload
from infra.jobs.queue import build_worker, enqueue_job, get_redis_pool, register_job

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture
def jobs_config() -> JobsConfig:
    # Fast retries (0.01s base) and a small max_tries so this test doesn't
    # spend real wall-clock time waiting out backoff.
    return JobsConfig(redis_url=_REDIS_URL, max_tries=2, retry_backoff_base_seconds=0.01)


@pytest.fixture
def queue_name() -> str:
    return f"infra-jobs-phase24-{uuid.uuid4().hex[:8]}"


@pytest.fixture(autouse=True)
async def _require_reachable_redis(jobs_config: JobsConfig) -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(jobs_config.redis_url))
    except Exception as exc:  # noqa: BLE001 -- turned into a clear skip, not a failure
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    try:
        await pool.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Redis not reachable at the configured REDIS_URL "
            f"({jobs_config.redis_url.split('@')[-1]}): {exc}. Run "
            "`docker compose up -d redis` first -- see this file's module docstring."
        )
    finally:
        await pool.aclose()


async def _succeeds(payload: TenantJobPayload | None) -> str:
    return "ok"


async def _always_fails(payload: TenantJobPayload | None) -> None:
    raise RuntimeError("simulated job failure")


async def test_sample_job_enqueues_executes_and_completes(
    jobs_config: JobsConfig, queue_name: str
) -> None:
    functions = [register_job(_succeeds, config=jobs_config)]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        pool = await get_redis_pool(jobs_config)
        try:
            job_id = await enqueue_job(
                "_succeeds",
                TenantJobPayload(tenant_id="t1"),
                pool=pool,
                queue_name=queue_name,
            )
        finally:
            await pool.aclose()

        await worker.main()

        result_pool = await get_redis_pool(jobs_config)
        try:
            job = Job(job_id, redis=result_pool, _queue_name=queue_name)
            result = await job.result(timeout=5, poll_delay=0.05)
        finally:
            await result_pool.aclose()

        assert result == "ok"
    finally:
        await worker.close()


async def test_sample_failing_job_retries_then_dead_letters(
    jobs_config: JobsConfig, queue_name: str
) -> None:
    functions = [register_job(_always_fails, config=jobs_config)]
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        pool = await get_redis_pool(jobs_config)
        try:
            assert await count_dead_letters(pool, jobs_config) == 0
            await enqueue_job(
                "_always_fails",
                TenantJobPayload(tenant_id="t1"),
                pool=pool,
                queue_name=queue_name,
            )
        finally:
            await pool.aclose()

        # max_tries=2: burst run 1 executes try 1 (raises Retry, deferred
        # briefly), burst run 2 executes try 2 (final attempt -> dead-letters).
        await worker.main()
        await asyncio.sleep(0.05)
        await worker.main()

        verify_pool = await get_redis_pool(jobs_config)
        try:
            assert await count_dead_letters(verify_pool, jobs_config) == 1
            entries = await list_dead_letters(verify_pool, jobs_config)
            assert entries[0].function_name == "_always_fails"
            assert entries[0].tenant_id == "t1"
            assert entries[0].attempts == 2
            assert "simulated job failure" in entries[0].error
        finally:
            await verify_pool.delete(jobs_config.dead_letter_key)
            await verify_pool.aclose()
    finally:
        await worker.close()
