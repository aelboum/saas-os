"""Ledger row F5 (2026-11-01), through a real arq worker and a real Redis:
a job that runs out of time reaches SaaS OS's dead-letter list.

The second test characterizes the defect the fix addresses: when arq's own
timeout fires first, arq finishes the job with nothing in the dead-letter
list. It builds the arq function by hand with the short arq timeout and the
long handler deadline that the fix rules out for every function registered
through `saas_os.infra.jobs`.

Marked `integration`; skips with a message when Redis is not reachable.
Every test uses its own queue and dead-letter key and deletes them.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from arq.worker import func

from saas_os.infra.jobs import queue as jobs_queue
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.context import JobKind, TenantJobContext
from saas_os.infra.jobs.dead_letter import count_dead_letters, list_dead_letters
from saas_os.infra.jobs.payload import TenantJobPayload
from saas_os.infra.jobs.queue import build_worker, enqueue_job, get_redis_pool, register_tenant_job

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_TENANT = "00000000-0000-4000-8000-0000000000f5"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def jobs_config() -> AsyncIterator[JobsConfig]:
    config = JobsConfig(
        redis_url=_REDIS_URL,
        max_tries=3,
        retry_backoff_base_seconds=0.01,
        dead_letter_key=f"test:f5:dead-letter:{uuid.uuid4().hex[:8]}",
    )
    try:
        pool = await create_pool(RedisSettings.from_dsn(config.redis_url))
        await pool.ping()
    except Exception as exc:  # noqa: BLE001 -- turned into a clear skip
        pytest.skip(f"Redis not reachable for the F5 integration test: {type(exc).__name__}")
    try:
        yield config
    finally:
        await pool.delete(config.dead_letter_key)
        await pool.aclose()


async def _sleeps(context: TenantJobContext, payload: TenantJobPayload) -> None:
    await asyncio.sleep(10)


async def _run_once(worker_functions: list, config: JobsConfig) -> None:  # type: ignore[type-arg]
    queue_name = f"infra-jobs-f5-{uuid.uuid4().hex[:8]}"
    worker = build_worker(worker_functions, config=config, burst=True, queue_name=queue_name)
    try:
        pool = await get_redis_pool(config)
        try:
            await enqueue_job(
                worker_functions[0].name,
                TenantJobPayload(tenant_id=_TENANT),
                pool=pool,
                queue_name=queue_name,
            )
        finally:
            await pool.aclose()
        await worker.main()
    finally:
        await worker.close()


async def test_a_job_that_runs_out_of_time_is_dead_lettered(
    jobs_config: JobsConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jobs_queue, "HANDLER_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(jobs_queue, "ARQ_JOB_TIMEOUT_SECONDS", 3.0)
    function = register_tenant_job(_sleeps, config=jobs_config)

    await _run_once([function], jobs_config)

    pool = await get_redis_pool(jobs_config)
    try:
        assert await count_dead_letters(pool, jobs_config) == 1
        entry = (await list_dead_letters(pool, jobs_config))[0]
    finally:
        await pool.aclose()
    assert entry.function_name == "_sleeps"
    assert entry.tenant_id == _TENANT
    assert entry.attempts == 1  # not retried in the same run
    assert entry.error.startswith("TimeoutError")


async def test_characterization_arq_alone_finishes_a_timed_out_job_without_a_dead_letter(
    jobs_config: JobsConfig,
) -> None:
    """Without the wrapper's own deadline firing first, arq cancels the job
    and finishes it: nothing reaches the dead-letter list. This is the
    behaviour every registered function had before the fix."""
    wrapped = jobs_queue._with_retry_and_dead_letter(  # pyright: ignore[reportPrivateUsage]
        _sleeps, config=jobs_config, kind=JobKind.TENANT
    )
    function = func(wrapped, name="_sleeps", keep_result=0, max_tries=3, timeout=0.3)

    await _run_once([function], jobs_config)

    pool = await get_redis_pool(jobs_config)
    try:
        assert await count_dead_letters(pool, jobs_config) == 0
    finally:
        await pool.aclose()
