"""PRIV-03 Phase P10 -- no arq result record is ever stored (privacy
re-audit finding RA-06), against a real Redis.

The audit showed that arq's default `keep_result=3600` kept, for every
finished job, a pickled record of the whole call -- the complete
`TenantJobPayload` (recipient address, notification body, webhook event
data, ...) plus the return value or exception -- under an opaque, non
tenant-scoped `arq:result:<job_id>` key that nothing in this codebase
reads and that tenant purge never touches. `infra.jobs` now registers
every function and builds every worker with `keep_result=0`. These tests
assert the strong invariant directly in Redis: *no result key is created
at all* -- not a short TTL -- for a successful job, for a job that
exhausts its retries and is dead-lettered, and for a job arq itself fails
before the handler runs (worker-level path). Retry and dead-letter
behavior is asserted unchanged.

Marked `integration`, mirroring `test_jobs_integration.py`: uuid-namespaced
queue and dead-letter key, safe against a shared Redis, cleans up after
itself.

How to run this test locally:

    docker compose up -d redis
    REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/infra/jobs/test_result_retention_integration.py
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus
from infra.jobs.config import JobsConfig
from infra.jobs.dead_letter import list_dead_letters
from infra.jobs.payload import TenantJobPayload
from infra.jobs.queue import build_worker, enqueue_job, get_redis_pool, register_job

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Distinctive payload content: if any of it survives in any `arq:*` key
# after the run, the retention has not been disabled.
_MARK_EMAIL = "carol@example.com"
_MARK_BODY = "BODY-PRIVATE-CONTENT-ra06"
_MARK_SECRET = "value-that-must-not-persist-ra06"
_MARKERS = (_MARK_EMAIL, _MARK_BODY, _MARK_SECRET)

_executed: list[str] = []


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(
        redis_url=_REDIS_URL,
        max_tries=2,
        retry_backoff_base_seconds=0.01,
        dead_letter_key=f"arq:dead-letter-ra06-{uuid.uuid4().hex[:8]}",
    )


@pytest.fixture
def queue_name() -> str:
    return f"infra-jobs-ra06-{uuid.uuid4().hex[:8]}"


@pytest.fixture(autouse=True)
async def _require_reachable_redis(jobs_config: JobsConfig) -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(jobs_config.redis_url))
    except Exception as exc:  # noqa: BLE001 -- turned into a clear skip, not a failure
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    try:
        await pool.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at REDIS_URL: {exc}")
    finally:
        await pool.aclose()
    _executed.clear()


def _payload(tenant_id: str = "tenant-a") -> TenantJobPayload:
    return TenantJobPayload(
        tenant_id=tenant_id,
        data={
            "recipient_email": _MARK_EMAIL,
            "subject": "Invoice",
            "body": _MARK_BODY,
            "event_data": {"token": _MARK_SECRET},
        },
    )


async def _succeeds(payload: TenantJobPayload | None) -> dict[str, str]:
    assert payload is not None
    _executed.append(payload.tenant_id)
    return {"delivered_to": payload.data["recipient_email"]}  # a value arq would have kept


async def _always_fails(payload: TenantJobPayload | None) -> None:
    _executed.append("attempt")
    raise RuntimeError("simulated job failure")


async def _dropped_like_a_closed_tenant(payload: TenantJobPayload | None) -> None:
    """The exact shape of the RA-03 execution-time fence: a normal return
    without doing the work (`_dispatch_notification_job` and friends)."""
    _executed.append("dropped")
    return None


async def _keys_for(pool, queue_name: str, job_ids: list[str]) -> dict[str, list[str]]:
    """Every `arq:*` key that still names one of `job_ids`, grouped by job."""
    found: dict[str, list[str]] = {job_id: [] for job_id in job_ids}
    async for key in pool.scan_iter(match="arq:*"):
        name = key.decode()
        for job_id in job_ids:
            if job_id in name:
                found[job_id].append(name)
    return found


async def _payload_bytes_anywhere(pool, queue_name: str, dead_letter_key: str) -> bool:
    """Do the payload markers survive in any `arq:*` string/list key (the
    queue's own sorted set holds only job ids)?"""
    async for key in pool.scan_iter(match="arq:*"):
        kind = await pool.type(key)
        blobs: list[bytes] = []
        if kind == b"string":
            blobs.append(await pool.get(key) or b"")
        elif kind == b"list":
            blobs.extend(await pool.lrange(key, 0, -1))
        if any(marker.encode() in blob for blob in blobs for marker in _MARKERS):
            return True
    return False


async def _run_worker(functions, jobs_config: JobsConfig, queue_name: str, bursts: int) -> None:
    worker = build_worker(functions, config=jobs_config, burst=True, queue_name=queue_name)
    try:
        for index in range(bursts):
            if index:
                await asyncio.sleep(0.05)  # let a deferred retry become due
            await worker.main()
    finally:
        await worker.close()


async def _cleanup(pool, jobs_config: JobsConfig, queue_name: str, job_ids: list[str]) -> None:
    """Remove only this test's own keys (its uuid-namespaced queue and
    dead-letter key, and every per-job key of the jobs it enqueued) --
    never a blanket `arq:*` sweep, so a shared Redis is left alone."""
    await pool.delete(jobs_config.dead_letter_key, queue_name)
    for job_id in job_ids:
        await pool.delete(
            f"arq:job:{job_id}",
            f"arq:result:{job_id}",
            f"arq:retry:{job_id}",
            f"arq:in-progress:{job_id}",
        )


async def test_successful_job_leaves_no_result_record(
    jobs_config: JobsConfig, queue_name: str
) -> None:
    pool = await get_redis_pool(jobs_config)
    try:
        job_id = await enqueue_job("_succeeds", _payload(), pool=pool, queue_name=queue_name)
        # Before execution the queued job key legitimately carries the
        # payload (it is what the worker executes) -- the transient,
        # bounded queue state the docs describe.
        assert await pool.exists(f"arq:job:{job_id}") == 1
        assert await pool.ttl(f"arq:job:{job_id}") > 0

        await _run_worker([register_job(_succeeds, config=jobs_config)], jobs_config, queue_name, 1)

        assert _executed == ["tenant-a"]  # the handler ran exactly once
        assert await pool.exists(f"arq:result:{job_id}") == 0  # never created, not merely expiring
        assert await pool.exists(f"arq:job:{job_id}") == 0  # normal finish still deletes it
        assert await pool.exists(f"arq:retry:{job_id}") == 0
        assert await _keys_for(pool, queue_name, [job_id]) == {job_id: []}
        assert await Job(job_id, redis=pool, _queue_name=queue_name).status() == JobStatus.not_found
        assert not await _payload_bytes_anywhere(pool, queue_name, jobs_config.dead_letter_key)
    finally:
        await _cleanup(pool, jobs_config, queue_name, [job_id])
        await pool.aclose()


async def test_retry_then_dead_letter_leaves_no_result_record_and_dead_letter_is_unchanged(
    jobs_config: JobsConfig, queue_name: str
) -> None:
    pool = await get_redis_pool(jobs_config)
    try:
        job_id = await enqueue_job("_always_fails", _payload(), pool=pool, queue_name=queue_name)

        # max_tries=2: burst 1 = try 1 (Retry, deferred), burst 2 = try 2 (dead-letter).
        await _run_worker(
            [register_job(_always_fails, config=jobs_config)], jobs_config, queue_name, 2
        )

        assert _executed == ["attempt", "attempt"]  # retry policy untouched
        assert (
            await pool.exists(f"arq:result:{job_id}") == 0
        )  # the failure record is not kept either
        assert await _keys_for(pool, queue_name, [job_id]) == {job_id: []}
        assert await Job(job_id, redis=pool, _queue_name=queue_name).status() == JobStatus.not_found

        # The dead-letter entry is exactly what it was before this change:
        # function, tenant, attempt count, error text -- and no payload.
        entries = await list_dead_letters(pool, jobs_config)
        assert len(entries) == 1
        assert entries[0].function_name == "_always_fails"
        assert entries[0].tenant_id == "tenant-a"
        assert entries[0].attempts == 2
        assert entries[0].error == "RuntimeError: simulated job failure"
        assert (
            await pool.ttl(jobs_config.dead_letter_key) == -1
        )  # its own retention is out of scope
        assert not await _payload_bytes_anywhere(pool, queue_name, jobs_config.dead_letter_key)
    finally:
        await _cleanup(pool, jobs_config, queue_name, [job_id])
        await pool.aclose()


async def test_closed_tenant_shaped_no_op_leaves_no_result_record(
    jobs_config: JobsConfig, queue_name: str
) -> None:
    """The RA-03 drop path is a *successful* execution to arq (normal
    return, no retry, no dead-letter) -- the case the audit showed still
    wrote a full result record for an already-purged tenant. The real
    handlers against a real closed tenant are covered in
    `tests/core/test_job_result_retention_integration.py`; this pins the
    queue-level invariant for the return shape itself."""
    pool = await get_redis_pool(jobs_config)
    try:
        job_id = await enqueue_job(
            "_dropped_like_a_closed_tenant",
            _payload("purged-tenant"),
            pool=pool,
            queue_name=queue_name,
        )
        await _run_worker(
            [register_job(_dropped_like_a_closed_tenant, config=jobs_config)],
            jobs_config,
            queue_name,
            1,
        )
        assert _executed == ["dropped"]
        assert await pool.exists(f"arq:result:{job_id}") == 0
        assert await _keys_for(pool, queue_name, [job_id]) == {job_id: []}
        assert await Job(job_id, redis=pool, _queue_name=queue_name).status() == JobStatus.not_found
        assert await list_dead_letters(pool, jobs_config) == []
        assert not await _payload_bytes_anywhere(pool, queue_name, jobs_config.dead_letter_key)
    finally:
        await _cleanup(pool, jobs_config, queue_name, [job_id])
        await pool.aclose()


async def test_job_arq_fails_before_the_handler_leaves_no_result_record(
    jobs_config: JobsConfig, queue_name: str
) -> None:
    """arq's own failure path (`finish_failed_job`) never reaches the
    per-function setting: a job naming a function this worker does not
    have is failed by arq itself. The worker-level `keep_result=0` is what
    keeps that path from storing the record (which would still carry the
    full payload)."""
    pool = await get_redis_pool(jobs_config)
    try:
        job_id = await enqueue_job("_not_registered", _payload(), pool=pool, queue_name=queue_name)
        await _run_worker([register_job(_succeeds, config=jobs_config)], jobs_config, queue_name, 1)

        assert _executed == []  # nothing ran
        assert await pool.exists(f"arq:result:{job_id}") == 0
        assert await _keys_for(pool, queue_name, [job_id]) == {job_id: []}
        assert await Job(job_id, redis=pool, _queue_name=queue_name).status() == JobStatus.not_found
        assert not await _payload_bytes_anywhere(pool, queue_name, jobs_config.dead_letter_key)
    finally:
        await _cleanup(pool, jobs_config, queue_name, [job_id])
        await pool.aclose()
