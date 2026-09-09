"""`enqueue_job()` tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4) --
against a fake pool, so these stay independent of a real Redis instance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from infra.jobs.errors import InvalidJobPayloadError, JobsConfigurationError
from infra.jobs.payload import TenantJobPayload
from infra.jobs.queue import enqueue_job

if TYPE_CHECKING:
    from arq import ArqRedis
    from tests.infra.jobs.conftest import FakeRedisPool

pytestmark = pytest.mark.anyio


async def test_enqueue_job_returns_the_job_id(fake_redis_pool: FakeRedisPool) -> None:
    fake_redis_pool.next_job_id = "job-123"
    job_id = await enqueue_job(
        "sample_job", TenantJobPayload(tenant_id="t1"), pool=cast("ArqRedis", fake_redis_pool)
    )
    assert job_id == "job-123"


async def test_enqueue_job_passes_the_function_name_and_payload(
    fake_redis_pool: FakeRedisPool,
) -> None:
    payload = TenantJobPayload(tenant_id="t1")
    await enqueue_job("sample_job", payload, pool=cast("ArqRedis", fake_redis_pool))
    assert fake_redis_pool.enqueued == [("sample_job", payload)]


async def test_enqueue_job_allows_no_payload_for_a_non_tenant_job(
    fake_redis_pool: FakeRedisPool,
) -> None:
    await enqueue_job("platform_job", pool=cast("ArqRedis", fake_redis_pool))
    assert fake_redis_pool.enqueued == [("platform_job", None)]


async def test_enqueue_job_raises_when_the_pool_reports_no_job(
    fake_redis_pool: FakeRedisPool,
) -> None:
    fake_redis_pool.next_job_id = None
    with pytest.raises(JobsConfigurationError):
        await enqueue_job("sample_job", pool=cast("ArqRedis", fake_redis_pool))


async def test_enqueue_job_does_not_close_a_pool_it_did_not_open(
    fake_redis_pool: FakeRedisPool,
) -> None:
    await enqueue_job("sample_job", pool=cast("ArqRedis", fake_redis_pool))
    assert fake_redis_pool.closed is False


# --- Queue-boundary tenant-payload enforcement (Phase 2.4 correction, F1) ---
#
# TenantJobPayload's own constructor already rejects a missing tenant_id
# (tests/infra/jobs/test_payload.py) -- these tests prove enqueue_job()
# itself, the queue boundary, rejects anything that isn't a TenantJobPayload
# or None, so a caller cannot bypass the schema by never constructing one.
# Each assertion on fake_redis_pool.enqueued == [] is what makes this
# non-vacuous: if the isinstance(payload, TenantJobPayload) check in
# enqueue_job() were removed, the raw dict/object below would reach the
# pool and this assertion would fail.


async def test_enqueue_job_accepts_a_real_tenant_job_payload(
    fake_redis_pool: FakeRedisPool,
) -> None:
    payload = TenantJobPayload(tenant_id="tenant-a", data={"k": "v"})
    job_id = await enqueue_job("sample_job", payload, pool=cast("ArqRedis", fake_redis_pool))
    assert job_id == fake_redis_pool.next_job_id
    assert fake_redis_pool.enqueued == [("sample_job", payload)]


async def test_enqueue_job_rejects_a_raw_dict_payload(fake_redis_pool: FakeRedisPool) -> None:
    with pytest.raises(InvalidJobPayloadError) as excinfo:
        await enqueue_job(
            "sample_job",
            {"tenant_id": "tenant-a"},  # type: ignore[arg-type]
            pool=cast("ArqRedis", fake_redis_pool),
        )
    assert excinfo.value.function_name == "sample_job"
    assert excinfo.value.payload_type is dict
    assert fake_redis_pool.enqueued == []


async def test_enqueue_job_rejects_an_arbitrary_object_payload(
    fake_redis_pool: FakeRedisPool,
) -> None:
    class _NotAPayload:
        tenant_id = "tenant-a"

    with pytest.raises(InvalidJobPayloadError):
        await enqueue_job("sample_job", _NotAPayload(), pool=cast("ArqRedis", fake_redis_pool))  # type: ignore[arg-type]
    assert fake_redis_pool.enqueued == []


async def test_enqueue_job_allows_none_payload(fake_redis_pool: FakeRedisPool) -> None:
    job_id = await enqueue_job("platform_job", None, pool=cast("ArqRedis", fake_redis_pool))
    assert job_id == fake_redis_pool.next_job_id
    assert fake_redis_pool.enqueued == [("platform_job", None)]


async def test_enqueue_job_rejects_invalid_payload_before_touching_redis(
    fake_redis_pool: FakeRedisPool,
) -> None:
    """The check happens before any pool activity -- not just before the
    enqueue call landing, but before the queue is touched at all.
    """
    with pytest.raises(InvalidJobPayloadError):
        await enqueue_job(
            "sample_job",
            ["not", "a", "payload"],  # type: ignore[arg-type]
            pool=cast("ArqRedis", fake_redis_pool),
        )
    assert fake_redis_pool.enqueued == []
    assert fake_redis_pool.closed is False


async def test_invalid_payload_error_never_includes_the_payload_contents() -> None:
    """The error message must identify the required type and the function,
    never echo the invalid payload's own data (docs/SECURITY.md)."""
    with pytest.raises(InvalidJobPayloadError) as excinfo:
        await enqueue_job(
            "sample_job",
            {"tenant_id": "tenant-a", "api_key": "sk-should-never-appear"},  # type: ignore[arg-type]
        )
    message = str(excinfo.value)
    assert "sk-should-never-appear" not in message
    assert "tenant-a" not in message
    assert "TenantJobPayload" in message
    assert "sample_job" in message
