"""Dead-letter recording tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4)."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from infra.jobs.config import JobsConfig
from infra.jobs.dead_letter import count_dead_letters, list_dead_letters, record_dead_letter
from infra.jobs.payload import TenantJobPayload

if TYPE_CHECKING:
    from arq import ArqRedis
    from tests.infra.jobs.conftest import FakeRedisPool

pytestmark = pytest.mark.anyio

_CONFIG = JobsConfig(redis_url="redis://localhost:6379/0")


async def test_record_dead_letter_increments_count(fake_redis_pool: FakeRedisPool) -> None:
    pool = cast("ArqRedis", fake_redis_pool)
    assert await count_dead_letters(pool, _CONFIG) == 0

    await record_dead_letter(
        pool,
        _CONFIG,
        function_name="fake_job",
        payload=TenantJobPayload(tenant_id="t1"),
        error=RuntimeError("boom"),
        attempts=3,
    )

    assert await count_dead_letters(pool, _CONFIG) == 1


async def test_record_dead_letter_captures_expected_fields(fake_redis_pool: FakeRedisPool) -> None:
    pool = cast("ArqRedis", fake_redis_pool)
    await record_dead_letter(
        pool,
        _CONFIG,
        function_name="fake_job",
        payload=TenantJobPayload(tenant_id="t1"),
        error=RuntimeError("boom"),
        attempts=3,
    )

    entries = await list_dead_letters(pool, _CONFIG)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.function_name == "fake_job"
    assert entry.tenant_id == "t1"
    assert entry.error == "RuntimeError: boom"
    assert entry.attempts == 3
    assert entry.dead_lettered_at > 0


async def test_record_dead_letter_with_no_tenant_payload(fake_redis_pool: FakeRedisPool) -> None:
    pool = cast("ArqRedis", fake_redis_pool)
    await record_dead_letter(
        pool,
        _CONFIG,
        function_name="platform_job",
        payload=None,
        error=RuntimeError("boom"),
        attempts=1,
    )

    entries = await list_dead_letters(pool, _CONFIG)
    assert entries[0].tenant_id is None


async def test_record_dead_letter_never_leaks_a_secret_looking_value_beyond_the_error_text(
    fake_redis_pool: FakeRedisPool,
) -> None:
    """The dead-letter entry stores only the error's own text -- confirm
    it doesn't also serialize the payload's full contents or anything
    beyond error/attempts/function/tenant.
    """
    pool = cast("ArqRedis", fake_redis_pool)
    payload = TenantJobPayload(tenant_id="t1", data={"api_key": "sk-should-never-appear"})
    await record_dead_letter(
        pool,
        _CONFIG,
        function_name="fake_job",
        payload=payload,
        error=RuntimeError("boom"),
        attempts=1,
    )

    raw = fake_redis_pool.lists[_CONFIG.dead_letter_key][0].decode("utf-8")
    assert "sk-should-never-appear" not in raw
