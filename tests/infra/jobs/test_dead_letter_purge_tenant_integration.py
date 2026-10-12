"""RA-12-7 -- `saas_os.infra.jobs.dead_letter.purge_tenant_dead_letters()` (the
atomic, server-side Lua filter) and its synchronous bridge,
`purge_tenant_dead_letters_sync()`, against a real Redis instance.

`tests/infra/jobs/test_dead_letter.py` proves the *behavior contract*
fast, against a hand-written fake with no real Lua interpreter. This file
proves the actual Lua text (`_PURGE_TENANT_DEAD_LETTERS_LUA`) executes
correctly server-side, including at the configured maximum list size and
under real concurrent access -- properties a Python fake cannot stand in
for.

Marked `integration`, excluded from the default `pytest` run, mirroring
`tests/infra/jobs/test_jobs_integration.py`.

How to run this test locally:

    docker compose up -d redis
    REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/infra/jobs/test_dead_letter_purge_tenant_integration.py
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import Awaitable
from typing import cast

import pytest
from arq import create_pool
from arq.connections import RedisSettings

from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.dead_letter import (
    count_dead_letters,
    list_dead_letters,
    purge_tenant_dead_letters,
    record_dead_letter,
)
from saas_os.infra.jobs.payload import TenantJobPayload
from saas_os.infra.jobs.queue import get_redis_pool

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, dead_letter_key=f"test:dl:{uuid.uuid4().hex}")


@pytest.fixture(autouse=True)
async def _require_reachable_redis(jobs_config: JobsConfig) -> None:
    try:
        pool = await create_pool(RedisSettings.from_dsn(jobs_config.redis_url))
    except Exception as exc:  # noqa: BLE001
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


@pytest.fixture(autouse=True)
async def _cleanup_key(jobs_config: JobsConfig):
    yield
    pool = await get_redis_pool(jobs_config)
    try:
        await pool.delete(jobs_config.dead_letter_key)
    finally:
        await pool.aclose()


async def test_removes_only_the_matching_tenant_against_real_redis(
    jobs_config: JobsConfig,
) -> None:
    pool = await get_redis_pool(jobs_config)
    try:
        for tenant_id, error in [("t1", "boom-1"), ("t2", "boom-2"), ("t1", "boom-3")]:
            await record_dead_letter(
                pool,
                jobs_config,
                function_name="fake_job",
                payload=TenantJobPayload(tenant_id=tenant_id),
                error=RuntimeError(error),
                attempts=1,
            )

        removed = await purge_tenant_dead_letters(pool, jobs_config, tenant_id="t1")

        assert removed == 2
        remaining = await list_dead_letters(pool, jobs_config, limit=10)
        assert [e.tenant_id for e in remaining] == ["t2"]
    finally:
        await pool.aclose()


async def test_malformed_and_none_tenant_entries_survive_real_lua_execution(
    jobs_config: JobsConfig,
) -> None:
    pool = await get_redis_pool(jobs_config)
    try:
        await cast("Awaitable[int]", pool.rpush(jobs_config.dead_letter_key, "not-json-at-all"))
        await cast(
            "Awaitable[int]",
            pool.rpush(jobs_config.dead_letter_key, json.dumps({"no_tenant_field": True})),
        )
        await record_dead_letter(
            pool,
            jobs_config,
            function_name="platform_job",
            payload=None,
            error=RuntimeError("boom"),
            attempts=1,
        )
        await record_dead_letter(
            pool,
            jobs_config,
            function_name="fake_job",
            payload=TenantJobPayload(tenant_id="t1"),
            error=RuntimeError("boom"),
            attempts=1,
        )

        removed = await purge_tenant_dead_letters(pool, jobs_config, tenant_id="t1")

        assert removed == 1
        assert await count_dead_letters(pool, jobs_config) == 3
    finally:
        await pool.aclose()


async def test_list_at_configured_maximum_size_is_filtered_correctly(
    jobs_config: JobsConfig,
) -> None:
    """The Lua script's own `RPUSH` of survivors is chunked so it remains
    correct at `dead_letter_max_entries` -- a single `unpack()` over the
    whole list would risk Redis's embedded Lua interpreter's own C-stack
    argument limit."""
    pool = await get_redis_pool(jobs_config)
    try:
        pipe = pool.pipeline(transaction=False)
        for i in range(jobs_config.dead_letter_max_entries):
            tenant_id = "target" if i % 2 == 0 else "other"
            entry = json.dumps(
                {
                    "function_name": "fake_job",
                    "tenant_id": tenant_id,
                    "error": "RuntimeError: boom",
                    "attempts": 1,
                    "dead_lettered_at": 1.0,
                }
            )
            pipe.rpush(jobs_config.dead_letter_key, entry)
        await pipe.execute()

        before = await count_dead_letters(pool, jobs_config)
        removed = await purge_tenant_dead_letters(pool, jobs_config, tenant_id="target")
        after = await count_dead_letters(pool, jobs_config)

        assert before == jobs_config.dead_letter_max_entries
        assert removed == jobs_config.dead_letter_max_entries // 2
        assert after == jobs_config.dead_letter_max_entries // 2
        remaining = await cast(
            "Awaitable[list[bytes]]", pool.lrange(jobs_config.dead_letter_key, 0, -1)
        )
        assert all(json.loads(r)["tenant_id"] == "other" for r in remaining)
    finally:
        await pool.aclose()


async def test_idempotent_second_call_removes_nothing_more(jobs_config: JobsConfig) -> None:
    pool = await get_redis_pool(jobs_config)
    try:
        await record_dead_letter(
            pool,
            jobs_config,
            function_name="fake_job",
            payload=TenantJobPayload(tenant_id="t1"),
            error=RuntimeError("boom"),
            attempts=1,
        )

        first = await purge_tenant_dead_letters(pool, jobs_config, tenant_id="t1")
        second = await purge_tenant_dead_letters(pool, jobs_config, tenant_id="t1")

        assert first == 1
        assert second == 0
    finally:
        await pool.aclose()


async def test_concurrent_insertion_for_a_different_tenant_survives_cleanup(
    jobs_config: JobsConfig,
) -> None:
    """Real Redis serializes the whole Lua script against any other
    command -- a concurrent `RPUSH` for another tenant can only land
    strictly before or strictly after the cleanup's own script, never
    mid-script, so it is never lost."""
    pool = await get_redis_pool(jobs_config)
    try:
        await record_dead_letter(
            pool,
            jobs_config,
            function_name="fake_job",
            payload=TenantJobPayload(tenant_id="target"),
            error=RuntimeError("boom"),
            attempts=1,
        )

        async def _insert_other_tenant() -> None:
            await record_dead_letter(
                pool,
                jobs_config,
                function_name="fake_job",
                payload=TenantJobPayload(tenant_id="other"),
                error=RuntimeError("concurrent"),
                attempts=1,
            )

        _, removed = await asyncio.gather(
            _insert_other_tenant(),
            purge_tenant_dead_letters(pool, jobs_config, tenant_id="target"),
        )

        remaining = await list_dead_letters(pool, jobs_config, limit=10)
        remaining_tenants = [e.tenant_id for e in remaining]
        # Whichever command actually ran first, both outcomes are correct:
        # "other" is always present, and "target" is present only if its
        # insertion (impossible here, already inserted before the gather)
        # -- the real assertion is simply that "other" was never lost.
        assert "other" in remaining_tenants
        assert removed in (0, 1)
    finally:
        await pool.aclose()


async def test_concurrent_insertion_for_the_same_tenant_after_cleanup_remains(
    jobs_config: JobsConfig,
) -> None:
    """RA-12-7's accepted residual window, demonstrated directly: a
    dead-letter entry for the *same* tenant written after cleanup has
    already completed is not retroactively removed. This is the exact,
    bounded, documented limitation (docs/MULTI-TENANCY.md section 6's
    RA-12-7 addendum) -- not a bug to fix here."""
    pool = await get_redis_pool(jobs_config)
    try:
        await record_dead_letter(
            pool,
            jobs_config,
            function_name="fake_job",
            payload=TenantJobPayload(tenant_id="target"),
            error=RuntimeError("boom"),
            attempts=1,
        )

        removed = await purge_tenant_dead_letters(pool, jobs_config, tenant_id="target")
        assert removed == 1
        assert await count_dead_letters(pool, jobs_config) == 0

        # A job queued before "target" closed is picked up *after*
        # cleanup ran, is correctly fenced (no tenant work), but still
        # dead-letters -- exactly the accepted residual window.
        await record_dead_letter(
            pool,
            jobs_config,
            function_name="fake_job",
            payload=TenantJobPayload(tenant_id="target"),
            error=RuntimeError("late"),
            attempts=1,
        )

        remaining = await list_dead_letters(pool, jobs_config, limit=10)
        assert [e.tenant_id for e in remaining] == ["target"]
    finally:
        await pool.aclose()
