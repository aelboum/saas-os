"""RA-12-7 -- `infra.jobs.dead_letter.purge_tenant_dead_letters_sync()`,
the plain synchronous bridge `core.tenancy.service.purge_tenant()`
actually calls, against a real Redis instance.

A separate file, not part of `test_dead_letter_purge_tenant_integration.py`:
this bridge's entire point is running with **no already-running asyncio
event loop** (exactly `purge_tenant()`'s own calling context), so its
tests must be plain `def`, never `async def` -- and a plain sync test
cannot use that other file's `async def` autouse fixtures (pytest has no
plugin that runs an async fixture for a sync test). This file keeps its
own reachability check synchronous instead.

Marked `integration`, excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d redis
    REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration \\
        tests/infra/jobs/test_dead_letter_purge_tenant_sync_bridge_integration.py
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from infra.jobs.config import JobsConfig
from infra.jobs.dead_letter import (
    list_dead_letters,
    purge_tenant_dead_letters_sync,
    record_dead_letter,
)
from infra.jobs.payload import TenantJobPayload
from infra.jobs.queue import get_redis_pool

pytestmark = pytest.mark.integration

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture
def jobs_config() -> JobsConfig:
    return JobsConfig(redis_url=_REDIS_URL, dead_letter_key=f"test:dl:sync:{uuid.uuid4().hex}")


@pytest.fixture(autouse=True)
def _require_reachable_redis(jobs_config: JobsConfig):
    async def _probe() -> None:
        pool = await get_redis_pool(jobs_config)
        try:
            await pool.ping()
        finally:
            await pool.aclose()

    try:
        asyncio.run(_probe())
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Redis not reachable at the configured REDIS_URL "
            f"({jobs_config.redis_url.split('@')[-1]}): {exc}. Run "
            "`docker compose up -d redis` first -- see this file's module docstring."
        )
    yield
    asyncio.run(_cleanup(jobs_config))


async def _cleanup(config: JobsConfig) -> None:
    pool = await get_redis_pool(config)
    try:
        await pool.delete(config.dead_letter_key)
    finally:
        await pool.aclose()


def _seed(config: JobsConfig, entries: list[tuple[str, str]]) -> None:
    async def _run() -> None:
        pool = await get_redis_pool(config)
        try:
            for tenant_id, error in entries:
                await record_dead_letter(
                    pool,
                    config,
                    function_name="fake_job",
                    payload=TenantJobPayload(tenant_id=tenant_id),
                    error=RuntimeError(error),
                    attempts=1,
                )
        finally:
            await pool.aclose()

    asyncio.run(_run())


def _remaining_tenant_ids(config: JobsConfig) -> list[str | None]:
    async def _run() -> list[str | None]:
        pool = await get_redis_pool(config)
        try:
            entries = await list_dead_letters(pool, config, limit=10)
            return [e.tenant_id for e in entries]
        finally:
            await pool.aclose()

    return asyncio.run(_run())


def test_sync_bridge_removes_only_the_matching_tenant(jobs_config: JobsConfig) -> None:
    """Runs with no already-running event loop -- exactly
    `purge_tenant()`'s own calling convention."""
    _seed(jobs_config, [("sync-target", "boom"), ("sync-other", "boom")])

    removed = purge_tenant_dead_letters_sync("sync-target", config=jobs_config)

    assert removed == 1
    assert _remaining_tenant_ids(jobs_config) == ["sync-other"]


def test_sync_bridge_is_idempotent(jobs_config: JobsConfig) -> None:
    _seed(jobs_config, [("sync-target", "boom")])

    first = purge_tenant_dead_letters_sync("sync-target", config=jobs_config)
    second = purge_tenant_dead_letters_sync("sync-target", config=jobs_config)

    assert first == 1
    assert second == 0
    assert _remaining_tenant_ids(jobs_config) == []
