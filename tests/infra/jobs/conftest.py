"""A minimal, duck-typed in-memory stand-in for `arq.ArqRedis`, used by
`infra/jobs` unit tests that exercise dead-letter recording and retry
logic without needing a real Redis instance (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.4 section 9: "avoid unnecessary external-network dependencies").
Real end-to-end behavior against a real Redis is covered separately by
`tests/infra/jobs/test_jobs_integration.py` (marked `integration`).
"""

from __future__ import annotations

import pytest


class FakeRedisPool:
    def __init__(self) -> None:
        self.lists: dict[str, list[bytes]] = {}
        self.closed = False
        self.enqueued: list[tuple[str, object]] = []
        self.next_job_id: str | None = "fake-job-id"

    async def rpush(self, key: str, value: str) -> int:
        encoded = value.encode("utf-8") if isinstance(value, str) else value
        self.lists.setdefault(key, []).append(encoded)
        return len(self.lists[key])

    async def llen(self, key: str) -> int:
        return len(self.lists.get(key, []))

    async def lrange(self, key: str, start: int, end: int) -> list[bytes]:
        items = self.lists.get(key, [])
        stop = len(items) if end == -1 else end + 1
        return items[start:stop]

    async def aclose(self) -> None:
        self.closed = True

    async def enqueue_job(self, function: str, *args: object, **kwargs: object) -> object | None:
        self.enqueued.append((function, args[0] if args else None))
        if self.next_job_id is None:
            return None
        return _FakeJob(self.next_job_id)


class _FakeJob:
    def __init__(self, job_id: str) -> None:
        self.job_id = job_id


@pytest.fixture
def fake_redis_pool() -> FakeRedisPool:
    return FakeRedisPool()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
