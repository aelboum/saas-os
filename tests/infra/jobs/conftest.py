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

    async def ltrim(self, key: str, start: int, end: int) -> bool:
        """Mirrors real Redis `LTRIM` semantics closely enough for tests
        (CP-07 J-INFRA-02: `infra.jobs.dead_letter.record_dead_letter()`
        now trims after every push): both bounds support negative
        indexing (`-1` is the last element), and an empty resulting range
        clears the list rather than raising."""
        items = self.lists.get(key, [])
        length = len(items)
        norm_start = start if start >= 0 else max(length + start, 0)
        norm_end = end if end >= 0 else length + end
        norm_end = min(norm_end, length - 1)
        self.lists[key] = items[norm_start : norm_end + 1] if norm_start <= norm_end else []
        return True

    async def eval(self, script: str, numkeys: int, *keys_and_args: str) -> int:
        """RA-12-7: a narrow, hand-written stand-in for this repository's
        one Lua script (`infra.jobs.dead_letter._PURGE_TENANT_DEAD_LETTERS_LUA`)
        -- not a general Lua interpreter (this fake has none). Mirrors
        that script's own documented contract exactly (decode each entry;
        keep anything that isn't a JSON object with a string `tenant_id`
        equal to the target; replace the list only if something actually
        matched) so unit tests can exercise the *behavior contract* fast,
        without a real Redis. The real Lua text executing correctly
        server-side is proven separately, against real Redis, by
        `tests/infra/jobs/test_dead_letter_purge_tenant_integration.py`.
        """
        import json as _json

        key = keys_and_args[0]
        tenant_id = keys_and_args[1]
        items = self.lists.get(key, [])
        survivors: list[bytes] = []
        removed = 0
        for raw in items:
            try:
                decoded = _json.loads(raw)
            except Exception:  # noqa: BLE001 -- undecodable entries are always kept
                survivors.append(raw)
                continue
            if (
                isinstance(decoded, dict)
                and isinstance(decoded.get("tenant_id"), str)
                and decoded["tenant_id"] == tenant_id
            ):
                removed += 1
            else:
                survivors.append(raw)
        if removed > 0:
            self.lists[key] = survivors
        return removed

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
