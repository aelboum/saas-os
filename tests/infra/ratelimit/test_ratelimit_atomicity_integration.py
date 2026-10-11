"""RE-3 (audit finding RE-F6): the rate limiter's increment and window
expiry are one atomic Redis operation, against a real Redis.

Before RE-3, `INCR` and `EXPIRE` were separate round trips; a failure
between them left a counter with no TTL, which then rate-limited its key
forever. These tests drive the real Lua script and inspect the real key:

- a new key gets its window with its first increment, and later increments
  never extend it;
- there is no observable moment at which the counter exists without a TTL,
  even under many concurrent first requests;
- a key the old code left without a TTL is repaired by its next request;
- Redis-side errors and a flushed script cache behave correctly;
- the threshold, key format and fail-closed contract are unchanged.

Concurrency uses an `asyncio.Event` start gate (every request is released at
once); expiry is observed by polling the key, never by a fixed sleep.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Awaitable
from typing import cast

import pytest
import redis.asyncio as redis

from saas_os.infra.ratelimit.config import RateLimitConfig
from saas_os.infra.ratelimit.errors import RateLimitBackendError
from saas_os.infra.ratelimit.limiter import check_rate_limit

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def admin() -> AsyncIterator[redis.Redis]:
    client = redis.Redis.from_url(_REDIS_URL)
    try:
        await client.ping()
    except Exception as exc:  # noqa: BLE001
        await client.aclose()
        pytest.skip(f"Redis not reachable at the configured REDIS_URL: {exc}")
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
async def key(admin: redis.Redis) -> AsyncIterator[str]:
    name = f"re3-{uuid.uuid4().hex[:10]}"
    yield name
    await admin.delete(f"ratelimit:{name}")


def _config(*, requests_per_window: int = 5, window_seconds: int = 60) -> RateLimitConfig:
    return RateLimitConfig(
        redis_url=_REDIS_URL,
        requests_per_window=requests_per_window,
        window_seconds=window_seconds,
    )


async def _count(admin: redis.Redis, key: str) -> int:
    raw = await admin.get(f"ratelimit:{key}")
    assert raw is not None
    return int(raw)


async def test_the_first_increment_creates_the_window(admin: redis.Redis, key: str) -> None:
    result = await check_rate_limit(key, config=_config())

    assert result.allowed is True
    assert result.remaining == 4
    assert await _count(admin, key) == 1
    assert 0 < await admin.pttl(f"ratelimit:{key}") <= 60_000
    assert 0 < result.retry_after_seconds <= 60


async def test_later_increments_never_extend_the_window(admin: redis.Redis, key: str) -> None:
    await check_rate_limit(key, config=_config())
    # Shrink the live window to a known value; a later increment that
    # (wrongly) re-armed the expiry would push it back up to ~60 s.
    await admin.pexpire(f"ratelimit:{key}", 20_000)

    for _ in range(3):
        result = await check_rate_limit(key, config=_config())

    assert 0 < await admin.pttl(f"ratelimit:{key}") <= 20_000
    assert result.retry_after_seconds <= 20


async def test_the_threshold_is_unchanged(key: str) -> None:
    results = [await check_rate_limit(key, config=_config()) for _ in range(7)]
    assert [r.allowed for r in results] == [True] * 5 + [False] * 2
    assert [r.remaining for r in results] == [4, 3, 2, 1, 0, 0, 0]


async def test_the_window_expires_naturally_and_a_new_one_starts(
    admin: redis.Redis, key: str
) -> None:
    config = _config(requests_per_window=1)
    await check_rate_limit(key, config=config)
    assert (await check_rate_limit(key, config=config)).allowed is False

    await admin.pexpire(f"ratelimit:{key}", 1)  # end the window now
    while await admin.exists(f"ratelimit:{key}"):  # observe the expiry itself
        await asyncio.sleep(0.005)

    fresh = await check_rate_limit(key, config=config)
    assert fresh.allowed is True
    assert await _count(admin, key) == 1
    assert 0 < await admin.pttl(f"ratelimit:{key}") <= 60_000


async def test_concurrent_first_requests_initialise_exactly_one_window(
    admin: redis.Redis, key: str
) -> None:
    """Forty requests released at once against a key that does not exist
    yet, each on its own connection: every count is distinct (no lost
    increment), exactly `requests_per_window` are allowed with distinct
    `remaining` values, and the key ends with a TTL."""
    gate = asyncio.Event()
    config = _config(requests_per_window=10)

    async def _request() -> tuple[bool, int]:
        await gate.wait()
        result = await check_rate_limit(key, config=config)
        return result.allowed, result.remaining

    tasks = [asyncio.create_task(_request()) for _ in range(40)]
    await asyncio.sleep(0)  # let every task reach the gate
    gate.set()
    outcomes = await asyncio.gather(*tasks)

    assert await _count(admin, key) == 40
    assert sum(allowed for allowed, _ in outcomes) == 10
    assert sorted(remaining for allowed, remaining in outcomes if allowed) == list(range(10))
    assert 0 < await admin.pttl(f"ratelimit:{key}") <= 60_000


async def test_the_counter_is_never_observable_without_a_ttl(admin: redis.Redis, key: str) -> None:
    """Probe the key alongside concurrent first increments: whenever it
    exists, it has an expiry. With separate INCR/EXPIRE round trips the
    probe could land in the gap; with one script there is no gap."""
    redis_key = f"ratelimit:{key}"
    stop = asyncio.Event()
    seen_without_ttl = 0

    async def _probe() -> None:
        nonlocal seen_without_ttl
        while not stop.is_set():
            if await admin.pttl(redis_key) == -1:  # exists, no expiry
                seen_without_ttl += 1
            await asyncio.sleep(0)

    probe = asyncio.create_task(_probe())
    try:
        for _ in range(5):
            await admin.delete(redis_key)
            await asyncio.gather(*(check_rate_limit(key, config=_config()) for _ in range(20)))
    finally:
        stop.set()
        await probe

    assert seen_without_ttl == 0


async def test_a_counter_left_without_a_ttl_is_repaired(admin: redis.Redis, key: str) -> None:
    """The original failure: INCR succeeded, the process died before
    EXPIRE, and the counter (already over the limit) had no TTL. The next
    request gives it a fresh window instead of denying forever."""
    redis_key = f"ratelimit:{key}"
    await admin.set(redis_key, 999)
    assert await admin.pttl(redis_key) == -1

    result = await check_rate_limit(key, config=_config())

    assert result.allowed is False  # the stale count still counts in this window...
    assert 0 < await admin.pttl(redis_key) <= 60_000  # ...but the window now ends


async def test_an_error_inside_the_script_fails_closed_and_changes_nothing(
    admin: redis.Redis, key: str
) -> None:
    """A Redis-side script error (INCR on a key of the wrong type) raises
    the backend error -- never an allow -- and leaves the key untouched."""
    redis_key = f"ratelimit:{key}"
    await cast("Awaitable[int]", admin.hset(redis_key, "x", "1"))

    with pytest.raises(RateLimitBackendError):
        await check_rate_limit(key, config=_config())
    assert await admin.type(redis_key) == b"hash"
    assert await admin.pttl(redis_key) == -1


async def test_a_flushed_script_cache_is_reloaded_transparently(
    admin: redis.Redis, key: str
) -> None:
    """Redis restarted (or `SCRIPT FLUSH`): `EVALSHA` reports `NOSCRIPT`
    and the script is loaded again on the same call."""
    await check_rate_limit(key, config=_config())
    await admin.script_flush()

    result = await check_rate_limit(key, config=_config())

    assert result.remaining == 3
    assert await _count(admin, key) == 2


async def test_an_unreachable_redis_fails_closed() -> None:
    config = RateLimitConfig(redis_url="redis://127.0.0.1:1/0", redis_timeout_seconds=0.5)
    with pytest.raises(RateLimitBackendError):
        await check_rate_limit(f"re3-{uuid.uuid4().hex[:8]}", config=config)
