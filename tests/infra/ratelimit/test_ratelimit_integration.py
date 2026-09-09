"""Rate limiter integration tests against a real Redis instance
(docs/IMPLEMENTATION-ROADMAP.md Phase 8.2's own Security Requirement:
"rate limiting active on this route from day one").

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d redis
    REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/infra/ratelimit/test_ratelimit_integration.py
"""

from __future__ import annotations

import os
import uuid

import pytest
import redis.asyncio as redis
from infra.ratelimit.config import RateLimitConfig
from infra.ratelimit.errors import RateLimitExceededError
from infra.ratelimit.limiter import check_rate_limit, enforce_rate_limit

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture(autouse=True)
async def _require_reachable_redis():
    client = redis.Redis.from_url(_REDIS_URL)
    try:
        await client.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"Redis not reachable at the configured REDIS_URL ({_REDIS_URL}): {exc}. "
            "Run `docker compose up -d redis` first -- see this file's module docstring."
        )
    finally:
        await client.aclose()


def _unique_key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
async def cleanup_keys():
    created: list[str] = []
    yield created
    client = redis.Redis.from_url(_REDIS_URL)
    try:
        for key in created:
            await client.delete(f"ratelimit:{key}")
    finally:
        await client.aclose()


async def test_requests_within_limit_are_allowed(cleanup_keys: list[str]) -> None:
    key = _unique_key("within-limit")
    cleanup_keys.append(key)
    config = RateLimitConfig(redis_url=_REDIS_URL, requests_per_window=5, window_seconds=60)

    for i in range(5):
        result = await check_rate_limit(key, config=config)
        assert result.allowed is True
        assert result.remaining == 5 - (i + 1)


async def test_request_exceeding_limit_is_denied(cleanup_keys: list[str]) -> None:
    key = _unique_key("exceed-limit")
    cleanup_keys.append(key)
    config = RateLimitConfig(redis_url=_REDIS_URL, requests_per_window=3, window_seconds=60)

    for _ in range(3):
        result = await check_rate_limit(key, config=config)
        assert result.allowed is True

    result = await check_rate_limit(key, config=config)
    assert result.allowed is False
    assert result.remaining == 0
    assert result.retry_after_seconds > 0


async def test_enforce_rate_limit_raises_when_exceeded(cleanup_keys: list[str]) -> None:
    key = _unique_key("enforce-exceed")
    cleanup_keys.append(key)
    config = RateLimitConfig(redis_url=_REDIS_URL, requests_per_window=1, window_seconds=60)

    await enforce_rate_limit(key, config=config)
    with pytest.raises(RateLimitExceededError) as excinfo:
        await enforce_rate_limit(key, config=config)
    assert excinfo.value.key == key
    assert excinfo.value.retry_after_seconds > 0


async def test_window_reset_allows_requests_again(cleanup_keys: list[str]) -> None:
    """Non-vacuous proof the counter genuinely expires: a 1-second window
    is exhausted, then a real wait past that window shows the limiter
    allowing requests again -- not merely asserting the TTL was set."""
    import asyncio

    key = _unique_key("window-reset")
    cleanup_keys.append(key)
    config = RateLimitConfig(redis_url=_REDIS_URL, requests_per_window=1, window_seconds=1)

    first = await check_rate_limit(key, config=config)
    assert first.allowed is True
    second = await check_rate_limit(key, config=config)
    assert second.allowed is False

    await asyncio.sleep(1.5)

    third = await check_rate_limit(key, config=config)
    assert third.allowed is True


async def test_different_keys_are_independently_limited(cleanup_keys: list[str]) -> None:
    key_a = _unique_key("tenant-a")
    key_b = _unique_key("tenant-b")
    cleanup_keys.extend([key_a, key_b])
    config = RateLimitConfig(redis_url=_REDIS_URL, requests_per_window=1, window_seconds=60)

    result_a = await check_rate_limit(key_a, config=config)
    assert result_a.allowed is True

    # tenant B's own counter is untouched by tenant A's usage.
    result_b = await check_rate_limit(key_b, config=config)
    assert result_b.allowed is True
