"""Concurrency leases against a real Redis (ADR-0054 Phase AI-D, decision
Q12: bounded per-tenant concurrency enforced across application instances).

Pinned: acquisition up to the limit and refusal beyond it; atomicity across
scopes (a refusal in one scope takes no slot in another); release; expiry
after the TTL (a crashed holder frees its slot); a stale or repeated release
is a no-op and never frees another holder's slot; scopes are isolated;
concurrent acquisitions never exceed the limit; an unreachable Redis raises
`RateLimitBackendError` (never "acquired", never "full").

Marked `integration`; needs `REDIS_URL`.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator

import pytest
import redis.asyncio as redis

from saas_os.infra.ratelimit import (
    ConcurrencyLeases,
    Lease,
    LeaseRefusal,
    LeaseScope,
    RateLimitBackendError,
)

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
async def _require_reachable_redis() -> None:
    client = redis.Redis.from_url(_REDIS_URL)
    try:
        await client.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis not reachable at REDIS_URL: {exc}")
    finally:
        await client.aclose()


@pytest.fixture
async def leases() -> AsyncIterator[ConcurrencyLeases]:
    prefix = f"test-lease-{uuid.uuid4().hex[:8]}"
    yield ConcurrencyLeases(redis_url=_REDIS_URL, timeout_seconds=2.0, key_prefix=prefix)
    client = redis.Redis.from_url(_REDIS_URL)
    try:
        keys = [k async for k in client.scan_iter(match=f"{prefix}:*")]
        if keys:
            await client.delete(*keys)
    finally:
        await client.aclose()


async def test_slots_up_to_the_limit_then_refusal(leases: ConcurrencyLeases) -> None:
    scope = LeaseScope("tenant:a", 2)
    first = await leases.acquire([scope], ttl_seconds=30)
    second = await leases.acquire([scope], ttl_seconds=30)
    third = await leases.acquire([scope], ttl_seconds=30)
    assert isinstance(first, Lease) and isinstance(second, Lease)
    assert third == LeaseRefusal("tenant:a")
    assert await leases.held("tenant:a") == 2
    await leases.release(first)
    assert isinstance(await leases.acquire([scope], ttl_seconds=30), Lease)


async def test_a_refusal_in_one_scope_takes_no_slot_in_another(leases: ConcurrencyLeases) -> None:
    full = await leases.acquire([LeaseScope("global", 1)], ttl_seconds=30)
    assert isinstance(full, Lease)
    refused = await leases.acquire(
        [LeaseScope("tenant:b", 5), LeaseScope("global", 1)], ttl_seconds=30
    )
    assert refused == LeaseRefusal("global")
    assert await leases.held("tenant:b") == 0


async def test_scopes_are_isolated(leases: ConcurrencyLeases) -> None:
    assert isinstance(await leases.acquire([LeaseScope("tenant:c", 1)], ttl_seconds=30), Lease)
    assert isinstance(await leases.acquire([LeaseScope("tenant:d", 1)], ttl_seconds=30), Lease)
    assert await leases.acquire([LeaseScope("tenant:c", 1)], ttl_seconds=30) == LeaseRefusal(
        "tenant:c"
    )


async def test_an_expired_lease_frees_its_slot(leases: ConcurrencyLeases) -> None:
    """A holder that crashed never releases; the TTL does it."""
    scope = LeaseScope("tenant:e", 1)
    crashed = await leases.acquire([scope], ttl_seconds=0.3)
    assert isinstance(crashed, Lease)
    assert await leases.acquire([scope], ttl_seconds=30) == LeaseRefusal("tenant:e")
    await asyncio.sleep(0.5)
    assert isinstance(await leases.acquire([scope], ttl_seconds=30), Lease)


async def test_a_stale_or_repeated_release_never_frees_another_slot(
    leases: ConcurrencyLeases,
) -> None:
    scope = LeaseScope("tenant:f", 1)
    expired = await leases.acquire([scope], ttl_seconds=0.2)
    assert isinstance(expired, Lease)
    await asyncio.sleep(0.4)
    current = await leases.acquire([scope], ttl_seconds=30)
    assert isinstance(current, Lease)
    await leases.release(expired)  # stale: its member is gone
    await leases.release(expired)  # repeated
    assert await leases.held("tenant:f") == 1
    assert await leases.acquire([scope], ttl_seconds=30) == LeaseRefusal("tenant:f")
    await leases.release(current)
    assert await leases.held("tenant:f") == 0


async def test_concurrent_acquisitions_never_exceed_the_limit(leases: ConcurrencyLeases) -> None:
    scope = LeaseScope("tenant:g", 3)
    outcomes = await asyncio.gather(*(leases.acquire([scope], ttl_seconds=30) for _ in range(20)))
    assert sum(isinstance(o, Lease) for o in outcomes) == 3
    assert await leases.held("tenant:g") == 3


async def test_an_unreachable_redis_fails_closed() -> None:
    dead = ConcurrencyLeases(
        redis_url="redis://127.0.0.1:1/0", timeout_seconds=0.5, key_prefix="unreachable"
    )
    with pytest.raises(RateLimitBackendError):
        await dead.acquire([LeaseScope("tenant:h", 1)], ttl_seconds=1)
    # Release never raises: the lease expires on its own.
    await dead.release(Lease("x", ("unreachable:tenant:h",)))


@pytest.mark.parametrize(
    ("scopes", "ttl"),
    [([], 1.0), ([LeaseScope("", 1)], 1.0), ([LeaseScope("s", 0)], 1.0), ([LeaseScope("s", 1)], 0)],
)
async def test_invalid_requests_are_refused(
    leases: ConcurrencyLeases, scopes: list[LeaseScope], ttl: float
) -> None:
    with pytest.raises(ValueError):
        await leases.acquire(scopes, ttl_seconds=ttl)


async def test_the_bound_holds_across_two_application_instances(
    leases: ConcurrencyLeases,
) -> None:
    """Two instances (separate clients, same Redis) share one limit."""
    prefix = leases._prefix  # pyright: ignore[reportPrivateUsage]
    other = ConcurrencyLeases(redis_url=_REDIS_URL, timeout_seconds=2.0, key_prefix=prefix)
    scope = LeaseScope("tenant:i", 2)
    outcomes = await asyncio.gather(
        *(instance.acquire([scope], ttl_seconds=30) for instance in [leases, other] * 5)
    )
    assert sum(isinstance(o, Lease) for o in outcomes) == 2
    held = [o for o in outcomes if isinstance(o, Lease)]
    await other.release(held[0])  # released by the other instance
    assert await leases.held("tenant:i") == 1


async def test_shared_circuit_opens_for_every_instance_and_closes_on_success() -> None:
    from saas_os.infra.ratelimit import SharedCircuitBreaker

    prefix = f"test-circuit-{uuid.uuid4().hex[:8]}"
    a = SharedCircuitBreaker(
        redis_url=_REDIS_URL, timeout_seconds=2.0, key_prefix=prefix, threshold=2, open_seconds=0.5
    )
    b = SharedCircuitBreaker(
        redis_url=_REDIS_URL, timeout_seconds=2.0, key_prefix=prefix, threshold=2, open_seconds=0.5
    )
    try:
        assert await a.failure("provider") is False
        assert await b.failure("provider") is True  # counted across instances
        assert await a.is_open("provider") and await b.is_open("provider")
        assert not await a.is_open("other")
        await asyncio.sleep(0.7)
        assert not await b.is_open("provider")  # the open state expires
        await a.failure("provider")
        await b.success("provider")
        assert await a.failure("provider") is False  # the success reset the run
    finally:
        client = redis.Redis.from_url(_REDIS_URL)
        keys = [k async for k in client.scan_iter(match=f"{prefix}:*")]
        if keys:
            await client.delete(*keys)
        await client.aclose()


async def test_an_unreachable_circuit_store_reports_closed() -> None:
    from saas_os.infra.ratelimit import SharedCircuitBreaker

    dead = SharedCircuitBreaker(redis_url="redis://127.0.0.1:1/0", timeout_seconds=0.5)
    assert await dead.is_open("p") is False
    assert await dead.failure("p") is False
    await dead.success("p")
