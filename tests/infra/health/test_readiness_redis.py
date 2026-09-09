"""Redis readiness check tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.5)
-- against a duck-typed fake pool, so the default suite stays independent
of a real Redis instance. Real Redis behavior is covered separately by
`test_health_integration.py` (marked `integration`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from infra.health.readiness import _check_redis
from infra.health.results import HealthStatus

if TYPE_CHECKING:
    from arq import ArqRedis
    from tests.infra.health.conftest import FakePingRedisPool

pytestmark = pytest.mark.anyio


async def test_healthy_redis_produces_a_healthy_check(
    healthy_redis_pool: FakePingRedisPool,
) -> None:
    result = await _check_redis(pool=cast("ArqRedis", healthy_redis_pool))
    assert result.name == "redis"
    assert result.status == HealthStatus.HEALTHY
    assert result.detail is None
    assert healthy_redis_pool.ping_called is True


async def test_unavailable_redis_produces_a_failed_check(
    failing_redis_pool: FakePingRedisPool,
) -> None:
    result = await _check_redis(pool=cast("ArqRedis", failing_redis_pool))
    assert result.name == "redis"
    assert result.status == HealthStatus.UNHEALTHY
    assert result.detail == "ConnectionError"


async def test_check_does_not_close_a_pool_it_did_not_open(
    healthy_redis_pool: FakePingRedisPool,
) -> None:
    await _check_redis(pool=cast("ArqRedis", healthy_redis_pool))
    assert healthy_redis_pool.closed is False


async def test_check_actually_pings_the_given_pool(healthy_redis_pool: FakePingRedisPool) -> None:
    """Non-vacuous: prove the check really calls ping() on the pool it's
    given, rather than returning a hard-coded success.
    """
    assert healthy_redis_pool.ping_called is False
    await _check_redis(pool=cast("ArqRedis", healthy_redis_pool))
    assert healthy_redis_pool.ping_called is True


async def test_no_credentials_appear_in_a_failed_redis_check(
    failing_redis_pool: FakePingRedisPool,
) -> None:
    """Fake secret-shaped Redis URL embedded in the underlying client
    exception -- confirm it never surfaces in the failed check's result
    (docs/SECURITY.md): only the exception's type name is kept.
    """
    failing_redis_pool.fail_message = "redis://:SUPER_SECRET_PASSWORD@redis:6379/0"

    result = await _check_redis(pool=cast("ArqRedis", failing_redis_pool))

    assert result.detail is not None
    assert "SUPER_SECRET_PASSWORD" not in result.detail
    assert "SUPER_SECRET_PASSWORD" not in repr(result)
    assert "SUPER_SECRET_PASSWORD" not in str(result)
