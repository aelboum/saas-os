"""Fakes for `infra/health` unit tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.5) -- keep the default suite independent of a real Redis instance,
mirroring `tests/infra/jobs/conftest.py`'s `FakeRedisPool`.
"""

from __future__ import annotations

import pytest


class FakePingRedisPool:
    def __init__(
        self, *, fail: bool = False, fail_message: str = "simulated redis failure"
    ) -> None:
        self.fail = fail
        self.fail_message = fail_message
        self.closed = False
        self.ping_called = False

    async def ping(self) -> bool:
        self.ping_called = True
        if self.fail:
            raise ConnectionError(self.fail_message)
        return True

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture
def healthy_redis_pool() -> FakePingRedisPool:
    return FakePingRedisPool(fail=False)


@pytest.fixture
def failing_redis_pool() -> FakePingRedisPool:
    return FakePingRedisPool(fail=True)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
