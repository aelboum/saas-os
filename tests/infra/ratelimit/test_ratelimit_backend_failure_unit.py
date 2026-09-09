"""P1.5 -- unit tests for `infra/ratelimit`'s Redis-backend-failure
handling. A duck-typed fake Redis client (never a real connection) lets
these run in the default suite with no external dependency, exactly
`tests/infra/jobs/conftest.py`'s own `FakeRedisPool` precedent for
`infra/jobs`.

`tests/infra/ratelimit/test_ratelimit_integration.py` covers the same
contract against a real Redis instance (including a genuine connection
failure), marked `integration`.
"""

from __future__ import annotations

import logging
from typing import cast

import pytest
import redis.asyncio as redis_asyncio
import redis.exceptions
from infra.ratelimit.config import RateLimitConfig
from infra.ratelimit.errors import RateLimitBackendError, RateLimitExceededError
from infra.ratelimit.limiter import check_rate_limit, enforce_rate_limit

pytestmark = pytest.mark.anyio


def _as_client(fake: object) -> redis_asyncio.Redis:
    """Duck-typed test doubles below implement only the handful of
    methods `check_rate_limit()` actually calls -- the same
    `cast(..., fake_redis_pool)` convention `tests/infra/jobs/test_dead_letter.py`
    already uses for its own duck-typed `FakeRedisPool`."""
    return cast("redis_asyncio.Redis", fake)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _BrokenClient:
    """Raises a given `redis.exceptions.RedisError` subclass on the very
    first call the limiter makes (`INCR`), and records whether it was
    closed -- proves the client is always cleaned up even on failure."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.closed = False

    async def incr(self, key: str) -> int:
        raise self._exc

    async def expire(self, key: str, seconds: int) -> None:  # pragma: no cover -- never reached
        raise AssertionError("expire() must not be called after incr() fails")

    async def ttl(self, key: str) -> int:  # pragma: no cover -- never reached
        raise AssertionError("ttl() must not be called after incr() fails")

    async def aclose(self) -> None:
        self.closed = True


_CONFIG = RateLimitConfig(redis_url="redis://localhost:6379/0")


@pytest.mark.parametrize(
    "exc",
    [
        redis.exceptions.ConnectionError("Error 111 connecting to redis:6379. Refused."),
        redis.exceptions.TimeoutError("Timeout connecting to server."),
        redis.exceptions.ResponseError("ERR unknown command"),
        redis.exceptions.RedisError("generic redis error"),
    ],
    ids=["connection_refused", "timeout", "command_exception", "generic_redis_error"],
)
async def test_every_redis_error_class_becomes_a_rate_limit_backend_error(
    exc: Exception,
) -> None:
    client = _BrokenClient(exc)
    with pytest.raises(RateLimitBackendError) as excinfo:
        await check_rate_limit("tenant-x:/v1/route", config=_CONFIG, client=_as_client(client))
    assert excinfo.value.key == "tenant-x:/v1/route"
    assert excinfo.value.__cause__ is exc


async def test_backend_error_is_never_a_rate_limit_exceeded_error() -> None:
    """The central P1.5 distinction: a backend failure must never be
    mistaken for -- or silently converted into -- "the caller exceeded
    their limit"."""
    client = _BrokenClient(redis.exceptions.ConnectionError("refused"))
    with pytest.raises(RateLimitBackendError):
        await check_rate_limit("k", config=_CONFIG, client=_as_client(client))
    # and never raised as the sibling type either
    client2 = _BrokenClient(redis.exceptions.ConnectionError("refused"))
    try:
        await check_rate_limit("k", config=_CONFIG, client=_as_client(client2))
    except RateLimitExceededError:
        pytest.fail("a backend failure must never surface as RateLimitExceededError")
    except RateLimitBackendError:
        pass


async def test_backend_error_message_never_contains_the_underlying_exception_text() -> None:
    """The raw Redis exception can carry a host/port (or worse); the
    module docstring's own promise is that `RateLimitBackendError`'s
    message never repeats it -- only `.__cause__` (server-side-only)
    carries the original detail."""
    secret_looking_detail = (
        "Error connecting to redis-primary.internal.example:6379"  # pragma: allowlist secret
    )
    client = _BrokenClient(redis.exceptions.ConnectionError(secret_looking_detail))
    with pytest.raises(RateLimitBackendError) as excinfo:
        await check_rate_limit("k", config=_CONFIG, client=_as_client(client))
    assert secret_looking_detail not in str(excinfo.value)


async def test_caller_supplied_client_is_not_closed_by_the_limiter_on_failure() -> None:
    """A caller-supplied client's lifecycle belongs to the caller
    (`limiter.py`'s own `owns_client` distinction) -- the `finally`
    block must not close it out from under them, failure or not."""
    client = _BrokenClient(redis.exceptions.ConnectionError("refused"))
    with pytest.raises(RateLimitBackendError):
        await check_rate_limit("k", config=_CONFIG, client=_as_client(client))
    assert client.closed is False


async def test_limiter_owned_client_is_still_closed_when_backend_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the limiter creates its own client (`client=None`, the real
    per-call-pool path every real caller uses), the `finally` block must
    still close it even though `incr()` raised -- proves the cleanup
    guarantee holds on the actual code path production traffic takes,
    not only the caller-supplied-client path above."""
    import infra.ratelimit.limiter as limiter_module

    created = _BrokenClient(redis.exceptions.ConnectionError("refused"))
    monkeypatch.setattr(limiter_module.redis.Redis, "from_url", lambda *a, **k: created)

    with pytest.raises(RateLimitBackendError):
        await check_rate_limit("k", config=_CONFIG)
    assert created.closed is True


async def test_enforce_rate_limit_propagates_backend_error_unchanged() -> None:
    client = _BrokenClient(redis.exceptions.ConnectionError("refused"))
    with pytest.raises(RateLimitBackendError):
        await enforce_rate_limit("k", config=_CONFIG, client=_as_client(client))


async def test_backend_failure_logs_a_warning_with_safe_classification_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING)
    secret_looking_detail = (
        "Error connecting to redis-primary.internal.example:6379"  # pragma: allowlist secret
    )
    client = _BrokenClient(redis.exceptions.ConnectionError(secret_looking_detail))
    with pytest.raises(RateLimitBackendError):
        await check_rate_limit("k", config=_CONFIG, client=_as_client(client))

    matching = [r for r in caplog.records if r.getMessage() == "rate_limit_backend_unavailable"]
    assert matching
    record = matching[0]
    assert getattr(record, "rate_limit_error_type", None) == "ConnectionError"
    # never the raw exception text anywhere on the record
    for value in vars(record).values():
        assert secret_looking_detail not in str(value)


async def test_a_healthy_client_is_unaffected_by_this_change() -> None:
    """Regression: the success path (a client that behaves normally)
    still returns a plain `RateLimitResult`, never raises."""

    class _HealthyClient:
        def __init__(self) -> None:
            self._count = 0

        async def incr(self, key: str) -> int:
            self._count += 1
            return self._count

        async def expire(self, key: str, seconds: int) -> None:
            pass

        async def ttl(self, key: str) -> int:
            return 60

        async def aclose(self) -> None:
            pass

    result = await check_rate_limit(
        "k",
        config=RateLimitConfig(redis_url="redis://x", requests_per_window=5),
        client=_as_client(_HealthyClient()),
    )
    assert result.allowed is True
    assert result.remaining == 4


async def test_concurrent_backend_failures_are_all_consistently_fail_closed() -> None:
    """P1.5's concurrency requirement: many genuinely concurrent callers
    hitting a failing backend at once must *all* fail closed -- none may
    slip through as `allowed=True` (a race letting one request bypass
    rate limiting) and none may be misreported as `RateLimitExceededError`
    (a race falsely claiming a checked-and-denied request)."""
    import asyncio

    async def _one_call(i: int) -> Exception | None:
        client = _BrokenClient(redis.exceptions.ConnectionError(f"refused-{i}"))
        try:
            await check_rate_limit(f"key-{i}", config=_CONFIG, client=_as_client(client))
        except Exception as exc:  # noqa: BLE001 -- capturing the exact type for assertion below
            return exc
        return None

    results = await asyncio.gather(*(_one_call(i) for i in range(25)))

    assert all(exc is not None for exc in results), "every concurrent call must fail closed"
    assert all(isinstance(exc, RateLimitBackendError) for exc in results)
    assert all(not isinstance(exc, RateLimitExceededError) for exc in results)
