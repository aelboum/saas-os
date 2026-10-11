"""P1.5 -- unit tests for `saas_os/infra/ratelimit`'s Redis-backend-failure
handling. A duck-typed fake Redis client (never a real connection) lets
these run in the default suite with no external dependency, exactly
`tests/infra/jobs/conftest.py`'s own `FakeRedisPool` precedent for
`saas_os/infra/jobs`.

`tests/infra/ratelimit/test_ratelimit_integration.py` covers the same
contract against a real Redis instance (including a genuine connection
failure), marked `integration`.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import cast

import pytest
import redis.asyncio as redis_asyncio
import redis.exceptions

from saas_os.infra.ratelimit.config import RateLimitConfig
from saas_os.infra.ratelimit.errors import RateLimitBackendError, RateLimitExceededError
from saas_os.infra.ratelimit.limiter import check_rate_limit, enforce_rate_limit

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


class _ScriptClient:
    """A duck-typed client exposing only what `check_rate_limit()` uses:
    `register_script()` (RE-3: the increment is one atomic script call)
    and `aclose()`. `respond(keys, args)` plays the script's single round
    trip -- returning `[count, ttl]` or raising."""

    def __init__(self, respond: Callable[[list[str], list[int]], list[int]]) -> None:
        self._respond = respond
        self.closed = False
        self.calls: list[tuple[list[str], list[int]]] = []

    def register_script(self, script: str) -> Callable[..., Awaitable[list[int]]]:
        async def _run(keys: list[str], args: list[int]) -> list[int]:
            self.calls.append((keys, args))
            return self._respond(keys, args)

        return _run

    async def aclose(self) -> None:
        self.closed = True


class _BrokenClient(_ScriptClient):
    """The script call raises a given `redis.exceptions.RedisError`
    subclass; records whether the client was closed -- proves the client
    is always cleaned up even on failure."""

    def __init__(self, exc: Exception) -> None:
        def _raise(keys: list[str], args: list[int]) -> list[int]:
            raise exc

        super().__init__(_raise)


class _HealthyClient(_ScriptClient):
    """Counts like the real script: a fresh key at 1, a 60-second TTL."""

    def __init__(self) -> None:
        self._count = 0

        def _increment(keys: list[str], args: list[int]) -> list[int]:
            self._count += 1
            return [self._count, 60]

        super().__init__(_increment)


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
    still close it even though the script call raised -- proves the cleanup
    guarantee holds on the actual code path production traffic takes,
    not only the caller-supplied-client path above."""
    import saas_os.infra.ratelimit.limiter as limiter_module

    created = _BrokenClient(redis.exceptions.ConnectionError("refused"))
    monkeypatch.setattr(limiter_module.redis.Redis, "from_url", lambda *a, **k: created)

    with pytest.raises(RateLimitBackendError):
        await check_rate_limit("k", config=_CONFIG)
    assert created.closed is True


async def test_owned_client_is_constructed_with_the_configured_redis_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CP-07 J-INFRA-01 regression: the per-call client `check_rate_limit()`
    opens for itself (`client=None`, the real production path) must always
    bound both the connect and the per-command timeout to
    `config.redis_timeout_seconds` -- previously neither was set at all,
    so a Redis instance that accepted the TCP connection but never
    answered a command hung the caller forever instead of raising
    `RateLimitBackendError` (the documented fail-closed contract)."""
    import saas_os.infra.ratelimit.limiter as limiter_module

    captured_kwargs: dict[str, object] = {}

    def _fake_from_url(url: str, **kwargs: object) -> _HealthyClient:
        captured_kwargs.update(kwargs)
        return _HealthyClient()

    monkeypatch.setattr(limiter_module.redis.Redis, "from_url", _fake_from_url)

    config = RateLimitConfig(redis_url="redis://localhost:6379/0", redis_timeout_seconds=3.5)
    await check_rate_limit("k", config=config)

    assert captured_kwargs["socket_connect_timeout"] == 3.5
    assert captured_kwargs["socket_timeout"] == 3.5


async def test_caller_supplied_client_is_unaffected_by_the_configured_timeout() -> None:
    """The timeout is only applied when the limiter opens its own client
    (`client=None`) -- a caller-supplied client's construction is entirely
    the caller's own responsibility, unchanged by this config field."""

    result = await check_rate_limit("k", config=_CONFIG, client=_as_client(_HealthyClient()))
    assert result.allowed is True


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


# --- RE-3: one atomic script call, unchanged policy ------------------------------


async def test_the_increment_is_one_script_call_on_the_unchanged_key_and_window() -> None:
    """The counter key stays `<key_prefix>:<caller key>` and the script is
    given the configured window -- exactly one round trip per check."""
    client = _HealthyClient()
    config = RateLimitConfig(redis_url="redis://x", window_seconds=45, key_prefix="ratelimit")
    await check_rate_limit("tenant-x:/v1/route", config=config, client=_as_client(client))
    assert client.calls == [(["ratelimit:tenant-x:/v1/route"], [45])]


@pytest.mark.parametrize(
    ("count", "allowed", "remaining"),
    [(1, True, 2), (3, True, 0), (4, False, 0), (40, False, 0)],
)
async def test_the_threshold_is_unchanged(count: int, allowed: bool, remaining: int) -> None:
    client = _ScriptClient(lambda keys, args: [count, 30])
    result = await check_rate_limit(
        "k",
        config=RateLimitConfig(redis_url="redis://x", requests_per_window=3),
        client=_as_client(client),
    )
    assert (result.allowed, result.remaining, result.retry_after_seconds) == (
        allowed,
        remaining,
        30,
    )


@pytest.mark.parametrize("ttl", [0, -1, -2])
async def test_retry_after_falls_back_to_the_window_without_a_positive_ttl(ttl: int) -> None:
    client = _ScriptClient(lambda keys, args: [5, ttl])
    result = await check_rate_limit(
        "k",
        config=RateLimitConfig(redis_url="redis://x", requests_per_window=3, window_seconds=60),
        client=_as_client(client),
    )
    assert result.retry_after_seconds == 60


async def test_a_script_error_fails_closed() -> None:
    """A Redis-side script failure (a `NOSCRIPT` that could not be recovered,
    or an error raised inside the script) is a backend failure, never an
    allow."""
    client = _BrokenClient(redis.exceptions.NoScriptError("NOSCRIPT No matching script."))
    with pytest.raises(RateLimitBackendError):
        await enforce_rate_limit("k", config=_CONFIG, client=_as_client(client))
