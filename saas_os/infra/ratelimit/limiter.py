"""Redis-backed fixed-window rate limiter (docs/IMPLEMENTATION-ROADMAP.md
Phase 8.2's own Security Requirement: "rate limiting ... active on this
route from day one"; docs/API-ARCHITECTURE.md section 6: "scoped by
tenant and by API key").

Reuses the same Redis instance `saas_os/infra/jobs` already depends on (`REDIS_URL`,
resolved through `saas_os.infra.secrets` exactly like `saas_os/infra/jobs/config.py`) --
no second Redis deployment, no new external dependency (`redis` is
already a direct project dependency, `pyproject.toml`). A plain
`redis.asyncio.Redis` client is used directly here rather than routing
through `saas_os.infra.jobs.queue.get_redis_pool()` -- that function returns an
arq-flavored `ArqRedis` whose own connection lifecycle is scoped to job
enqueue/worker use; rate limiting is a distinct, simpler access pattern
(one atomic increment script) that does not need arq's job-specific wrapper.

A fresh client is opened and closed on every call -- mirrors
`saas_os.infra.jobs.queue.enqueue_job()`'s own "open a pool, use it, close it"
shape exactly (that function's own `owns_pool`/`finally: aclose()`
pattern), rather than a module-level cached client. A cached
long-lived client is tempting (avoid reconnecting on every request), but
an `asyncio` transport is bound to the event loop that created it; a
cross-event-loop reuse (each `pytest-anyio` test function gets its own
loop, and Windows' default `ProactorEventLoop` does not tolerate this at
all) breaks with a raw `RuntimeError: Event loop is closed` deep inside
the transport -- confirmed empirically while building this module's own
test suite. `saas_os/infra/jobs`'s identical per-call-pool convention already
avoids this class of bug; this module now matches it exactly instead of
being a second, differently-behaved pattern.

CP-07 J-INFRA-01: the per-call client is constructed with
`config.redis_timeout_seconds` as both `socket_connect_timeout` and
`socket_timeout` -- `redis.Redis.from_url()` otherwise leaves both at
`None` (block forever), which previously let a Redis instance that
accepts the TCP connection but never answers a command (a partial
network partition, an overloaded/wedged Redis) hang `check_rate_limit()`
indefinitely instead of raising. `redis.exceptions.TimeoutError` is
itself a `RedisError` subclass, so the existing `except RedisError`
below already turns a timeout into the same fail-closed
`RateLimitBackendError` a connection-refused gets -- no new except
branch is needed, only a bound on how long "no response" is tolerated
before that branch is reached.

Fixed-window counter, not a sliding-window/token-bucket algorithm --
the simplest correct primitive that satisfies "rate limiting active from
day one" without over-engineering a feature no acceptance criterion asks
for (a token-bucket/sliding-window refinement is a legitimate future
improvement, not required here). The first increment in a window sets the
key's expiry so the counter self-resets without a separate cleanup process.

**Atomic increment (Reliability & Events RE-3, audit finding RE-F6).** The
increment, the window's expiry and the TTL read are one Lua script
(`_INCREMENT_SCRIPT`), which Redis runs atomically -- no other command, and
no client failure, can fall between them. Previously `INCR` and `EXPIRE`
were separate round trips: a timeout, a cancelled request or a crash
between them left the key with no TTL, so its count only grew and the
tenant route (or client address) stayed rate-limited permanently. The
script also gives a fresh window to a key it finds without a TTL, so a key
the old code left behind repairs itself on its next request. Semantics are
otherwise unchanged: a whole-second window (`EXPIRE`) started by the first
request and never extended by later ones, and `retry_after` from `TTL`.

The script runs through redis-py's own `register_script()` -- `EVALSHA`,
falling back to loading the script whenever Redis reports `NOSCRIPT` (a
restarted Redis, `SCRIPT FLUSH`) -- on the same per-call client, so there is
no script state to keep in this process and nothing tied to one connection.

`check_rate_limit()` is scoped by an opaque `key` the caller constructs
(e.g. `f"{tenant_id}:{route}"`, docs/API-ARCHITECTURE.md section 6's own
"scoped by tenant" requirement) -- this module has no opinion on what a
caller scopes by; `saas_os/api/dependencies.py` is where that policy decision is
made.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import redis.asyncio as redis
from redis.exceptions import RedisError

from saas_os.infra.ratelimit.config import RateLimitConfig
from saas_os.infra.ratelimit.errors import RateLimitBackendError, RateLimitExceededError

logger = logging.getLogger(__name__)

# KEYS[1] = the counter key, ARGV[1] = the window in whole seconds.
# Returns {count, ttl_seconds}. Runs atomically inside Redis.
_INCREMENT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if count == 1 or ttl == -1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
    ttl = redis.call('TTL', KEYS[1])
end
return {count, ttl}
"""


async def _increment(client: redis.Redis, redis_key: str, window_seconds: int) -> tuple[int, int]:
    """One atomic increment: the new count and the key's remaining TTL in
    seconds (module docstring)."""
    script = client.register_script(_INCREMENT_SCRIPT)
    count, ttl = await script(keys=[redis_key], args=[window_seconds])
    return int(count), int(ttl)


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int


async def check_rate_limit(
    key: str, *, config: RateLimitConfig, client: redis.Redis | None = None
) -> RateLimitResult:
    """Increment `key`'s counter for the current fixed window and report
    whether the caller is still within `config.requests_per_window`.
    Never raises on its own to report an allow/deny decision -- returns a
    `RateLimitResult` the caller inspects; use `enforce_rate_limit()` for
    the raise-on-exceeded convenience wrapper.

    P1.5: raises `RateLimitBackendError` (never `RateLimitExceededError`,
    never a raw `redis.exceptions.RedisError`) if the Redis backend
    itself fails -- connection refused, timeout, or any other command
    error. This is a distinct outcome from "allowed" or "not allowed":
    the limit genuinely could not be evaluated, and the caller (`api/
    dependencies.py`) is responsible for choosing a fail-closed response
    rather than silently treating a backend outage as either a pass or a
    429 -- this module has no opinion on HTTP status, matching its
    existing "no opinion on what a caller scopes by" boundary."""
    owns_client = client is None
    active_client = client or redis.Redis.from_url(
        config.redis_url,
        socket_connect_timeout=config.redis_timeout_seconds,
        socket_timeout=config.redis_timeout_seconds,
    )
    redis_key = f"{config.key_prefix}:{key}"

    try:
        count, ttl = await _increment(active_client, redis_key, config.window_seconds)
        retry_after = ttl if ttl > 0 else config.window_seconds
    except RedisError as exc:
        # Exception *type name* only -- never the underlying message,
        # which can embed a host/port or other connection detail
        # (saas_os/infra/health's own established precedent). request_id (P1.4)
        # is attached automatically by the already-configured structured
        # logger, no coupling to `api` needed here.
        logger.warning(
            "rate_limit_backend_unavailable",
            extra={"rate_limit_error_type": type(exc).__name__},
        )
        raise RateLimitBackendError(key) from exc
    finally:
        if owns_client:
            await active_client.aclose()

    if count > config.requests_per_window:
        return RateLimitResult(allowed=False, remaining=0, retry_after_seconds=retry_after)

    return RateLimitResult(
        allowed=True,
        remaining=config.requests_per_window - count,
        retry_after_seconds=retry_after,
    )


async def peek_rate_limit(
    key: str, *, config: RateLimitConfig, client: redis.Redis | None = None
) -> RateLimitResult:
    """`key`'s standing in the current window *without* counting a
    request: `allowed` is false once the window's count has reached
    `config.requests_per_window`. For a limit that counts only some
    outcomes (failed authentications) but must be checked before every
    attempt. Fails like `check_rate_limit()`: `RateLimitBackendError` when
    Redis cannot answer."""
    owns_client = client is None
    active_client = client or redis.Redis.from_url(
        config.redis_url,
        socket_connect_timeout=config.redis_timeout_seconds,
        socket_timeout=config.redis_timeout_seconds,
    )
    redis_key = f"{config.key_prefix}:{key}"
    try:
        # One round trip: the count and its window's remaining time.
        async with active_client.pipeline(transaction=False) as pipe:
            pipe.get(redis_key)
            pipe.ttl(redis_key)
            raw_count, raw_ttl = await pipe.execute()
        ttl = int(raw_ttl) if raw_count is not None else -2
    except RedisError as exc:
        logger.warning(
            "rate_limit_backend_unavailable",
            extra={"rate_limit_error_type": type(exc).__name__},
        )
        raise RateLimitBackendError(key) from exc
    finally:
        if owns_client:
            await active_client.aclose()
    count = int(raw_count) if raw_count is not None else 0
    retry_after = ttl if ttl > 0 else config.window_seconds
    if count >= config.requests_per_window:
        return RateLimitResult(allowed=False, remaining=0, retry_after_seconds=retry_after)
    return RateLimitResult(
        allowed=True,
        remaining=config.requests_per_window - count,
        retry_after_seconds=retry_after,
    )


async def enforce_rate_limit(
    key: str, *, config: RateLimitConfig, client: redis.Redis | None = None
) -> RateLimitResult:
    """Like `check_rate_limit()`, but raises `RateLimitExceededError`
    instead of returning `allowed=False` -- the convenience form
    `saas_os/api/dependencies.py`'s ingress dependency uses."""
    result = await check_rate_limit(key, config=config, client=client)
    if not result.allowed:
        raise RateLimitExceededError(key, result.retry_after_seconds)
    return result
