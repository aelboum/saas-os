"""Redis-backed fixed-window rate limiter (docs/IMPLEMENTATION-ROADMAP.md
Phase 8.2's own Security Requirement: "rate limiting ... active on this
route from day one"; docs/API-ARCHITECTURE.md section 6: "scoped by
tenant and by API key").

Reuses the same Redis instance `infra/jobs` already depends on (`REDIS_URL`,
resolved through `infra.secrets` exactly like `infra/jobs/config.py`) --
no second Redis deployment, no new external dependency (`redis` is
already a direct project dependency, `pyproject.toml`). A plain
`redis.asyncio.Redis` client is used directly here rather than routing
through `infra.jobs.queue.get_redis_pool()` -- that function returns an
arq-flavored `ArqRedis` whose own connection lifecycle is scoped to job
enqueue/worker use; rate limiting is a distinct, simpler access pattern
(`INCR`/`EXPIRE` only) that does not need arq's job-specific wrapper.

A fresh client is opened and closed on every call -- mirrors
`infra.jobs.queue.enqueue_job()`'s own "open a pool, use it, close it"
shape exactly (that function's own `owns_pool`/`finally: aclose()`
pattern), rather than a module-level cached client. A cached
long-lived client is tempting (avoid reconnecting on every request), but
an `asyncio` transport is bound to the event loop that created it; a
cross-event-loop reuse (each `pytest-anyio` test function gets its own
loop, and Windows' default `ProactorEventLoop` does not tolerate this at
all) breaks with a raw `RuntimeError: Event loop is closed` deep inside
the transport -- confirmed empirically while building this module's own
test suite. `infra/jobs`'s identical per-call-pool convention already
avoids this class of bug; this module now matches it exactly instead of
being a second, differently-behaved pattern.

Fixed-window counter, not a sliding-window/token-bucket algorithm --
the simplest correct primitive that satisfies "rate limiting active from
day one" without over-engineering a feature no acceptance criterion asks
for (a token-bucket/sliding-window refinement is a legitimate future
improvement, not required here). `INCR` on a Redis key is atomic; the
first increment in a window sets the key's expiry so the counter
self-resets without a separate cleanup process.

`check_rate_limit()` is scoped by an opaque `key` the caller constructs
(e.g. `f"{tenant_id}:{route}"`, docs/API-ARCHITECTURE.md section 6's own
"scoped by tenant" requirement) -- this module has no opinion on what a
caller scopes by; `api/dependencies.py` is where that policy decision is
made.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import redis.asyncio as redis
from redis.exceptions import RedisError

from infra.ratelimit.config import RateLimitConfig
from infra.ratelimit.errors import RateLimitBackendError, RateLimitExceededError

logger = logging.getLogger(__name__)


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
    active_client = client or redis.Redis.from_url(config.redis_url)
    redis_key = f"{config.key_prefix}:{key}"

    try:
        count = await active_client.incr(redis_key)
        if count == 1:
            await active_client.expire(redis_key, config.window_seconds)

        ttl = await active_client.ttl(redis_key)
        retry_after = ttl if ttl and ttl > 0 else config.window_seconds
    except RedisError as exc:
        # Exception *type name* only -- never the underlying message,
        # which can embed a host/port or other connection detail
        # (infra/health's own established precedent). request_id (P1.4)
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


async def enforce_rate_limit(
    key: str, *, config: RateLimitConfig, client: redis.Redis | None = None
) -> RateLimitResult:
    """Like `check_rate_limit()`, but raises `RateLimitExceededError`
    instead of returning `allowed=False` -- the convenience form
    `api/dependencies.py`'s ingress dependency uses."""
    result = await check_rate_limit(key, config=config, client=client)
    if not result.allowed:
        raise RateLimitExceededError(key, result.retry_after_seconds)
    return result
