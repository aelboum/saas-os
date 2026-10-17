"""Bounded concurrency leases across application instances (Redis).

A *lease* holds one slot in each of several scopes at once (for example one
slot of a tenant's limit and one of an installation-wide limit). It is
acquired atomically in all scopes or in none, and it expires on its own
after `ttl_seconds`, so a crashed process never holds a slot forever.

Representation: one sorted set per scope, `<prefix>:<scope>`, whose members
are lease ids scored by their expiry time in milliseconds of the *Redis
server's* clock (`TIME`), so instances with skewed clocks agree. One Lua
script, run atomically by Redis, for each scope: removes expired members,
compares the remaining count with the limit; if every scope has room, adds
the lease id to each and extends each key's own expiry. Release removes the
lease id from each scope; releasing an expired, already-removed or unknown
lease is a no-op, and can never remove another lease (ids are random UUIDs).

Failure: any Redis error (refused, timeout, script error) raises
`RateLimitBackendError` -- never "acquired" and never "full". The caller
decides how to fail closed. A per-call client is used, as in `limiter.py`
(an asyncio transport is bound to its event loop).

Infrastructure only: scopes are opaque strings; no tenant or AI knowledge.
"""

from __future__ import annotations

import logging
import math
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

import redis.asyncio as redis
from redis.exceptions import RedisError

from saas_os.infra.ratelimit.errors import RateLimitBackendError

logger = logging.getLogger(__name__)

_NOW_MS = (
    "local now = redis.call('TIME')\n"
    "local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)\n"
)

_ACQUIRE_SCRIPT = (
    _NOW_MS
    + """
local ttl_ms = tonumber(ARGV[1])
local member = ARGV[2]
local n = #KEYS
for i = 1, n do
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now_ms)
  local limit = tonumber(ARGV[2 + i])
  if redis.call('ZCARD', KEYS[i]) >= limit then
    return {0, i}
  end
end
for i = 1, n do
  redis.call('ZADD', KEYS[i], now_ms + ttl_ms, member)
  local key_ttl = redis.call('PTTL', KEYS[i])
  if key_ttl < ttl_ms then
    redis.call('PEXPIRE', KEYS[i], ttl_ms)
  end
end
return {1, 0}
"""
)

_RELEASE_SCRIPT = """
local removed = 0
for i = 1, #KEYS do
  removed = removed + redis.call('ZREM', KEYS[i], ARGV[1])
end
return removed
"""

_HELD_SCRIPT = (
    _NOW_MS
    + """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms)
return redis.call('ZCARD', KEYS[1])
"""
)


@dataclass(frozen=True)
class LeaseScope:
    """One bounded scope: an opaque name and its limit (> 0)."""

    name: str
    limit: int


@dataclass(frozen=True)
class Lease:
    lease_id: str
    keys: tuple[str, ...]


@dataclass(frozen=True)
class LeaseRefusal:
    """No slot: `scope` is the first scope found full."""

    scope: str


class ConcurrencyLeases:
    def __init__(
        self,
        *,
        redis_url: str,
        timeout_seconds: float,
        key_prefix: str = "lease",
        client: redis.Redis | None = None,
    ) -> None:
        if not timeout_seconds > 0:
            raise ValueError("timeout_seconds must be > 0")
        self._redis_url = redis_url
        self._timeout = timeout_seconds
        self._prefix = key_prefix
        self._client = client

    def _open(self) -> tuple[redis.Redis, bool]:
        if self._client is not None:
            return self._client, False
        client = redis.Redis.from_url(
            self._redis_url,
            socket_connect_timeout=self._timeout,
            socket_timeout=self._timeout,
        )
        return client, True

    def _key(self, scope: str) -> str:
        return f"{self._prefix}:{scope}"

    async def acquire(
        self, scopes: Sequence[LeaseScope], *, ttl_seconds: float
    ) -> Lease | LeaseRefusal:
        if not scopes:
            raise ValueError("at least one scope is required")
        if any(not s.name or isinstance(s.limit, bool) or s.limit < 1 for s in scopes):
            raise ValueError("every scope needs a name and a positive limit")
        if not ttl_seconds > 0:
            raise ValueError("ttl_seconds must be > 0")
        keys = tuple(self._key(s.name) for s in scopes)
        lease_id = uuid.uuid4().hex
        ttl_ms = max(1, math.ceil(ttl_seconds * 1000))
        client, owns = self._open()
        try:
            script = client.register_script(_ACQUIRE_SCRIPT)
            acquired, index = await script(
                keys=list(keys), args=[ttl_ms, lease_id, *(s.limit for s in scopes)]
            )
        except RedisError as exc:
            logger.warning(
                "lease_backend_unavailable", extra={"lease_error_type": type(exc).__name__}
            )
            raise RateLimitBackendError("lease") from exc
        finally:
            if owns:
                await client.aclose()
        if int(acquired) == 1:
            return Lease(lease_id=lease_id, keys=keys)
        return LeaseRefusal(scope=scopes[int(index) - 1].name)

    async def release(self, lease: Lease) -> None:
        """Remove the lease from every scope. A Redis failure is logged and
        swallowed: the lease then expires on its own after its TTL."""
        client, owns = self._open()
        try:
            script = client.register_script(_RELEASE_SCRIPT)
            await script(keys=list(lease.keys), args=[lease.lease_id])
        except RedisError as exc:
            logger.warning("lease_release_failed", extra={"lease_error_type": type(exc).__name__})
        finally:
            if owns:
                await client.aclose()

    async def held(self, scope: str) -> int:
        """Live leases in `scope` (observability and tests)."""
        client, owns = self._open()
        try:
            script = client.register_script(_HELD_SCRIPT)
            return int(await script(keys=[self._key(scope)], args=[]))
        except RedisError as exc:
            raise RateLimitBackendError("lease") from exc
        finally:
            if owns:
                await client.aclose()
