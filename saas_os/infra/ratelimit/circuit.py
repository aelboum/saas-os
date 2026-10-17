"""A circuit breaker shared by all application instances (Redis).

Per named circuit: consecutive failures are counted in `<prefix>:<name>:failures`
(a counter that expires `window_seconds` after the first failure of a run);
when the count reaches `threshold`, `<prefix>:<name>:open` is set for
`open_seconds` and the counter is cleared. A success clears both. One Lua
script per transition, so instances never race between "count" and "open".

A circuit protects a dependency from load; it is not a security control.
When Redis cannot be reached, `is_open` reports the circuit closed (and
logs it) and failures and successes are not recorded: the request path has
already been admitted, and refusing because the breaker is unreadable would
turn a Redis outage into a provider outage.

Infrastructure only: names are opaque strings.
"""

from __future__ import annotations

import logging
import math

import redis.asyncio as redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

_FAILURE_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
end
if count >= tonumber(ARGV[1]) then
  redis.call('SET', KEYS[2], '1', 'PX', tonumber(ARGV[3]))
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
"""


class SharedCircuitBreaker:
    def __init__(
        self,
        *,
        redis_url: str,
        timeout_seconds: float,
        key_prefix: str = "circuit",
        threshold: int = 5,
        window_seconds: float = 60.0,
        open_seconds: float = 30.0,
        client: redis.Redis | None = None,
    ) -> None:
        if threshold < 1 or not window_seconds > 0 or not open_seconds > 0:
            raise ValueError("threshold, window_seconds and open_seconds must be positive")
        if not timeout_seconds > 0:
            raise ValueError("timeout_seconds must be > 0")
        self._redis_url = redis_url
        self._timeout = timeout_seconds
        self._prefix = key_prefix
        self._threshold = threshold
        self._window_ms = max(1, math.ceil(window_seconds * 1000))
        self._open_ms = max(1, math.ceil(open_seconds * 1000))
        self._client = client

    def _open_client(self) -> tuple[redis.Redis, bool]:
        if self._client is not None:
            return self._client, False
        return (
            redis.Redis.from_url(
                self._redis_url,
                socket_connect_timeout=self._timeout,
                socket_timeout=self._timeout,
            ),
            True,
        )

    def _keys(self, name: str) -> tuple[str, str]:
        return f"{self._prefix}:{name}:failures", f"{self._prefix}:{name}:open"

    async def is_open(self, name: str) -> bool:
        client, owns = self._open_client()
        try:
            return bool(await client.exists(self._keys(name)[1]))
        except RedisError as exc:
            logger.warning(
                "circuit_backend_unavailable", extra={"circuit_error_type": type(exc).__name__}
            )
            return False
        finally:
            if owns:
                await client.aclose()

    async def failure(self, name: str) -> bool:
        """Record a failure; True when this failure opened the circuit."""
        client, owns = self._open_client()
        try:
            script = client.register_script(_FAILURE_SCRIPT)
            opened = await script(
                keys=list(self._keys(name)), args=[self._threshold, self._window_ms, self._open_ms]
            )
        except RedisError as exc:
            logger.warning(
                "circuit_backend_unavailable", extra={"circuit_error_type": type(exc).__name__}
            )
            return False
        finally:
            if owns:
                await client.aclose()
        if int(opened) == 1:
            logger.warning("circuit_open", extra={"circuit_name": name})
            return True
        return False

    async def success(self, name: str) -> None:
        client, owns = self._open_client()
        try:
            await client.delete(*self._keys(name))
        except RedisError as exc:
            logger.warning(
                "circuit_backend_unavailable", extra={"circuit_error_type": type(exc).__name__}
            )
        finally:
            if owns:
                await client.aclose()
