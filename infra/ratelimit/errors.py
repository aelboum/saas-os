"""Typed errors for `infra/ratelimit` (docs/IMPLEMENTATION-ROADMAP.md
Phase 8.2's own Security Requirement: "rate limiting active on this
route from day one", docs/API-ARCHITECTURE.md section 6)."""

from __future__ import annotations


class RateLimitConfigurationError(ValueError):
    pass


class RateLimitExceededError(RuntimeError):
    """Raised by `check_rate_limit()` when the caller has exceeded its
    allotted requests for the current window. Carries only the
    identifying `key` and the number of seconds until the window resets
    -- never the internal Redis key structure or counter value, which
    are implementation detail, not information the caller needs."""

    def __init__(self, key: str, retry_after_seconds: int) -> None:
        self.key = key
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Rate limit exceeded for {key!r}; retry after {retry_after_seconds} seconds."
        )


class RateLimitBackendError(RuntimeError):
    """P1.5: raised by `check_rate_limit()`/`enforce_rate_limit()` when
    the Redis backend itself fails (connection refused, timeout, a
    command error, or any other `redis.exceptions.RedisError`) --
    deliberately a *different* exception type from `RateLimitExceededError`,
    never conflated with it: this means "the limit could not be
    evaluated," not "the limit was exceeded." A caller must not treat
    this as `allowed=True` (would silently bypass rate limiting) or as
    `allowed=False` (would falsely tell a caller it was rate-limited when
    it may not have been) -- `api/dependencies.py` maps it to a distinct
    HTTP 503, never a 429.

    Carries only the identifying `key` -- never the underlying Redis
    exception's own message, which can embed a host, port, or other
    connection detail (`infra/health`'s own established precedent: a
    failing dependency's exception *type name* is safe to surface,
    its message is not). The original exception is still available via
    `__cause__` for anyone with legitimate access to server-side logs/
    tracebacks; it is never included in this exception's own message or
    returned to an HTTP caller."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Rate limit backend unavailable for {key!r}.")
