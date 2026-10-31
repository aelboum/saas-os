"""Dispatch policy for the durable outbox (Foundation Reliability & Events,
RE-2). Plain, non-secret tunables read from the environment, each with a
default; `get_outbox_dispatch_config()` is cached like every other module
config."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache


class OutboxConfigurationError(ValueError):
    """A dispatch tunable is malformed or out of range."""


@dataclass(frozen=True)
class OutboxDispatchConfig:
    """
    max_attempts           attempts (claims) before an event is dead-lettered
    retry_base_seconds     delay after the first failed attempt; doubles per
                           attempt
    retry_max_seconds      cap on that delay
    retry_jitter_ratio     up to this fraction is added to each delay, so
                           retries of many events spread out (0 disables it)
    lease_seconds          how long a claim owns an event before another
                           dispatcher may reclaim it. Must exceed the time
                           a claimed event can spend queued plus the job
                           timeout (300 s), or live work is redone
    enqueue_retry_seconds  delay before retrying an event whose hand-off to
                           the queue failed (the attempt is not consumed)
    batch_size             events claimed per dispatch cycle, across tenants
    per_tenant_limit       events claimed per tenant per cycle
    poll_seconds           dispatch cycle interval (a divisor of 60)
    retry_hint_max_seconds the longest delay a consumer's
                           `RetryAfterEventError` may ask for; a longer one
                           is capped to it (outbox decision brief Q1, 1A)
    """

    max_attempts: int = 10
    retry_base_seconds: float = 30.0
    retry_max_seconds: float = 3600.0
    retry_jitter_ratio: float = 0.1
    lease_seconds: float = 900.0
    enqueue_retry_seconds: float = 30.0
    batch_size: int = 100
    per_tenant_limit: int = 25
    poll_seconds: int = 10
    retry_hint_max_seconds: float = 86_400.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise OutboxConfigurationError("OUTBOX_MAX_ATTEMPTS must be >= 1")
        if self.retry_base_seconds <= 0 or self.retry_max_seconds < self.retry_base_seconds:
            raise OutboxConfigurationError(
                "OUTBOX_RETRY_BASE_SECONDS must be > 0 and <= OUTBOX_RETRY_MAX_SECONDS"
            )
        if not 0 <= self.retry_jitter_ratio <= 1:
            raise OutboxConfigurationError("OUTBOX_RETRY_JITTER_RATIO must be within [0, 1]")
        if self.lease_seconds <= 0 or self.enqueue_retry_seconds <= 0:
            raise OutboxConfigurationError(
                "OUTBOX_LEASE_SECONDS and OUTBOX_ENQUEUE_RETRY_SECONDS must be > 0"
            )
        if self.batch_size < 1 or self.per_tenant_limit < 1:
            raise OutboxConfigurationError(
                "OUTBOX_BATCH_SIZE and OUTBOX_PER_TENANT_LIMIT must be >= 1"
            )
        if not 1 <= self.poll_seconds <= 60 or 60 % self.poll_seconds:
            raise OutboxConfigurationError("OUTBOX_POLL_SECONDS must be a divisor of 60")
        if not 0 < self.retry_hint_max_seconds <= 31 * 86_400:
            raise OutboxConfigurationError(
                "OUTBOX_RETRY_HINT_MAX_SECONDS must be > 0 and at most 31 days"
            )

    @property
    def lease(self) -> timedelta:
        return timedelta(seconds=self.lease_seconds)

    @property
    def enqueue_retry_delay(self) -> timedelta:
        return timedelta(seconds=self.enqueue_retry_seconds)


_INT_FIELDS = {
    "max_attempts": "OUTBOX_MAX_ATTEMPTS",
    "batch_size": "OUTBOX_BATCH_SIZE",
    "per_tenant_limit": "OUTBOX_PER_TENANT_LIMIT",
    "poll_seconds": "OUTBOX_POLL_SECONDS",
}
_FLOAT_FIELDS = {
    "retry_base_seconds": "OUTBOX_RETRY_BASE_SECONDS",
    "retry_max_seconds": "OUTBOX_RETRY_MAX_SECONDS",
    "retry_jitter_ratio": "OUTBOX_RETRY_JITTER_RATIO",
    "lease_seconds": "OUTBOX_LEASE_SECONDS",
    "enqueue_retry_seconds": "OUTBOX_ENQUEUE_RETRY_SECONDS",
    "retry_hint_max_seconds": "OUTBOX_RETRY_HINT_MAX_SECONDS",
}


@lru_cache
def get_outbox_dispatch_config() -> OutboxDispatchConfig:
    values: dict[str, int | float] = {}
    for field, name in _INT_FIELDS.items():
        raw = os.environ.get(name)
        if raw is not None:
            try:
                values[field] = int(raw)
            except ValueError as exc:
                raise OutboxConfigurationError(f"{name} must be an integer, got {raw!r}") from exc
    for field, name in _FLOAT_FIELDS.items():
        raw = os.environ.get(name)
        if raw is not None:
            try:
                values[field] = float(raw)
            except ValueError as exc:
                raise OutboxConfigurationError(f"{name} must be a number, got {raw!r}") from exc
    return OutboxDispatchConfig(**values)  # type: ignore[arg-type]
