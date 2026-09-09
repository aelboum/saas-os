"""`core/idempotency` configuration (P1.11). Mirrors `infra/ratelimit/config.py`'s
own shape exactly: plain, non-secret tunables read directly from the
environment, validated, cached process-wide.

Two tunables:

- `IDEMPOTENCY_RETENTION_SECONDS` -- how long a resolved (succeeded)
  record remains available for replay before `purge_expired_idempotency_records()`
  may delete it (`IdempotencyRecord.expires_at`, set at creation time).
  Default 24 hours: long enough to cover any realistic client retry
  window (network partition, client restart) without keeping records
  indefinitely (this checkpoint's own "the database must not grow
  forever" requirement).
- `IDEMPOTENCY_PENDING_TTL_SECONDS` -- how long a `pending` reservation
  (an operation genuinely still in flight, or abandoned after a crash
  between reserving and finalizing -- `core/idempotency/service.py`'s
  own docstring) is treated as "still running" before a new attempt with
  the same key is allowed to supersede it. Default 30 seconds: long
  enough for any of this repository's actual idempotent operations
  (a database transaction, or one outbound HTTP call to a billing
  provider) to complete normally, short enough that a genuinely crashed
  attempt does not permanently block a legitimate retry.

Missing configuration always falls back to these safe defaults -- never
to "no expiry at all" or "always treat pending as immediately stale."
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from core.idempotency.errors import IdempotencyConfigurationError

_DEFAULT_RETENTION_SECONDS = 24 * 60 * 60
_DEFAULT_PENDING_TTL_SECONDS = 30


@dataclass(frozen=True)
class IdempotencyConfig:
    retention_seconds: int = _DEFAULT_RETENTION_SECONDS
    pending_ttl_seconds: int = _DEFAULT_PENDING_TTL_SECONDS

    def __post_init__(self) -> None:
        if self.retention_seconds < 1:
            raise IdempotencyConfigurationError(
                f"IDEMPOTENCY_RETENTION_SECONDS must be >= 1, got: {self.retention_seconds}"
            )
        if self.pending_ttl_seconds < 1:
            raise IdempotencyConfigurationError(
                f"IDEMPOTENCY_PENDING_TTL_SECONDS must be >= 1, got: {self.pending_ttl_seconds}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise IdempotencyConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _idempotency_config_from_env() -> IdempotencyConfig:
    retention_raw = os.environ.get("IDEMPOTENCY_RETENTION_SECONDS")
    pending_ttl_raw = os.environ.get("IDEMPOTENCY_PENDING_TTL_SECONDS")
    return IdempotencyConfig(
        retention_seconds=(
            _parse_int("IDEMPOTENCY_RETENTION_SECONDS", retention_raw)
            if retention_raw is not None
            else _DEFAULT_RETENTION_SECONDS
        ),
        pending_ttl_seconds=(
            _parse_int("IDEMPOTENCY_PENDING_TTL_SECONDS", pending_ttl_raw)
            if pending_ttl_raw is not None
            else _DEFAULT_PENDING_TTL_SECONDS
        ),
    )


@lru_cache
def get_idempotency_config() -> IdempotencyConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need different values should call
    `get_idempotency_config.cache_clear()` after `monkeypatch.setenv(...)`.
    """
    return _idempotency_config_from_env()
