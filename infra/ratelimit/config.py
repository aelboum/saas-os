"""`infra/ratelimit` configuration (docs/IMPLEMENTATION-ROADMAP.md Phase
8.2; docs/API-ARCHITECTURE.md section 6: "Owned by Infra as a
cross-cutting ingress concern").

Mirrors `infra/jobs/config.py`'s own shape exactly: `REDIS_URL` is
retrieved through `infra.secrets` (a connection URL can embed
credentials, so it is never read from `os.environ` directly); the limit
tunables are plain, non-secret configuration read directly from the
environment, the same convention `infra/observability/config.py` and
`infra/jobs/config.py` both already use for their own non-secret
tunables. A separate config object from `infra.jobs.JobsConfig` --
sharing the same Redis instance is fine (`limiter.py`'s own docstring),
but rate-limit tunables (requests-per-window, window length) have
nothing to do with job retry/backoff tunables and should not be
conflated into one dataclass.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from infra.ratelimit.errors import RateLimitConfigurationError
from infra.secrets import get_secrets_provider


@dataclass(frozen=True)
class RateLimitConfig:
    redis_url: str
    requests_per_window: int = 60
    window_seconds: int = 60
    key_prefix: str = "ratelimit"

    def __post_init__(self) -> None:
        if self.requests_per_window < 1:
            raise RateLimitConfigurationError(
                f"RATE_LIMIT_REQUESTS_PER_WINDOW must be >= 1, got: {self.requests_per_window}"
            )
        if self.window_seconds < 1:
            raise RateLimitConfigurationError(
                f"RATE_LIMIT_WINDOW_SECONDS must be >= 1, got: {self.window_seconds}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise RateLimitConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _ratelimit_config_from_env() -> RateLimitConfig:
    redis_url = get_secrets_provider().get("REDIS_URL")
    if not redis_url:
        raise RateLimitConfigurationError(
            "REDIS_URL is not set. Copy .env.example to .env and set a value "
            "(see docs/ADR/0012-secrets-management.md)."
        )

    requests_raw = os.environ.get("RATE_LIMIT_REQUESTS_PER_WINDOW")
    window_raw = os.environ.get("RATE_LIMIT_WINDOW_SECONDS")

    return RateLimitConfig(
        redis_url=redis_url,
        requests_per_window=(
            _parse_int("RATE_LIMIT_REQUESTS_PER_WINDOW", requests_raw)
            if requests_raw is not None
            else 60
        ),
        window_seconds=(
            _parse_int("RATE_LIMIT_WINDOW_SECONDS", window_raw) if window_raw is not None else 60
        ),
    )


@lru_cache
def get_ratelimit_config() -> RateLimitConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different configuration should call
    `get_ratelimit_config.cache_clear()` after `monkeypatch.setenv(...)`.
    """
    return _ratelimit_config_from_env()
