"""`infra/jobs` configuration (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4,
docs/ADR/0007-background-job-and-workflow-engine.md).

`REDIS_URL` is retrieved through `infra.secrets` -- like `DATABASE_URL`
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.3), a connection URL can embed
credentials, so it is never read from `os.environ` directly. The retry
policy's own tunables (`JOBS_MAX_TRIES`, `JOBS_RETRY_BACKOFF_BASE_SECONDS`)
are plain, non-secret configuration and are read directly from the
environment, the same convention `infra/observability/config.py` uses for
its own non-secret tunables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from infra.jobs.errors import JobsConfigurationError
from infra.secrets import get_secrets_provider


@dataclass(frozen=True)
class JobsConfig:
    redis_url: str
    max_tries: int = 3
    retry_backoff_base_seconds: float = 1.0
    dead_letter_key: str = "arq:dead-letter"

    def __post_init__(self) -> None:
        if self.max_tries < 1:
            raise JobsConfigurationError(f"JOBS_MAX_TRIES must be >= 1, got: {self.max_tries}")
        if self.retry_backoff_base_seconds <= 0:
            raise JobsConfigurationError(
                "JOBS_RETRY_BACKOFF_BASE_SECONDS must be > 0, got: "
                f"{self.retry_backoff_base_seconds}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise JobsConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _parse_float(name: str, raw: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:
        raise JobsConfigurationError(f"{name} must be a number, got: {raw!r}") from exc


def _jobs_config_from_env() -> JobsConfig:
    redis_url = get_secrets_provider().get("REDIS_URL")
    if not redis_url:
        raise JobsConfigurationError(
            "REDIS_URL is not set. Copy .env.example to .env and set a value "
            "(see docs/ADR/0012-secrets-management.md)."
        )

    max_tries_raw = os.environ.get("JOBS_MAX_TRIES")
    backoff_raw = os.environ.get("JOBS_RETRY_BACKOFF_BASE_SECONDS")

    return JobsConfig(
        redis_url=redis_url,
        max_tries=_parse_int("JOBS_MAX_TRIES", max_tries_raw) if max_tries_raw is not None else 3,
        retry_backoff_base_seconds=(
            _parse_float("JOBS_RETRY_BACKOFF_BASE_SECONDS", backoff_raw)
            if backoff_raw is not None
            else 1.0
        ),
    )


@lru_cache
def get_jobs_config() -> JobsConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different configuration should call
    `get_jobs_config.cache_clear()` after `monkeypatch.setenv(...)`.
    """
    return _jobs_config_from_env()
