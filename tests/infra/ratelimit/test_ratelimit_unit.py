"""Pure unit tests for `infra/ratelimit/config.py` -- no Redis needed
(docs/IMPLEMENTATION-ROADMAP.md Phase 8.2's own Security Requirement:
"rate limiting active on this route from day one")."""

from __future__ import annotations

import pytest
from infra.ratelimit.config import RateLimitConfig, get_ratelimit_config
from infra.ratelimit.errors import RateLimitConfigurationError


def test_valid_config_accepted() -> None:
    config = RateLimitConfig(redis_url="redis://localhost:6379/0")
    assert config.requests_per_window == 60
    assert config.window_seconds == 60
    assert config.redis_timeout_seconds == 2.0


def test_zero_requests_per_window_rejected() -> None:
    with pytest.raises(RateLimitConfigurationError):
        RateLimitConfig(redis_url="redis://localhost:6379/0", requests_per_window=0)


def test_negative_window_seconds_rejected() -> None:
    with pytest.raises(RateLimitConfigurationError):
        RateLimitConfig(redis_url="redis://localhost:6379/0", window_seconds=-1)


def test_zero_redis_timeout_rejected() -> None:
    """CP-07 J-INFRA-01: a non-positive timeout would mean "no bound at
    all" again -- the exact regression this config field exists to close."""
    with pytest.raises(RateLimitConfigurationError):
        RateLimitConfig(redis_url="redis://localhost:6379/0", redis_timeout_seconds=0)


def test_negative_redis_timeout_rejected() -> None:
    with pytest.raises(RateLimitConfigurationError):
        RateLimitConfig(redis_url="redis://localhost:6379/0", redis_timeout_seconds=-1.0)


def test_get_ratelimit_config_raises_without_redis_url(monkeypatch: pytest.MonkeyPatch) -> None:
    from infra.secrets.config import get_secrets_provider

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("REDIS_URL", raising=False)
    get_secrets_provider.cache_clear()
    get_ratelimit_config.cache_clear()
    try:
        with pytest.raises(RateLimitConfigurationError):
            get_ratelimit_config()
    finally:
        get_secrets_provider.cache_clear()
        get_ratelimit_config.cache_clear()


def test_get_ratelimit_config_reads_tunables_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from infra.secrets.config import get_secrets_provider

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "5")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "10")
    monkeypatch.setenv("RATE_LIMIT_REDIS_TIMEOUT_SECONDS", "0.5")
    get_secrets_provider.cache_clear()
    get_ratelimit_config.cache_clear()
    try:
        config = get_ratelimit_config()
        assert config.requests_per_window == 5
        assert config.window_seconds == 10
        assert config.redis_timeout_seconds == 0.5
    finally:
        get_secrets_provider.cache_clear()
        get_ratelimit_config.cache_clear()


def test_get_ratelimit_config_defaults_the_redis_timeout_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CP-07 J-INFRA-01: every real deployment that does not set
    `RATE_LIMIT_REDIS_TIMEOUT_SECONDS` must still get a bounded timeout,
    never `None`/unbounded."""
    from infra.secrets.config import get_secrets_provider

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.delenv("RATE_LIMIT_REDIS_TIMEOUT_SECONDS", raising=False)
    get_secrets_provider.cache_clear()
    get_ratelimit_config.cache_clear()
    try:
        config = get_ratelimit_config()
        assert config.redis_timeout_seconds == 2.0
    finally:
        get_secrets_provider.cache_clear()
        get_ratelimit_config.cache_clear()
