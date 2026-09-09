"""`infra/jobs` configuration tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4).

Pins `ENVIRONMENT=test` and clears `get_secrets_provider`'s cache, the
same isolation `tests/infra/test_db_config.py` uses (Phase 2.3) -- without
it, the default "development" secrets provider would read a real
developer machine's own local `.env`, which may already define
`REDIS_URL`.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from infra.jobs.config import JobsConfig, get_jobs_config
from infra.jobs.errors import JobsConfigurationError
from infra.secrets.config import get_secrets_provider


@pytest.fixture(autouse=True)
def _isolate_secrets_provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_secrets_provider.cache_clear()
    get_jobs_config.cache_clear()
    yield
    get_secrets_provider.cache_clear()
    get_jobs_config.cache_clear()


def test_redis_url_is_sourced_through_secrets_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    config = get_jobs_config()
    assert config.redis_url == "redis://localhost:6379/0"


def test_missing_redis_url_fails_predictably(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    with pytest.raises(JobsConfigurationError):
        get_jobs_config()


def test_configuration_error_never_includes_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("SOME_OTHER_SECRET_LOOKING_VAR", "sk-should-never-appear")
    with pytest.raises(JobsConfigurationError) as excinfo:
        get_jobs_config()
    assert "sk-should-never-appear" not in str(excinfo.value)


def test_default_retry_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.delenv("JOBS_MAX_TRIES", raising=False)
    monkeypatch.delenv("JOBS_RETRY_BACKOFF_BASE_SECONDS", raising=False)
    config = get_jobs_config()
    assert config.max_tries == 3
    assert config.retry_backoff_base_seconds == 1.0


def test_retry_policy_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("JOBS_MAX_TRIES", "5")
    monkeypatch.setenv("JOBS_RETRY_BACKOFF_BASE_SECONDS", "2.5")
    config = get_jobs_config()
    assert config.max_tries == 5
    assert config.retry_backoff_base_seconds == 2.5


def test_max_tries_must_be_at_least_one() -> None:
    with pytest.raises(JobsConfigurationError):
        JobsConfig(redis_url="redis://localhost:6379/0", max_tries=0)


def test_backoff_must_be_positive() -> None:
    with pytest.raises(JobsConfigurationError):
        JobsConfig(redis_url="redis://localhost:6379/0", retry_backoff_base_seconds=0.0)


def test_get_jobs_config_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    first = get_jobs_config()
    second = get_jobs_config()
    assert first is second
