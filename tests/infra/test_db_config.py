"""infra/db configuration tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1;
Phase 2.3 migrated DATABASE_URL sourcing to infra/secrets -- see
infra/db/config.py).

Each test pins `ENVIRONMENT=test` and clears `get_secrets_provider`'s cache
so these stay independent of the active `SecretsProvider` implementation:
without it, the default "development" selection would read a real
developer machine's own local (gitignored) `.env` file, which may already
define DATABASE_URL -- these tests must exercise `os.environ` directly,
regardless of ambient repo state (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from infra.db.config import DatabaseConfigurationError, get_database_config
from infra.secrets.config import get_secrets_provider


@pytest.fixture(autouse=True)
def _isolate_secrets_provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_secrets_provider.cache_clear()
    yield
    get_secrets_provider.cache_clear()


def test_database_url_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    get_database_config.cache_clear()
    try:
        config = get_database_config()
        assert config.url == "postgresql+psycopg://u:p@localhost:5432/db"
    finally:
        get_database_config.cache_clear()


def test_missing_database_url_fails_predictably(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    get_database_config.cache_clear()
    try:
        with pytest.raises(DatabaseConfigurationError):
            get_database_config()
    finally:
        get_database_config.cache_clear()


def test_get_database_config_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    get_database_config.cache_clear()
    try:
        first = get_database_config()
        second = get_database_config()
        assert first is second
    finally:
        get_database_config.cache_clear()


def test_configuration_error_never_includes_the_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-vacuous (docs/SECURITY.md: no secret value may appear in an
    exception): DATABASE_URL commonly carries a password. Confirm the
    error raised for a *missing* URL never echoes back environment
    content, and stays a fixed, generic message.
    """
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SOME_OTHER_SECRET_LOOKING_VAR", "sk-should-never-appear")
    get_database_config.cache_clear()
    try:
        with pytest.raises(DatabaseConfigurationError) as excinfo:
            get_database_config()
        assert "sk-should-never-appear" not in str(excinfo.value)
    finally:
        get_database_config.cache_clear()
