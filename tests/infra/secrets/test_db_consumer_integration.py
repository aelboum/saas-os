"""Proves `infra/db` sources `DATABASE_URL` through `infra.secrets`'s
`SecretsProvider` abstraction (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3
section 7/11: "consumer code uses the provider abstraction rather than
directly reading the environment"), non-vacuously -- by substituting a
fake provider and confirming `infra/db` uses *its* answer, not
`os.environ`'s.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from infra.db.config import DatabaseConfigurationError, get_database_config
from infra.secrets.provider import SecretsProvider


class _FakeProvider(SecretsProvider):
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)


@pytest.fixture(autouse=True)
def _clear_db_config_cache() -> Iterator[None]:
    get_database_config.cache_clear()
    yield
    get_database_config.cache_clear()


def test_database_url_comes_from_the_secrets_provider_not_os_environ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A value present in os.environ that must be ignored, proving infra/db
    # reads DATABASE_URL through the provider rather than os.environ
    # directly.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://from-os-environ/db")
    fake_provider = _FakeProvider({"DATABASE_URL": "postgresql+psycopg://from-fake-provider/db"})
    monkeypatch.setattr("infra.db.config.get_secrets_provider", lambda: fake_provider)

    config = get_database_config()

    assert config.url == "postgresql+psycopg://from-fake-provider/db"


def test_missing_database_url_from_the_provider_still_fails_predictably(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even with a DATABASE_URL present in os.environ, a provider that
    # doesn't have it must still fail -- proving os.environ is not a
    # fallback path around the provider.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://from-os-environ/db")
    fake_provider = _FakeProvider({})
    monkeypatch.setattr("infra.db.config.get_secrets_provider", lambda: fake_provider)

    with pytest.raises(DatabaseConfigurationError):
        get_database_config()
