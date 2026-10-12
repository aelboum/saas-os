"""S-05 (BANK-SEC-01/05) -- `saas_os/infra/db/config.py`'s PostgreSQL transport-
encryption enforcement: `DB_REQUIRE_TLS` (default: `ENVIRONMENT ==
"production"`), `sslmode` validation/injection, and fail-closed behavior
on an explicit downgrade. No database needed -- these are pure
configuration-construction tests, the same style
`test_db_pool_config_unit.py` already establishes.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from saas_os.infra.db.config import (
    DatabaseConfigurationError,
    get_database_config,
    get_migrations_database_config,
)
from saas_os.infra.secrets.config import get_secrets_provider


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_secrets_provider.cache_clear()
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    yield
    get_secrets_provider.cache_clear()
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()


def _reconfigure(monkeypatch: pytest.MonkeyPatch) -> None:
    get_secrets_provider.cache_clear()
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()


# --- default: TLS requirement follows ENVIRONMENT ---------------------------


def test_development_does_not_require_tls_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    _reconfigure(monkeypatch)

    config = get_database_config()

    assert config.require_tls is False
    assert config.url == "postgresql+psycopg://u:p@localhost:5432/db"


def test_test_environment_does_not_require_tls_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    _reconfigure(monkeypatch)

    config = get_database_config()

    assert config.require_tls is False
    assert config.url == "postgresql+psycopg://u:p@localhost:5432/db"


def test_production_requires_tls_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    _reconfigure(monkeypatch)

    config = get_database_config()

    assert config.require_tls is True
    assert "sslmode=require" in config.url


# --- valid production TLS configuration -------------------------------------


def test_production_with_explicit_sslmode_require_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db?sslmode=require")
    _reconfigure(monkeypatch)

    config = get_database_config()

    assert config.url == "postgresql+psycopg://u:p@localhost:5432/db?sslmode=require"


def test_production_with_verify_full_is_left_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator's own stricter choice (certificate + hostname
    verification) is never weakened to plain `require`."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db?sslmode=verify-full"
    )
    _reconfigure(monkeypatch)

    config = get_database_config()

    assert config.url == "postgresql+psycopg://u:p@localhost:5432/db?sslmode=verify-full"


# --- fail closed: explicit downgrade / invalid configuration ----------------


@pytest.mark.parametrize("weak_sslmode", ["disable", "allow", "prefer"])
def test_production_with_weak_sslmode_fails_closed(
    monkeypatch: pytest.MonkeyPatch, weak_sslmode: str
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "DATABASE_URL", f"postgresql+psycopg://u:p@localhost:5432/db?sslmode={weak_sslmode}"
    )
    _reconfigure(monkeypatch)

    with pytest.raises(DatabaseConfigurationError):
        get_database_config()


def test_production_with_invalid_sslmode_value_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db?sslmode=not-a-real-mode"
    )
    _reconfigure(monkeypatch)

    with pytest.raises(DatabaseConfigurationError):
        get_database_config()


def test_error_message_never_contains_the_raw_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    secret_looking_url = (
        "postgresql+psycopg://a:hunter2@h:5432/d?sslmode=disable"  # pragma: allowlist secret
    )
    monkeypatch.setenv("DATABASE_URL", secret_looking_url)
    _reconfigure(monkeypatch)

    with pytest.raises(DatabaseConfigurationError) as exc_info:
        get_database_config()

    assert "hunter2" not in str(exc_info.value)
    assert secret_looking_url not in str(exc_info.value)


# --- explicit DB_REQUIRE_TLS override, either direction ---------------------


def test_db_require_tls_true_overrides_non_production_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DB_REQUIRE_TLS", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    _reconfigure(monkeypatch)

    config = get_database_config()

    assert config.require_tls is True
    assert "sslmode=require" in config.url


def test_db_require_tls_false_overrides_production_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The documented, explicit opt-out this repository's own
    docker-compose.prod.yml uses (network-isolated Postgres, no TLS
    certificate configured -- docs/ADR/0021-...)."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DB_REQUIRE_TLS", "false")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    _reconfigure(monkeypatch)

    config = get_database_config()

    assert config.require_tls is False
    assert config.url == "postgresql+psycopg://u:p@localhost:5432/db"


def test_invalid_db_require_tls_value_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DB_REQUIRE_TLS", "not-a-boolean")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    _reconfigure(monkeypatch)

    with pytest.raises(DatabaseConfigurationError):
        get_database_config()


# --- migrations connection: identical requirement ----------------------------


def test_migrations_connection_requires_tls_in_production_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("MIGRATIONS_DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    _reconfigure(monkeypatch)

    config = get_migrations_database_config()

    assert config.require_tls is True
    assert "sslmode=require" in config.url


def test_migrations_connection_with_weak_sslmode_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "MIGRATIONS_DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db?sslmode=disable"
    )
    _reconfigure(monkeypatch)

    with pytest.raises(DatabaseConfigurationError):
        get_migrations_database_config()
