"""P1.6 -- unit tests for `infra/db/config.py`'s connection-pool
configuration (`DatabaseConfig.pool_size`/`max_overflow`/`pool_timeout`/
`pool_recycle`/`pool_pre_ping`, and the `DB_POOL_*` environment variables
that populate them). No database needed.
"""

from __future__ import annotations

import pytest
from infra.db.config import (
    DatabaseConfig,
    DatabaseConfigurationError,
    get_database_config,
    get_migrations_database_config,
)

# --- Defaults ---------------------------------------------------------------


def test_default_pool_configuration() -> None:
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db")
    assert config.pool_size == 5
    assert config.max_overflow == 10
    assert config.pool_timeout == 30
    assert config.pool_recycle == 1800
    assert config.pool_pre_ping is True


# --- Explicit environment overrides -----------------------------------------


def test_env_overrides_are_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    monkeypatch.setenv("DB_POOL_SIZE", "3")
    monkeypatch.setenv("DB_POOL_MAX_OVERFLOW", "1")
    monkeypatch.setenv("DB_POOL_TIMEOUT_SECONDS", "7")
    monkeypatch.setenv("DB_POOL_RECYCLE_SECONDS", "600")
    monkeypatch.setenv("DB_POOL_PRE_PING", "false")

    from infra.secrets.config import get_secrets_provider

    get_secrets_provider.cache_clear()
    get_database_config.cache_clear()
    try:
        config = get_database_config()
        assert config.pool_size == 3
        assert config.max_overflow == 1
        assert config.pool_timeout == 7
        assert config.pool_recycle == 600
        assert config.pool_pre_ping is False
    finally:
        get_secrets_provider.cache_clear()
        get_database_config.cache_clear()


def test_unset_env_vars_fall_back_to_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    for name in (
        "DB_POOL_SIZE",
        "DB_POOL_MAX_OVERFLOW",
        "DB_POOL_TIMEOUT_SECONDS",
        "DB_POOL_RECYCLE_SECONDS",
        "DB_POOL_PRE_PING",
    ):
        monkeypatch.delenv(name, raising=False)

    from infra.secrets.config import get_secrets_provider

    get_secrets_provider.cache_clear()
    get_database_config.cache_clear()
    try:
        config = get_database_config()
        assert config.pool_size == 5
        assert config.max_overflow == 10
        assert config.pool_timeout == 30
        assert config.pool_recycle == 1800
        assert config.pool_pre_ping is True
    finally:
        get_secrets_provider.cache_clear()
        get_database_config.cache_clear()


@pytest.mark.parametrize("raw,expected", [("1", True), ("true", True), ("0", False), ("no", False)])
def test_pre_ping_bool_parsing_accepts_common_spellings(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    monkeypatch.setenv("DB_POOL_PRE_PING", raw)

    from infra.secrets.config import get_secrets_provider

    get_secrets_provider.cache_clear()
    get_database_config.cache_clear()
    try:
        assert get_database_config().pool_pre_ping is expected
    finally:
        get_secrets_provider.cache_clear()
        get_database_config.cache_clear()


# --- Invalid configuration is rejected early --------------------------------


@pytest.mark.parametrize("pool_size", [0, -1])
def test_zero_or_negative_pool_size_is_rejected(pool_size: int) -> None:
    with pytest.raises(DatabaseConfigurationError):
        DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", pool_size=pool_size)


def test_negative_max_overflow_is_rejected() -> None:
    with pytest.raises(DatabaseConfigurationError):
        DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", max_overflow=-1)


def test_max_overflow_of_zero_is_accepted() -> None:
    """Zero overflow is a legitimate, deliberately-bounded policy ("never
    exceed pool_size") -- only *negative* overflow is nonsensical."""
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", max_overflow=0)
    assert config.max_overflow == 0


@pytest.mark.parametrize("pool_timeout", [0, -5])
def test_non_positive_pool_timeout_is_rejected(pool_timeout: int) -> None:
    with pytest.raises(DatabaseConfigurationError):
        DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", pool_timeout=pool_timeout)


@pytest.mark.parametrize("pool_recycle", [0, -2, -100])
def test_invalid_recycle_values_are_rejected(pool_recycle: int) -> None:
    with pytest.raises(DatabaseConfigurationError):
        DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", pool_recycle=pool_recycle)


def test_recycle_of_negative_one_is_the_valid_never_recycle_sentinel() -> None:
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db", pool_recycle=-1)
    assert config.pool_recycle == -1


def test_invalid_env_var_value_is_rejected_with_a_clear_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    monkeypatch.setenv("DB_POOL_SIZE", "not-a-number")

    from infra.secrets.config import get_secrets_provider

    get_secrets_provider.cache_clear()
    get_database_config.cache_clear()
    try:
        with pytest.raises(DatabaseConfigurationError, match="DB_POOL_SIZE"):
            get_database_config()
    finally:
        get_secrets_provider.cache_clear()
        get_database_config.cache_clear()


def test_error_messages_never_contain_the_database_url() -> None:
    """The class docstring's own promise: pool-validation errors are safe
    to log/surface (plain integers), but must still never accidentally
    carry a URL that could embed a credential."""
    secret_looking_url = (
        "postgresql+psycopg://admin:hunter2@db.internal:5432/prod"  # pragma: allowlist secret
    )
    with pytest.raises(DatabaseConfigurationError) as excinfo:
        DatabaseConfig(url=secret_looking_url, pool_size=0)
    assert secret_looking_url not in str(excinfo.value)
    assert "hunter2" not in str(excinfo.value)


# --- Migration config is unaffected by pool tuning --------------------------


def test_migrations_config_does_not_read_pool_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md P1.6: application pool settings must
    apply only to the application engine. `get_migrations_database_config()`
    must keep the dataclass defaults regardless of `DB_POOL_*` -- it never
    even looks at them (module docstring)."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("MIGRATIONS_DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    monkeypatch.setenv("DB_POOL_SIZE", "99")
    monkeypatch.setenv("DB_POOL_PRE_PING", "false")

    from infra.secrets.config import get_secrets_provider

    get_secrets_provider.cache_clear()
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
        assert config.pool_size == 5  # still the plain dataclass default
        assert config.pool_pre_ping is True  # still the plain dataclass default
    finally:
        get_secrets_provider.cache_clear()
        get_migrations_database_config.cache_clear()


def test_default_config_is_frozen_and_bounded() -> None:
    """Defaults themselves must already satisfy the dataclass's own
    validation (a non-vacuous check that the shipped defaults are not
    accidentally invalid)."""
    config = DatabaseConfig(url="postgresql+psycopg://u:p@localhost:5432/db")
    assert config.pool_size >= 1
    assert config.max_overflow >= 0
    assert config.pool_timeout >= 1
    assert config.pool_recycle == -1 or config.pool_recycle >= 1
