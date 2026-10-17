"""Unit tests for the platform-configuration connection's configuration
(docs/ADR/0056-platform-configuration-database-identity.md) -- no database.

- the URL comes only from `PLATFORM_CONFIG_DATABASE_URL`; missing is an
  error, never a fallback to `DATABASE_URL`;
- it carries the same TLS requirement as the application connection;
- a process that must not hold it detects it in the environment, its
  `_FILE` form, or the secrets provider;
- error messages never contain a URL;
- the application-role guard refuses writable protected tables.
"""

from __future__ import annotations

import pytest

from saas_os.infra.db import platform_config
from saas_os.infra.db.config import DatabaseConfigurationError
from saas_os.infra.db.platform_config import (
    PLATFORM_CONFIG_URL_VARIABLE,
    PlatformConfigCredentialExposedError,
    assert_no_platform_config_credential,
    get_platform_config_database_config,
    reset_platform_config_connection,
)
from saas_os.infra.db.role_guard import (
    PROTECTED_TABLES,
    UnsafeDatabaseRoleError,
    _evaluate_protected_tables,
)

_URL = (
    "postgresql+psycopg://platform_config:placeholder-secret"  # pragma: allowlist secret
    "@db.internal:5432/saas_os"
)


class _Secrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    for name in (
        PLATFORM_CONFIG_URL_VARIABLE,
        f"{PLATFORM_CONFIG_URL_VARIABLE}_FILE",
        "PLATFORM_CONFIG_DB_PASSWORD",
        "PLATFORM_CONFIG_DB_PASSWORD_FILE",
        "DB_REQUIRE_TLS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ENVIRONMENT", "test")
    reset_platform_config_connection()
    yield
    reset_platform_config_connection()


def _use_secrets(monkeypatch: pytest.MonkeyPatch, values: dict[str, str]) -> None:
    monkeypatch.setattr(platform_config, "get_secrets_provider", lambda: _Secrets(values))


def test_a_missing_url_fails_closed_without_falling_back(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_secrets(monkeypatch, {"DATABASE_URL": _URL})
    with pytest.raises(DatabaseConfigurationError, match=PLATFORM_CONFIG_URL_VARIABLE) as caught:
        get_platform_config_database_config()
    assert "placeholder-secret" not in str(caught.value)


def test_the_url_comes_from_its_own_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_secrets(monkeypatch, {PLATFORM_CONFIG_URL_VARIABLE: _URL})
    config = get_platform_config_database_config()
    assert config.url == _URL
    assert (config.pool_size, config.max_overflow) == (1, 1)


def test_production_requires_an_encrypted_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    _use_secrets(monkeypatch, {PLATFORM_CONFIG_URL_VARIABLE: _URL})
    assert get_platform_config_database_config().url.endswith("sslmode=require")


def test_a_plaintext_downgrade_is_refused_without_echoing_the_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    _use_secrets(monkeypatch, {PLATFORM_CONFIG_URL_VARIABLE: f"{_URL}?sslmode=disable"})
    with pytest.raises(DatabaseConfigurationError, match=PLATFORM_CONFIG_URL_VARIABLE) as caught:
        get_platform_config_database_config()
    assert "placeholder-secret" not in str(caught.value)


def test_no_credential_in_the_process_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_secrets(monkeypatch, {"DATABASE_URL": _URL})
    assert_no_platform_config_credential()


@pytest.mark.parametrize(
    "variable",
    [
        PLATFORM_CONFIG_URL_VARIABLE,
        f"{PLATFORM_CONFIG_URL_VARIABLE}_FILE",
        "PLATFORM_CONFIG_DB_PASSWORD",
        "PLATFORM_CONFIG_DB_PASSWORD_FILE",
    ],
)
def test_the_credential_in_the_environment_is_refused(
    monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    _use_secrets(monkeypatch, {})
    monkeypatch.setenv(variable, _URL)
    with pytest.raises(PlatformConfigCredentialExposedError) as caught:
        assert_no_platform_config_credential()
    assert "placeholder-secret" not in str(caught.value)


def test_the_credential_in_the_secrets_provider_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_secrets(monkeypatch, {PLATFORM_CONFIG_URL_VARIABLE: _URL})
    with pytest.raises(PlatformConfigCredentialExposedError):
        assert_no_platform_config_credential()


def test_the_application_role_guard_refuses_writable_protected_tables() -> None:
    with pytest.raises(UnsafeDatabaseRoleError, match=r"control_plane\.ai_providers"):
        _evaluate_protected_tables("saas_os_app", ["control_plane.ai_providers"])
    _evaluate_protected_tables("saas_os_app", [])


def test_the_protected_tables_are_the_global_ai_configuration() -> None:
    from saas_os.core.tenancy.isolation import IsolationClass, tables_with_isolation

    global_ai = {
        table
        for table in tables_with_isolation(IsolationClass.GLOBAL)
        if table.startswith("control_plane.ai_")
    }
    assert set(PROTECTED_TABLES) == global_ai
