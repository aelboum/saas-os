"""Configuration tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1)."""

from __future__ import annotations

import dataclasses

import pytest
from core.config.settings import ConfigurationError, Settings, get_settings

# Field names that would indicate a secret snuck into the plain, unmasked
# Settings dataclass. Nothing in Settings is a secret today
# (docs/SECURITY.md section 4) -- this is a forward-looking guard so a
# future contributor cannot silently add a secret-bearing field here
# without the test noticing.
_SECRET_SHAPED_SUBSTRINGS = ("secret", "password", "token", "api_key", "credential", "private_key")


def test_default_configuration_works() -> None:
    settings = Settings()
    assert settings.app_name == "saas-os"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.api_v1_prefix == "/v1"
    assert settings.port == 8000
    assert settings.log_level == "INFO"


def test_environment_override_changes_resulting_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_NAME", "custom-app")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("API_V1_PREFIX", "/api/v1")
    monkeypatch.setenv("PORT", "9000")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.app_name == "custom-app"
        assert settings.environment == "production"
        assert settings.debug is True
        assert settings.api_v1_prefix == "/api/v1"
        assert settings.port == 9000
        assert settings.log_level == "DEBUG"
    finally:
        get_settings.cache_clear()


def test_get_settings_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    get_settings.cache_clear()
    try:
        first = get_settings()
        second = get_settings()
        assert first is second
    finally:
        get_settings.cache_clear()


def test_invalid_environment_fails_predictably() -> None:
    with pytest.raises(ConfigurationError):
        Settings(environment="not-a-real-environment")


def test_invalid_log_level_fails_predictably() -> None:
    with pytest.raises(ConfigurationError):
        Settings(log_level="NOT_A_LEVEL")


def test_invalid_port_too_low_fails_predictably() -> None:
    with pytest.raises(ConfigurationError):
        Settings(port=0)


def test_invalid_port_too_high_fails_predictably() -> None:
    with pytest.raises(ConfigurationError):
        Settings(port=70000)


def test_invalid_boolean_env_var_fails_predictably(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEBUG", "not-a-boolean")
    get_settings.cache_clear()
    try:
        with pytest.raises(ConfigurationError):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_invalid_port_env_var_fails_predictably(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORT", "not-a-port")
    get_settings.cache_clear()
    try:
        with pytest.raises(ConfigurationError):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_no_settings_field_is_secret_shaped() -> None:
    """Guards docs/SECURITY.md section 4: no secret value may be logged or
    appear in an exception -- trivially true today because no field is a
    secret. This test exists so adding one is a deliberate, noticed choice.
    """
    field_names = {f.name for f in dataclasses.fields(Settings)}
    for name in field_names:
        for shape in _SECRET_SHAPED_SUBSTRINGS:
            assert shape not in name, (
                f"Settings field {name!r} looks secret-shaped; Phase 2.1 defines no secret "
                "configuration (docs/ADR/0012-secrets-management.md: secrets are read via "
                "infra/secrets's SecretsProvider, not plain Settings)"
            )
