"""infra/observability configuration tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.2)."""

from __future__ import annotations

import dataclasses

import pytest
from infra.observability.config import (
    ObservabilityConfig,
    ObservabilityConfigurationError,
    get_observability_config,
)


def test_default_configuration_works() -> None:
    """Defaults tested via the dataclass directly (not get_observability_
    config()), so this is independent of whatever the real environment
    happens to have set -- matches core/config's test convention.
    """
    config = ObservabilityConfig()
    assert config.enabled is True
    assert config.service_name == "saas-os"
    assert config.environment == "development"
    assert config.exporter == "console"
    assert config.deployment_id == "local"
    assert config.version == "0.0.0"
    assert config.log_level == "INFO"


def test_environment_override_changes_resulting_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OBSERVABILITY_ENABLED", "false")
    monkeypatch.setenv("OBSERVABILITY_SERVICE_NAME", "custom-service")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("OBSERVABILITY_EXPORTER", "none")
    monkeypatch.setenv("DEPLOYMENT_ID", "deploy-42")
    monkeypatch.setenv("VERSION", "1.2.3")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    get_observability_config.cache_clear()
    try:
        config = get_observability_config()
        assert config.enabled is False
        assert config.service_name == "custom-service"
        assert config.environment == "production"
        assert config.exporter == "none"
        assert config.deployment_id == "deploy-42"
        assert config.version == "1.2.3"
        assert config.log_level == "DEBUG"
    finally:
        get_observability_config.cache_clear()


def test_get_observability_config_is_cached() -> None:
    get_observability_config.cache_clear()
    try:
        first = get_observability_config()
        second = get_observability_config()
        assert first is second
    finally:
        get_observability_config.cache_clear()


def test_invalid_exporter_fails_predictably() -> None:
    with pytest.raises(ObservabilityConfigurationError):
        ObservabilityConfig(exporter="datadog")


def test_invalid_boolean_env_var_fails_predictably(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OBSERVABILITY_ENABLED", "not-a-boolean")
    get_observability_config.cache_clear()
    try:
        with pytest.raises(ObservabilityConfigurationError):
            get_observability_config()
    finally:
        get_observability_config.cache_clear()


def test_no_config_field_is_secret_shaped() -> None:
    """Guards docs/SECURITY.md section 4: no secret value may be logged or
    appear in an exception -- trivially true today because no field is a
    secret. This test exists so adding one is a deliberate, noticed choice.
    """
    secret_shaped = ("secret", "password", "token", "api_key", "credential", "private_key")
    for field in dataclasses.fields(ObservabilityConfig):
        for shape in secret_shaped:
            assert shape not in field.name, (
                f"ObservabilityConfig field {field.name!r} looks secret-shaped"
            )
