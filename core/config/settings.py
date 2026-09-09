"""Core application settings (docs/IMPLEMENTATION-ROADMAP.md Phase 2.1).

Configuration comes from environment variables only. Constructing `Settings`
never requires PostgreSQL, Redis, or ZITADEL, and never reads a secret --
none of the fields below are secrets (docs/SECURITY.md section 4: a real
secret, once one exists in a later phase, is read via `infra/secrets`'s
`SecretsProvider`, not this module).

A plain frozen dataclass is used rather than a settings framework (e.g.
pydantic-settings): six flat scalar fields don't yet justify a new
dependency. Revisit if/when nested or secret-bearing configuration is
needed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

_VALID_ENVIRONMENTS = frozenset({"development", "test", "production"})
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class ConfigurationError(ValueError):
    """Raised when an environment variable holds an invalid value.

    Only ever carries the variable *name* and the *offending value* --
    every field defined on `Settings` today is non-secret, so this is safe.
    If a secret-bearing field is ever added, its validation must not raise
    with the value included (docs/SECURITY.md: no secret in an exception).
    """


@dataclass(frozen=True)
class Settings:
    app_name: str = "saas-os"
    environment: str = "development"
    debug: bool = False
    api_v1_prefix: str = "/v1"
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if self.environment not in _VALID_ENVIRONMENTS:
            allowed = sorted(_VALID_ENVIRONMENTS)
            got = self.environment
            raise ConfigurationError(f"ENVIRONMENT must be one of {allowed}, got: {got!r}")
        if self.log_level not in _VALID_LOG_LEVELS:
            allowed = sorted(_VALID_LOG_LEVELS)
            got = self.log_level
            raise ConfigurationError(f"LOG_LEVEL must be one of {allowed}, got: {got!r}")
        if not 1 <= self.port <= 65535:
            raise ConfigurationError(f"PORT must be between 1 and 65535, got: {self.port}")


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


def _parse_port(raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"PORT must be an integer, got: {raw!r}") from exc


def _settings_from_env() -> Settings:
    debug_raw = os.environ.get("DEBUG")
    port_raw = os.environ.get("PORT")

    return Settings(
        app_name=os.environ.get("APP_NAME", "saas-os"),
        environment=os.environ.get("ENVIRONMENT", "development"),
        debug=_parse_bool("DEBUG", debug_raw) if debug_raw is not None else False,
        api_v1_prefix=os.environ.get("API_V1_PREFIX", "/v1"),
        host=os.environ.get("HOST", "0.0.0.0"),
        port=_parse_port(port_raw) if port_raw is not None else 8000,
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    )


@lru_cache
def get_settings() -> Settings:
    """Process-wide cached settings singleton, read once from the
    environment. Use `Depends(get_settings)` in routes; tests that need
    different environment variables should call `get_settings.cache_clear()`
    after `monkeypatch.setenv(...)`.
    """
    return _settings_from_env()
