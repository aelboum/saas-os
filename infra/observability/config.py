"""Observability configuration (docs/IMPLEMENTATION-ROADMAP.md Phase 2.2).

Read directly from the environment -- the same interim pattern
`core/config/settings.py` and `infra/db/config.py` already use.
`infra/observability` does not import `core.config` (Infrastructure
depends on nothing above it, docs/ARCHITECTURE.md section 2).

`deployment_id`/`version` are process-wide (the same for every signal
this process emits) and therefore live here, in config -- not in the
per-request `infra.observability.context.CorrelationContext`
(docs/OBSERVABILITY.md section 2).

`ENVIRONMENT` and `LOG_LEVEL` intentionally reuse the same environment
variable *names* `core/config/settings.py` reads -- one deployment has one
environment/log level, and both modules independently read the same
conventional env var without importing each other (no `infra` -> `core`
dependency, docs/ARCHITECTURE.md section 2).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

_VALID_EXPORTERS = frozenset({"console", "none"})
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class ObservabilityConfigurationError(ValueError):
    """Raised when an environment variable holds an invalid value. Never
    includes a secret -- none of these fields are secrets (docs/SECURITY.md
    section 4).
    """


@dataclass(frozen=True)
class ObservabilityConfig:
    enabled: bool = True
    service_name: str = "saas-os"
    environment: str = "development"
    # "console": ConsoleSpanExporter, prints to stdout, no network --
    # the default, and the only exporter this phase implements (OTLP/
    # vendor export is explicitly out of scope -- docs/ADR/0009-...).
    # "none": no exporter attached at all (used together with enabled=False,
    # or standalone for an explicit no-op).
    exporter: str = "console"
    deployment_id: str = "local"
    version: str = "0.0.0"
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if self.exporter not in _VALID_EXPORTERS:
            allowed = sorted(_VALID_EXPORTERS)
            raise ObservabilityConfigurationError(
                f"OBSERVABILITY_EXPORTER must be one of {allowed}, got: {self.exporter!r}"
            )


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ObservabilityConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


def _observability_config_from_env() -> ObservabilityConfig:
    enabled_raw = os.environ.get("OBSERVABILITY_ENABLED")
    enabled = True if enabled_raw is None else _parse_bool("OBSERVABILITY_ENABLED", enabled_raw)
    return ObservabilityConfig(
        enabled=enabled,
        service_name=os.environ.get("OBSERVABILITY_SERVICE_NAME", "saas-os"),
        environment=os.environ.get("ENVIRONMENT", "development"),
        exporter=os.environ.get("OBSERVABILITY_EXPORTER", "console"),
        deployment_id=os.environ.get("DEPLOYMENT_ID", "local"),
        version=os.environ.get("VERSION", "0.0.0"),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    )


@lru_cache
def get_observability_config() -> ObservabilityConfig:
    """Cached configuration singleton, read once from the environment.
    Tests that need different environment variables should call
    `get_observability_config.cache_clear()` after `monkeypatch.setenv(...)`.
    """
    return _observability_config_from_env()
