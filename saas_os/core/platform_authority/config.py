"""Configuration of the platform oversight reads
(docs/ADR/0045-installation-scoped-platform-authority.md section 9d).

Kept separate from `saas_os.core.config` for the reason
`saas_os.core.identity.config` gives: one setting, read by one feature.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

_DEFAULT_STATEMENT_TIMEOUT_MS = 5_000
_MIN_STATEMENT_TIMEOUT_MS = 100
_MAX_STATEMENT_TIMEOUT_MS = 60_000


class OversightReadConfigurationError(ValueError):
    """`PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS` is not an integer within
    the accepted range."""


@dataclass(frozen=True)
class OversightReadConfig:
    """`PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS`: the PostgreSQL statement
    timeout, in milliseconds, of both transactions of every oversight
    read. Default 5 000 when unset.

    Between 100 and 60 000. There is no value that means "no timeout": an
    oversight read that can wait without limit holds a connection, and the
    attempt row it has already committed, for as long as the database lets
    it. The value bounds each statement of a transaction, lock waits
    included, not the transaction as a whole."""

    statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS

    def __post_init__(self) -> None:
        value = self.statement_timeout_ms
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not _MIN_STATEMENT_TIMEOUT_MS <= value <= _MAX_STATEMENT_TIMEOUT_MS
        ):
            raise OversightReadConfigurationError(
                "PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS must be an integer between "
                f"{_MIN_STATEMENT_TIMEOUT_MS} and {_MAX_STATEMENT_TIMEOUT_MS}, got: {value!r}"
            )


def _oversight_read_config_from_env() -> OversightReadConfig:
    raw = os.environ.get("PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS")
    if raw is None:
        return OversightReadConfig()
    try:
        value = int(raw)
    except ValueError as exc:
        raise OversightReadConfigurationError(
            f"PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS must be an integer, got: {raw!r}"
        ) from exc
    return OversightReadConfig(statement_timeout_ms=value)


@lru_cache
def get_oversight_read_config() -> OversightReadConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. `saas_os.api.platform`'s lifespan reads it at startup, so
    an invalid value stops the application before it serves a request.
    Tests that need a different value call
    `get_oversight_read_config.cache_clear()` after
    `monkeypatch.setenv(...)`."""
    return _oversight_read_config_from_env()
