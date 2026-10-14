"""Statement timeouts of platform transactions
(docs/ADR/0045-installation-scoped-platform-authority.md section 9d and
its amendment of 2026-10-14): the oversight reads, and the platform
mutations a person performs together with the refusal rows.

Kept separate from `saas_os.core.config` for the reason
`saas_os.core.identity.config` gives: settings read by one feature.
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


class PlatformMutationConfigurationError(ValueError):
    """`PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS` is not an integer within
    the accepted range."""


@dataclass(frozen=True)
class PlatformMutationConfig:
    """`PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS`: the PostgreSQL statement
    timeout, in milliseconds, of every platform mutation a person (a
    `UserCaller`) performs, and of every refusal row written for a
    platform operation. Default 5 000 when unset.

    Between 100 and 60 000, with no value meaning "no timeout", for the
    reason `OversightReadConfig` gives: a mutation that waits on a lock
    without limit holds its connection, and the locks it already took,
    for as long as the lock it waits for is held. The value bounds each
    statement, lock waits included, not the transaction as a whole.

    A system purpose (`SystemCaller`: provisioning, purge, billing jobs)
    is not bounded by it: those run as commands and jobs, not as requests,
    and a purge may legitimately run long statements."""

    statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS

    def __post_init__(self) -> None:
        value = self.statement_timeout_ms
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not _MIN_STATEMENT_TIMEOUT_MS <= value <= _MAX_STATEMENT_TIMEOUT_MS
        ):
            raise PlatformMutationConfigurationError(
                "PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS must be an integer between "
                f"{_MIN_STATEMENT_TIMEOUT_MS} and {_MAX_STATEMENT_TIMEOUT_MS}, got: {value!r}"
            )


def _platform_mutation_config_from_env() -> PlatformMutationConfig:
    raw = os.environ.get("PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS")
    if raw is None:
        return PlatformMutationConfig()
    try:
        value = int(raw)
    except ValueError as exc:
        raise PlatformMutationConfigurationError(
            f"PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS must be an integer, got: {raw!r}"
        ) from exc
    return PlatformMutationConfig(statement_timeout_ms=value)


@lru_cache
def get_platform_mutation_config() -> PlatformMutationConfig:
    """Process-wide cached configuration singleton, read once from the
    environment and at startup, like `get_oversight_read_config()`."""
    return _platform_mutation_config_from_env()


@lru_cache
def get_oversight_read_config() -> OversightReadConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. `saas_os.api.platform`'s lifespan reads it at startup, so
    an invalid value stops the application before it serves a request.
    Tests that need a different value call
    `get_oversight_read_config.cache_clear()` after
    `monkeypatch.setenv(...)`."""
    return _oversight_read_config_from_env()
