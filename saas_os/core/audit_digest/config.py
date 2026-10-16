"""Tunables for the audit digests (docs/ADR/0053-audit-digests-in-external-logs.md).
Plain, non-secret values read from the environment, each with a default;
`get_audit_digest_config()` is cached like every other module config."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache


class AuditDigestConfigurationError(ValueError):
    """An audit-digest tunable is malformed or out of range."""


@dataclass(frozen=True)
class AuditDigestConfig:
    """
    window_seconds           length of a digested window; a divisor of
                             86400 and at least 300, so windows align to
                             UTC days
    settle_seconds           how long after a window's end it is digested.
                             A row carries its transaction's start time, so
                             this must exceed the longest transaction that
                             writes audit rows
    max_windows_per_run      windows digested per run (catch-up bound)
    """

    window_seconds: int = 3600
    settle_seconds: int = 900
    max_windows_per_run: int = 24

    def __post_init__(self) -> None:
        if self.window_seconds < 300 or 86400 % self.window_seconds:
            raise AuditDigestConfigurationError(
                "AUDIT_DIGEST_WINDOW_SECONDS must be a divisor of 86400 and >= 300"
            )
        if self.settle_seconds < 60:
            raise AuditDigestConfigurationError("AUDIT_DIGEST_SETTLE_SECONDS must be >= 60")
        if self.max_windows_per_run < 1:
            raise AuditDigestConfigurationError("AUDIT_DIGEST_MAX_WINDOWS_PER_RUN must be >= 1")

    @property
    def window(self) -> timedelta:
        return timedelta(seconds=self.window_seconds)

    @property
    def settle(self) -> timedelta:
        return timedelta(seconds=self.settle_seconds)


_INT_FIELDS = {
    "window_seconds": "AUDIT_DIGEST_WINDOW_SECONDS",
    "settle_seconds": "AUDIT_DIGEST_SETTLE_SECONDS",
    "max_windows_per_run": "AUDIT_DIGEST_MAX_WINDOWS_PER_RUN",
}


@lru_cache
def get_audit_digest_config() -> AuditDigestConfig:
    values: dict[str, int] = {}
    for field, name in _INT_FIELDS.items():
        raw = os.environ.get(name)
        if raw is not None:
            try:
                values[field] = int(raw)
            except ValueError as exc:
                raise AuditDigestConfigurationError(
                    f"{name} must be an integer, got {raw!r}"
                ) from exc
    return AuditDigestConfig(**values)
