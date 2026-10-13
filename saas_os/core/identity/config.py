"""`saas_os/core/identity` session-retention configuration (RA-12-5, following
RA-12-4's audit finding: "core.sessions" rows are never physically
cleaned up). Mirrors `saas_os/core/tenancy/config.py`'s own shape exactly: plain,
non-secret tunables read directly from the environment, validated, cached
process-wide.

Three tunables, all operational policy this application chooses, not a
claimed legal retention requirement (`saas_os/core/identity/session_retention.py`
restates this at its own point of use):

- `SESSION_REVOKED_GRACE_PERIOD_SECONDS` -- how long a *revoked* session
  row is kept after `revoked_at` before the cleanup job deletes it. A
  revoked session can never authenticate again the instant it is revoked
  (`saas_os.core.identity.sessions.validate_session()`), so this grace period
  exists only so a short window remains for operational/security
  investigation of a just-revoked session (e.g. "was this the same
  session an incident review is looking at") before the row is gone.
  Default 86400 (24 hours).
- `SESSION_CLEANUP_BATCH_SIZE` -- the maximum number of rows one cleanup
  DELETE statement removes at a time (`saas_os.core.identity.session_retention`).
  Bounds the size of any single deletion regardless of how large the
  backlog is. Default 500.
- `SESSION_CLEANUP_INTERVAL_SECONDS` -- how often production triggers the
  cleanup job (`deploy/saas-os-session-cleanup.timer`; see
  `docs/MULTI-TENANCY.md` section 6's RA-12-5 addendum). Purely
  documentation/operational metadata
  from this module's own point of view -- nothing here starts a timer;
  the value exists so the systemd timer file and this configuration
  cannot silently drift apart, the same cross-reference discipline
  `deploy/saas-os-backup.timer`'s own comment already uses for
  `BACKUP_SCHEDULE_HOUR_UTC`. Default 3600 (1 hour).

Missing configuration always falls back to these safe defaults -- never
to "unbounded" or "disabled".
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from saas_os.core.identity.errors import SessionRetentionConfigurationError

_DEFAULT_REVOKED_GRACE_PERIOD_SECONDS = 86_400
_DEFAULT_CLEANUP_BATCH_SIZE = 500
_DEFAULT_CLEANUP_INTERVAL_SECONDS = 3_600


@dataclass(frozen=True)
class SessionRetentionConfig:
    revoked_grace_period_seconds: int = _DEFAULT_REVOKED_GRACE_PERIOD_SECONDS
    cleanup_batch_size: int = _DEFAULT_CLEANUP_BATCH_SIZE
    cleanup_interval_seconds: int = _DEFAULT_CLEANUP_INTERVAL_SECONDS

    def __post_init__(self) -> None:
        if self.revoked_grace_period_seconds < 1:
            raise SessionRetentionConfigurationError(
                "SESSION_REVOKED_GRACE_PERIOD_SECONDS must be >= 1, got: "
                f"{self.revoked_grace_period_seconds}"
            )
        if self.cleanup_batch_size < 1:
            raise SessionRetentionConfigurationError(
                f"SESSION_CLEANUP_BATCH_SIZE must be >= 1, got: {self.cleanup_batch_size}"
            )
        if self.cleanup_interval_seconds < 1:
            raise SessionRetentionConfigurationError(
                f"SESSION_CLEANUP_INTERVAL_SECONDS must be >= 1, got: "
                f"{self.cleanup_interval_seconds}"
            )


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise SessionRetentionConfigurationError(
            f"{name} must be an integer, got: {raw!r}"
        ) from exc


def _session_retention_config_from_env() -> SessionRetentionConfig:
    grace_raw = os.environ.get("SESSION_REVOKED_GRACE_PERIOD_SECONDS")
    batch_raw = os.environ.get("SESSION_CLEANUP_BATCH_SIZE")
    interval_raw = os.environ.get("SESSION_CLEANUP_INTERVAL_SECONDS")

    return SessionRetentionConfig(
        revoked_grace_period_seconds=(
            _parse_int("SESSION_REVOKED_GRACE_PERIOD_SECONDS", grace_raw)
            if grace_raw is not None
            else _DEFAULT_REVOKED_GRACE_PERIOD_SECONDS
        ),
        cleanup_batch_size=(
            _parse_int("SESSION_CLEANUP_BATCH_SIZE", batch_raw)
            if batch_raw is not None
            else _DEFAULT_CLEANUP_BATCH_SIZE
        ),
        cleanup_interval_seconds=(
            _parse_int("SESSION_CLEANUP_INTERVAL_SECONDS", interval_raw)
            if interval_raw is not None
            else _DEFAULT_CLEANUP_INTERVAL_SECONDS
        ),
    )


@lru_cache
def get_session_retention_config() -> SessionRetentionConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. Tests that need a different value should call
    `get_session_retention_config.cache_clear()` after
    `monkeypatch.setenv(...)`.
    """
    return _session_retention_config_from_env()


# --- ADR-0045 section 11c, ruling R1: the deactivation scan ceiling ------------

_DEFAULT_DEACTIVATION_MAX_TENANTS = 10_000


class DeactivationScanConfigurationError(ValueError):
    """`PLATFORM_DEACTIVATION_MAX_TENANTS` is not a positive integer."""


@dataclass(frozen=True)
class DeactivationScanConfig:
    """`PLATFORM_DEACTIVATION_MAX_TENANTS`: how many tenants (rows of
    `core.tenants` that are not purged tombstones) `deactivate_user` may
    scan to discover where a user is a member. Default 10 000 when unset.

    Above the ceiling the operation refuses; it never truncates, skips or
    proceeds on a partial scan, because an invariant check over part of
    the registry is not a check. There is no value that means "unlimited"
    and no upper limit: a deployment may raise the ceiling and accepts the
    longer lock hold that follows. The ceiling bounds work. It says
    nothing about whether the operation's locking is correct."""

    max_tenants: int = _DEFAULT_DEACTIVATION_MAX_TENANTS

    def __post_init__(self) -> None:
        if self.max_tenants < 1:
            raise DeactivationScanConfigurationError(
                f"PLATFORM_DEACTIVATION_MAX_TENANTS must be >= 1, got: {self.max_tenants}"
            )


def _deactivation_scan_config_from_env() -> DeactivationScanConfig:
    raw = os.environ.get("PLATFORM_DEACTIVATION_MAX_TENANTS")
    if raw is None:
        return DeactivationScanConfig()
    try:
        value = int(raw)
    except ValueError as exc:
        raise DeactivationScanConfigurationError(
            f"PLATFORM_DEACTIVATION_MAX_TENANTS must be an integer, got: {raw!r}"
        ) from exc
    return DeactivationScanConfig(max_tenants=value)


@lru_cache
def get_deactivation_scan_config() -> DeactivationScanConfig:
    """Process-wide cached configuration singleton, read once from the
    environment. `saas_os.api.platform`'s lifespan reads it at startup, so
    an invalid value stops the application before it serves a request.
    Tests that need a different value call
    `get_deactivation_scan_config.cache_clear()` after
    `monkeypatch.setenv(...)`."""
    return _deactivation_scan_config_from_env()
