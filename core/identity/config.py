"""`core/identity` session-retention configuration (RA-12-5, following
RA-12-4's audit finding: "core.sessions" rows are never physically
cleaned up). Mirrors `core/tenancy/config.py`'s own shape exactly: plain,
non-secret tunables read directly from the environment, validated, cached
process-wide.

Three tunables, all operational policy this application chooses, not a
claimed legal retention requirement (`core/identity/session_retention.py`
restates this at its own point of use):

- `SESSION_REVOKED_GRACE_PERIOD_SECONDS` -- how long a *revoked* session
  row is kept after `revoked_at` before the cleanup job deletes it. A
  revoked session can never authenticate again the instant it is revoked
  (`core.identity.sessions.validate_session()`), so this grace period
  exists only so a short window remains for operational/security
  investigation of a just-revoked session (e.g. "was this the same
  session an incident review is looking at") before the row is gone.
  Default 86400 (24 hours).
- `SESSION_CLEANUP_BATCH_SIZE` -- the maximum number of rows one cleanup
  DELETE statement removes at a time (`core.identity.session_retention`).
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

from core.identity.errors import SessionRetentionConfigurationError

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
