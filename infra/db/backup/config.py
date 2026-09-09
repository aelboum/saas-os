"""P2.4 -- non-secret backup pipeline configuration. Mirrors
`core/email/config.py`'s exact shape: plain connection/policy tunables
read directly from the environment, validated, cached process-wide.
Secrets (encryption keys, S3 credentials) are deliberately never here --
`encryption.py`/`destination.py` each read their own secret through
`infra.secrets.get_secrets_provider()` at the point of use.

`RPO_HOURS`/`RTO_HOURS` are documented, configurable *targets* (this
checkpoint's own "these are engineering targets, not guarantees" --
nothing in this module or anywhere else in this repository enforces
them; they exist so an operator's actual schedule/retention configuration
can be checked for consistency against a stated target, and so
`docs/BACKUP-RESTORE.md` has one source of truth instead of a
documentation-only claim that configuration could silently drift from).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DEFAULT_RETENTION_COUNT = 7
_DEFAULT_SCHEDULE_HOUR_UTC = 3
_DEFAULT_RPO_HOURS = 24
_DEFAULT_RTO_HOURS = 4
_DEFAULT_MIN_FREE_BYTES = 500 * 1024 * 1024  # 500 MiB


class BackupConfigurationError(ValueError):
    """Raised for a missing/invalid non-secret backup setting. Never
    includes a secret -- none of these fields is one."""


@dataclass(frozen=True)
class BackupPipelineConfig:
    staging_dir: Path
    off_site_enabled: bool = False
    retention_count: int = _DEFAULT_RETENTION_COUNT
    schedule_hour_utc: int = _DEFAULT_SCHEDULE_HOUR_UTC
    rpo_hours: int = _DEFAULT_RPO_HOURS
    rto_hours: int = _DEFAULT_RTO_HOURS
    min_free_bytes: int = _DEFAULT_MIN_FREE_BYTES

    def __post_init__(self) -> None:
        if not self.staging_dir.is_absolute():
            raise BackupConfigurationError("BACKUP_STAGING_DIR must be an absolute path.")
        if self.retention_count < 1:
            raise BackupConfigurationError(
                f"BACKUP_RETENTION_COUNT must be >= 1, got: {self.retention_count}"
            )
        if not 0 <= self.schedule_hour_utc <= 23:
            raise BackupConfigurationError(
                f"BACKUP_SCHEDULE_HOUR_UTC must be 0-23, got: {self.schedule_hour_utc}"
            )
        if self.rpo_hours < 1:
            raise BackupConfigurationError(f"BACKUP_RPO_HOURS must be >= 1, got: {self.rpo_hours}")
        if self.rto_hours < 1:
            raise BackupConfigurationError(f"BACKUP_RTO_HOURS must be >= 1, got: {self.rto_hours}")
        if self.min_free_bytes < 1:
            raise BackupConfigurationError("BACKUP_MIN_FREE_BYTES must be >= 1.")


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise BackupConfigurationError(f"{name} must be a boolean-like value, got: {raw!r}")


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise BackupConfigurationError(f"{name} must be an integer, got: {raw!r}") from exc


def _backup_pipeline_config_from_env() -> BackupPipelineConfig:
    staging_dir_raw = os.environ.get("BACKUP_STAGING_DIR")
    if not staging_dir_raw:
        raise BackupConfigurationError(
            "BACKUP_STAGING_DIR is not set. Copy .env.example to .env and set an absolute path."
        )
    off_site_raw = os.environ.get("BACKUP_OFF_SITE_ENABLED")
    retention_raw = os.environ.get("BACKUP_RETENTION_COUNT")
    schedule_raw = os.environ.get("BACKUP_SCHEDULE_HOUR_UTC")
    rpo_raw = os.environ.get("BACKUP_RPO_HOURS")
    rto_raw = os.environ.get("BACKUP_RTO_HOURS")
    min_free_raw = os.environ.get("BACKUP_MIN_FREE_BYTES")

    return BackupPipelineConfig(
        staging_dir=Path(staging_dir_raw),
        off_site_enabled=(
            _parse_bool("BACKUP_OFF_SITE_ENABLED", off_site_raw)
            if off_site_raw is not None
            else False
        ),
        retention_count=(
            _parse_int("BACKUP_RETENTION_COUNT", retention_raw)
            if retention_raw is not None
            else _DEFAULT_RETENTION_COUNT
        ),
        schedule_hour_utc=(
            _parse_int("BACKUP_SCHEDULE_HOUR_UTC", schedule_raw)
            if schedule_raw is not None
            else _DEFAULT_SCHEDULE_HOUR_UTC
        ),
        rpo_hours=(
            _parse_int("BACKUP_RPO_HOURS", rpo_raw) if rpo_raw is not None else _DEFAULT_RPO_HOURS
        ),
        rto_hours=(
            _parse_int("BACKUP_RTO_HOURS", rto_raw) if rto_raw is not None else _DEFAULT_RTO_HOURS
        ),
        min_free_bytes=(
            _parse_int("BACKUP_MIN_FREE_BYTES", min_free_raw)
            if min_free_raw is not None
            else _DEFAULT_MIN_FREE_BYTES
        ),
    )


@lru_cache
def get_backup_pipeline_config() -> BackupPipelineConfig:
    """Process-wide cached singleton. Tests call
    `get_backup_pipeline_config.cache_clear()` after `monkeypatch.setenv(...)`."""
    return _backup_pipeline_config_from_env()
