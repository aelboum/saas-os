"""Unit tests for `infra.db.backup.config` -- environment parsing/
validation for every `BackupPipelineConfig` field, plus an AST-level
proof (mirrors `tests/api/test_worker_unit.py`'s own pattern) that
`encryption.py`/`destination.py` never read a secret value through
`os.environ`/`os.getenv` directly -- `SecretsProvider` is the only
sanctioned path (docs/ADR/0012-secrets-management.md).
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
from infra.db.backup import destination as destination_module
from infra.db.backup import encryption as encryption_module
from infra.db.backup import orchestrator as orchestrator_module
from infra.db.backup.config import (
    BackupConfigurationError,
    BackupPipelineConfig,
    _backup_pipeline_config_from_env,
    get_backup_pipeline_config,
)


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    get_backup_pipeline_config.cache_clear()
    yield
    get_backup_pipeline_config.cache_clear()


# --- BackupPipelineConfig validation ---------------------------------------


def test_defaults_are_applied_when_only_staging_dir_is_given(tmp_path: Path) -> None:
    config = BackupPipelineConfig(staging_dir=tmp_path)
    assert config.off_site_enabled is False
    assert config.retention_count == 7
    assert config.schedule_hour_utc == 3
    assert config.rpo_hours == 24
    assert config.rto_hours == 4
    assert config.min_free_bytes == 500 * 1024 * 1024


def test_relative_staging_dir_is_rejected() -> None:
    with pytest.raises(BackupConfigurationError, match="BACKUP_STAGING_DIR"):
        BackupPipelineConfig(staging_dir=Path("relative/dir"))


@pytest.mark.parametrize("retention_count", [0, -1])
def test_non_positive_retention_count_is_rejected(tmp_path: Path, retention_count: int) -> None:
    with pytest.raises(BackupConfigurationError, match="BACKUP_RETENTION_COUNT"):
        BackupPipelineConfig(staging_dir=tmp_path, retention_count=retention_count)


@pytest.mark.parametrize("hour", [-1, 24, 100])
def test_out_of_range_schedule_hour_is_rejected(tmp_path: Path, hour: int) -> None:
    with pytest.raises(BackupConfigurationError, match="BACKUP_SCHEDULE_HOUR_UTC"):
        BackupPipelineConfig(staging_dir=tmp_path, schedule_hour_utc=hour)


def test_zero_rpo_hours_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(BackupConfigurationError, match="BACKUP_RPO_HOURS"):
        BackupPipelineConfig(staging_dir=tmp_path, rpo_hours=0)


def test_zero_rto_hours_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(BackupConfigurationError, match="BACKUP_RTO_HOURS"):
        BackupPipelineConfig(staging_dir=tmp_path, rto_hours=0)


def test_zero_min_free_bytes_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(BackupConfigurationError, match="BACKUP_MIN_FREE_BYTES"):
        BackupPipelineConfig(staging_dir=tmp_path, min_free_bytes=0)


# --- _backup_pipeline_config_from_env --------------------------------------


def test_missing_staging_dir_env_var_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BACKUP_STAGING_DIR", raising=False)
    with pytest.raises(BackupConfigurationError, match="BACKUP_STAGING_DIR"):
        _backup_pipeline_config_from_env()


def test_env_values_are_parsed_into_every_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BACKUP_STAGING_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_OFF_SITE_ENABLED", "true")
    monkeypatch.setenv("BACKUP_RETENTION_COUNT", "14")
    monkeypatch.setenv("BACKUP_SCHEDULE_HOUR_UTC", "5")
    monkeypatch.setenv("BACKUP_RPO_HOURS", "12")
    monkeypatch.setenv("BACKUP_RTO_HOURS", "2")
    monkeypatch.setenv("BACKUP_MIN_FREE_BYTES", "1000")

    config = _backup_pipeline_config_from_env()
    assert config.staging_dir == tmp_path
    assert config.off_site_enabled is True
    assert config.retention_count == 14
    assert config.schedule_hour_utc == 5
    assert config.rpo_hours == 12
    assert config.rto_hours == 2
    assert config.min_free_bytes == 1000


@pytest.mark.parametrize("raw", ["1", "true", "yes", "on", "TRUE", "On"])
def test_off_site_enabled_truthy_strings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv("BACKUP_STAGING_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_OFF_SITE_ENABLED", raw)
    assert _backup_pipeline_config_from_env().off_site_enabled is True


@pytest.mark.parametrize("raw", ["0", "false", "no", "off"])
def test_off_site_enabled_falsy_strings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv("BACKUP_STAGING_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_OFF_SITE_ENABLED", raw)
    assert _backup_pipeline_config_from_env().off_site_enabled is False


def test_off_site_enabled_garbage_string_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BACKUP_STAGING_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_OFF_SITE_ENABLED", "maybe")
    with pytest.raises(BackupConfigurationError, match="BACKUP_OFF_SITE_ENABLED"):
        _backup_pipeline_config_from_env()


def test_non_integer_retention_count_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BACKUP_STAGING_DIR", str(tmp_path))
    monkeypatch.setenv("BACKUP_RETENTION_COUNT", "not-a-number")
    with pytest.raises(BackupConfigurationError, match="BACKUP_RETENTION_COUNT"):
        _backup_pipeline_config_from_env()


def test_get_backup_pipeline_config_is_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BACKUP_STAGING_DIR", str(tmp_path))
    first = get_backup_pipeline_config()
    monkeypatch.setenv("BACKUP_STAGING_DIR", str(tmp_path / "other"))
    second = get_backup_pipeline_config()
    assert first is second  # cached -- env change alone does not take effect

    get_backup_pipeline_config.cache_clear()
    third = get_backup_pipeline_config()
    assert third.staging_dir == tmp_path / "other"


# --- AST proof: no direct os.environ/os.getenv secret access --------------


@pytest.mark.parametrize("module", [encryption_module, destination_module, orchestrator_module])
def test_module_never_reads_secrets_via_os_environ_directly(module: ModuleType) -> None:
    tree = ast.parse(inspect.getsource(module))
    attribute_accesses = {
        f"{node.value.id}.{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
    }
    assert "os.environ" not in attribute_accesses
    assert "os.getenv" not in attribute_accesses
    subscripted_environ = any(
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "environ"
        for node in ast.walk(tree)
    )
    assert not subscripted_environ
