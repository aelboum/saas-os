"""`EnvironmentSecretsProvider` -- Docker/host production implementation
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.3, docs/ADR/0012-secrets-management.md).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from infra.secrets.provider import SecretsConfigurationError
from infra.secrets.providers import EnvironmentSecretsProvider


def test_reads_a_value_from_the_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_SECRET", "fake-value-abc")
    provider = EnvironmentSecretsProvider()
    assert provider.get("FAKE_SECRET") == "fake-value-abc"


def test_missing_key_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFINITELY_NOT_SET", raising=False)
    provider = EnvironmentSecretsProvider()
    assert provider.get("DEFINITELY_NOT_SET") is None


def test_reads_a_value_from_a_docker_secrets_file_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `<NAME>_FILE` convention (ADR-0012: "env vars or files mounted
    via Docker Compose secrets:")."""
    secret_file = tmp_path / "fake_secret"
    secret_file.write_text("fake-value-from-file\n", encoding="utf-8")
    monkeypatch.delenv("FAKE_SECRET", raising=False)
    monkeypatch.setenv("FAKE_SECRET_FILE", str(secret_file))
    provider = EnvironmentSecretsProvider()
    assert provider.get("FAKE_SECRET") == "fake-value-from-file"


def test_direct_env_var_takes_precedence_over_file_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "fake_secret"
    secret_file.write_text("from-file", encoding="utf-8")
    monkeypatch.setenv("FAKE_SECRET", "from-environ")
    monkeypatch.setenv("FAKE_SECRET_FILE", str(secret_file))
    provider = EnvironmentSecretsProvider()
    assert provider.get("FAKE_SECRET") == "from-environ"


def test_unreadable_file_mount_raises_configuration_error_not_leaking_path_or_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FAKE_SECRET", raising=False)
    monkeypatch.setenv("FAKE_SECRET_FILE", "/definitely/does/not/exist/fake_secret")
    provider = EnvironmentSecretsProvider()
    with pytest.raises(SecretsConfigurationError) as excinfo:
        provider.get("FAKE_SECRET")
    assert "FAKE_SECRET" in str(excinfo.value)


def test_repr_does_not_leak_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_SECRET", "fake-value-abc")
    provider = EnvironmentSecretsProvider()
    provider.get("FAKE_SECRET")
    assert "fake-value-abc" not in repr(provider)
    assert "fake-value-abc" not in str(provider)
