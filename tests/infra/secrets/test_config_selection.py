"""`get_secrets_provider()` selection (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.3, docs/ADR/0012-secrets-management.md): `ENVIRONMENT` picks the
implementation, and a required secret fails fast with a typed error
regardless of which implementation is active.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from infra.secrets.config import get_secrets_provider
from infra.secrets.provider import SecretNotFoundError, SecretsConfigurationError
from infra.secrets.providers import EnvFileSecretsProvider, EnvironmentSecretsProvider


@pytest.fixture(autouse=True)
def _clear_provider_cache() -> Iterator[None]:
    get_secrets_provider.cache_clear()
    yield
    get_secrets_provider.cache_clear()


def test_development_environment_selects_the_env_file_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    provider = get_secrets_provider()
    assert isinstance(provider, EnvFileSecretsProvider)


def test_unset_environment_defaults_to_the_env_file_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    provider = get_secrets_provider()
    assert isinstance(provider, EnvFileSecretsProvider)


def test_production_environment_selects_the_environment_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    provider = get_secrets_provider()
    assert isinstance(provider, EnvironmentSecretsProvider)


def test_test_environment_selects_the_environment_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "test")
    provider = get_secrets_provider()
    assert isinstance(provider, EnvironmentSecretsProvider)


def test_development_provider_never_runs_when_production_is_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-vacuous version of the roadmap's "dev implementation never runs
    under a production flag (and vice versa)" test: prove the *other*
    implementation is not merely absent from isinstance, but that the
    active provider genuinely ignores a value only the dev `.env` file
    would supply.
    """
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("ONLY_IN_ENV_FILE", raising=False)
    provider = get_secrets_provider()
    assert isinstance(provider, EnvironmentSecretsProvider)
    assert provider.get("ONLY_IN_ENV_FILE") is None


def test_invalid_environment_raises_configuration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "not-a-real-environment")
    with pytest.raises(SecretsConfigurationError):
        get_secrets_provider()


def test_secrets_env_file_override_is_honored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "custom.env"
    env_file.write_text(
        "FAKE_SECRET=fake-value-from-custom-file\n",  # pragma: allowlist secret
        encoding="utf-8",
    )
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRETS_ENV_FILE", str(env_file))
    provider = get_secrets_provider()
    assert (
        provider.get_required("FAKE_SECRET") == "fake-value-from-custom-file"
    )  # pragma: allowlist secret


def test_provider_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    first = get_secrets_provider()
    second = get_secrets_provider()
    assert first is second


def test_missing_required_secret_fails_fast_with_a_typed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("NEVER_SET_ANYWHERE", raising=False)
    provider = get_secrets_provider()
    with pytest.raises(SecretNotFoundError):
        provider.get_required("NEVER_SET_ANYWHERE")
