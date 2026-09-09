"""Cross-cutting secret-value-safety tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.3 section 11, docs/SECURITY.md): a secret value must never surface
in `repr()`, exception text, or (for the exception raised on a missing
required secret) an object's default `str()`.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from infra.secrets.config import get_secrets_provider
from infra.secrets.provider import SecretNotFoundError
from infra.secrets.providers import EnvFileSecretsProvider, EnvironmentSecretsProvider

_FAKE_VALUE = "fake-super-secret-value-xyz"


@pytest.fixture(autouse=True)
def _clear_provider_cache() -> Iterator[None]:
    get_secrets_provider.cache_clear()
    yield
    get_secrets_provider.cache_clear()


def test_env_file_provider_repr_never_contains_a_parsed_value(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f"FAKE_SECRET={_FAKE_VALUE}\n", encoding="utf-8")
    provider = EnvFileSecretsProvider(path=env_file)
    provider.get("FAKE_SECRET")  # force a lookup; must still not leak
    assert _FAKE_VALUE not in repr(provider)


def test_environment_provider_repr_never_contains_a_resolved_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_SECRET", _FAKE_VALUE)
    provider = EnvironmentSecretsProvider()
    provider.get("FAKE_SECRET")
    assert _FAKE_VALUE not in repr(provider)


def test_get_secrets_provider_result_repr_never_contains_a_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end through the public factory, not just the concrete class."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("FAKE_SECRET", _FAKE_VALUE)
    provider = get_secrets_provider()
    provider.get("FAKE_SECRET")
    assert _FAKE_VALUE not in repr(provider)


def test_secret_not_found_error_repr_never_contains_a_value(tmp_path: Path) -> None:
    """The exception object itself, including its Python repr (as would
    appear in a traceback or pytest failure output), must carry only the
    secret's name -- confirmed by seeding an unrelated present secret with
    a fake value and raising for a different, missing name.
    """
    env_file = tmp_path / ".env"
    env_file.write_text(f"OTHER_SECRET={_FAKE_VALUE}\n", encoding="utf-8")
    provider = EnvFileSecretsProvider(path=env_file)
    with pytest.raises(SecretNotFoundError) as excinfo:
        provider.get_required("MISSING_ONE")
    assert _FAKE_VALUE not in repr(excinfo.value)
    assert _FAKE_VALUE not in str(excinfo.value)


def test_get_required_does_not_convert_a_present_but_empty_secret_to_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("EMPTY_SECRET", "")
    provider = get_secrets_provider()
    with pytest.raises(SecretNotFoundError):
        provider.get_required("EMPTY_SECRET")
