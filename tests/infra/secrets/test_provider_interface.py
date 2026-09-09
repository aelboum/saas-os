"""`SecretsProvider` interface behavior (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.3): `get_required()`'s fail-fast/no-silent-empty-string contract,
exercised against a minimal in-memory fake so these tests are independent
of any concrete provider's own I/O.
"""

from __future__ import annotations

import pytest
from infra.secrets.provider import SecretNotFoundError, SecretsProvider


class _FakeProvider(SecretsProvider):
    """Minimal concrete `SecretsProvider` backed by a plain dict -- exists
    only to exercise the base class's `get_required()` logic in isolation.
    """

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)


def test_get_returns_value_when_present() -> None:
    provider = _FakeProvider({"API_KEY": "fake-value-123"})
    assert provider.get("API_KEY") == "fake-value-123"


def test_get_returns_none_when_absent() -> None:
    provider = _FakeProvider({})
    assert provider.get("MISSING") is None


def test_get_required_returns_value_when_present() -> None:
    provider = _FakeProvider({"API_KEY": "fake-value-123"})
    assert provider.get_required("API_KEY") == "fake-value-123"


def test_get_required_raises_secret_not_found_when_absent() -> None:
    provider = _FakeProvider({})
    with pytest.raises(SecretNotFoundError) as excinfo:
        provider.get_required("MISSING")
    assert excinfo.value.name == "MISSING"


def test_get_required_raises_secret_not_found_when_empty() -> None:
    """A required secret that resolves to `""` must not be silently
    treated as present (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3: "do not
    silently convert missing required secrets into empty strings").
    """
    provider = _FakeProvider({"EMPTY": ""})
    with pytest.raises(SecretNotFoundError) as excinfo:
        provider.get_required("EMPTY")
    assert excinfo.value.name == "EMPTY"


def test_secret_not_found_error_message_names_the_secret() -> None:
    with pytest.raises(SecretNotFoundError) as excinfo:
        _FakeProvider({}).get_required("SOME_SECRET_NAME")
    assert "SOME_SECRET_NAME" in str(excinfo.value)


def test_secret_not_found_error_never_includes_a_value() -> None:
    """Non-vacuous secret-value-safety check: seed the fake with a
    secret-shaped value under a *different* name, and confirm raising for
    the *missing* required name never echoes any stored value.
    """
    provider = _FakeProvider({"OTHER_SECRET": "sk-should-never-appear"})
    with pytest.raises(SecretNotFoundError) as excinfo:
        provider.get_required("MISSING")
    assert "sk-should-never-appear" not in str(excinfo.value)
