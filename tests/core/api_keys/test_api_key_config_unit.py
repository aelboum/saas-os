"""`API_KEY_MAX_PER_USER` (ledger row 954; ADR-0045 amendment of
2026-10-31): a default, never unbounded, and a configuration error for any
value that is not an integer from 1 to 100000."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from saas_os.core.api_keys import ApiKeyConfigurationError, get_api_key_config


@pytest.fixture(autouse=True)
def _fresh_config(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("API_KEY_MAX_PER_USER", raising=False)
    get_api_key_config.cache_clear()
    yield
    get_api_key_config.cache_clear()


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_unset_or_empty_is_the_default_of_50(
    raw: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if raw is not None:
        monkeypatch.setenv("API_KEY_MAX_PER_USER", raw)
    assert get_api_key_config().max_per_user == 50


@pytest.mark.parametrize(("raw", "expected"), [("1", 1), (" 7 ", 7), ("100000", 100_000)])
def test_a_valid_value_is_used(raw: str, expected: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_KEY_MAX_PER_USER", raw)
    assert get_api_key_config().max_per_user == expected


@pytest.mark.parametrize("raw", ["0", "-1", "100001", "ten", "1.5", "5O"])
def test_an_invalid_value_is_a_configuration_error(
    raw: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("API_KEY_MAX_PER_USER", raw)
    with pytest.raises(ApiKeyConfigurationError):
        get_api_key_config()
