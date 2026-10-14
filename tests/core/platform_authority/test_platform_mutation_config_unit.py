"""`PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS` (ADR-0045, amendment of
2026-10-14) -- hermetic."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from saas_os.core.platform_authority import (
    PlatformMutationConfig,
    PlatformMutationConfigurationError,
    get_platform_mutation_config,
)

_NAME = "PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS"


@pytest.fixture(autouse=True)
def _fresh_config() -> Iterator[None]:
    get_platform_mutation_config.cache_clear()
    yield
    get_platform_mutation_config.cache_clear()


def test_the_default_is_five_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_NAME, raising=False)
    assert get_platform_mutation_config() == PlatformMutationConfig(statement_timeout_ms=5_000)


@pytest.mark.parametrize("raw", ["100", "5000", "60000"])
def test_a_value_within_the_range_is_accepted(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(_NAME, raw)
    assert get_platform_mutation_config().statement_timeout_ms == int(raw)


@pytest.mark.parametrize("raw", ["0", "-1", "99", "60001", "", "5s", "5000.0", "none", "inf"])
def test_a_value_that_would_mean_no_timeout_or_is_not_an_integer_is_refused(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    """Zero, which PostgreSQL reads as "no timeout", is outside the range."""
    monkeypatch.setenv(_NAME, raw)
    with pytest.raises(PlatformMutationConfigurationError):
        get_platform_mutation_config()


@pytest.mark.parametrize("value", [True, 5000.0, "5000", None])
def test_the_config_object_refuses_a_value_that_is_not_an_integer(value: Any) -> None:
    with pytest.raises(PlatformMutationConfigurationError):
        PlatformMutationConfig(statement_timeout_ms=value)
