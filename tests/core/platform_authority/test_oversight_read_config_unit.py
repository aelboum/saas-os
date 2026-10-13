"""`PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS` and the statement-timeout
helper's argument check (ADR-0045 section 9d) -- hermetic."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from saas_os.core.platform_authority import (
    OversightReadConfig,
    OversightReadConfigurationError,
    get_oversight_read_config,
)
from saas_os.infra.db import is_statement_timeout, set_local_statement_timeout

_NAME = "PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS"


@pytest.fixture(autouse=True)
def _fresh_config() -> Iterator[None]:
    get_oversight_read_config.cache_clear()
    yield
    get_oversight_read_config.cache_clear()


def test_the_default_is_five_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_NAME, raising=False)
    assert get_oversight_read_config() == OversightReadConfig(statement_timeout_ms=5_000)


@pytest.mark.parametrize("raw", ["100", "5000", "60000"])
def test_a_value_within_the_range_is_accepted(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(_NAME, raw)
    assert get_oversight_read_config().statement_timeout_ms == int(raw)


@pytest.mark.parametrize("raw", ["0", "-1", "99", "60001", "", "5s", "5000.0", "none", "inf"])
def test_a_value_that_would_mean_no_timeout_or_is_not_an_integer_is_refused(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    """There is no value that disables the timeout: zero, which PostgreSQL
    reads as "none", is outside the range like any other."""
    monkeypatch.setenv(_NAME, raw)
    with pytest.raises(OversightReadConfigurationError):
        get_oversight_read_config()


@pytest.mark.parametrize("value", [True, 5000.0, "5000", None])
def test_the_config_object_refuses_a_value_that_is_not_an_integer(value: Any) -> None:
    with pytest.raises(OversightReadConfigurationError):
        OversightReadConfig(statement_timeout_ms=value)


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, statement: Any, parameters: dict[str, object]) -> None:
        self.calls.append((str(statement), parameters))


def test_the_helper_binds_the_value_and_sets_it_for_the_transaction_only() -> None:
    session = _Recorder()
    set_local_statement_timeout(session, 250)  # type: ignore[arg-type]
    ((statement, parameters),) = session.calls
    # `is_local = true`: PostgreSQL resets it at COMMIT or ROLLBACK.
    assert statement == "SELECT set_config('statement_timeout', :milliseconds, true)"
    assert parameters == {"milliseconds": "250"}  # bound, never interpolated


@pytest.mark.parametrize("value", [0, -5, True, 1.5, "250", None, 2**31])
def test_the_helper_refuses_anything_but_a_positive_integer(value: Any) -> None:
    session = _Recorder()
    with pytest.raises(ValueError):
        set_local_statement_timeout(session, value)  # type: ignore[arg-type]
    assert session.calls == []  # nothing was sent


class _Driver(Exception):
    def __init__(self, sqlstate: str | None) -> None:
        self.sqlstate = sqlstate


class _Wrapped(Exception):
    def __init__(self, orig: object) -> None:
        self.orig = orig


def test_only_a_cancelled_statement_is_a_statement_timeout() -> None:
    assert is_statement_timeout(_Wrapped(_Driver("57014")))
    assert not is_statement_timeout(_Wrapped(_Driver("40P01")))  # a deadlock
    assert not is_statement_timeout(_Wrapped(_Driver(None)))
    assert not is_statement_timeout(_Wrapped(None))
    assert not is_statement_timeout(RuntimeError("57014"))
