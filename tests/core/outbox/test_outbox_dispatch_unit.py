"""Durable outbox dispatch policy (Foundation Reliability & Events, RE-2):
retry backoff, jitter bounds and configuration validation. No database."""

from __future__ import annotations

import math
from datetime import timedelta

import pytest

from saas_os.core.outbox import (
    OutboxConfigurationError,
    OutboxDispatchConfig,
    RetryAfterEventError,
    retry_delay,
    retry_hint_delay,
)
from saas_os.core.outbox.config import get_outbox_dispatch_config
from saas_os.core.outbox.dispatch import describe_error

_NO_JITTER = OutboxDispatchConfig(
    retry_base_seconds=30, retry_max_seconds=600, retry_jitter_ratio=0
)


def test_retry_delay_doubles_per_attempt_up_to_the_cap() -> None:
    delays = [retry_delay(n, _NO_JITTER).total_seconds() for n in range(1, 8)]
    assert delays == [30, 60, 120, 240, 480, 600, 600]


def test_jitter_only_ever_adds_and_stays_within_its_ratio() -> None:
    config = OutboxDispatchConfig(
        retry_base_seconds=100, retry_max_seconds=100, retry_jitter_ratio=0.2
    )
    assert retry_delay(1, config, lambda: 0.0) == timedelta(seconds=100)
    highest = retry_delay(1, config, lambda: 0.999999).total_seconds()
    assert 100 < highest < 120


def test_default_policy_never_retries_in_a_tight_loop() -> None:
    config = OutboxDispatchConfig()
    assert retry_delay(1, config, lambda: 0.0) >= timedelta(seconds=30)
    assert config.max_attempts > 3  # not the ARQ max_tries=3 default
    assert config.lease_seconds > 300  # longer than ARQ's job timeout


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_attempts": 0},
        {"retry_base_seconds": 0},
        {"retry_base_seconds": 100, "retry_max_seconds": 10},
        {"retry_jitter_ratio": 1.5},
        {"lease_seconds": 0},
        {"enqueue_retry_seconds": 0},
        {"batch_size": 0},
        {"per_tenant_limit": 0},
        {"poll_seconds": 7},
        {"retry_hint_max_seconds": 0},
        {"retry_hint_max_seconds": 31 * 86_400 + 1},
    ],
)
def test_invalid_policy_is_refused(overrides: dict[str, float]) -> None:
    with pytest.raises(OutboxConfigurationError):
        OutboxDispatchConfig(**overrides)  # type: ignore[arg-type]


def test_policy_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    get_outbox_dispatch_config.cache_clear()
    monkeypatch.setenv("OUTBOX_MAX_ATTEMPTS", "4")
    monkeypatch.setenv("OUTBOX_LEASE_SECONDS", "1200")
    try:
        config = get_outbox_dispatch_config()
        assert (config.max_attempts, config.lease_seconds) == (4, 1200)
        monkeypatch.setenv("OUTBOX_MAX_ATTEMPTS", "many")
        get_outbox_dispatch_config.cache_clear()
        with pytest.raises(OutboxConfigurationError):
            get_outbox_dispatch_config()
    finally:
        get_outbox_dispatch_config.cache_clear()


def test_the_recorded_error_is_bounded() -> None:
    assert describe_error(ValueError("x" * 2000)).startswith("ValueError: x")
    assert len(describe_error(ValueError("x" * 2000))) == 500


def test_the_recorded_error_holds_no_nul() -> None:
    """PostgreSQL text cannot store NUL; redis-py's errors can contain one."""
    recorded = describe_error(ValueError("PSETEX arq:job:1 \x80\x05\x00\x00 end"))
    assert "\x00" not in recorded
    assert recorded == "ValueError: PSETEX arq:job:1 \x80\x05\ufffd\ufffd end"
    assert "\x00" not in describe_error("\x00" * 600)
    assert len(describe_error("\x00" * 600)) == 500


# --- retry hints (outbox decision brief Q1, option 1A) ---------------------------


_HINT_CAP = OutboxDispatchConfig(retry_hint_max_seconds=3600)


@pytest.mark.parametrize(
    ("hint", "seconds"),
    [
        (120, 120),
        (120.5, 120.5),
        (3600, 3600),
        (7200, 3600),  # capped
        (math.inf, 3600),  # "as long as the bound allows"
        (0, 0),
        (-5, 0),
        (math.nan, 0),
        (True, 0),
        ("120", 0),
        (None, 0),
    ],
)
def test_a_retry_hint_is_bounded_and_anything_unreadable_is_no_hint(
    hint: object, seconds: float
) -> None:
    assert retry_hint_delay(hint, _HINT_CAP) == timedelta(seconds=seconds)


def test_the_default_hint_bound_is_one_day() -> None:
    assert OutboxDispatchConfig().retry_hint_max_seconds == 86_400
    assert retry_hint_delay(math.inf, OutboxDispatchConfig()) == timedelta(days=1)


def test_the_hint_bound_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    get_outbox_dispatch_config.cache_clear()
    monkeypatch.setenv("OUTBOX_RETRY_HINT_MAX_SECONDS", "600")
    try:
        assert get_outbox_dispatch_config().retry_hint_max_seconds == 600
    finally:
        get_outbox_dispatch_config.cache_clear()


def test_a_retry_after_error_carries_its_hint_and_a_category_only() -> None:
    error = RetryAfterEventError(30, "rate_limit_exceeded")
    assert error.retry_after_seconds == 30
    assert str(error) == "rate_limit_exceeded"
