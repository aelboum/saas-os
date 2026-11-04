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
from saas_os.core.outbox.config import MIN_LEASE_SECONDS, get_outbox_dispatch_config
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


# --- Review of b6a7f07 (LOW): a malformed stored initiator never fails the event -------


@pytest.mark.parametrize(
    "stored",
    [
        {"type": ["user"], "user_id": "00000000-0000-0000-0000-000000000001"},
        {"type": {"nested": True}},
        {"type": "system", "kind": ["worker_job"], "name": "x"},
        {"type": "user", "user_id": "00000000-0000-0000-0000-00000000000A"},
        ["not", "a", "dict"],
        42,
    ],
)
def test_a_malformed_stored_initiator_is_unavailable_and_logged(
    stored: object, caplog: pytest.LogCaptureFixture
) -> None:
    import logging
    import uuid

    from saas_os.core.outbox.dispatch import _split_initiator

    event_id = uuid.uuid4()
    with caplog.at_level(logging.WARNING, logger="saas_os.core.outbox.dispatch"):
        payload, initiator = _split_initiator(event_id, {"n": 1, "saas_os.initiated_by": stored})
    assert payload == {"n": 1}
    assert initiator is None
    assert "outbox_event_initiator_unreadable" in caplog.text


@pytest.mark.parametrize("error", [TypeError("unhashable"), ValueError("bad")])
def test_any_parse_error_of_a_stored_initiator_is_unavailable(
    error: Exception, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Defence in depth: whatever the parser raises for a malformed stored
    initiator, the event runs with the initiator unavailable."""
    import logging
    import uuid

    from saas_os.core.outbox import dispatch

    def _raise(value: object) -> None:
        raise error

    monkeypatch.setattr(dispatch.Initiator, "from_metadata", staticmethod(_raise))
    with caplog.at_level(logging.WARNING, logger="saas_os.core.outbox.dispatch"):
        payload, initiator = dispatch._split_initiator(
            uuid.uuid4(), {"n": 1, "saas_os.initiated_by": {"type": "user"}}
        )
    assert (payload, initiator) == ({"n": 1}, None)
    assert "outbox_event_initiator_unreadable" in caplog.text


def test_the_minimum_lease_covers_the_outbox_job_and_its_consumer_deadline() -> None:
    """Ledger row F5 (review of #189): a lease shorter than the outbox job's
    time limit lets another dispatcher reclaim and re-run an event whose
    first consumer is still inside its deadline."""
    from saas_os.api.outbox_dispatcher import OUTBOX_CONSUMER_TIMEOUT_SECONDS
    from saas_os.infra.jobs.queue import HANDLER_TIMEOUT_SECONDS

    assert MIN_LEASE_SECONDS > HANDLER_TIMEOUT_SECONDS > OUTBOX_CONSUMER_TIMEOUT_SECONDS
    assert OutboxDispatchConfig().lease_seconds >= MIN_LEASE_SECONDS


@pytest.mark.parametrize("lease", ["1", "270", "300", "359.9"])
def test_a_lease_shorter_than_the_job_is_refused_at_load(
    monkeypatch: pytest.MonkeyPatch, lease: str
) -> None:
    get_outbox_dispatch_config.cache_clear()
    monkeypatch.setenv("OUTBOX_LEASE_SECONDS", lease)
    try:
        with pytest.raises(OutboxConfigurationError, match="OUTBOX_LEASE_SECONDS"):
            get_outbox_dispatch_config()
    finally:
        get_outbox_dispatch_config.cache_clear()


def test_the_minimum_lease_itself_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    get_outbox_dispatch_config.cache_clear()
    monkeypatch.setenv("OUTBOX_LEASE_SECONDS", "360")
    try:
        assert get_outbox_dispatch_config().lease_seconds == MIN_LEASE_SECONDS
    finally:
        get_outbox_dispatch_config.cache_clear()
