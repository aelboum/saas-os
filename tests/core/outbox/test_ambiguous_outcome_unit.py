"""`AmbiguousOutcomeError` and the outbox's record of an ambiguous outcome
(owner decision of 2026-11-01, ledger row F5;
design in PR #194).

No database: the typed error's contract and the `last_error` deadline tag
that keeps an idempotent-retry window without a migration. The state
transitions themselves run against PostgreSQL in
`tests/api/test_outbox_ambiguous_outcome_integration.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from saas_os.core.email.errors import EmailOutcomeUnknownError, EmailProviderError
from saas_os.core.notifications.errors import (
    NotificationAmbiguousDispatchError,
    NotificationDispatchError,
)
from saas_os.core.outbox import (
    AmbiguousOutcomeError,
    PermanentEventError,
    RetryAfterEventError,
    dispatch,
)
from saas_os.core.webhooks.errors import WebhookAmbiguousDeliveryError, WebhookDeliveryError

_DEADLINE = datetime(2026, 11, 2, 9, 30, 15, 987654, tzinfo=UTC)


def test_the_default_is_no_retry() -> None:
    error = AmbiguousOutcomeError("read_timeout", phase="read")
    assert (error.reason, error.phase, error.retry_within, error.at_least_once) == (
        "read_timeout",
        "read",
        None,
        False,
    )
    assert str(error) == "Outcome unknown: read_timeout (read)"
    # A category of its own: neither permanent nor a retry hint.
    assert not isinstance(error, PermanentEventError | RetryAfterEventError)


@pytest.mark.parametrize(
    "options",
    [
        {"retry_within": timedelta(hours=1), "at_least_once": True},
        {"retry_within": timedelta(0)},
        {"retry_within": timedelta(seconds=-1)},
    ],
)
def test_an_inconsistent_retry_policy_is_refused(options: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        AmbiguousOutcomeError("read_timeout", phase="read", **options)


def test_the_consumer_errors_carry_the_typed_outcome() -> None:
    import uuid

    recipient = uuid.uuid4()
    smtp = NotificationAmbiguousDispatchError(recipient, "SMTPServerDisconnected", phase="data")
    assert isinstance(smtp, NotificationDispatchError)
    assert isinstance(smtp, AmbiguousOutcomeError)
    assert (smtp.reason, smtp.phase, smtp.retry_within, smtp.at_least_once) == (
        "SMTPServerDisconnected",
        "data",
        None,
        False,
    )
    assert str(smtp) == f"Notification dispatch to recipient {recipient} failed: " + (
        "SMTPServerDisconnected"
    )
    resend = NotificationAmbiguousDispatchError(
        recipient, "read_timeout", phase="read", retry_within=timedelta(hours=23)
    )
    assert resend.retry_within == timedelta(hours=23)

    subscription = uuid.uuid4()
    webhook = WebhookAmbiguousDeliveryError(subscription, "ReadTimeout", phase="read")
    assert isinstance(webhook, WebhookDeliveryError)
    assert webhook.at_least_once is True and webhook.retry_within is None
    assert str(webhook) == f"Webhook delivery to subscription {subscription} failed: ReadTimeout"

    email = EmailOutcomeUnknownError("send", "read_timeout", phase="read")
    assert isinstance(email, EmailProviderError)
    assert email.permanent is False and email.retry_within is None


def test_the_deadline_tag_round_trips_and_is_never_later_than_the_deadline() -> None:
    tag = dispatch._deadline_tag(_DEADLINE)  # pyright: ignore[reportPrivateUsage]
    assert tag == "[idempotent-retry-until 2026-11-02T09:30:15+00:00]"
    parsed = dispatch._retry_deadline(f"OutcomeUnknown: x (read); y {tag}")  # pyright: ignore[reportPrivateUsage]
    assert parsed is not None and parsed <= _DEADLINE
    assert _DEADLINE - parsed < timedelta(seconds=1)


@pytest.mark.parametrize(
    "text", [None, "", "TimeoutError: client read timeout", "(idempotent-retry-until x)"]
)
def test_no_tag_means_no_deadline(text: str | None) -> None:
    assert dispatch._retry_deadline(text) is None  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "text",
    [
        "[idempotent-retry-until 2026-11-02T09:30:15+00:00] not at the end",
        "x [idempotent-retry-until not-a-time]",
        "x [idempotent-retry-until 2026-11-02T09:30:15]",  # naive
        "x [idempotent-retry-until 2026-11-02T09:30:15+01:00]",  # not UTC
        "x [idempotent-retry-until 2026-13-45T99:99:99+00:00]",  # not a time
        "x [idempotent-retry-until 2026-11-02T09:30:15+00:00",  # truncated
    ],
    ids=["moved", "garbage", "naive", "offset", "invalid", "truncated"],
)
def test_a_marker_that_is_not_an_exact_tag_fails_closed(text: str) -> None:
    """Review of #197: never a TypeError later (a naive time compared with
    an aware one), never "no deadline": a deadline long past, so a retry is
    dead-lettered for an operator instead of possibly repeating a send."""
    deadline = dispatch._retry_deadline(text)  # pyright: ignore[reportPrivateUsage]
    assert deadline == dispatch._DEADLINE_UNREADABLE  # pyright: ignore[reportPrivateUsage]
    assert deadline is not None and deadline.tzinfo is not None
    assert datetime.now(UTC) >= deadline


def test_an_error_message_can_never_forge_a_deadline_tag() -> None:
    """Review of #197: an exception's text (which may quote a remote server)
    is stored with the marker neutralised, so it neither sets a deadline nor
    is mistaken for one; only the dispatcher's own tag is read."""
    forged = "[idempotent-retry-until 2099-01-01T00:00:00+00:00]"
    text = dispatch.describe_error(RuntimeError(f"remote said {forged}"))
    assert "[idempotent-retry-until" not in text
    assert dispatch._retry_deadline(text) is None  # pyright: ignore[reportPrivateUsage]

    row: Any = SimpleNamespace(last_error=None)
    dispatch._record_error(row, RuntimeError(f"boom {forged}"))  # pyright: ignore[reportPrivateUsage]
    assert dispatch._retry_deadline(row.last_error) is None  # pyright: ignore[reportPrivateUsage]

    # A real tag survives a later failure whose text tries to replace it.
    tag = dispatch._deadline_tag(_DEADLINE)  # pyright: ignore[reportPrivateUsage]
    tagged: Any = SimpleNamespace(last_error=f"OutcomeUnknown: r (read); retried {tag}")
    dispatch._record_error(tagged, RuntimeError(f"boom {forged}"))  # pyright: ignore[reportPrivateUsage]
    assert tagged.last_error.endswith(tag)
    parsed = dispatch._retry_deadline(tagged.last_error)  # pyright: ignore[reportPrivateUsage]
    assert parsed is not None and parsed <= _DEADLINE


def test_a_later_failure_keeps_the_deadline_and_truncation_never_cuts_it() -> None:
    tag = dispatch._deadline_tag(_DEADLINE)  # pyright: ignore[reportPrivateUsage]
    row: Any = SimpleNamespace(last_error=f"OutcomeUnknown: read_timeout (read); retried {tag}")
    dispatch._record_error(row, "ConnectError: " + "x" * 2000)  # pyright: ignore[reportPrivateUsage]
    assert row.last_error.startswith("ConnectError: xxx")
    assert row.last_error.endswith(tag)
    assert len(row.last_error) <= 500
    assert dispatch._retry_deadline(row.last_error) is not None  # pyright: ignore[reportPrivateUsage]

    untagged: Any = SimpleNamespace(last_error="TimeoutError: earlier")
    dispatch._record_error(untagged, RuntimeError("boom"))  # pyright: ignore[reportPrivateUsage]
    assert untagged.last_error == "RuntimeError: boom"


def test_the_stored_text_names_category_and_phase_with_bounded_lengths() -> None:
    error = AmbiguousOutcomeError("r" * 1000, phase="p" * 1000)
    text = dispatch._outcome_unknown(error, "note")  # pyright: ignore[reportPrivateUsage]
    assert text == f"OutcomeUnknown: {'r' * 120} ({'p' * 40}); note"
