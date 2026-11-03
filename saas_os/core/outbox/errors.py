"""Typed errors for `saas_os/core/outbox` (Foundation Reliability & Events, RE-1).
Errors carry only the offending field's name and a reason -- never the
event payload, which may hold tenant data."""

from __future__ import annotations

from datetime import timedelta

from saas_os.infra.jobs.errors import NonRetriableJobError


class InvalidOutboxEventError(ValueError):
    """`append_event()` was given a malformed event. Raised before anything
    is written, so the caller's transaction is untouched."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid outbox event {field}: {reason}.")


class PermanentEventError(Exception):
    """Raised by an outbox event's consumer when retrying cannot succeed: a
    malformed event, a destination that permanently refuses it, or a
    security-policy rejection (RE-4). The dispatcher dead-letters the event
    at once instead of spending its remaining attempts. Any other exception
    is treated as transient and retried with backoff. The message must
    carry identifiers and a category only, never payload content -- it is
    stored as the event's `last_error`."""


class RetryAfterEventError(Exception):
    """Raised by an outbox event's consumer when the destination asked to be
    retried later: a provider's `Retry-After`, or a quota that resets at a
    known boundary (outbox decision brief Q1, option 1A). The dispatcher
    schedules the next attempt no earlier than `retry_after_seconds` from
    now, bounded by `OUTBOX_RETRY_HINT_MAX_SECONDS` (default 86400), and
    never earlier than the ordinary backoff. The attempt is still counted,
    so an event that keeps being deferred is still dead-lettered once its
    attempts run out.

    `retry_after_seconds` may be `math.inf` ("as long as the bound
    allows"). A negative, `NaN` or non-numeric value is read as no hint.
    The message must carry identifiers and a category only, never payload
    content -- it is stored as the event's `last_error`."""

    retry_after_seconds: float

    def __init__(self, retry_after_seconds: float, reason: str) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(reason)


class AmbiguousOutcomeError(NonRetriableJobError):
    """Raised by an outbox event's consumer when its external request may
    already have been sent and its outcome is unknown: a write or read
    timeout, a connection closed before a complete answer, an unreadable
    acceptance (owner decision of 2026-11-01, ledger row F5;
    design in PR #194). Only the
    transport that saw the phase raises it: a generic `TimeoutError` alone
    never proves that nothing was sent. A bare `TimeoutError` that escapes
    a consumer unclassified is itself treated as ambiguous, with no retry
    policy (owner decision D of 2026-11-01; `ConfirmedNotSentError`).

    An ambiguous outcome is never recorded as success. By default the
    dispatcher dead-letters the event at once with `last_error`
    `OutcomeUnknown: <reason> (<phase>)`; an operator brings it back with the
    audited replay (`saas-os-operator replay-outbox-events`) after checking
    the destination. A consumer whose operation has a safe idempotency
    mechanism may declare one retry policy instead:

    - `retry_within`: the destination de-duplicates a repeated request (the
      same idempotency key with an identical payload) for a known period.
      The event is retried with the normal backoff, the attempt counted,
      only while the retry can run before the event's creation time
      (`core.outbox_events.created_at`, a lower bound of the first send
      attempt) plus `retry_within`; after that it is dead-lettered, and a
      retry still pending when the window closes is dead-lettered instead of
      running.
    - `at_least_once`: the destination's documented contract is
      at-least-once with a stable identity it de-duplicates on (webhooks:
      the `event_id`). The event is retried within the normal attempt
      budget and dead-lettered when the attempts run out.

    `reason` and `phase` are short categories (`read_timeout`, `read`); they
    are stored as `last_error`, so they never carry a URL, a recipient, a
    secret or payload content."""

    reason: str
    phase: str
    retry_within: timedelta | None
    at_least_once: bool

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if issubclass(cls, ConfirmedNotSentError):
            raise TypeError("an error cannot be both ambiguous and confirmed not sent")

    def __init__(
        self,
        reason: str,
        *,
        phase: str,
        retry_within: timedelta | None = None,
        at_least_once: bool = False,
    ) -> None:
        if retry_within is not None and at_least_once:
            raise ValueError("an ambiguous outcome declares at most one retry policy")
        if retry_within is not None and retry_within <= timedelta(0):
            raise ValueError("retry_within must be a positive duration")
        self.reason = reason
        self.phase = phase
        self.retry_within = retry_within
        self.at_least_once = at_least_once
        # Review of #197: a directly queued job (`saas_os.infra.jobs`, no
        # outbox event) that raises this is not retried by the job wrapper
        # (`NonRetriableJobError`) unless the receiver de-duplicates on a
        # stable id. An idempotency window is not honoured there: nothing
        # records when the first attempt ran, so it is not retried either.
        self.job_retry_safe = at_least_once
        super().__init__(f"Outcome unknown: {reason} ({phase})")


class ConfirmedNotSentError(Exception):
    """Raised (or mixed into its own error class) by an outbox event's
    consumer that has explicit evidence that its external request was NOT
    sent: no connection was established (refused, unresolvable, a connect or
    pool timeout), the attempt's deadline expired before any request was
    started, or no external request was attempted at all (configuration,
    validation). Owner decision D of 2026-11-01.

    It changes one thing: the dispatcher treats a bare `TimeoutError`
    (`asyncio.TimeoutError`, `socket.timeout`, an `httpx` timeout, ...) that
    escapes a consumer as an ambiguous outcome and dead-letters the event,
    because a timeout alone never proves that nothing was sent. An error
    that is a `ConfirmedNotSentError` is exempt from that rule and gets the
    ordinary retry policy (backoff, attempt counted, dead-lettered when the
    attempts run out), even when it is also a `TimeoutError`.
    `PermanentEventError` and `RetryAfterEventError` keep their meaning when
    combined with it. A class cannot be both a `ConfirmedNotSentError` and an
    `AmbiguousOutcomeError` (`TypeError` at class definition).

    Raise it only on evidence, from the code that saw the phase; it is a
    statement that a retry cannot duplicate an external effect of this
    attempt. Like every consumer error, its message carries identifiers and
    a category only -- it is stored as the event's `last_error`."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if issubclass(cls, AmbiguousOutcomeError):
            raise TypeError("an error cannot be both ambiguous and confirmed not sent")
