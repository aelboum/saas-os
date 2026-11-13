"""Typed errors for `saas_os/core/email` (P1.12). Every error here carries only
identifying metadata -- never a message body, an SMTP credential, or a
raw provider exception's own text, mirroring `saas_os/core/billing/errors.py`'s
`BillingProviderError` convention exactly.
"""

from __future__ import annotations

from datetime import timedelta

from saas_os.infra.jobs.errors import NonRetriableJobError


class InvalidEmailAddressError(ValueError):
    """Raised when a sender/recipient/reply-to address is malformed, or
    contains a character (`\\r`/`\\n`) that could be used for SMTP header
    injection. Never echoes the offending value back -- it may be
    attacker-controlled input, and a rejected address carries no
    legitimate need to be repeated to the caller."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class InvalidEmailHeaderError(InvalidEmailAddressError):
    """Raised when `EmailMessage.list_unsubscribe`, `list_unsubscribe_post`,
    `in_reply_to` or `references` is refused (issue 224, ADR-0057): a
    malformed or unsafe value, a bound exceeded, or a combination the headers
    do not allow. An additive subclass of `InvalidEmailAddressError`, so a
    caller can tell a header failure from a bad address while code that
    catches the parent keeps working. The message names the rule, never the
    value: an unsubscribe URI identifies the recipient."""


class EmailConfigurationError(ValueError):
    """Raised when `saas_os/core/email` configuration (non-secret tunables, or a
    required secret resolved through `saas_os.infra.secrets`) is missing or
    invalid. Never includes a secret value -- only a variable/field name
    and, for non-secret fields, the offending value."""


class EmailProviderError(RuntimeError):
    """Raised when the underlying email provider (SMTP, or a future
    concrete provider) fails to send. Carries only the provider's error
    *type name* and a short, fixed reason -- never the raw provider
    exception (which could echo connection details, an SMTP response
    line potentially containing account-identifying detail, or -- in the
    worst case -- a credential a misconfigured server echoed back).

    `permanent` (ADR-0057) is true only when resending the same message
    cannot succeed -- e.g. an SMTP 5xx refusing every recipient. Everything
    else, including an ambiguous outcome, stays transient (`False`), so the
    caller's existing retry policy still owns the decision. `reply_code` is
    the provider's numeric status, when there is one: a number, never the
    server's reply text.

    `retry_after_seconds` is the provider's own request to be retried no
    sooner than that (a rate limit's `Retry-After`), or `math.inf` for a
    quota that resets at an unstated boundary; `None` when the provider
    said nothing. The outbox bounds it (`saas_os.core.outbox.RetryAfterEventError`)."""

    def __init__(
        self,
        operation: str,
        reason: str,
        *,
        permanent: bool = False,
        reply_code: int | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        self.operation = operation
        self.reason = reason
        self.permanent = permanent
        self.reply_code = reply_code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Email provider operation {operation!r} failed: {reason}")


class EmailOutcomeUnknownError(EmailProviderError, NonRetriableJobError):
    """The provider's transport failed after the message may already have
    been handed over, so whether it was accepted is unknown (owner decision
    of 2026-11-01, ledger row F5): an SMTP connection lost after the server
    invited the message data and before its final reply, or an HTTP request
    whose response never arrived or could not be read. Never permanent:
    nothing says the message was refused.

    `phase` names where the transport was (`data`, `read`, `response`, ...).
    `retry_within` is set only when a repeated request is provably
    de-duplicated by the provider for that long (Resend: the same
    `Idempotency-Key` with an identical body); `None` means a retry may
    deliver the message twice, so the caller must not retry automatically.
    Like every `EmailProviderError`, it carries categories only.

    It is a `NonRetriableJobError`: a product's own job that lets it escape
    is dead-lettered by the job wrapper, not retried. A `retry_within`
    window does not change that, as for `AmbiguousOutcomeError`: nothing
    records when such a job's first attempt ran, so the window cannot be
    honoured there (ledger row of 2026-11-02, second review of #197)."""

    def __init__(
        self,
        operation: str,
        reason: str,
        *,
        phase: str,
        retry_within: timedelta | None = None,
        reply_code: int | None = None,
    ) -> None:
        super().__init__(operation, reason, reply_code=reply_code)
        self.phase = phase
        self.retry_within = retry_within


class EmailNotSentError(EmailProviderError):
    """The provider's transport failed before any of the message could have
    been handed over (owner decision D of 2026-11-01): an SMTP connection
    refused, lost or timed out before the relay invited the message data and
    without a reply code, or an HTTP request that was never sent (resolution,
    connection, TLS, proxy, or the deadline before the exchange started).
    Transient and safe to retry: nothing was sent, so a retry cannot deliver
    the message twice. Like every `EmailProviderError`, it carries
    categories only."""
