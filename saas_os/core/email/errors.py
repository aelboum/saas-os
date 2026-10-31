"""Typed errors for `saas_os/core/email` (P1.12). Every error here carries only
identifying metadata -- never a message body, an SMTP credential, or a
raw provider exception's own text, mirroring `saas_os/core/billing/errors.py`'s
`BillingProviderError` convention exactly.
"""

from __future__ import annotations


class InvalidEmailAddressError(ValueError):
    """Raised when a sender/recipient/reply-to address is malformed, or
    contains a character (`\\r`/`\\n`) that could be used for SMTP header
    injection. Never echoes the offending value back -- it may be
    attacker-controlled input, and a rejected address carries no
    legitimate need to be repeated to the caller."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


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
