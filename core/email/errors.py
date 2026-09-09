"""Typed errors for `core/email` (P1.12). Every error here carries only
identifying metadata -- never a message body, an SMTP credential, or a
raw provider exception's own text, mirroring `core/billing/errors.py`'s
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
    """Raised when `core/email` configuration (non-secret tunables, or a
    required secret resolved through `infra.secrets`) is missing or
    invalid. Never includes a secret value -- only a variable/field name
    and, for non-secret fields, the offending value."""


class EmailProviderError(RuntimeError):
    """Raised when the underlying email provider (SMTP, or a future
    concrete provider) fails to send. Carries only the provider's error
    *type name* and a short, fixed reason -- never the raw provider
    exception (which could echo connection details, an SMTP response
    line potentially containing account-identifying detail, or -- in the
    worst case -- a credential a misconfigured server echoed back)."""

    def __init__(self, operation: str, reason: str) -> None:
        self.operation = operation
        super().__init__(f"Email provider operation {operation!r} failed: {reason}")
