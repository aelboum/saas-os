"""Transactional email sending (P1.12).

`send_email()` validates every address (sender, all recipients, reply-to
if present) before ever constructing a provider call -- rejecting a
malformed address, or one containing a CR/LF/NUL byte (SMTP header
injection: an attacker-controlled "recipient" containing `\\r\\nBcc:
attacker@evil.example` could otherwise inject additional headers into
the outgoing message), deterministically and before any network I/O.

`provider` is an explicit, optional parameter, defaulting to a lazily-
constructed `SmtpEmailProvider` (`core/email/smtp_provider.py`) reading
its credentials through `infra.secrets.get_secrets_provider()` -- never
`os.environ` directly -- exactly mirroring
`core/billing/service.py::_default_provider()`'s identical pattern.
Tests substitute `core/email/provider.py::FakeEmailProvider` instead,
proving the abstraction isn't leaky (the same discipline
`core/billing`'s own Tests requirement already established for
`BillingProvider`).

This module is intentionally synchronous and has no opinion on *how* a
caller invokes it -- a caller on the request path may call it directly;
a caller that wants asynchronous, retried dispatch calls it from inside
an `infra.jobs` job handler (this checkpoint's own Step 6: reuse the
existing job infrastructure, never a second queue). `core/notifications`'s
own `"email"` channel does exactly the latter (`core/notifications/service.py`'s
own docstring) -- `core/email` itself owns no queue, no retry policy, and
no job registration of its own.
"""

from __future__ import annotations

import re

from core.email.errors import EmailProviderError, InvalidEmailAddressError
from core.email.provider import EmailMessage, EmailProvider, EmailSendResult

# Deliberately not a full RFC 5322 parser (unnecessary breadth for a
# transactional-email foundation) -- practical local-part@domain shape,
# plus an explicit, separate rejection of control characters below (this
# pattern alone would already reject a literal \r/\n via `$`-anchoring,
# but the explicit check makes the security property visible and testable
# on its own, independent of the shape regex ever changing).
_ADDRESS_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_FORBIDDEN_CHARACTERS = ("\r", "\n", "\x00")


def validate_email_address(address: str) -> None:
    """Raise `InvalidEmailAddressError` unless `address` is a plausible,
    injection-safe email address. Called for every address role (sender,
    each recipient, reply-to) before any provider call -- the actual
    SMTP-header-injection defense this checkpoint's own Security
    Requirements section requires.
    """
    if not address:
        raise InvalidEmailAddressError("Email address must not be empty.")
    for forbidden in _FORBIDDEN_CHARACTERS:
        if forbidden in address:
            raise InvalidEmailAddressError("Email address contains a forbidden control character.")
    if not _ADDRESS_PATTERN.match(address):
        raise InvalidEmailAddressError("Email address is not a valid address.")


def _validate_message(message: EmailMessage) -> None:
    validate_email_address(message.sender)
    if not message.to:
        raise InvalidEmailAddressError("At least one recipient is required.")
    for recipient in message.to:
        validate_email_address(recipient)
    if message.reply_to is not None:
        validate_email_address(message.reply_to)
    for forbidden in _FORBIDDEN_CHARACTERS:
        if forbidden in message.subject:
            raise InvalidEmailAddressError("Subject contains a forbidden control character.")


def _default_provider() -> EmailProvider:
    from core.email.smtp_provider import SmtpEmailProvider

    return SmtpEmailProvider()


def send_email(message: EmailMessage, *, provider: EmailProvider | None = None) -> EmailSendResult:
    """Validate `message`, then send it through `provider` (default: a
    real SMTP provider). Raises `InvalidEmailAddressError` for a
    malformed/unsafe address (before any provider call) or
    `EmailProviderError` if the provider itself fails to send -- never a
    raw transport/library exception (see that error's own docstring for
    what it may and may never carry).

    Returns the provider's normalized `EmailSendResult` -- `accepted`
    reflects only that the provider *accepted* the message for delivery,
    never that a recipient's mailbox actually received it (this
    checkpoint's own required distinction between "request accepted" and
    "email successfully delivered/accepted by provider": this function
    proves the latter, not final mailbox delivery, which no transactional
    provider can promise synchronously).
    """
    _validate_message(message)
    active_provider = provider or _default_provider()
    try:
        return active_provider.send(message)
    except EmailProviderError:
        raise
    except Exception as exc:  # noqa: BLE001 -- any other provider failure is normalized
        raise EmailProviderError("send", type(exc).__name__) from exc
