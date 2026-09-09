"""The `EmailProvider` interface (P1.12) -- mirrors
`core/billing/provider.py::BillingProvider`'s exact shape (a
`@runtime_checkable Protocol` plus one in-memory `Fake*` implementation
of the identical interface, docs/ADR/0008-billing-provider.md's own
provider-abstraction pattern, reused here rather than reinvented).

`core/email` and this module are the only vocabulary Core/Product code
needs -- neither imports `smtplib` (confirmed by
`tests/core/email/test_email_provider_boundary.py`'s no-direct-smtplib-
import test). Only `core/email/smtp_provider.py` knows SMTP's specific
transport details, exactly the same boundary ADR-0008 draws around
Stripe.

`EmailMessage`/`EmailSendResult` are the complete, deliberately minimal
transactional-email vocabulary this checkpoint's own Step 3 calls for --
sender, recipient(s), subject, text/HTML body, optional reply-to,
optional correlation metadata; a normalized accepted/message-id result.
No campaign, audience-list, open/click-tracking, unsubscribe-management,
or bulk-delivery concept exists here, deliberately -- P1.12 is a
transactional-email foundation, never a marketing-email product.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class EmailMessage:
    """A single transactional email to send. `metadata` is a small,
    caller-supplied dict a concrete provider *may* forward as correlation
    data (e.g. an SMTP header, or a provider-specific "tag") -- never a
    place for a secret or a credential; `core/email/service.py::send_email()`
    never puts one there itself, and neither should a caller."""

    sender: str
    to: tuple[str, ...]
    subject: str
    text_body: str
    html_body: str | None = None
    reply_to: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EmailSendResult:
    """The one normalized outcome every `EmailProvider` implementation
    returns -- never a provider-specific response object (this
    checkpoint's own Step 3: "Do not expose provider-specific response
    objects to Core")."""

    accepted: bool
    provider_message_id: str | None = None


@runtime_checkable
class EmailProvider(Protocol):
    """The one provider-side operation a transactional-email foundation
    needs. Deliberately smaller than `BillingProvider`'s three lifecycle
    operations -- sending is the entire lifecycle for a transactional
    email; there is no "change" or "cancel" analog once a message has
    been accepted by a provider."""

    def send(self, message: EmailMessage) -> EmailSendResult:
        """Send `message`. Must raise `core.email.errors.EmailProviderError`
        (never a raw provider/transport exception) on failure -- see that
        error's own docstring for what it may and may never carry."""
        ...


class FakeEmailProvider:
    """An in-memory `EmailProvider` -- no network access, no credentials.
    Records every message it was asked to send so tests can assert
    against it directly, mirroring `core.billing.provider.FakeBillingProvider`'s
    identical role for `BillingProvider`. This is what
    `core/email/service.py`'s own tests, and any future real consumer's
    tests, run against by default."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.sent: list[EmailMessage] = []

    def send(self, message: EmailMessage) -> EmailSendResult:
        from core.email.errors import EmailProviderError

        if self.fail:
            raise EmailProviderError("send", "FakeEmailProvider configured to fail")
        self.sent.append(message)
        return EmailSendResult(accepted=True, provider_message_id=f"fake-{len(self.sent)}")
