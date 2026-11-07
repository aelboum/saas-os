"""The `EmailProvider` interface (P1.12) -- mirrors
`saas_os/core/billing/provider.py::BillingProvider`'s exact shape (a
`@runtime_checkable Protocol` plus one in-memory `Fake*` implementation
of the identical interface, docs/ADR/0008-billing-provider.md's own
provider-abstraction pattern, reused here rather than reinvented).

`saas_os/core/email` and this module are the only vocabulary Core/Product code
needs -- neither imports `smtplib` (confirmed by
`tests/core/email/test_email_provider_unit.py`'s no-direct-smtplib-
import test). Only `saas_os/core/email/smtp_provider.py` knows SMTP's specific
transport details, exactly the same boundary ADR-0008 draws around
Stripe.

`EmailMessage`/`EmailSendResult` are the complete, deliberately minimal
transactional-email vocabulary this checkpoint's own Step 3 calls for --
sender, recipient(s), subject, text/HTML body, optional reply-to,
optional correlation metadata; a normalized accepted/message-id result.
No campaign, audience-list, open/click-tracking, unsubscribe-management,
or bulk-delivery concept exists here, deliberately -- P1.12 is a
transactional-email foundation, never a marketing-email product. The four
optional header fields below (issue 224) only carry validated, well-formed
`List-Unsubscribe`, `List-Unsubscribe-Post`, `In-Reply-To` and `References`
headers; recipient lists, suppression, the unsubscribe endpoint and its token
stay the product's, and no RFC 8058 compliance is claimed (ADR-0057).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class EmailMessage:
    """A single transactional email to send. `metadata` is a small,
    caller-supplied dict a concrete provider *may* forward as correlation
    data (e.g. an SMTP header, or a provider-specific "tag") -- never a
    place for a secret or a credential; `saas_os/core/email/service.py::send_email()`
    never puts one there itself, and neither should a caller.

    `message_id` (ADR-0057) is an optional RFC 5322 `Message-ID`, angle
    brackets included. A caller that may resend the same logical message
    (a retried job) passes a stable one so receivers that deduplicate on it
    can; it never makes delivery exactly-once. Unset, the provider
    generates one.

    `idempotency_key` (owner decision of 2026-11-01) is an optional stable
    identity of the logical send -- the notification job uses its outbox
    event id -- that a provider with request de-duplication (Resend) sends
    as its idempotency key, so the key does not change with configuration
    such as the sender's domain. Unset, such a provider derives the key from
    `message_id`, as before. Printable ASCII, at most 200 characters; it is
    hashed before it leaves the process and never becomes a header.

    The last four fields (issue 224, ADR-0057) are the only way to set these
    headers; there is no generic header mapping. `list_unsubscribe` is a tuple
    of URIs without angle brackets (one `https:` and/or one plain `mailto:`;
    the message must have exactly one recipient); `list_unsubscribe_post`
    asks for `List-Unsubscribe-Post: List-Unsubscribe=One-Click` and needs an
    `https:` URI; `in_reply_to` and `references` are tuples of `<id@host>`
    message ids, angle brackets included. Their values must be a function of
    the logical message (identical on every retry). `repr=False`: an
    unsubscribe URI identifies the recipient."""

    sender: str
    to: tuple[str, ...]
    subject: str
    text_body: str
    html_body: str | None = None
    reply_to: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    message_id: str | None = None
    idempotency_key: str | None = None
    list_unsubscribe: tuple[str, ...] = field(default=(), repr=False)
    list_unsubscribe_post: bool = field(default=False, repr=False)
    in_reply_to: tuple[str, ...] = field(default=(), repr=False)
    references: tuple[str, ...] = field(default=(), repr=False)


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
        """Send `message`. Must raise `saas_os.core.email.errors.EmailProviderError`
        (never a raw provider/transport exception) on failure -- see that
        error's own docstring for what it may and may never carry."""
        ...


class FakeEmailProvider:
    """An in-memory `EmailProvider` -- no network access, no credentials.
    Records every message it was asked to send so tests can assert
    against it directly, mirroring `saas_os.core.billing.provider.FakeBillingProvider`'s
    identical role for `BillingProvider`. This is what
    `saas_os/core/email/service.py`'s own tests, and any future real consumer's
    tests, run against by default."""

    name = "fake"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.sent: list[EmailMessage] = []

    def send(self, message: EmailMessage) -> EmailSendResult:
        from saas_os.core.email.errors import EmailProviderError

        if self.fail:
            raise EmailProviderError("send", "FakeEmailProvider configured to fail")
        self.sent.append(message)
        return EmailSendResult(accepted=True, provider_message_id=f"fake-{len(self.sent)}")
