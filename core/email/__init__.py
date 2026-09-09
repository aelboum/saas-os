"""`core/email` -- provider-agnostic transactional email foundation
(P1.12).

Owns:
- `EmailMessage`/`EmailSendResult` (`core/email/provider.py`) -- the
  complete, deliberately minimal transactional-email vocabulary;
- `EmailProvider`, the provider-abstraction interface, and
  `FakeEmailProvider`, its in-memory implementation (mirrors
  `core.billing.provider.BillingProvider`/`FakeBillingProvider` exactly,
  docs/ADR/0008-billing-provider.md's own pattern);
- `SmtpEmailProvider` (`core/email/smtp_provider.py`), the one concrete
  production implementation -- stdlib `smtplib`, explicit TLS, bounded
  timeout, credentials via `infra.secrets`;
- `validate_email_address()`/`send_email()` (`core/email/service.py`),
  the entrypoint every caller (synchronous, or from within a job handler)
  uses.

Real consumer: `core.notifications`'s own `"email"` channel
(`core/notifications/service.py`) -- an existing, already-shipped
extension point this checkpoint's own discovery found already designed
for exactly this ("adding a future channel means a new dispatch branch
and provider adapter, never a schema migration",
`core/notifications/__init__.py`'s own pre-existing docstring).

Does NOT own (Non-Goals, deliberately deferred -- P1.12 is a foundation,
not a complete product email system):
- Marketing email: campaigns, audience lists, opens/clicks, unsubscribe
  management, bulk delivery -- none of this is a transactional-email
  concept, and none is built here.
- Templates-as-a-product / a template-authoring system -- `docs/ARCHITECTURE.md`
  section 4 already defers "templates" to a future Product Contract for
  `core/notifications` generally; this module inherits that same
  boundary rather than building a parallel one.
- Email verification / password-reset flows -- `core/identity`'s own
  `User` model deliberately stores no email address yet
  (`core/identity/models.py`'s own docstring: "email specifically must
  never become the canonical identity key ... can be added in a later
  phase without touching this identity boundary"); building a
  verification flow now would mean either inventing a second,
  parallel place to store an email address or modifying that identity
  boundary, both explicitly out of this phase's scope.
- A queue/job system of its own -- `core/email` is synchronous; anything
  that needs asynchronous, retried dispatch (this checkpoint's own
  Step 6) reuses `infra.jobs` through `core/notifications`, never a
  second queue.
- Idempotency-key deduplication of its own -- no business operation in
  this repository yet creates a duplicate-transactional-email risk that
  `core.idempotency` (P1.11) does not already correctly protect once
  wired around the *business* operation; see
  `core/notifications/service.py`'s own docstring for the full reasoning.
"""

from core.email.config import EmailConfig, get_email_config
from core.email.errors import (
    EmailConfigurationError,
    EmailProviderError,
    InvalidEmailAddressError,
)
from core.email.provider import EmailMessage, EmailProvider, EmailSendResult, FakeEmailProvider
from core.email.service import send_email, validate_email_address
from core.email.smtp_provider import SmtpEmailProvider

__all__ = [
    "EmailMessage",
    "EmailSendResult",
    "EmailProvider",
    "FakeEmailProvider",
    "SmtpEmailProvider",
    "EmailConfig",
    "get_email_config",
    "validate_email_address",
    "send_email",
    "InvalidEmailAddressError",
    "EmailConfigurationError",
    "EmailProviderError",
]
