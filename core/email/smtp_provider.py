"""`SmtpEmailProvider` -- the one concrete `EmailProvider` implementation
(P1.12). The only file in this repository that imports `smtplib`
(confirmed by `tests/core/email/test_email_provider_boundary.py`), the
same "only the concrete adapter knows the vendor/protocol's specific
shape" boundary `core/billing/stripe_provider.py` already establishes for
Stripe (docs/ADR/0008-billing-provider.md).

SMTP, not a commercial vendor API, is this checkpoint's own suggested
initial choice: it is generic (works against any standards-compliant
mail relay -- a self-hosted relay, a transactional-email vendor's own
SMTP endpoint, or a local development mail-catcher), needs no vendor SDK
dependency (`smtplib`/`email` are both Python stdlib), and does not lock
SaaS-OS to one commercial provider the way a vendor-specific HTTP API
client would.

**Secrets**: `SMTP_USERNAME`/`SMTP_PASSWORD` are read once, at
construction time, through `infra.secrets.get_secrets_provider()` --
never `os.environ` directly, never stored anywhere outside this one
instance's private attributes, never logged, and never included in any
exception this module raises (`core/email/errors.py::EmailProviderError`'s
own "type name and a short reason only" convention). Both are optional
*together* -- a local development mail-catcher commonly accepts
unauthenticated connections -- but never independently: a username with
no password (or vice versa) is a configuration mistake, not a valid
"unauthenticated" state, and is rejected at construction time rather
than surfacing as a confusing mid-`send()` SMTP protocol error.

**TLS**: explicit, on by default (`EmailConfig.use_tls`,
`core/email/config.py`). When enabled, `STARTTLS` is negotiated using
`ssl.create_default_context()` -- Python's own secure default (hostname
verification and certificate validation both on; this module exposes no
option to disable either, so there is no accidental insecure escape
hatch). Plain, unencrypted SMTP is opt-out only (`use_tls=False`), never
the default -- intended for a local/dev mail-catcher on a trusted host,
never a production relay.

**Timeouts**: `EmailConfig.timeout_seconds` is passed straight to
`smtplib.SMTP(...)`'s own `timeout` parameter -- a bounded connect *and*
read timeout for the entire SMTP conversation (stdlib `smtplib`'s own
documented behavior), so a hung/unreachable relay can never block a
caller indefinitely. No retry loop exists in this module at all (this
checkpoint's own "no infinite retry loop inside the provider" -- and,
more generally, "no new retry engine"): a failed `send()` call raises
`EmailProviderError` exactly once; `core/notifications`'s own job-handler
integration reuses `infra.jobs`' existing retry/backoff/dead-letter
policy for anything that needs to retry, never a second one here.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage as MimeMessage

from core.email.config import EmailConfig, get_email_config
from core.email.errors import EmailConfigurationError, EmailProviderError
from core.email.provider import EmailMessage, EmailSendResult
from infra.secrets import get_secrets_provider


class SmtpEmailProvider:
    """A real `EmailProvider` backed by stdlib `smtplib`. Constructing an
    instance resolves configuration/credentials once; `send()` opens one
    short-lived SMTP connection per call (no persistent/pooled connection
    -- transactional email volume in this platform's own current scope
    does not justify one, and a fresh connection per send avoids any
    stale-connection failure mode entirely)."""

    def __init__(self, *, config: EmailConfig | None = None) -> None:
        self._config = config or get_email_config()

        secrets = get_secrets_provider()
        username = secrets.get("SMTP_USERNAME")
        password = secrets.get("SMTP_PASSWORD")
        if bool(username) != bool(password):
            raise EmailConfigurationError(
                "SMTP_USERNAME and SMTP_PASSWORD must both be set, or both left unset "
                "(an unauthenticated relay) -- one without the other is a configuration error."
            )
        self._username = username
        self._password = password

    def send(self, message: EmailMessage) -> EmailSendResult:
        mime_message = MimeMessage()
        mime_message["From"] = message.sender
        mime_message["To"] = ", ".join(message.to)
        mime_message["Subject"] = message.subject
        if message.reply_to is not None:
            mime_message["Reply-To"] = message.reply_to
        mime_message.set_content(message.text_body)
        if message.html_body is not None:
            mime_message.add_alternative(message.html_body, subtype="html")

        try:
            with smtplib.SMTP(
                self._config.smtp_host,
                self._config.smtp_port,
                timeout=self._config.timeout_seconds,
            ) as client:
                if self._config.use_tls:
                    client.starttls(context=ssl.create_default_context())
                if self._username and self._password:
                    client.login(self._username, self._password)
                client.send_message(mime_message)
        except (smtplib.SMTPException, OSError) as exc:
            raise EmailProviderError("send", type(exc).__name__) from exc

        # smtplib has no notion of a provider-assigned message id (that
        # is an HTTP-API-provider concept, e.g. SendGrid/Postmark) --
        # `None` here is a documented, honest absence, never a fabricated
        # value (core/email/provider.py::EmailSendResult's own docstring).
        return EmailSendResult(accepted=True, provider_message_id=None)
