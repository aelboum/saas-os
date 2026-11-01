"""`SmtpEmailProvider` -- the concrete SMTP `EmailProvider` implementation
(P1.12), and `MailpitEmailProvider`, its development-only profile (ADR-0057).
The only file in this repository that imports `smtplib` (confirmed by
`tests/core/email/test_email_provider_unit.py`'s no-direct-smtplib-import
test), the same "only the concrete adapter knows the vendor/protocol's
specific shape" boundary `saas_os/core/billing/stripe_provider.py` already
establishes for Stripe (docs/ADR/0008-billing-provider.md).

SMTP, not a commercial vendor API, is the first production adapter: it is
generic (works against any standards-compliant mail relay -- a self-hosted
relay, a transactional-email vendor's own SMTP endpoint, or a local
development mail-catcher), needs no vendor SDK dependency (`smtplib`/`email`
are both Python stdlib), and does not lock SaaS-OS to one commercial provider
the way a vendor-specific HTTP API client would.

**Secrets**: `SMTP_USERNAME`/`SMTP_PASSWORD` are read once, at
construction time, through `saas_os.infra.secrets.get_secrets_provider()` --
never `os.environ` directly, never stored anywhere outside this one
instance's private attributes, never logged, and never included in any
exception this module raises (`saas_os/core/email/errors.py::EmailProviderError`'s
own "type name and a short reason only" convention). Both are optional
*together* -- a relay may accept unauthenticated connections from a trusted
network -- but never independently: a username with no password (or vice
versa) is a configuration mistake, not a valid "unauthenticated" state, and
is rejected at construction time rather than surfacing as a confusing
mid-`send()` SMTP protocol error. `MailpitEmailProvider` never reads them at
all (ADR-0057): production relay credentials must not reach a development
mail catcher.

**TLS** (`EmailConfig.tls_mode`, `saas_os/core/email/config.py`): `starttls`
(the default) negotiates `STARTTLS` after connecting; `implicit` speaks TLS
from the first byte (`smtplib.SMTP_SSL`, typically port 465). Both use
`ssl.create_default_context()` -- Python's own secure default (hostname
verification and certificate validation both on); this module exposes no
option to disable either, so there is no insecure TLS mode. A server that
does not offer `STARTTLS` fails the send (`SMTPNotSupportedError`) rather
than silently continuing in plaintext. `none` is plaintext, refused in
production unless the operator sets `SMTP_REQUIRE_TLS=false` explicitly
(ADR-0057, following ADR-0021).

**Timeouts**: `EmailConfig.timeout_seconds` is passed straight to
`smtplib`'s own `timeout` parameter -- a bounded connect *and* read timeout
for the entire SMTP conversation (stdlib `smtplib`'s own documented
behavior), so a hung/unreachable relay can never block a caller
indefinitely.

**Failures** raise `EmailProviderError` exactly once; no retry loop exists in
this module (P1.12: "no new retry engine"). `saas_os/core/notifications`'s job
handler reuses the outbox/`saas_os.infra.jobs` retry and dead-letter policy.
ADR-0057 classifies a failure as `permanent` only when resending the same
message cannot succeed: an SMTP 5xx refusing every recipient, the sender, or
the message data. A failure before the message data was invited -- connect,
EHLO, STARTTLS, AUTH, MAIL FROM, RCPT TO, the DATA command itself -- means
the message was not handed over: with no reply code, or a 4xx, it stays
transient.

**Ambiguous outcomes** (owner decision of 2026-11-01, ledger row F5): once
the relay has answered `354` to DATA, the message bytes are on their way; a
connection lost, reset or timed out from then until the relay's final reply
leaves the outcome unknown (the relay may already have queued the message).
That raises `EmailOutcomeUnknownError` with phase `data` and no retry window:
SMTP has no request de-duplication, so it must not be retried automatically
(the notification job dead-letters it for an operator to replay). A final
reply code keeps its classification (`250` accepted; `4xx` transient; `5xx`
permanent). A failure after the final `250` (QUIT) does not undo the
acceptance. The phase is tracked on the live `smtplib` connection
(`_track_phase`); it never guesses from an exception type.

**Message-ID**: `EmailMessage.message_id` when the caller supplies one (the
notification job derives it from the outbox event id), otherwise a fresh
`email.utils.make_msgid()` on the sender's domain. It is always set on the
outgoing message and returned as `EmailSendResult.provider_message_id`, so
an operator can correlate a send with what the relay recorded.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage as MimeMessage
from email.utils import make_msgid
from typing import Any

from saas_os.core.email.config import (
    EmailConfig,
    assert_mailpit_environment,
    get_email_config,
    get_mailpit_config,
)
from saas_os.core.email.errors import (
    EmailConfigurationError,
    EmailOutcomeUnknownError,
    EmailProviderError,
)
from saas_os.core.email.provider import EmailMessage, EmailSendResult
from saas_os.infra.secrets import get_secrets_provider


def _is_permanent_code(code: object) -> bool:
    return isinstance(code, int) and 500 <= code <= 599


def _classify(exc: Exception) -> EmailProviderError:
    """Translate an `smtplib`/socket failure into `EmailProviderError`
    carrying only the exception's type name, a permanence flag and a
    numeric reply code -- never the server's reply text or a recipient."""
    reason = type(exc).__name__
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        codes = [
            entry[0] for entry in exc.recipients.values() if isinstance(entry, tuple) and entry
        ]
        permanent = bool(codes) and all(_is_permanent_code(code) for code in codes)
        reply_code = codes[0] if codes and isinstance(codes[0], int) else None
        return EmailProviderError("send", reason, permanent=permanent, reply_code=reply_code)
    if isinstance(exc, smtplib.SMTPSenderRefused | smtplib.SMTPDataError):
        code = exc.smtp_code
        return EmailProviderError(
            "send", reason, permanent=_is_permanent_code(code), reply_code=code
        )
    if isinstance(exc, smtplib.SMTPResponseException):
        return EmailProviderError("send", reason, reply_code=exc.smtp_code)
    return EmailProviderError("send", reason)


# Where an SMTP conversation is, for classifying a failure without a reply
# code (module docstring).
_PHASE_ENVELOPE = "envelope"  # before the relay invited the message data
_PHASE_DATA = "data"  # the relay answered 354: the message is being sent
_PHASE_ACCEPTED = "accepted"  # the relay's final reply to the data was 250


# The real class, bound at import: tests replace `smtplib.SMTP` with doubles.
_SMTP_CLIENT = smtplib.SMTP


class _Phase:
    value: str = _PHASE_ENVELOPE


def _track_phase(client: Any, phase: _Phase) -> None:
    """Record, on this one live connection, when the relay invites the
    message data (`354`) and when it accepts it (`250`). `smtplib.SMTP.data()`
    reads exactly two replies -- the answer to DATA, then the final one --
    through `getreply()`, which is wrapped for the duration of `data()`. A
    client that is not a `smtplib.SMTP` (a test double) is left alone."""
    if not isinstance(client, _SMTP_CLIENT):
        return
    real_data = client.data
    real_getreply = client.getreply

    def getreply() -> tuple[int, bytes]:
        code, reply = real_getreply()
        if phase.value == _PHASE_ENVELOPE and code == 354:
            phase.value = _PHASE_DATA
        return code, reply

    def data(msg: Any) -> tuple[int, bytes]:
        client.getreply = getreply
        try:
            code, reply = real_data(msg)
        finally:
            client.getreply = real_getreply
        if code == 250:
            phase.value = _PHASE_ACCEPTED
        return code, reply

    client.data = data


def _sender_domain(sender: str) -> str:
    return sender.rsplit("@", 1)[-1]


class SmtpEmailProvider:
    """A real `EmailProvider` backed by stdlib `smtplib`. Constructing an
    instance resolves configuration/credentials once; `send()` opens one
    short-lived SMTP connection per call (no persistent/pooled connection
    -- transactional email volume in this platform's own current scope
    does not justify one, and a fresh connection per send avoids any
    stale-connection failure mode entirely).

    `authenticate=False` skips reading `SMTP_USERNAME`/`SMTP_PASSWORD`
    entirely; only `MailpitEmailProvider` uses it."""

    name = "smtp"

    def __init__(self, *, config: EmailConfig | None = None, authenticate: bool = True) -> None:
        self._config = config or get_email_config()
        self._username: str | None = None
        self._password: str | None = None
        if not authenticate:
            return

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

    def _connect(self) -> smtplib.SMTP:
        config = self._config
        if config.tls_mode == "implicit":
            return smtplib.SMTP_SSL(
                config.smtp_host,
                config.smtp_port,
                timeout=config.timeout_seconds,
                context=ssl.create_default_context(),
            )
        return smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=config.timeout_seconds)

    def send(self, message: EmailMessage) -> EmailSendResult:
        message_id = message.message_id or make_msgid(domain=_sender_domain(message.sender))

        mime_message = MimeMessage()
        mime_message["From"] = message.sender
        mime_message["To"] = ", ".join(message.to)
        mime_message["Subject"] = message.subject
        mime_message["Message-ID"] = message_id
        if message.reply_to is not None:
            mime_message["Reply-To"] = message.reply_to
        mime_message.set_content(message.text_body)
        if message.html_body is not None:
            mime_message.add_alternative(message.html_body, subtype="html")

        phase = _Phase()
        failure: EmailProviderError
        try:
            with self._connect() as client:
                _track_phase(client, phase)
                if self._config.tls_mode == "starttls":
                    client.starttls(context=ssl.create_default_context())
                if self._username and self._password:
                    client.login(self._username, self._password)
                # The envelope is given explicitly, never derived from the
                # headers: `send_message()` would otherwise re-parse `To`,
                # where one recipient containing a comma reads as two
                # (ledger row F3, 2026-11-01). RCPT TO gets exactly the
                # validated recipients, one command each.
                client.send_message(
                    mime_message, from_addr=message.sender, to_addrs=list(message.to)
                )
        except (smtplib.SMTPException, OSError) as exc:
            if phase.value == _PHASE_ACCEPTED:
                # The relay said 250 to the data; only closing failed.
                return EmailSendResult(accepted=True, provider_message_id=message_id)
            if phase.value == _PHASE_DATA and not isinstance(exc, smtplib.SMTPResponseException):
                # No final reply after the data was invited: unknown outcome.
                failure = EmailOutcomeUnknownError("send", type(exc).__name__, phase=_PHASE_DATA)
            else:
                failure = _classify(exc)
            raise failure from exc

        # The relay assigns its own queue id, which smtplib does not expose;
        # the `Message-ID` this provider set is the one stable identifier.
        return EmailSendResult(accepted=True, provider_message_id=message_id)


class MailpitEmailProvider(SmtpEmailProvider):
    """The development-only Mailpit profile of the SMTP adapter (ADR-0057):
    the `MAILPIT_SMTP_HOST`/`MAILPIT_SMTP_PORT` endpoint, plaintext, and no
    credentials -- `SMTP_USERNAME`/`SMTP_PASSWORD` are never read. Refuses
    construction unless `ENVIRONMENT` is `development` or `test`, in
    addition to the same refusal in `get_mailpit_config()`, so production
    mail cannot reach Mailpit through either path."""

    name = "mailpit"

    def __init__(self) -> None:
        assert_mailpit_environment()
        mailpit = get_mailpit_config()
        super().__init__(
            config=EmailConfig(
                smtp_host=mailpit.smtp_host,
                smtp_port=mailpit.smtp_port,
                tls_mode="none",
                timeout_seconds=mailpit.timeout_seconds,
            ),
            authenticate=False,
        )
