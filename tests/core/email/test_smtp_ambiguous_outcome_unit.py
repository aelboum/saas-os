"""SMTP outcomes by phase, against a real local socket (owner decision of
2026-11-01, ledger row F5; `saas_os/core/email/smtp_provider.py`).

Not sent (connect, greeting, EHLO, MAIL, RCPT, the DATA command before the
relay invites the data) is an ordinary transient `EmailProviderError`.
Possibly sent (the relay invited the data, then no final reply) is
`EmailOutcomeUnknownError` with phase `data` and no retry window: SMTP has
no de-duplication. A final reply keeps today's classification. The same
exception type -- a disconnect, or a timeout -- lands on either side
depending only on where the conversation was.
"""

from __future__ import annotations

import pytest

from saas_os.core.email.config import EmailConfig
from saas_os.core.email.errors import (
    EmailNotSentError,
    EmailOutcomeUnknownError,
    EmailProviderError,
)
from saas_os.core.email.provider import EmailMessage
from saas_os.core.email.smtp_provider import SmtpEmailProvider
from saas_os.infra.secrets.provider import SecretsProvider
from smtp_fault_server import ScriptedSmtpServer, closed_port

_RECIPIENT = "recipient-canary@example.com"
_BODY = "body-canary-text"


class _NoSecrets(SecretsProvider):
    def get(self, name: str) -> str | None:
        return None


@pytest.fixture(autouse=True)
def _no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("saas_os.core.email.smtp_provider.get_secrets_provider", _NoSecrets)


def _message() -> EmailMessage:
    return EmailMessage(
        sender="no-reply@mail.example.com",
        to=(_RECIPIENT,),
        subject="subject",
        text_body=_BODY,
        message_id="<notification.1@mail.example.com>",
    )


def _send(port: int, *, timeout: int = 5) -> object:
    provider = SmtpEmailProvider(
        config=EmailConfig(
            smtp_host="127.0.0.1", smtp_port=port, tls_mode="none", timeout_seconds=timeout
        )
    )
    return provider.send(_message())


def _failure(port: int, *, timeout: int = 5) -> EmailProviderError:
    with pytest.raises(EmailProviderError) as excinfo:
        _send(port, timeout=timeout)
    error = excinfo.value
    text = f"{error!s} {error!r} {vars(error)!r}"
    assert _RECIPIENT not in text and _BODY not in text
    return error


def test_a_refused_connection_was_not_sent() -> None:
    error = _failure(closed_port())
    assert not isinstance(error, EmailOutcomeUnknownError)
    assert isinstance(error, EmailNotSentError)  # decision D: explicit
    assert error.permanent is False


def test_a_relay_that_never_greets_times_out_before_anything_is_sent() -> None:
    with ScriptedSmtpServer("stall_before_greeting", stall_seconds=3) as server:
        error = _failure(server.port, timeout=1)
    assert not isinstance(error, EmailOutcomeUnknownError)
    assert isinstance(error, EmailNotSentError)
    assert error.reason in {"TimeoutError", "SMTPServerDisconnected"}
    assert error.permanent is False


@pytest.mark.parametrize("mode", ["drop_after_rcpt"])
def test_a_disconnect_before_the_data_is_invited_was_not_sent(mode: str) -> None:
    with ScriptedSmtpServer(mode) as server:
        error = _failure(server.port)
        assert server.messages_received == 0
    assert not isinstance(error, EmailOutcomeUnknownError)
    assert isinstance(error, EmailNotSentError)
    assert error.permanent is False


@pytest.mark.parametrize("mode", ["drop_after_354", "drop_after_data_end"])
def test_a_disconnect_after_the_data_was_invited_is_ambiguous(mode: str) -> None:
    with ScriptedSmtpServer(mode) as server:
        error = _failure(server.port)
    assert isinstance(error, EmailOutcomeUnknownError)
    assert not isinstance(error, EmailNotSentError)
    assert error.phase == "data"
    assert error.retry_within is None  # SMTP: never retried automatically
    assert error.permanent is False
    assert error.reply_code is None


def test_a_timeout_after_the_message_was_sent_is_ambiguous() -> None:
    """The same exception type as the greeting stall above -- a timeout --
    is ambiguous here, because the whole message had been sent."""
    with ScriptedSmtpServer("stall_after_data_end", stall_seconds=3) as server:
        error = _failure(server.port, timeout=1)
        assert server.messages_received == 1
    assert isinstance(error, EmailOutcomeUnknownError)
    assert error.phase == "data"
    # smtplib reports a read timeout as a lost connection.
    assert error.reason in {"TimeoutError", "SMTPServerDisconnected"}


def test_a_4xx_final_reply_is_a_confirmed_transient_refusal() -> None:
    with ScriptedSmtpServer("final_4xx") as server:
        error = _failure(server.port)
    assert not isinstance(error, EmailOutcomeUnknownError)
    # A reply code is a confirmed answer, not "not sent".
    assert not isinstance(error, EmailNotSentError)
    assert (error.permanent, error.reply_code) == (False, 451)


def test_a_5xx_final_reply_is_permanent() -> None:
    with ScriptedSmtpServer("final_5xx") as server:
        error = _failure(server.port)
    assert not isinstance(error, EmailOutcomeUnknownError)
    assert (error.permanent, error.reply_code) == (True, 554)


def test_a_250_is_accepted() -> None:
    with ScriptedSmtpServer("accept") as server:
        result = _send(server.port)
        assert server.messages_received == 1
    assert getattr(result, "accepted", None) is True


def test_a_failure_after_the_250_does_not_undo_the_acceptance() -> None:
    """QUIT answered with 500 after the message was queued: the send
    succeeded, and reporting a failure would make the caller send again."""
    with ScriptedSmtpServer("bad_quit_after_250") as server:
        result = _send(server.port)
        assert server.messages_received == 1
    assert getattr(result, "provider_message_id", None) == "<notification.1@mail.example.com>"
