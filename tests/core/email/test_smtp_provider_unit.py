"""P1.12 -- `saas_os/core/email/smtp_provider.py::SmtpEmailProvider` tests.

Two kinds of proof, deliberately kept separate:

1. A *real* local SMTP server (a minimal, hand-rolled protocol responder
   over a genuine TCP socket, no `use_tls`/auth) -- proves
   `SmtpEmailProvider.send()` actually completes a real SMTP conversation
   end-to-end, this checkpoint's own "use real infrastructure where
   meaningful" requirement, without requiring a real external mail
   relay or production credentials.
2. Controlled unit tests (a fake `smtplib.SMTP` class) for the TLS/auth
   code paths, which would otherwise need a real TLS-terminating test
   server -- excessive complexity for a foundation phase; this proves
   `starttls()`/`login()` are called exactly when configured, deterministically.

No network access beyond `127.0.0.1`; no production credentials.
"""

from __future__ import annotations

import smtplib
import socket
import ssl
import threading
from email.message import EmailMessage as MimeMessage

import pytest

from saas_os.core.email.config import EmailConfig
from saas_os.core.email.errors import EmailConfigurationError, EmailProviderError
from saas_os.core.email.provider import EmailMessage
from saas_os.core.email.smtp_provider import MailpitEmailProvider, SmtpEmailProvider
from saas_os.infra.secrets.provider import SecretsProvider


class _FakeSecretsProvider(SecretsProvider):
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)


def _message(**overrides: object) -> EmailMessage:
    defaults: dict[str, object] = {
        "sender": "sender@example.com",
        "to": ("recipient@example.com",),
        "subject": "Test subject",
        "text_body": "Hello, world.",
    }
    defaults.update(overrides)
    return EmailMessage(**defaults)  # type: ignore[arg-type]


# --- Credential construction (SecretsProvider boundary) --------------------


def test_construction_reads_credentials_through_secrets_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_secrets = _FakeSecretsProvider({"SMTP_USERNAME": "alice", "SMTP_PASSWORD": "s3cret"})
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: fake_secrets
    )
    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))
    assert provider._username == "alice"  # noqa: SLF001 -- white-box construction proof
    assert provider._password == "s3cret"  # noqa: SLF001


def test_construction_allows_no_credentials_for_an_unauthenticated_relay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))
    assert provider._username is None  # noqa: SLF001
    assert provider._password is None  # noqa: SLF001


def test_construction_rejects_username_without_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider",
        lambda: _FakeSecretsProvider({"SMTP_USERNAME": "alice"}),
    )
    with pytest.raises(EmailConfigurationError):
        SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))


def test_construction_rejects_password_without_username(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider",
        lambda: _FakeSecretsProvider({"SMTP_PASSWORD": "s3cret"}),
    )
    with pytest.raises(EmailConfigurationError):
        SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))


def test_configuration_error_never_contains_the_credential_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider",
        lambda: _FakeSecretsProvider({"SMTP_USERNAME": "alice-the-secret-username"}),
    )
    with pytest.raises(EmailConfigurationError) as excinfo:
        SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))
    assert "alice-the-secret-username" not in str(excinfo.value)


# --- Real local SMTP server: end-to-end proof -----------------------------


class _FakeSmtpServer:
    """A minimal, hand-rolled SMTP responder over a real TCP socket --
    just enough of the protocol for `smtplib` to complete a plaintext,
    unauthenticated send. Not a general-purpose test SMTP server; exists
    only to prove `SmtpEmailProvider.send()` drives a genuine socket
    conversation to completion."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self._sock.settimeout(5)
        self.port = self._sock.getsockname()[1]
        self.received_data: bytes | None = None
        self._thread = threading.Thread(target=self._serve_one, daemon=True)

    def _serve_one(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            conn.sendall(b"220 fake.smtp.test ready\r\n")
            buffer = b""
            in_data = False
            data_lines: list[bytes] = []
            while True:
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                buffer += chunk
                while b"\r\n" in buffer:
                    line, buffer = buffer.split(b"\r\n", 1)
                    if in_data:
                        if line == b".":
                            in_data = False
                            self.received_data = b"\r\n".join(data_lines)
                            conn.sendall(b"250 OK: queued\r\n")
                        else:
                            data_lines.append(line)
                        continue
                    upper = line.decode("ascii", errors="replace").upper()
                    if upper.startswith(("EHLO", "HELO")):
                        conn.sendall(b"250-fake.smtp.test\r\n250 OK\r\n")
                    elif upper.startswith("DATA"):
                        in_data = True
                        data_lines = []
                        conn.sendall(b"354 Start mail input\r\n")
                    elif upper.startswith("QUIT"):
                        conn.sendall(b"221 Bye\r\n")
                        return
                    else:
                        conn.sendall(b"250 OK\r\n")

    def __enter__(self) -> _FakeSmtpServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def test_send_completes_a_real_smtp_conversation_over_a_real_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    with _FakeSmtpServer() as server:
        provider = SmtpEmailProvider(
            config=EmailConfig(smtp_host="127.0.0.1", smtp_port=server.port, use_tls=False)
        )
        result = provider.send(_message(subject="Real socket test"))

    assert result.accepted is True
    assert server.received_data is not None
    assert b"Real socket test" in server.received_data
    assert b"Hello, world." in server.received_data


def test_send_raises_email_provider_error_when_connection_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    # A bound-but-not-listening port on loopback reliably refuses.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    unused_port = probe.getsockname()[1]
    probe.close()

    provider = SmtpEmailProvider(
        config=EmailConfig(
            smtp_host="127.0.0.1", smtp_port=unused_port, use_tls=False, timeout_seconds=2
        )
    )
    with pytest.raises(EmailProviderError):
        provider.send(_message())


def test_provider_error_never_contains_raw_exception_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    unused_port = probe.getsockname()[1]
    probe.close()

    provider = SmtpEmailProvider(
        config=EmailConfig(
            smtp_host="127.0.0.1", smtp_port=unused_port, use_tls=False, timeout_seconds=2
        )
    )
    with pytest.raises(EmailProviderError) as excinfo:
        provider.send(_message())
    # Only the exception's type name may appear -- never a raw errno
    # string or connection-detail message.
    assert (
        str(excinfo.value)
        == f"Email provider operation 'send' failed: {type(excinfo.value.__cause__).__name__}"
    )


# --- TLS/auth code paths (controlled fake smtplib.SMTP) --------------------


class _RecordingSmtpClient:
    """A fake `smtplib.SMTP` -- records whether `starttls()`/`login()`
    were called, without any real network I/O."""

    instances: list[_RecordingSmtpClient] = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.starttls_called = False
        self.starttls_context = None
        self.login_called_with: tuple[str, str] | None = None
        self.sent_message = None
        _RecordingSmtpClient.instances.append(self)

    def __enter__(self) -> _RecordingSmtpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def starttls(self, *, context: object = None) -> None:
        self.starttls_called = True
        self.starttls_context = context

    def login(self, username: str, password: str) -> None:
        self.login_called_with = (username, password)

    def send_message(self, message: object) -> None:
        self.sent_message = message


def test_starttls_is_called_when_use_tls_is_true(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com", use_tls=True))
    provider.send(_message())

    assert _RecordingSmtpClient.instances[0].starttls_called is True


def test_starttls_is_not_called_when_use_tls_is_false(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com", use_tls=False))
    provider.send(_message())

    assert _RecordingSmtpClient.instances[0].starttls_called is False


def test_login_is_called_with_the_resolved_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider",
        lambda: _FakeSecretsProvider({"SMTP_USERNAME": "alice", "SMTP_PASSWORD": "s3cret"}),
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))
    provider.send(_message())

    assert _RecordingSmtpClient.instances[0].login_called_with == ("alice", "s3cret")


def test_login_is_not_called_when_no_credentials_are_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))
    provider.send(_message())

    assert _RecordingSmtpClient.instances[0].login_called_with is None


# --- ADR-0057: implicit TLS ------------------------------------------------


class _RecordingSmtpSslClient(_RecordingSmtpClient):
    """A fake `smtplib.SMTP_SSL` -- records the TLS context it was given."""

    def __init__(self, host: str, port: int, *, timeout: float, context: object = None) -> None:
        super().__init__(host, port, timeout)
        self.connect_context = context


def _no_plain_smtp(*args: object, **kwargs: object) -> None:
    raise AssertionError("implicit TLS must never open a plaintext SMTP connection")


def test_implicit_tls_connects_with_smtp_ssl_and_a_verifying_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider",
        lambda: _FakeSecretsProvider({"SMTP_USERNAME": "alice", "SMTP_PASSWORD": "s3cret"}),
    )
    monkeypatch.setattr(smtplib, "SMTP_SSL", _RecordingSmtpSslClient)
    monkeypatch.setattr(smtplib, "SMTP", _no_plain_smtp)

    provider = SmtpEmailProvider(
        config=EmailConfig(smtp_host="smtp.example.com", smtp_port=465, tls_mode="implicit")
    )
    provider.send(_message())

    client = _RecordingSmtpClient.instances[0]
    assert isinstance(client, _RecordingSmtpSslClient)
    assert (client.host, client.port) == ("smtp.example.com", 465)
    # Already TLS: no STARTTLS upgrade on top.
    assert client.starttls_called is False
    assert client.login_called_with == ("alice", "s3cret")
    context = client.connect_context
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_starttls_uses_a_verifying_context(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com", tls_mode="starttls")).send(
        _message()
    )

    client = _RecordingSmtpClient.instances[0]
    assert client.starttls_called is True
    assert isinstance(client.starttls_context, ssl.SSLContext)
    assert client.starttls_context.verify_mode == ssl.CERT_REQUIRED
    assert client.starttls_context.check_hostname is True


def test_a_server_without_starttls_fails_rather_than_continuing_in_plaintext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoStartTls(_RecordingSmtpClient):
        def starttls(self, *, context: object = None) -> None:
            raise smtplib.SMTPNotSupportedError("STARTTLS extension not supported by server.")

    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _NoStartTls)

    with pytest.raises(EmailProviderError) as excinfo:
        SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com")).send(_message())
    assert excinfo.value.permanent is False
    assert _RecordingSmtpClient.instances[0].sent_message is None


# --- ADR-0057: Message-ID ----------------------------------------------------


def test_send_sets_and_returns_a_generated_message_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    result = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com")).send(_message())

    sent = _RecordingSmtpClient.instances[0].sent_message
    assert isinstance(sent, MimeMessage)
    assert result.provider_message_id is not None
    assert sent["Message-ID"] == result.provider_message_id
    assert result.provider_message_id.endswith("@example.com>")


def test_send_uses_a_caller_supplied_message_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    result = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com")).send(
        _message(message_id="<notification.abc@example.com>")
    )

    assert result.provider_message_id == "<notification.abc@example.com>"
    sent = _RecordingSmtpClient.instances[0].sent_message
    assert isinstance(sent, MimeMessage)
    assert sent["Message-ID"] == "<notification.abc@example.com>"


def test_message_id_reaches_a_real_smtp_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    with _FakeSmtpServer() as server:
        provider = SmtpEmailProvider(
            config=EmailConfig(smtp_host="127.0.0.1", smtp_port=server.port, tls_mode="none")
        )
        provider.send(_message(message_id="<notification.real@example.com>"))

    assert server.received_data is not None
    assert b"Message-ID: <notification.real@example.com>" in server.received_data


# --- ADR-0057: permanent vs transient classification -----------------------


def _failing_client(exc: Exception) -> type:
    class _Failing(_RecordingSmtpClient):
        def send_message(self, message: object) -> None:
            raise exc

    return _Failing


@pytest.mark.parametrize(
    ("exc", "permanent", "reply_code"),
    [
        (smtplib.SMTPRecipientsRefused({"r@example.com": (550, b"no such user")}), True, 550),
        (
            smtplib.SMTPRecipientsRefused(
                {"r@example.com": (550, b"no"), "s@example.com": (451, b"later")}
            ),
            False,
            550,
        ),
        (smtplib.SMTPRecipientsRefused({"r@example.com": (450, b"mailbox busy")}), False, 450),
        (smtplib.SMTPSenderRefused(553, b"sender not allowed", "s@example.com"), True, 553),
        (smtplib.SMTPSenderRefused(451, b"try later", "s@example.com"), False, 451),
        (smtplib.SMTPDataError(554, b"message rejected"), True, 554),
        (smtplib.SMTPDataError(452, b"insufficient storage"), False, 452),
        (smtplib.SMTPAuthenticationError(535, b"bad credentials"), False, 535),
        (smtplib.SMTPServerDisconnected("Connection unexpectedly closed"), False, None),
        (TimeoutError("timed out"), False, None),
        (ConnectionResetError("reset"), False, None),
    ],
)
def test_failures_are_classified_permanent_only_when_a_resend_cannot_succeed(
    monkeypatch: pytest.MonkeyPatch, exc: Exception, permanent: bool, reply_code: int | None
) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _failing_client(exc))

    with pytest.raises(EmailProviderError) as excinfo:
        SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com")).send(_message())

    assert excinfo.value.permanent is permanent
    assert excinfo.value.reply_code == reply_code
    # Only the type name: never the server's reply text or a recipient.
    text = str(excinfo.value)
    assert text == f"Email provider operation 'send' failed: {type(exc).__name__}"
    for leaked in ("no such user", "r@example.com", "s@example.com", "bad credentials"):
        assert leaked not in text


def test_a_real_server_refusing_the_recipient_is_permanent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The classification against a genuine socket conversation, not only a
    fake client: a 550 to RCPT TO."""

    class _RefusingServer(_FakeSmtpServer):
        def _serve_one(self) -> None:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b"220 fake.smtp.test ready\r\n")
                buffer = b""
                while True:
                    try:
                        chunk = conn.recv(4096)
                    except OSError:
                        return
                    if not chunk:
                        return
                    buffer += chunk
                    while b"\r\n" in buffer:
                        line, buffer = buffer.split(b"\r\n", 1)
                        upper = line.decode("ascii", errors="replace").upper()
                        if upper.startswith(("EHLO", "HELO")):
                            conn.sendall(b"250-fake.smtp.test\r\n250 OK\r\n")
                        elif upper.startswith("RCPT"):
                            conn.sendall(b"550 5.1.1 user unknown here\r\n")
                        elif upper.startswith("QUIT"):
                            conn.sendall(b"221 Bye\r\n")
                            return
                        else:
                            conn.sendall(b"250 OK\r\n")

    monkeypatch.setattr(
        "saas_os.core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    with _RefusingServer() as server:
        provider = SmtpEmailProvider(
            config=EmailConfig(smtp_host="127.0.0.1", smtp_port=server.port, tls_mode="none")
        )
        with pytest.raises(EmailProviderError) as excinfo:
            provider.send(_message())

    assert excinfo.value.permanent is True
    assert excinfo.value.reply_code == 550
    assert "user unknown" not in str(excinfo.value)


# --- ADR-0057: Mailpit profile ------------------------------------------------


def test_mailpit_provider_sends_plaintext_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _no_secrets() -> None:
        raise AssertionError("Mailpit must never read SMTP credentials")

    _RecordingSmtpClient.instances.clear()
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("MAILPIT_SMTP_HOST", "mailpit")
    monkeypatch.delenv("MAILPIT_SMTP_PORT", raising=False)
    monkeypatch.setattr("saas_os.core.email.smtp_provider.get_secrets_provider", _no_secrets)
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    MailpitEmailProvider().send(_message())

    client = _RecordingSmtpClient.instances[0]
    assert (client.host, client.port) == ("mailpit", 1025)
    assert client.starttls_called is False
    assert client.login_called_with is None
