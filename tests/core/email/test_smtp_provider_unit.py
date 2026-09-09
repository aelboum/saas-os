"""P1.12 -- `core/email/smtp_provider.py::SmtpEmailProvider` tests.

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
import threading

import pytest
from core.email.config import EmailConfig
from core.email.errors import EmailConfigurationError, EmailProviderError
from core.email.provider import EmailMessage
from core.email.smtp_provider import SmtpEmailProvider
from infra.secrets.provider import SecretsProvider


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
    monkeypatch.setattr("core.email.smtp_provider.get_secrets_provider", lambda: fake_secrets)
    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))
    assert provider._username == "alice"  # noqa: SLF001 -- white-box construction proof
    assert provider._password == "s3cret"  # noqa: SLF001


def test_construction_allows_no_credentials_for_an_unauthenticated_relay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))
    assert provider._username is None  # noqa: SLF001
    assert provider._password is None  # noqa: SLF001


def test_construction_rejects_username_without_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "core.email.smtp_provider.get_secrets_provider",
        lambda: _FakeSecretsProvider({"SMTP_USERNAME": "alice"}),
    )
    with pytest.raises(EmailConfigurationError):
        SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))


def test_construction_rejects_password_without_username(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "core.email.smtp_provider.get_secrets_provider",
        lambda: _FakeSecretsProvider({"SMTP_PASSWORD": "s3cret"}),
    )
    with pytest.raises(EmailConfigurationError):
        SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))


def test_configuration_error_never_contains_the_credential_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.email.smtp_provider.get_secrets_provider",
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
        "core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
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
        "core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
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
        "core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
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
        "core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com", use_tls=True))
    provider.send(_message())

    assert _RecordingSmtpClient.instances[0].starttls_called is True


def test_starttls_is_not_called_when_use_tls_is_false(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com", use_tls=False))
    provider.send(_message())

    assert _RecordingSmtpClient.instances[0].starttls_called is False


def test_login_is_called_with_the_resolved_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingSmtpClient.instances.clear()
    monkeypatch.setattr(
        "core.email.smtp_provider.get_secrets_provider",
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
        "core.email.smtp_provider.get_secrets_provider", lambda: _FakeSecretsProvider({})
    )
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtpClient)

    provider = SmtpEmailProvider(config=EmailConfig(smtp_host="smtp.example.com"))
    provider.send(_message())

    assert _RecordingSmtpClient.instances[0].login_called_with is None
