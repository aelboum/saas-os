"""P1.12 -- pure unit tests for `core/email/service.py`:
`validate_email_address()` and `send_email()`, against `FakeEmailProvider`
only. No network needed.
"""

from __future__ import annotations

import pytest
from core.email.errors import EmailProviderError, InvalidEmailAddressError
from core.email.provider import EmailMessage, FakeEmailProvider
from core.email.service import send_email, validate_email_address


def _message(**overrides: object) -> EmailMessage:
    defaults: dict[str, object] = {
        "sender": "sender@example.com",
        "to": ("recipient@example.com",),
        "subject": "Test subject",
        "text_body": "Hello, world.",
    }
    defaults.update(overrides)
    return EmailMessage(**defaults)  # type: ignore[arg-type]


# --- validate_email_address() -------------------------------------------


def test_validate_accepts_a_normal_address() -> None:
    validate_email_address("user@example.com")  # must not raise


def test_validate_rejects_empty_address() -> None:
    with pytest.raises(InvalidEmailAddressError):
        validate_email_address("")


def test_validate_rejects_missing_at_sign() -> None:
    with pytest.raises(InvalidEmailAddressError):
        validate_email_address("not-an-email")


def test_validate_rejects_missing_domain_dot() -> None:
    with pytest.raises(InvalidEmailAddressError):
        validate_email_address("user@localhost")


@pytest.mark.parametrize(
    "malicious",
    [
        "user@example.com\r\nBcc: attacker@evil.example",
        "user@example.com\nX-Injected: true",
        "user@example.com\x00",
    ],
)
def test_validate_rejects_header_injection_attempts(malicious: str) -> None:
    with pytest.raises(InvalidEmailAddressError):
        validate_email_address(malicious)


def test_validate_error_never_echoes_the_offending_address() -> None:
    malicious = "user@example.com\r\nBcc: attacker@evil.example"
    with pytest.raises(InvalidEmailAddressError) as excinfo:
        validate_email_address(malicious)
    assert malicious not in str(excinfo.value)
    assert "attacker" not in str(excinfo.value)


# --- send_email() --------------------------------------------------------


def test_send_email_accepts_a_valid_message() -> None:
    provider = FakeEmailProvider()
    result = send_email(_message(), provider=provider)
    assert result.accepted is True
    assert len(provider.sent) == 1


def test_send_email_rejects_malformed_sender_before_calling_the_provider() -> None:
    provider = FakeEmailProvider()
    with pytest.raises(InvalidEmailAddressError):
        send_email(_message(sender="not-an-email"), provider=provider)
    assert provider.sent == []


def test_send_email_rejects_malformed_recipient_before_calling_the_provider() -> None:
    provider = FakeEmailProvider()
    with pytest.raises(InvalidEmailAddressError):
        send_email(_message(to=("not-an-email",)), provider=provider)
    assert provider.sent == []


def test_send_email_rejects_empty_recipient_list() -> None:
    provider = FakeEmailProvider()
    with pytest.raises(InvalidEmailAddressError):
        send_email(_message(to=()), provider=provider)
    assert provider.sent == []


def test_send_email_rejects_header_injection_in_subject() -> None:
    provider = FakeEmailProvider()
    with pytest.raises(InvalidEmailAddressError):
        send_email(_message(subject="Hi\r\nBcc: attacker@evil.example"), provider=provider)
    assert provider.sent == []


def test_send_email_rejects_malformed_reply_to() -> None:
    provider = FakeEmailProvider()
    with pytest.raises(InvalidEmailAddressError):
        send_email(_message(reply_to="not-an-email"), provider=provider)
    assert provider.sent == []


def test_send_email_normalizes_provider_failure() -> None:
    provider = FakeEmailProvider(fail=True)
    with pytest.raises(EmailProviderError):
        send_email(_message(), provider=provider)


def test_send_email_normalizes_an_unexpected_provider_exception() -> None:
    class _ExplodingProvider:
        def send(self, message: EmailMessage) -> None:  # noqa: ARG002
            raise ConnectionRefusedError("boom")

    with pytest.raises(EmailProviderError) as excinfo:
        send_email(_message(), provider=_ExplodingProvider())  # type: ignore[arg-type]
    assert "ConnectionRefusedError" in str(excinfo.value)
    assert "boom" not in str(excinfo.value)


def test_send_email_result_is_never_the_raw_provider_object() -> None:
    provider = FakeEmailProvider()
    result = send_email(_message(), provider=provider)
    from core.email.provider import EmailSendResult

    assert type(result) is EmailSendResult
