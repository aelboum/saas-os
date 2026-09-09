"""P1.12 -- pure unit tests for `core/email/provider.py`: `EmailMessage`/
`EmailSendResult` shape, `FakeEmailProvider` behavior, and the
`EmailProvider` protocol boundary. No network needed.
"""

from __future__ import annotations

import inspect

import pytest
from core.email.errors import EmailProviderError
from core.email.provider import EmailMessage, EmailProvider, EmailSendResult, FakeEmailProvider


def _message(**overrides: object) -> EmailMessage:
    defaults: dict[str, object] = {
        "sender": "sender@example.com",
        "to": ("recipient@example.com",),
        "subject": "Test subject",
        "text_body": "Hello, world.",
    }
    defaults.update(overrides)
    return EmailMessage(**defaults)  # type: ignore[arg-type]


def test_fake_provider_satisfies_the_email_provider_protocol() -> None:
    provider = FakeEmailProvider()
    assert isinstance(provider, EmailProvider)


def test_fake_provider_accepts_a_valid_message() -> None:
    provider = FakeEmailProvider()
    result = provider.send(_message())
    assert result.accepted is True
    assert result.provider_message_id is not None
    assert len(provider.sent) == 1
    assert provider.sent[0].subject == "Test subject"


def test_fake_provider_normalizes_a_failure() -> None:
    provider = FakeEmailProvider(fail=True)
    with pytest.raises(EmailProviderError):
        provider.send(_message())
    assert provider.sent == []


def test_email_send_result_is_a_normalized_small_shape() -> None:
    result = EmailSendResult(accepted=True, provider_message_id="abc123")
    assert result.accepted is True
    assert result.provider_message_id == "abc123"


def test_email_message_supports_optional_html_and_reply_to() -> None:
    message = _message(html_body="<p>Hello</p>", reply_to="reply@example.com")
    assert message.html_body == "<p>Hello</p>"
    assert message.reply_to == "reply@example.com"


def test_email_message_has_no_marketing_concepts() -> None:
    """This checkpoint's own Step 3: no campaign/audience/tracking
    vocabulary belongs on the message type at all."""
    fields = {f for f in EmailMessage.__dataclass_fields__}
    forbidden = {"campaign", "audience", "unsubscribe", "open_tracking", "click_tracking"}
    assert fields.isdisjoint(forbidden)


def test_core_email_does_not_import_smtplib_outside_the_smtp_provider() -> None:
    """Mirrors `tests/core/billing/test_billing_unit.py::
    test_core_billing_service_does_not_import_stripe_directly()`'s exact
    pattern -- only `core/email/smtp_provider.py` may know SMTP's
    specific transport details."""
    import core.email.provider as provider_module
    import core.email.service as service_module

    for module in (service_module, provider_module):
        source = inspect.getsource(module)
        assert "import smtplib" not in source
