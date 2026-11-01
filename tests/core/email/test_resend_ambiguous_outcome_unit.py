"""Resend outcomes by phase, over real local TLS sockets (owner decision of
2026-11-01, ledger row F5; `saas_os/core/email/resend_provider.py`).

- Not sent (connection refused, closed before the request was read) is a
  transient `EmailProviderError`, safe to retry.
- Possibly sent (the request was read and the answer lost, a read timeout,
  an unreadable `2xx`) is `EmailOutcomeUnknownError`; its retry window is
  23 hours only when the request carried an `Idempotency-Key`.
- A retry of the same logical send carries the same key and a byte-identical
  body; a body that differs under the same key is refused by Resend and
  dead-lettered here as `idempotency_payload_mismatch`, never sent under
  another key.
- Status codes keep their classification.

`FakeResend` (`tests/support/resend_fault_server.py`) models Resend's
documented key handling, so "delivered once" is observable.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path

import pytest

from resend_fault_server import FakeResend
from saas_os.core.email.config import ResendConfig
from saas_os.core.email.errors import (
    EmailNotSentError,
    EmailOutcomeUnknownError,
    EmailProviderError,
)
from saas_os.core.email.provider import EmailMessage, EmailSendResult
from saas_os.core.email.resend_provider import (
    RESEND_IDEMPOTENT_RETRY_WINDOW,
    ResendEmailProvider,
    request_body,
)
from saas_os.infra.secrets.provider import SecretsProvider
from smtp_fault_server import closed_port

CANARY_KEY = "re_canary_ambiguous_0123456789"  # pragma: allowlist secret -- fake
_RECIPIENT = "recipient-canary@example.com"
_BODY = "body-canary-text"

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Secrets(SecretsProvider):
    def get(self, name: str) -> str | None:
        return CANARY_KEY if name == "RESEND_API_KEY" else None


@pytest.fixture(autouse=True)
def _api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("saas_os.core.email.resend_provider.get_secrets_provider", _Secrets)


def _message(*, keyed: bool = True, sender: str = "no-reply@mail.example.com") -> EmailMessage:
    return EmailMessage(
        sender=sender,
        to=(_RECIPIENT,),
        subject="subject",
        text_body=_BODY,
        message_id="<notification.e1@mail.example.com>" if keyed else None,
        idempotency_key="notification.e1" if keyed else None,
    )


async def _send(provider: ResendEmailProvider, message: EmailMessage) -> EmailSendResult:
    # The provider is synchronous; the fake server runs on this loop.
    return await asyncio.to_thread(provider.send, message)


async def _failure(provider: ResendEmailProvider, message: EmailMessage) -> EmailProviderError:
    with pytest.raises(EmailProviderError) as excinfo:
        await _send(provider, message)
    error = excinfo.value
    shown = f"{error!s} {error!r} {vars(error)!r}"
    for canary in (CANARY_KEY, _RECIPIENT, _BODY):
        assert canary not in shown
    return error


async def test_a_refused_connection_was_not_sent(tmp_path: Path) -> None:
    async with FakeResend(["ok"], tmp_path) as fake:
        error = await _failure(fake.provider(port=closed_port()), _message())
        assert fake.requests == []
    assert not isinstance(error, EmailOutcomeUnknownError)
    assert isinstance(error, EmailNotSentError)  # decision D: explicit
    assert error.permanent is False


async def test_a_connection_closed_before_the_request_is_read_is_ambiguous(
    tmp_path: Path,
) -> None:
    """The TLS session was up and the request may have been written before
    the close: the client cannot tell, so it is not "not sent"."""
    async with FakeResend(["close_before_read"], tmp_path) as fake:
        error = await _failure(fake.provider(), _message())
    assert isinstance(error, EmailOutcomeUnknownError)
    assert error.retry_within == RESEND_IDEMPOTENT_RETRY_WINDOW


@pytest.mark.parametrize("keyed", [True, False], ids=["with-key", "without-key"])
async def test_a_request_read_then_answered_by_a_close_is_ambiguous(
    tmp_path: Path, keyed: bool
) -> None:
    async with FakeResend(["drop_after_read"], tmp_path) as fake:
        error = await _failure(fake.provider(), _message(keyed=keyed))
        assert fake.deliveries == 1  # Resend did process it
    assert isinstance(error, EmailOutcomeUnknownError)
    assert error.permanent is False
    # Only a keyed request may be retried, and only within 23 hours.
    assert error.retry_within == (timedelta(hours=23) if keyed else None)


async def test_an_answer_after_the_read_timeout_is_ambiguous(tmp_path: Path) -> None:
    async with FakeResend(["stall"], tmp_path, stall_seconds=2) as fake:
        error = await _failure(fake.provider(read_timeout=0.3), _message())
    assert isinstance(error, EmailOutcomeUnknownError)
    assert (error.reason, error.phase) == ("read_timeout", "read")


async def test_an_unreadable_2xx_is_ambiguous(tmp_path: Path) -> None:
    async with FakeResend(["garbage_2xx"], tmp_path) as fake:
        error = await _failure(fake.provider(), _message())
    assert isinstance(error, EmailOutcomeUnknownError)
    assert (error.reason, error.phase, error.reply_code) == ("malformed_response", "response", 200)


async def test_a_2xx_is_accepted(tmp_path: Path) -> None:
    async with FakeResend(["ok"], tmp_path) as fake:
        result = await _send(fake.provider(), _message())
        assert fake.deliveries == 1
    assert result.accepted is True and result.provider_message_id


@pytest.mark.parametrize(
    ("action", "permanent", "hint"),
    [
        ((429, "rate_limit_exceeded", {"Retry-After": "30"}), False, 30.0),
        ((503, "service_unavailable"), False, None),
        ((409, "concurrent_idempotent_requests"), False, None),
        ((400, "validation_error"), True, None),
        ((422, "invalid_parameter"), True, None),
    ],
)
async def test_status_codes_keep_their_classification(
    tmp_path: Path, action: tuple[object, ...], permanent: bool, hint: float | None
) -> None:
    async with FakeResend([action], tmp_path) as fake:
        error = await _failure(fake.provider(), _message())
    assert not isinstance(error, EmailOutcomeUnknownError)
    assert error.permanent is permanent
    assert error.retry_after_seconds == hint


async def test_a_retry_after_an_ambiguous_send_reuses_the_key_and_the_exact_bytes(
    tmp_path: Path,
) -> None:
    """The first answer is lost after Resend processed the request; the
    retry carries the same key and byte-identical body, so Resend returns
    the first result and the recipient gets one email."""
    async with FakeResend(["drop_after_read", "ok"], tmp_path) as fake:
        # Two provider instances: a retry runs in another job, maybe another worker.
        first = await _failure(fake.provider(), _message())
        result = await _send(fake.provider(), _message())
        assert isinstance(first, EmailOutcomeUnknownError)
        assert result.accepted is True
        (key_1, body_1), (key_2, body_2) = fake.requests
        assert key_1 is not None and key_1 == key_2
        assert body_1 == body_2 == request_body(_message())
        assert fake.deliveries == 1


def test_the_key_follows_the_event_not_the_senders_domain() -> None:
    provider = ResendEmailProvider(config=ResendConfig(), client=object())  # type: ignore[arg-type]
    one = provider._request(_message(sender="a@one.example.com"))[0]  # pyright: ignore[reportPrivateUsage]
    two = provider._request(_message(sender="a@two.example.com"))[0]  # pyright: ignore[reportPrivateUsage]
    assert one["Idempotency-Key"] == two["Idempotency-Key"]
    other = EmailMessage(**{**vars(_message()), "idempotency_key": "notification.e2"})
    three = provider._request(other)[0]  # pyright: ignore[reportPrivateUsage]
    assert three["Idempotency-Key"] != one["Idempotency-Key"]


async def test_a_retry_whose_body_changed_is_refused_never_sent_under_another_key(
    tmp_path: Path,
) -> None:
    """The configured sender changed between the ambiguous attempt and the
    retry. Resend refuses the reused key; that is permanent here, so the
    event is dead-lettered instead of retried, and only one email exists."""
    async with FakeResend(["drop_after_read", "ok"], tmp_path) as fake:
        await _failure(fake.provider(), _message(sender="old@mail.example.com"))
        error = await _failure(fake.provider(), _message(sender="new@mail.example.com"))
        assert fake.deliveries == 1
        (key_1, _), (key_2, _) = fake.requests
        assert key_1 == key_2
    assert (error.reason, error.permanent, error.reply_code) == (
        "idempotency_payload_mismatch",
        True,
        409,
    )


def test_the_body_is_deterministic() -> None:
    body = request_body(_message())
    assert body == request_body(_message())
    parsed = json.loads(body)
    assert list(parsed) == sorted(parsed)
    assert b": " not in body and b", " not in body
    assert parsed["headers"] == {"Message-ID": "<notification.e1@mail.example.com>"}
