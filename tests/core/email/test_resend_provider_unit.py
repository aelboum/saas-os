"""ADR-0058 -- `saas_os/core/email/resend_provider.py::ResendEmailProvider`.

Every request goes through the real `StrictEgressClient` with a scripted
resolver and an `httpx.MockTransport`, so URL validation, address pinning,
redirect refusal and the response limit are the production code paths. No
request leaves the process, no real email is sent and no real API key is
used: `CANARY_KEY` is a made-up value whose only job is to be searched for.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from egress_support import PUBLIC_V4, StaticResolver, mock_transport_factory
from saas_os.core.email.config import ResendConfig
from saas_os.core.email.errors import (
    EmailConfigurationError,
    EmailProviderError,
    InvalidEmailAddressError,
)
from saas_os.core.email.provider import EmailMessage, EmailProvider
from saas_os.core.email.resend_provider import RESEND_API_URL, ResendEmailProvider
from saas_os.core.email.service import send_email
from saas_os.infra.egress import StrictEgressClient, StrictEgressPolicy
from saas_os.infra.secrets.provider import SecretsProvider

CANARY_KEY = "re_canary_0123456789abcdef"  # pragma: allowlist secret -- fake
CANARY_TEXT = "canary-provider-message-text"
RESEND_ID = "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"

Handler = Callable[[httpx.Request], Any]


class _RecordingSecrets(SecretsProvider):
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values
        self.requested: list[str] = []

    def get(self, name: str) -> str | None:
        self.requested.append(name)
        return self._values.get(name)


@pytest.fixture
def secrets(monkeypatch: pytest.MonkeyPatch) -> _RecordingSecrets:
    recording = _RecordingSecrets({"RESEND_API_KEY": CANARY_KEY})
    monkeypatch.setattr(
        "saas_os.core.email.resend_provider.get_secrets_provider", lambda: recording
    )
    return recording


def _message(**overrides: object) -> EmailMessage:
    defaults: dict[str, object] = {
        "sender": "no-reply@mail.example.com",
        "to": ("recipient@example.com",),
        "subject": "Test subject",
        "text_body": "Hello, world.",
    }
    defaults.update(overrides)
    return EmailMessage(**defaults)  # type: ignore[arg-type]


def _client(handler: Handler, *, answer: str = PUBLIC_V4) -> StrictEgressClient:
    return StrictEgressClient(
        StrictEgressPolicy(
            connect_timeout_seconds=5, read_timeout_seconds=5, max_response_bytes=65536
        ),
        resolver=StaticResolver([[answer]]),
        transport_factory=mock_transport_factory(handler),
    )


class _Recorder:
    """A Resend stand-in: records each request and answers with `status`
    and a JSON `body` (or `raw` bytes)."""

    def __init__(self, status: int = 200, body: object = None, raw: bytes | None = None) -> None:
        self.status = status
        self.body = {"id": RESEND_ID} if body is None and raw is None else body
        self.raw = raw
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raw is not None:
            return httpx.Response(self.status, content=self.raw)
        return httpx.Response(self.status, json=self.body)

    def payload(self, index: int = 0) -> dict[str, Any]:
        return json.loads(self.requests[index].content)


def _provider(handler: Handler, **client_options: Any) -> ResendEmailProvider:
    return ResendEmailProvider(config=ResendConfig(), client=_client(handler, **client_options))


def _assert_no_secret(exc: BaseException, caplog: pytest.LogCaptureFixture) -> None:
    rendered = [str(exc), repr(exc), caplog.text]
    cause: BaseException | None = exc.__cause__
    while cause is not None:
        rendered += [str(cause), repr(cause)]
        cause = cause.__cause__
    for text in rendered:
        assert CANARY_KEY not in text
        assert CANARY_TEXT not in text


# --- Construction and configuration ------------------------------------------


def test_construction_reads_only_the_resend_key_through_the_secrets_provider(secrets) -> None:
    ResendEmailProvider(config=ResendConfig(), client=_client(_Recorder()))
    assert secrets.requested == ["RESEND_API_KEY"]


def test_the_provider_satisfies_the_email_provider_protocol(secrets) -> None:
    assert isinstance(_provider(_Recorder()), EmailProvider)


@pytest.mark.parametrize("value", [None, ""])
def test_a_missing_api_key_is_a_configuration_error(monkeypatch, value) -> None:
    values = {} if value is None else {"RESEND_API_KEY": value}
    monkeypatch.setattr(
        "saas_os.core.email.resend_provider.get_secrets_provider",
        lambda: _RecordingSecrets(values),
    )
    with pytest.raises(EmailConfigurationError, match="RESEND_API_KEY is not set"):
        ResendEmailProvider(config=ResendConfig())


@pytest.mark.parametrize(
    "value",
    [f"{CANARY_KEY}\r\nX-Injected: 1", f" {CANARY_KEY}", f"{CANARY_KEY}\x00", f"{CANARY_KEY}é"],
)
def test_an_api_key_that_could_break_the_header_is_refused_without_echoing_it(
    monkeypatch, value
) -> None:
    monkeypatch.setattr(
        "saas_os.core.email.resend_provider.get_secrets_provider",
        lambda: _RecordingSecrets({"RESEND_API_KEY": value}),
    )
    with pytest.raises(EmailConfigurationError) as excinfo:
        ResendEmailProvider(config=ResendConfig())
    assert CANARY_KEY not in str(excinfo.value)


def test_repr_never_shows_the_api_key(secrets) -> None:
    provider = _provider(_Recorder())
    assert CANARY_KEY not in repr(provider)
    assert CANARY_KEY not in str(provider)


def test_the_default_client_is_the_strict_egress_client_bounded_by_the_email_timeout(
    secrets,
) -> None:
    provider = ResendEmailProvider(config=ResendConfig(timeout_seconds=7))
    client = provider._client  # noqa: SLF001
    assert isinstance(client, StrictEgressClient)
    assert client.policy.connect_timeout_seconds == 7
    assert client.policy.read_timeout_seconds == 7
    assert client.policy.allowed_ports == frozenset({443})
    assert client.policy.trusted_endpoints == ()


def test_an_unsupported_http_stack_is_a_configuration_error(secrets, monkeypatch) -> None:
    monkeypatch.setattr("saas_os.infra.egress.compat.httpx.__version__", "0.27.0")
    with pytest.raises(EmailConfigurationError, match="unsupported_httpx_version"):
        ResendEmailProvider(config=ResendConfig())


def test_resend_config_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(EmailConfigurationError):
        ResendConfig(timeout_seconds=0)


# --- Request construction ------------------------------------------------------


def test_a_successful_send_returns_resends_email_id(secrets) -> None:
    recorder = _Recorder()
    result = _provider(recorder).send(_message())
    assert result.accepted is True
    assert result.provider_message_id == RESEND_ID
    assert len(recorder.requests) == 1


def test_the_request_is_an_authenticated_json_post_to_the_official_endpoint(secrets) -> None:
    recorder = _Recorder()
    _provider(recorder).send(_message())
    request = recorder.requests[0]
    assert RESEND_API_URL == "https://api.resend.com/emails"
    assert request.method == "POST"
    assert request.url.scheme == "https"
    assert request.url.path == "/emails"
    # Pinned to the validated address; the name stays in Host (and in SNI).
    assert request.url.host == PUBLIC_V4
    assert request.headers["host"] == "api.resend.com"
    assert request.headers["authorization"] == f"Bearer {CANARY_KEY}"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["accept"] == "application/json"


def test_sender_recipients_subject_and_text_are_mapped(secrets) -> None:
    recorder = _Recorder()
    _provider(recorder).send(
        _message(to=("a@example.com", "b@example.com"), subject="Grüße", text_body="Body ✓")
    )
    assert recorder.payload() == {
        "from": "no-reply@mail.example.com",
        "to": ["a@example.com", "b@example.com"],
        "subject": "Grüße",
        "text": "Body ✓",
    }


def test_html_and_reply_to_are_mapped_when_present(secrets) -> None:
    recorder = _Recorder()
    _provider(recorder).send(_message(html_body="<p>Hi</p>", reply_to="support@example.com"))
    payload = recorder.payload()
    assert payload["html"] == "<p>Hi</p>"
    assert payload["reply_to"] == "support@example.com"


def test_metadata_is_never_forwarded(secrets) -> None:
    recorder = _Recorder()
    _provider(recorder).send(_message(metadata={"correlation": "abc-123"}))
    assert "abc-123" not in recorder.requests[0].content.decode()
    assert "tags" not in recorder.payload()


def test_without_a_message_id_there_is_no_idempotency_key_or_custom_header(secrets) -> None:
    recorder = _Recorder()
    _provider(recorder).send(_message())
    assert "idempotency-key" not in recorder.requests[0].headers
    assert "headers" not in recorder.payload()


def test_a_message_id_gives_a_stable_opaque_idempotency_key_and_message_id_header(
    secrets,
) -> None:
    recorder = _Recorder()
    provider = _provider(recorder)
    message_id = "<notification.0b9e@mail.example.com>"
    provider.send(_message(message_id=message_id))
    provider.send(_message(message_id=message_id))
    provider.send(_message(message_id="<notification.other@mail.example.com>"))

    keys = [request.headers["idempotency-key"] for request in recorder.requests]
    assert keys[0] == keys[1] != keys[2]
    assert 1 <= len(keys[0]) <= 256
    assert "notification" not in keys[0] and "example" not in keys[0]
    assert recorder.payload()["headers"] == {"Message-ID": message_id}


def test_more_than_fifty_recipients_is_permanent_and_sends_nothing(secrets) -> None:
    recorder = _Recorder()
    recipients = tuple(f"user{i}@example.com" for i in range(51))
    with pytest.raises(EmailProviderError) as excinfo:
        _provider(recorder).send(_message(to=recipients))
    assert excinfo.value.permanent is True
    assert excinfo.value.reason == "too_many_recipients"
    assert recorder.requests == []


def test_fifty_recipients_are_sent(secrets) -> None:
    recorder = _Recorder()
    recipients = tuple(f"user{i}@example.com" for i in range(50))
    _provider(recorder).send(_message(to=recipients))
    assert len(recorder.payload()["to"]) == 50


# --- Failure classification ---------------------------------------------------


@pytest.mark.parametrize(
    ("status", "name", "permanent"),
    [
        (400, "validation_error", True),
        (400, "invalid_idempotency_key", True),
        (422, "missing_required_field", True),
        (422, "invalid_parameter", True),
        (401, "missing_api_key", False),
        (401, "restricted_api_key", False),
        (403, "validation_error", False),  # unverified domain: the operator fixes it
        (403, "suspended_api_key", False),
        (404, "not_found", False),
        (405, "method_not_allowed", False),
        (409, "concurrent_idempotent_requests", False),
        (409, "invalid_idempotent_request", False),
        (429, "rate_limit_exceeded", False),
        (429, "daily_quota_exceeded", False),
        (429, "monthly_quota_exceeded", False),
        (500, "application_error", False),
        (503, "service_unavailable", False),
    ],
)
def test_api_errors_are_classified_permanent_only_when_a_resend_cannot_succeed(
    secrets, caplog, status: int, name: str, permanent: bool
) -> None:
    body = {"statusCode": status, "name": name, "message": f"{CANARY_TEXT} {CANARY_KEY}"}
    with caplog.at_level(logging.DEBUG), pytest.raises(EmailProviderError) as excinfo:
        _provider(_Recorder(status, body)).send(_message())
    assert excinfo.value.permanent is permanent
    assert excinfo.value.reply_code == status
    assert excinfo.value.reason == name
    _assert_no_secret(excinfo.value, caplog)


@pytest.mark.parametrize(
    "body",
    [
        {"name": "not_a_documented_name", "message": CANARY_TEXT},
        {"name": "validation_error\r\nX-Injected: 1"},
        {"name": 42},
        {"message": CANARY_TEXT},
        ["validation_error"],
    ],
)
def test_an_unrecognized_error_body_is_never_copied(secrets, caplog, body: object) -> None:
    with pytest.raises(EmailProviderError) as excinfo:
        _provider(_Recorder(400, body)).send(_message())
    assert excinfo.value.reason == "http_error"
    assert excinfo.value.permanent is True
    _assert_no_secret(excinfo.value, caplog)


def test_a_non_json_error_body_is_a_generic_transient_failure(secrets, caplog) -> None:
    raw = f"<html>{CANARY_TEXT}</html>".encode()
    with pytest.raises(EmailProviderError) as excinfo:
        _provider(_Recorder(502, raw=raw)).send(_message())
    assert (excinfo.value.reason, excinfo.value.permanent, excinfo.value.reply_code) == (
        "http_error",
        False,
        502,
    )
    _assert_no_secret(excinfo.value, caplog)


@pytest.mark.parametrize(
    ("body", "raw"),
    [
        (None, b"not json"),
        (None, b"\xff\xfe"),
        (["id"], None),
        ({}, None),
        ({"id": ""}, None),
        ({"id": 123}, None),
        ({"id": "abc\r\ndef"}, None),
        ({"id": "x" * 257}, None),
    ],
)
def test_an_unreadable_success_is_transient_and_ambiguous(secrets, body, raw) -> None:
    with pytest.raises(EmailProviderError) as excinfo:
        _provider(_Recorder(200, body, raw=raw)).send(_message())
    assert excinfo.value.reason == "malformed_response"
    assert excinfo.value.permanent is False
    assert excinfo.value.reply_code == 200


def test_a_redirect_is_never_followed(secrets) -> None:
    recorder = _Recorder(302, {"id": RESEND_ID})
    with pytest.raises(EmailProviderError) as excinfo:
        _provider(recorder).send(_message())
    assert excinfo.value.reason == "redirect_rejected"
    assert excinfo.value.permanent is False
    assert len(recorder.requests) == 1


def test_an_oversized_response_is_refused(secrets) -> None:
    raw = json.dumps({"id": RESEND_ID, "pad": "x" * 70000}).encode()
    with pytest.raises(EmailProviderError) as excinfo:
        _provider(_Recorder(200, raw=raw)).send(_message())
    assert excinfo.value.reason == "response_too_large"


# --- Network failures and timeouts ---------------------------------------------


def _raising(exc: Exception) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


@pytest.mark.parametrize(
    ("exc", "reason"),
    [
        (httpx.ConnectError("refused"), "connect_failed"),
        (httpx.ConnectTimeout("slow"), "connect_timeout"),
        (httpx.ReadTimeout("slow"), "read_timeout"),
        (httpx.WriteTimeout("slow"), "write_timeout"),
        (httpx.RemoteProtocolError("reset"), "exchange_failed"),
    ],
)
def test_network_failures_and_timeouts_are_transient(
    secrets, caplog, exc: Exception, reason: str
) -> None:
    with caplog.at_level(logging.DEBUG), pytest.raises(EmailProviderError) as excinfo:
        _provider(_raising(exc)).send(_message(message_id="<n.1@mail.example.com>"))
    assert excinfo.value.reason == reason
    assert excinfo.value.permanent is False
    assert excinfo.value.reply_code is None
    _assert_no_secret(excinfo.value, caplog)


def test_a_non_public_resolution_is_refused_before_anything_is_sent(secrets) -> None:
    recorder = _Recorder()
    with pytest.raises(EmailProviderError) as excinfo:
        _provider(recorder, answer="10.0.0.5").send(_message())
    assert excinfo.value.reason == "non_public_address"
    assert recorder.requests == []


def test_the_total_deadline_bounds_a_hung_request(secrets) -> None:
    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)
        raise AssertionError("unreachable")

    provider = ResendEmailProvider(config=ResendConfig(timeout_seconds=1), client=_client(hang))
    with pytest.raises(EmailProviderError) as excinfo:
        provider.send(_message())
    assert excinfo.value.reason == "deadline_expired"
    assert excinfo.value.permanent is False


def test_a_retry_after_an_ambiguous_timeout_reuses_the_idempotency_key(secrets) -> None:
    """The adapter never retries by itself; the caller's retry of the same
    message carries the same key, so Resend can return the first result."""
    attempts: list[httpx.Request] = []

    def flaky(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        if len(attempts) == 1:
            raise httpx.ReadTimeout("response lost")
        return httpx.Response(200, json={"id": RESEND_ID})

    provider = _provider(flaky)
    message = _message(message_id="<notification.7@mail.example.com>")
    with pytest.raises(EmailProviderError):
        provider.send(message)
    assert len(attempts) == 1  # no hidden retry inside the adapter
    assert provider.send(message).provider_message_id == RESEND_ID
    assert attempts[0].headers["idempotency-key"] == attempts[1].headers["idempotency-key"]


# --- Calling conventions --------------------------------------------------------


def test_send_works_from_a_thread_that_runs_an_event_loop(secrets) -> None:
    provider = _provider(_Recorder())

    async def caller() -> str | None:
        return provider.send(_message()).provider_message_id

    assert asyncio.run(caller()) == RESEND_ID


def test_send_works_through_asyncio_to_thread_like_the_notification_job(secrets) -> None:
    provider = _provider(_Recorder())

    async def caller() -> str | None:
        result = await asyncio.to_thread(provider.send, _message())
        return result.provider_message_id

    assert asyncio.run(caller()) == RESEND_ID


def test_send_email_validates_before_calling_resend(secrets) -> None:
    recorder = _Recorder()
    with pytest.raises(InvalidEmailAddressError):
        send_email(_message(to=("bad\r\nBcc: x@example.com",)), provider=_provider(recorder))
    assert recorder.requests == []
    assert send_email(_message(), provider=_provider(recorder)).provider_message_id == RESEND_ID
