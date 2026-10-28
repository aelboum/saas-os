"""The subscription-time `InvalidWebhookUrlError` never repeats the URL
(ledger row 900, follow-up of 2026-10-28).

A subscription URL can carry a credential or token in its user info, path or
query. The error used to quote it, so a consumer route that let the error
propagate had SaaS OS's request middleware write the token to the
`unhandled_request_error` log line (the formatted exception) and to the
request span (`exception.message`, `exception.stacktrace`). These tests use
fake canaries only, no network and no database: every rejection here happens
before `subscribe()` opens a session.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from saas_os.api import middleware
from saas_os.core.authority.caller import SystemAuthority, SystemCaller
from saas_os.core.outbox import PermanentEventError
from saas_os.core.outbox.dispatch import describe_error
from saas_os.core.webhooks import service as webhooks_service
from saas_os.core.webhooks.config import get_webhook_security_config
from saas_os.core.webhooks.errors import InvalidWebhookUrlError
from saas_os.infra.observability.logging import JsonFormatter
from saas_os.infra.observability.otel import InMemorySpanExporter

_MESSAGE = "Invalid webhook URL (must be http:// or https://)."
_TOKEN = "subscribe-token-canary-0900"
_PASSWORD = "subscribe-pw-canary-0900"  # pragma: allowlist secret -- a fake credential
_CANARIES = (_TOKEN, _PASSWORD, "hooks-canary.example")
_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

# Each URL is refused by a different subscription-time check.
_REFUSED = {
    "scheme": f"ftp://user:{_PASSWORD}@hooks-canary.example/x?token={_TOKEN}",
    "no_host": f"https://user:{_PASSWORD}@/x?token={_TOKEN}",
    "too_long": f"https://user:{_PASSWORD}@hooks-canary.example/{'a' * 2048}?token={_TOKEN}",
    "literal_non_public": f"https://user:{_PASSWORD}@127.0.0.1/x?token={_TOKEN}",
    "malformed_port": f"https://user:{_PASSWORD}@hooks-canary.example:99999/x?token={_TOKEN}",
    "port_not_allowed": f"https://user:{_PASSWORD}@hooks-canary.example:8443/x?token={_TOKEN}",
    "http_refused": f"http://user:{_PASSWORD}@hooks-canary.example/x?token={_TOKEN}",
}


@pytest.fixture(autouse=True)
def _security_config(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Only 443 allowed and plain `http://` refused, so that the last two
    URLs above are refused by their own check."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_PORTS", "443")
    monkeypatch.setenv("WEBHOOK_ALLOW_HTTP", "false")
    get_webhook_security_config.cache_clear()
    yield
    get_webhook_security_config.cache_clear()


def _linked(exc: BaseException) -> list[BaseException]:
    seen: set[int] = set()
    found: list[BaseException] = []
    pending: list[BaseException | None] = [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        found.append(current)
        pending.extend((current.__cause__, current.__context__))
    return found


def _subscribe(url: str) -> None:
    webhooks_service.subscribe(uuid.uuid4(), url, caller=_PROVISIONING)


@pytest.mark.parametrize("reason", sorted(_REFUSED))
def test_a_refused_subscription_url_is_not_in_the_error(reason: str) -> None:
    with pytest.raises(InvalidWebhookUrlError) as excinfo:
        _subscribe(_REFUSED[reason])
    error = excinfo.value

    # The type and classification are unchanged: a plain `ValueError` for
    # the caller, nothing to retry or dead-letter...
    assert type(error) is InvalidWebhookUrlError
    assert isinstance(error, ValueError)
    assert not isinstance(error, PermanentEventError)
    # ...and no part of the URL is in it or in anything linked to it.
    assert str(error) == _MESSAGE
    assert error.args == (_MESSAGE,)
    assert describe_error(error) == f"InvalidWebhookUrlError: {_MESSAGE}"
    for item in _linked(error):
        shown = f"{item!s} {item!r} {vars(item)!r}"
        for canary in _CANARIES:
            assert canary not in shown, (reason, canary, shown)


def test_a_valid_https_url_still_passes_the_subscription_checks() -> None:
    """The checks themselves are unchanged: a public `https` URL with a
    token in its query passes (`subscribe()` itself would go on to the
    database, which this unit test does not have)."""
    url = f"https://hooks-canary.example/x?token={_TOKEN}"
    webhooks_service._validate_url(url)  # pyright: ignore[reportPrivateUsage]
    webhooks_service._require_http_allowed(url, InvalidWebhookUrlError, phase="subscribe")  # pyright: ignore[reportPrivateUsage]


class _Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(JsonFormatter())
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


def test_an_unhandled_subscription_error_reaches_no_log_or_span_with_the_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A consumer route that does not handle the error: the middleware logs
    it with its traceback and records it on the span. Neither carries any
    part of the URL; the client gets the generic 500."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(middleware, "get_tracer", provider.get_tracer)
    lines = _Lines()
    middleware.logger.addHandler(lines)

    app = FastAPI()
    app.add_middleware(middleware.CorrelationIdMiddleware)

    @app.post("/hooks/{reason}")
    def create(reason: str) -> dict[str, str]:
        _subscribe(_REFUSED[reason])
        return {}

    client = TestClient(app, raise_server_exceptions=False)
    try:
        responses = [client.post(f"/hooks/{reason}") for reason in sorted(_REFUSED)]
    finally:
        middleware.logger.removeHandler(lines)

    assert [response.status_code for response in responses] == [500] * len(_REFUSED)
    assert {response.text for response in responses} == {"Internal Server Error"}

    unhandled = [
        record
        for record in map(json.loads, lines.lines)
        if record["message"] == "unhandled_request_error"
    ]
    assert len(unhandled) == len(_REFUSED)
    events = [event for span in exporter.get_finished_spans() for event in span.events]
    assert [event.name for event in events] == ["exception"] * len(_REFUSED)
    for record in unhandled:
        assert f"InvalidWebhookUrlError: {_MESSAGE}" in record["exception"]
    for event in events:
        assert (event.attributes or {})["exception.message"] == _MESSAGE

    sinks = [*lines.lines, *(repr(dict(event.attributes or {})) for event in events)]
    for text in sinks:
        for canary in _CANARIES:
            assert canary not in text, (canary, text)
