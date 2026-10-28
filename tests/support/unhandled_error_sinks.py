"""What SaaS OS's request middleware does with an error a route lets
through: run `action` in a route behind `CorrelationIdMiddleware`, and
return the response with what reached the `unhandled_request_error` log
line (formatted by the repository's own `JsonFormatter`) and the request
span's events (on a local tracer provider; the global one is untouched).

It is on `sys.path` through `pythonpath` in `pyproject.toml`.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from saas_os.api import middleware
from saas_os.infra.observability.logging import JsonFormatter
from saas_os.infra.observability.otel import InMemorySpanExporter


@dataclass(frozen=True)
class UnhandledErrorSinks:
    status_code: int
    body: str
    log_exceptions: list[str]  # the `exception` field of each `unhandled_request_error` line
    span_events: list[dict[str, object]]

    def texts(self) -> list[str]:
        return [self.body, *self.log_exceptions, *(repr(event) for event in self.span_events)]


class _Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(JsonFormatter())
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


def unhandled_error_sinks(
    monkeypatch: pytest.MonkeyPatch, action: Callable[[], object]
) -> UnhandledErrorSinks:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(middleware, "get_tracer", provider.get_tracer)
    lines = _Lines()
    middleware.logger.addHandler(lines)

    app = FastAPI()
    app.add_middleware(middleware.CorrelationIdMiddleware)

    @app.post("/unhandled")
    def route() -> dict[str, str]:
        action()
        return {}

    try:
        response = TestClient(app, raise_server_exceptions=False).post("/unhandled")
    finally:
        middleware.logger.removeHandler(lines)
    records = [json.loads(line) for line in lines.lines]
    return UnhandledErrorSinks(
        status_code=response.status_code,
        body=response.text,
        log_exceptions=[
            str(record.get("exception", ""))
            for record in records
            if record["message"] == "unhandled_request_error"
        ],
        span_events=[
            dict(event.attributes or {})
            for span in exporter.get_finished_spans()
            for event in span.events
        ],
    )


def linked(exc: BaseException) -> list[BaseException]:
    """Every exception reachable from `exc` through `__cause__` and
    `__context__`, whatever `__suppress_context__` says."""
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
