"""FastAPI's native telemetry is off in `build_platform_app()`.

FastAPI 0.142+ opens its own server span whenever a global tracer
provider exists, with `url.query` copied verbatim. On `/auth/callback`
that is the OIDC authorization `code` and `state` (found in the ADR-0064
E2E run, 2026-11-20). The one request span must stay
`CorrelationIdMiddleware`'s, which records method, path, status and the
correlation ID, and no query string.

No database: the app is driven without its lifespan.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry import trace as otel_trace_api
from opentelemetry.util._once import Once

import saas_os.infra.observability.otel as otel_module
from saas_os.api.platform import build_platform_app
from saas_os.infra.observability.config import ObservabilityConfig
from saas_os.infra.observability.otel import InMemorySpanExporter, configure_tracing

_CODE = "authorization-code-that-must-not-be-recorded"
_STATE = "state-that-must-not-be-recorded"


def _reset() -> None:
    otel_trace_api._TRACER_PROVIDER = None
    otel_trace_api._TRACER_PROVIDER_SET_ONCE = Once()
    otel_module._configured = False


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    _reset()
    exporter = InMemorySpanExporter()
    configure_tracing(
        ObservabilityConfig(service_name="telemetry-probe"), exporter=exporter, force=True
    )
    yield exporter
    _reset()


def _app() -> FastAPI:
    app = build_platform_app(title="telemetry", version="test")

    @app.get("/probe")
    def probe() -> dict[str, str]:
        return {"ok": "yes"}

    return app


def test_a_request_produces_only_the_correlation_span(spans: InMemorySpanExporter) -> None:
    response = TestClient(_app()).get("/probe", params={"code": _CODE, "state": _STATE})
    assert response.status_code == 200

    finished = spans.get_finished_spans()
    assert [span.name for span in finished] == ["GET /probe"]
    scope = finished[0].instrumentation_scope
    assert scope is not None and scope.name == "saas_os.api.middleware"


def test_no_span_records_the_query_string(spans: InMemorySpanExporter) -> None:
    TestClient(_app()).get("/probe", params={"code": _CODE, "state": _STATE})

    finished = spans.get_finished_spans()
    assert finished
    for span in finished:
        attributes = dict(span.attributes or {})
        assert "url.query" not in attributes
        for value in attributes.values():
            assert _CODE not in str(value) and _STATE not in str(value)
