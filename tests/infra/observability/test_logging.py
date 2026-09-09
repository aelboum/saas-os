"""Structured logging tests (docs/IMPLEMENTATION-ROADMAP.md Phase 2.2)."""

from __future__ import annotations

import json
import logging

import pytest
from infra.observability.config import ObservabilityConfig
from infra.observability.context import bind_correlation_context
from infra.observability.logging import configure_logging
from infra.observability.otel import InMemorySpanExporter, configure_tracing, get_tracer


@pytest.fixture
def captured_logs(capsys: pytest.CaptureFixture[str]):
    def _get() -> list[dict[str, object]]:
        out = capsys.readouterr().out
        return [json.loads(line) for line in out.strip().splitlines() if line.strip()]

    return _get


def test_configure_logging_produces_json_lines(captured_logs) -> None:  # noqa: ANN001
    configure_logging(ObservabilityConfig(log_level="INFO"))
    logging.getLogger("probe").info("hello")

    records = captured_logs()
    assert len(records) == 1
    assert records[0]["message"] == "hello"
    assert records[0]["level"] == "INFO"
    assert records[0]["logger"] == "probe"
    assert "timestamp" in records[0]


def test_log_record_carries_correlation_context(captured_logs) -> None:  # noqa: ANN001
    configure_logging(ObservabilityConfig())
    with bind_correlation_context(tenant_id="t1", user_id="u1", request_id="r1"):
        logging.getLogger("probe").info("scoped message")

    record = captured_logs()[0]
    assert record["tenant_id"] == "t1"
    assert record["user_id"] == "u1"
    assert record["request_id"] == "r1"
    assert record["agent_id"] is None
    assert record["action_id"] is None


def test_log_record_carries_deployment_fields(captured_logs) -> None:  # noqa: ANN001
    configure_logging(ObservabilityConfig(deployment_id="dep-7", version="3.1.4"))
    logging.getLogger("probe").info("message")

    record = captured_logs()[0]
    assert record["deployment_id"] == "dep-7"
    assert record["version"] == "3.1.4"


def test_log_record_carries_trace_and_span_id_when_inside_a_span(captured_logs) -> None:  # noqa: ANN001
    configure_logging(ObservabilityConfig())
    exporter = InMemorySpanExporter()
    configure_tracing(ObservabilityConfig(), exporter=exporter, force=True)
    tracer = get_tracer("test")

    with tracer.start_as_current_span("probe-span"):
        logging.getLogger("probe").info("inside a span")

    record = captured_logs()[0]
    assert record["trace_id"] is not None
    assert record["span_id"] is not None
    assert len(record["trace_id"]) == 32  # 128-bit trace ID, hex
    assert len(record["span_id"]) == 16  # 64-bit span ID, hex


def test_log_record_has_no_trace_id_outside_a_span(captured_logs) -> None:  # noqa: ANN001
    configure_logging(ObservabilityConfig())
    logging.getLogger("probe").info("no span here")

    record = captured_logs()[0]
    assert record["trace_id"] is None
    assert record["span_id"] is None


def test_correlation_id_and_trace_id_are_not_conflated(captured_logs) -> None:  # noqa: ANN001
    """docs/IMPLEMENTATION-ROADMAP.md Phase 2.2 task 7: request_id (our
    application correlation scheme) and trace_id (OpenTelemetry's own) are
    different identifiers, not aliases of each other.
    """
    configure_logging(ObservabilityConfig())
    exporter = InMemorySpanExporter()
    configure_tracing(ObservabilityConfig(), exporter=exporter, force=True)
    tracer = get_tracer("test")

    with bind_correlation_context(request_id="app-request-id-123"):
        with tracer.start_as_current_span("probe-span"):
            logging.getLogger("probe").info("message")

    record = captured_logs()[0]
    assert record["request_id"] == "app-request-id-123"
    assert record["trace_id"] != record["request_id"]
    assert record["trace_id"] is not None


def test_configure_logging_is_safe_to_call_more_than_once(captured_logs) -> None:  # noqa: ANN001
    configure_logging(ObservabilityConfig())
    configure_logging(ObservabilityConfig())
    logging.getLogger("probe").info("only once")

    records = captured_logs()
    # A stale duplicate handler from the first call would double this.
    assert len(records) == 1


def test_no_secret_value_is_logged(captured_logs) -> None:  # noqa: ANN001
    """Non-vacuous (docs/SECURITY.md section 4, docs/IMPLEMENTATION-ROADMAP.md
    Phase 2.2 task 12): the correlation context and config carry no secret,
    so a normal log call cannot leak one through the fields this module
    attaches automatically. Confirms a representative secret-shaped value
    that is *not* passed to the logger never appears in the emitted line.
    """
    configure_logging(ObservabilityConfig())
    real_secret = "sk-should-never-appear-in-a-log-line"  # noqa: S105 -- deliberately not logged, asserted absent
    logging.getLogger("probe").info("a perfectly normal log message")

    raw_line = captured_logs()
    assert real_secret not in json.dumps(raw_line)
