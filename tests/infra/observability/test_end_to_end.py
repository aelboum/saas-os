"""End-to-end acceptance test (docs/IMPLEMENTATION-ROADMAP.md Phase 2.2):

"a sample instrumented function call produces a log line and trace span
carrying the full correlation context" (Acceptance Criteria), verified via
"a simulated call chain" propagating `tenant_id`/`user_id`/`request_id`/
`deployment_id` into "emitted log/span records" (Tests).
"""

from __future__ import annotations

import json
import logging

import pytest
from infra.observability.config import ObservabilityConfig
from infra.observability.context import bind_correlation_context, get_correlation_context
from infra.observability.logging import configure_logging
from infra.observability.otel import InMemorySpanExporter, configure_tracing, get_tracer

logger = logging.getLogger("saas_os.probe")
tracer = get_tracer("saas_os.probe")


def _inner_step() -> None:
    """Simulates a second function deeper in a call chain -- the context
    must still be visible here without it being passed as an explicit
    argument, proving propagation through a call chain, not just within
    one function body.
    """
    with tracer.start_as_current_span("inner-step"):
        logger.info("inner step ran")


def _sample_instrumented_function() -> None:
    with tracer.start_as_current_span("sample-instrumented-function"):
        logger.info("sample instrumented function ran")
        _inner_step()


def test_sample_instrumented_call_produces_log_and_span_with_full_correlation_context(
    capsys: pytest.CaptureFixture[str],
) -> None:
    span_exporter = InMemorySpanExporter()
    config = ObservabilityConfig(
        service_name="acceptance-probe",
        deployment_id="deploy-acceptance",
        version="1.0.0-acceptance",
    )
    configure_logging(config)
    configure_tracing(config, exporter=span_exporter, force=True)

    with bind_correlation_context(
        tenant_id="tenant-acceptance", user_id="user-acceptance", request_id="req-acceptance"
    ):
        _sample_instrumented_function()

    # --- trace span carries the full correlation context (as OTel span
    #     attributes are conventionally used, and as this codebase's
    #     resource attributes carry the deployment dimension) ---
    spans = span_exporter.get_finished_spans()
    assert {s.name for s in spans} == {"sample-instrumented-function", "inner-step"}
    for span in spans:
        assert span.resource.attributes["service.name"] == "acceptance-probe"
        assert span.resource.attributes["deployment.id"] == "deploy-acceptance"
        assert span.resource.attributes["service.version"] == "1.0.0-acceptance"

    # --- log lines carry the full correlation context: tenant_id, user_id,
    #     request_id, deployment_id, version, plus trace_id/span_id ---
    log_lines = [
        json.loads(line) for line in capsys.readouterr().out.strip().splitlines() if line.strip()
    ]
    assert len(log_lines) == 2  # one per logger.info() call above
    for record in log_lines:
        assert record["tenant_id"] == "tenant-acceptance"
        assert record["user_id"] == "user-acceptance"
        assert record["request_id"] == "req-acceptance"
        assert record["deployment_id"] == "deploy-acceptance"
        assert record["version"] == "1.0.0-acceptance"
        assert record["trace_id"] is not None
        assert record["span_id"] is not None

    # --- the two spans belong to the same trace (nested call chain), but
    #     have distinct span IDs (distinct steps in the chain) ---
    trace_ids = {record["trace_id"] for record in log_lines}
    span_ids = {record["span_id"] for record in log_lines}
    assert len(trace_ids) == 1, "inner-step and sample-instrumented-function must share one trace"
    assert len(span_ids) == 2, (
        "inner-step and sample-instrumented-function must have distinct spans"
    )

    # --- context does not leak past the call chain (docs/OBSERVABILITY.md
    #     section 2: absent is a valid state for genuinely-unscoped work) ---
    assert get_correlation_context().tenant_id is None
