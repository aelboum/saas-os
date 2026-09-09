"""OpenTelemetry tracer-provider tests (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.2). Uses `InMemorySpanExporter` throughout -- no network, no
external collector, deterministic.
"""

from __future__ import annotations

from infra.observability.config import ObservabilityConfig
from infra.observability.otel import InMemorySpanExporter, configure_tracing, get_tracer


def test_configure_tracing_produces_a_span_with_expected_resource_attributes() -> None:
    exporter = InMemorySpanExporter()
    config = ObservabilityConfig(
        service_name="probe-service", version="9.9.9", deployment_id="dep-1"
    )
    configure_tracing(config, exporter=exporter, force=True)

    tracer = get_tracer("test")
    with tracer.start_as_current_span("probe-span"):
        pass

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "probe-span"
    resource_attrs = spans[0].resource.attributes
    assert resource_attrs["service.name"] == "probe-service"
    assert resource_attrs["service.version"] == "9.9.9"
    assert resource_attrs["deployment.id"] == "dep-1"


def test_disabled_observability_produces_no_exported_spans() -> None:
    exporter = InMemorySpanExporter()
    config = ObservabilityConfig(enabled=False)
    # Note: exporter is passed, but disabled=True skips attaching any
    # processor at all -- proving disablement isn't merely "exporter=none".
    configure_tracing(config, exporter=exporter, force=True)

    tracer = get_tracer("test")
    with tracer.start_as_current_span("should-not-export"):
        pass

    assert exporter.get_finished_spans() == ()


def test_none_exporter_produces_no_exported_spans() -> None:
    config = ObservabilityConfig(exporter="none")
    configure_tracing(config, force=True)

    tracer = get_tracer("test")
    with tracer.start_as_current_span("should-not-export"):
        pass
    # No exporter attached at all; nothing to assert against directly, but
    # this must not raise and the span must still be creatable (task 8:
    # instrumented code shouldn't need to branch on whether tracing is on).


def test_console_exporter_makes_no_network_connection(monkeypatch) -> None:  # noqa: ANN001
    """Non-vacuous proof (matches the discipline established in
    core/application and infra/db's equivalent tests): the console
    exporter is the default and must never attempt outbound I/O.
    """
    import socket

    def _forbidden_connection(*args: object, **kwargs: object) -> None:
        raise AssertionError("console exporter attempted an outbound network connection")

    monkeypatch.setattr(socket, "create_connection", _forbidden_connection)

    config = ObservabilityConfig(exporter="console")
    configure_tracing(config, force=True)
    tracer = get_tracer("test")
    with tracer.start_as_current_span("probe-span"):
        pass


def test_configure_tracing_is_idempotent_without_force() -> None:
    """Repeated initialization from multiple entry points must not crash
    or duplicate span processors.
    """
    exporter_one = InMemorySpanExporter()
    configure_tracing(ObservabilityConfig(), exporter=exporter_one, force=True)

    # A second call *without* force must not replace the already-installed
    # global provider -- the second exporter should never receive spans.
    exporter_two = InMemorySpanExporter()
    configure_tracing(ObservabilityConfig(), exporter=exporter_two)

    tracer = get_tracer("test")
    with tracer.start_as_current_span("probe-span"):
        pass

    assert len(exporter_one.get_finished_spans()) == 1
    assert len(exporter_two.get_finished_spans()) == 0
