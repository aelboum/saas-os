"""OpenTelemetry tracer provider setup (docs/IMPLEMENTATION-ROADMAP.md
Phase 2.2; docs/ADR/0009-observability-backend.md).

`configure_tracing()` is the single place a `TracerProvider` is built and
installed as the global default -- no other module constructs its own.
Safe to call more than once: idempotent, guarded by a module-level flag
(the same discipline `infra/db/engine.py`'s cached-singleton follows,
adapted here for OpenTelemetry's own global-provider model rather than
`functools.lru_cache`, since OTel's API is "set a global," not "return a
cached object").

Only the `console` exporter (ships inside `opentelemetry-sdk`, no network)
is implemented. `enabled=False` (or `exporter="none"`) installs no span
processor at all -- with no processor attached, spans are still created
(so instrumented code doesn't need to branch on whether tracing is
enabled) but are simply dropped, never doing any I/O.
"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.resources import (
    DEPLOYMENT_ENVIRONMENT,
    SERVICE_NAME,
    SERVICE_VERSION,
    Resource,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from infra.observability.config import ObservabilityConfig, get_observability_config

_configured = False


def _build_resource(config: ObservabilityConfig) -> Resource:
    return Resource.create(
        {
            SERVICE_NAME: config.service_name,
            SERVICE_VERSION: config.version,
            DEPLOYMENT_ENVIRONMENT: config.environment,
            "deployment.id": config.deployment_id,
        }
    )


def _build_exporter(config: ObservabilityConfig) -> SpanExporter | None:
    if config.exporter == "console":
        return ConsoleSpanExporter()
    if config.exporter == "none":
        return None
    # config.__post_init__ already validates this; unreachable in practice.
    raise AssertionError(f"unhandled exporter: {config.exporter!r}")


def configure_tracing(
    config: ObservabilityConfig | None = None,
    *,
    exporter: SpanExporter | None = None,
    force: bool = False,
) -> TracerProvider:
    """Build and install the global `TracerProvider`.

    `config` defaults to `get_observability_config()`. `exporter` overrides
    the config-driven exporter selection entirely -- for tests that need
    to assert on captured spans (pass an `InMemorySpanExporter`).
    `force=True` reconfigures even if already configured (test-only; do
    not use in application code -- OpenTelemetry does not support cleanly
    replacing an already-installed global TracerProvider's processors, so
    this always builds a fresh provider instance).
    """
    global _configured

    resolved_config = config or get_observability_config()
    provider = TracerProvider(resource=_build_resource(resolved_config))

    if resolved_config.enabled:
        resolved_exporter = exporter if exporter is not None else _build_exporter(resolved_config)
        if resolved_exporter is not None:
            provider.add_span_processor(SimpleSpanProcessor(resolved_exporter))

    if not _configured or force:
        trace.set_tracer_provider(provider)
        _configured = True

    return provider


def get_tracer(name: str) -> trace.Tracer:
    """A tracer bound to the currently installed global TracerProvider.
    Call `configure_tracing()` first in application startup; if it was
    never called, this resolves OpenTelemetry's own no-op default tracer
    (creates spans that do nothing and export nowhere) -- never raises.
    """
    return trace.get_tracer(name)


__all__ = ["configure_tracing", "get_tracer", "InMemorySpanExporter"]
