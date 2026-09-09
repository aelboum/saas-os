"""Infra observability foundation (docs/IMPLEMENTATION-ROADMAP.md Phase
2.2; docs/OBSERVABILITY.md).

Owns the instrumentation SDK/conventions for logs and traces
(docs/OBSERVABILITY.md section 1) -- every other module instruments
*through* this one rather than configuring its own logging format or
OpenTelemetry setup. Metrics are explicitly out of scope for this phase:
the roadmap's Phase 2.2 acceptance criterion only exercises log/span
correlation, and there is no metric to record yet anywhere in the
codebase -- adding a metrics pipeline now would be exactly the kind of
premature scaffolding docs/IMPLEMENTATION-ROADMAP.md Phase 2.1's
correction (application-factory/health-endpoint removal) exists to warn
against. Revisit when a Core module actually has something to measure.

`infra/observability` does not import `core`, `products`, or
`control_plane`, and does not import any AI/LLM framework -- enforced by
import-linter (`pyproject.toml` `[tool.importlinter]`) and proven
non-vacuous in `tests/architecture/test_layer_boundaries.py`.
"""

from infra.observability.config import (
    ObservabilityConfig,
    ObservabilityConfigurationError,
    get_observability_config,
)
from infra.observability.context import (
    CorrelationContext,
    bind_correlation_context,
    get_correlation_context,
)
from infra.observability.logging import configure_logging
from infra.observability.otel import configure_tracing, get_tracer

__all__ = [
    "ObservabilityConfig",
    "ObservabilityConfigurationError",
    "get_observability_config",
    "CorrelationContext",
    "bind_correlation_context",
    "get_correlation_context",
    "configure_logging",
    "configure_tracing",
    "get_tracer",
]
