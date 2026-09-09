"""Test isolation for infra/observability.

OpenTelemetry's global TracerProvider can only be set once per process
(`opentelemetry.trace._TRACER_PROVIDER_SET_ONCE`) -- `force=True` in
`configure_tracing` replaces *our* module-level `_configured` flag, but
cannot make OTel's own global accept a second real provider. Without this
fixture, whichever test runs first would "win" the global provider for
the rest of the suite. Resetting OTel's private global state between
tests is the same approach OpenTelemetry's own test suite uses.

Reset runs both *before* and *after* each test in this directory (P1.4:
`api.main`'s `lifespan` now calls `configure_tracing()` too, as real
application startup code, the same as any real deployment would -- so in
the one shared pytest process the whole suite runs in, an earlier,
unrelated test file that happens to start the real app first (e.g. via
`TestClient(app)`) can otherwise "win" OTel's global ahead of these
tests, silently no-op'ing their own `force=True` calls. Resetting before
each test here makes this suite robust to that regardless of execution
order -- exactly the same isolation guarantee this fixture already gave
tests in this directory against *each other*, extended to cover a caller
outside this directory too.
"""

from __future__ import annotations

from collections.abc import Iterator

import infra.observability.otel as otel_module
import pytest
from opentelemetry import trace as otel_trace_api
from opentelemetry.util._once import Once


def _reset() -> None:
    otel_trace_api._TRACER_PROVIDER = None
    otel_trace_api._TRACER_PROVIDER_SET_ONCE = Once()
    otel_module._configured = False


@pytest.fixture(autouse=True)
def _reset_otel_global_tracer_provider() -> Iterator[None]:
    _reset()
    yield
    _reset()
