"""Request correlation middleware (P1.4: wiring `infra/observability`'s
existing correlation/logging/tracing foundation into the actual API
request lifecycle -- docs/OBSERVABILITY.md section 2, section 7 "What Is
Hard to Change Later").

Every inbound request is given a `request_id`: an incoming `X-Request-ID`
header is reused if present and shape-safe (`_SAFE_ID_PATTERN` --
bounded length, restricted character set, so an attacker-controlled
header value can never inject a newline/control character into a log
line or carry an unbounded payload); otherwise one is generated with
`uuid.uuid4()` (cryptographically random, `os.urandom`-backed). `X-Request-
ID` is this repository's only canonical correlation header -- chosen here
because no other convention exists yet anywhere in the codebase or docs.

The `request_id` is bound into `infra.observability.context`'s existing
`contextvars`-backed `CorrelationContext` for the duration of the request
(async-safe, already proven not to leak across concurrent requests --
`tests/infra/observability/test_context.py`) -- this module does not
invent a second correlation mechanism, only calls the one that already
exists. Every log record emitted while a request is being handled
therefore already carries `request_id` via `infra.observability.logging`'s
existing `CorrelationFilter`, with no call-site change required anywhere
else in the codebase.

A single request span is opened via `infra.observability.otel.get_tracer()`
(the existing, already-configured tracer -- no second tracing stack, no
new OpenTelemetry auto-instrumentation dependency) so the request is
visible in traces the same way `docs/OBSERVABILITY.md` section 2 requires
for every signal.

**Never included in the header, the span, or the one access-log line this
module emits**: the `Authorization` header, session/bearer tokens, API
keys, cookies, request bodies, or raw query strings (docs/SECURITY.md
section 4). Only method, path, status code, duration, and the correlation
ID are logged -- deliberately not `tenant_id`/`user_id`, which this
middleware runs *before* authentication/tenant resolution ever happen
(`api/dependencies.py`) and therefore does not have; those fields are
attached to later log lines by the same `CorrelationFilter` once
`api/dependencies.py` establishes them (a future, separate wiring step,
not part of this module's scope).

**Security boundary (docs/IMPLEMENTATION-ROADMAP.md P1.4 section 12)**:
`request_id` is never used, here or anywhere downstream, to determine
identity, tenant, permissions, or rate-limit state -- it is pure
correlation metadata, sourced (in the accepted-header case) directly from
an unauthenticated caller, and is never conflated with `core.identity`'s
own actor resolution or `core.tenancy`'s own tenant resolution
(`api/dependencies.py` remains the sole source of truth for both,
unmodified by this module).

An unhandled exception is caught here (not left to Starlette's default
`ServerErrorMiddleware`, which sits *outside* this middleware in the ASGI
stack and would otherwise build its fallback response without this
module ever getting a chance to attach the header): logged in full
(server-side only, via the existing structured logger -- never returned
to the caller) and answered with the exact same generic, non-leaking body
Starlette's own default `error_response()` would produce
(`PlainTextResponse("Internal Server Error", status_code=500)`) --
present the header, unchanged client-visible behavior otherwise.
"""

from __future__ import annotations

import logging
import re
import time
import uuid

from infra.observability.context import bind_correlation_context
from infra.observability.otel import get_tracer
from opentelemetry.trace import Status, StatusCode
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

logger = logging.getLogger(__name__)

CORRELATION_ID_HEADER = "X-Request-ID"

# Bounded length + restricted character set: safe to embed in a JSON log
# line, a span attribute, and an HTTP response header without escaping
# concerns, and cheap to reject rather than sanitize if a caller sends
# something unexpected -- an incoming value that fails this check is
# simply treated as absent (module docstring).
_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _resolve_request_id(request: Request) -> str:
    incoming = request.headers.get(CORRELATION_ID_HEADER)
    if incoming and _SAFE_ID_PATTERN.match(incoming):
        return incoming
    return str(uuid.uuid4())


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Resolve/bind/propagate one `request_id` per inbound request. See
    module docstring for the full contract."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = _resolve_request_id(request)
        started_at = time.monotonic()
        tracer = get_tracer(__name__)

        with (
            tracer.start_as_current_span(f"{request.method} {request.url.path}") as span,
            bind_correlation_context(request_id=request_id),
        ):
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.target", request.url.path)
            span.set_attribute("correlation.request_id", request_id)

            try:
                response = await call_next(request)
            except Exception as exc:
                # Full detail server-side only, via the existing structured
                # logger (request_id already attached by CorrelationFilter,
                # since we are inside bind_correlation_context above);
                # the client only ever sees the generic body below.
                logger.exception(
                    "unhandled_request_error",
                    extra={"http_method": request.method, "http_path": request.url.path},
                )
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                response = PlainTextResponse("Internal Server Error", status_code=500)

            span.set_attribute("http.status_code", response.status_code)

            # Logged *inside* the bind_correlation_context block on purpose
            # -- CorrelationFilter reads the context at log-emission time,
            # and request_id would already be gone once the block exits.
            duration_ms = round((time.monotonic() - started_at) * 1000, 2)
            logger.info(
                "request_completed",
                extra={
                    "http_method": request.method,
                    "http_path": request.url.path,
                    "http_status_code": response.status_code,
                    "duration_ms": duration_ms,
                },
            )

        response.headers[CORRELATION_ID_HEADER] = request_id
        return response
