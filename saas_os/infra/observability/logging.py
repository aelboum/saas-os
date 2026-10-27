"""Structured logging (docs/IMPLEMENTATION-ROADMAP.md Phase 2.2).

`configure_logging()` is the single place logging is configured --
application/business modules call it once at startup and otherwise just
use `logging.getLogger(__name__)` as normal; they never need to know the
formatter, handler, or correlation-context mechanics (docs/OBSERVABILITY.md
section 1: "each module owns *what* it instruments... through the shared
SDK/conventions rather than inventing its own logging format").

Every emitted record carries, where available (docs/OBSERVABILITY.md
section 2):
  - `tenant_id`, `user_id`, `request_id`, `agent_id`, `action_id` -- the
    application-level `saas_os.infra.observability.context.CorrelationContext`
  - `deployment_id`, `version` -- process-wide, from `ObservabilityConfig`
  - `trace_id`, `span_id` -- OpenTelemetry's own current-span identifiers
    (a distinct concept from the correlation context above; both are
    attached, never conflated -- docs/IMPLEMENTATION-ROADMAP.md Phase 2.2
    task 7)

No secret, credential, token, password, `Authorization` header, cookie, or
`DATABASE_URL` is ever attached or logged by this module -- it does not
log request bodies or headers at all, and none of the fields above are
secrets (docs/SECURITY.md section 4).

**S-03 (BANK-SEC-04) redaction boundary**: `JsonFormatter` recursively
scrubs every `extra=` field a caller passes to `logger.info(..., extra=
{...})` (and `.warning`/`.error`/etc.) through
`saas_os.infra.observability.redaction.redact()` before JSON-serializing it --
see that module's own docstring for the sensitive-key classification and
its explicit scope: this covers the `extra=` mapping (including nested
dicts/lists within it), not the flattened `%s`-formatted message string
or `logging.Formatter`'s own exception-traceback text (`record.exc_info`
below), neither of which this module attempts to scrub for the reasons
`saas_os/infra/observability/redaction.py` documents. Callers handling sensitive
operations should pass context through `extra=` keys, never interpolate
a potentially-sensitive value directly into a message string.
"""

from __future__ import annotations

import json
import logging as _stdlib_logging
import sys
from typing import Any, cast

from opentelemetry import trace

from saas_os.infra.observability.config import ObservabilityConfig, get_observability_config
from saas_os.infra.observability.context import get_correlation_context
from saas_os.infra.observability.redaction import redact

_RESERVED_LOG_RECORD_ATTRS = frozenset(vars(_stdlib_logging.LogRecord("", 0, "", 0, "", (), None)))


class CorrelationFilter(_stdlib_logging.Filter):
    """Attaches correlation-context and OpenTelemetry trace/span fields to
    every `LogRecord` that passes through it. A `logging.Filter`, not a
    `Formatter` -- filters run before formatters and can be reused with
    any formatter (including a developer's own, in a REPL or a future
    application entry point), keeping this module's public surface small.
    """

    def __init__(self, config: ObservabilityConfig) -> None:
        super().__init__()
        self._config = config

    def filter(self, record: _stdlib_logging.LogRecord) -> bool:
        ctx = get_correlation_context()
        record.tenant_id = ctx.tenant_id
        record.user_id = ctx.user_id
        record.request_id = ctx.request_id
        record.agent_id = ctx.agent_id
        record.action_id = ctx.action_id
        record.deployment_id = self._config.deployment_id
        record.version = self._config.version

        span_context = trace.get_current_span().get_span_context()
        if span_context.is_valid:
            record.trace_id = trace.format_trace_id(span_context.trace_id)
            record.span_id = trace.format_span_id(span_context.span_id)
        else:
            record.trace_id = None
            record.span_id = None
        return True


class JsonFormatter(_stdlib_logging.Formatter):
    """The smallest reusable structured formatter needed: one JSON object
    per line, the standard fields plus whatever `CorrelationFilter`
    attached. Stdlib `json` only -- no new dependency.
    """

    def format(self, record: _stdlib_logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in (
            "tenant_id",
            "user_id",
            "request_id",
            "agent_id",
            "action_id",
            "deployment_id",
            "version",
            "trace_id",
            "span_id",
        ):
            payload[key] = getattr(record, key, None)

        # Any *extra* fields a caller passed to logger.info(..., extra={...})
        # -- deliberately not a blanket "log everything on the record",
        # which would risk leaking internal LogRecord attributes. Each
        # extra field is redacted independently (BANK-SEC-04 S-03): a
        # dict-shaped value is recursed into by `redact()` itself; a
        # top-level key that is itself sensitive (e.g.
        # `extra={"api_key": ...}`) is caught the same way a nested one
        # would be, since `redact()` is applied to the whole extras
        # mapping in one call below, not field-by-field.
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RESERVED_LOG_RECORD_ATTRS and key not in payload
        }
        # `redact()` on a `dict` input always returns a `dict` (its own
        # first branch) -- `cast` reflects that without a runtime check
        # `-O` could strip.
        payload.update(cast("dict[str, Any]", redact(extras)))

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(config: ObservabilityConfig | None = None) -> None:
    """Configure the root logger: level from config, one handler, the
    `CorrelationFilter` + `JsonFormatter` above. Safe to call more than
    once (`force=True`) -- each call fully reconfigures rather than
    silently no-op'ing, so the configured level/filter always matches the
    `ObservabilityConfig` passed in (mirrors `core`'s now-removed
    interim logging setup's `force=True` rationale: repeated calls from
    tests or multiple entry points must not leave stale handlers/filters
    attached).
    """
    resolved_config = config or get_observability_config()

    # Explicit sys.stdout (not StreamHandler()'s default sys.stderr): logs
    # are the intended primary output of this module (docs/OBSERVABILITY.md
    # section 1) and this must remain stable even if sys.stderr is
    # redirected -- also lets tests capture output via capsys.readouterr().out.
    handler = _stdlib_logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(CorrelationFilter(resolved_config))

    _stdlib_logging.basicConfig(
        level=resolved_config.log_level,
        handlers=[handler],
        force=True,
    )
    # `httpx` logs one `INFO` line per request, carrying the full URL. A
    # webhook destination's path or query is often a credential in itself,
    # so every delivery would write a tenant's secret into a log shared by
    # all tenants. `httpx` logs nothing above `INFO`; a product that wants
    # the request lines lowers this logger's level itself, knowing what
    # they carry.
    _stdlib_logging.getLogger("httpx").setLevel(_stdlib_logging.WARNING)
