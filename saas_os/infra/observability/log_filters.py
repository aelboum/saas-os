"""Filters that keep credential-bearing URL parts out of third-party log lines.

Two libraries log a URL SaaS OS does not control the format of:

- `httpx` logs every request at `INFO` as `HTTP Request: <method> <url> ...`.
  A webhook destination's path or query is often a credential in itself.
  `configure_logging()` holds the `httpx` logger at `WARNING`, but a product
  that configures logging another way, or lowers that logger, would get the
  line back. `OutboundUrlFilter` reduces every URL argument of an `httpx`
  record to its scheme, host and port, whatever level or handler is set.
- uvicorn's access logger writes each request line with its query string.
  The OIDC callback's query carries the authorization `code` and `state`;
  `CallbackQueryFilter` drops the query from `/auth/callback` lines.

Both are attached to the logger itself, not to a handler: a logger's filters
run for every record it creates, whichever handlers a product configures, and
`logging.config.dictConfig` (which uvicorn uses) adds filters but never
removes existing ones. `install_sensitive_log_filters()` is idempotent; it is
called by `configure_logging()` and when the modules that send such URLs are
imported (`saas_os.infra.egress.client`, `saas_os.core.webhooks.service`).
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

_HTTPX_LOGGER = "httpx"
_ACCESS_LOGGER = "uvicorn.access"
_CALLBACK_PATH_SUFFIX = "/auth/callback"


def _origin_only(value: str) -> str:
    """`scheme://host[:port]`: no user information, path, query or fragment.
    Anything that does not parse as an absolute URL is withheld entirely."""
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return "<url withheld>"
    if not parts.scheme or not parts.hostname:
        return "<url withheld>"
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")


def _looks_like_url(value: object) -> bool:
    # `httpx.URL` and plain strings alike; checked by text so this module
    # does not import `httpx`.
    text = str(value) if not isinstance(value, bytes | bytearray) else ""
    return text.startswith(("http://", "https://"))


class OutboundUrlFilter(logging.Filter):
    """Rewrites every URL-like argument of a record to its origin. A record
    whose message itself contains a URL (no arguments) has the whole
    message withheld, since it cannot be rewritten safely."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and args:
            record.args = tuple(
                _origin_only(str(arg)) if _looks_like_url(arg) else arg for arg in args
            )
        elif not args and "://" in str(record.msg):
            record.msg = "httpx log line withheld (it contained a URL)"
        return True


class CallbackQueryFilter(logging.Filter):
    """Drops the query string from uvicorn access-log lines for the OIDC
    callback. Other request lines are unchanged."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            path, separator, _query = args[2].partition("?")
            if separator and path.endswith(_CALLBACK_PATH_SUFFIX):
                record.args = (*args[:2], path, *args[3:])
        return True


def install_sensitive_log_filters() -> None:
    """Attach `OutboundUrlFilter` to the `httpx` logger and
    `CallbackQueryFilter` to `uvicorn.access`, once each."""
    for name, filter_type in (
        (_HTTPX_LOGGER, OutboundUrlFilter),
        (_ACCESS_LOGGER, CallbackQueryFilter),
    ):
        target = logging.getLogger(name)
        if not any(isinstance(existing, filter_type) for existing in target.filters):
            target.addFilter(filter_type())
