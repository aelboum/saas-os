"""Supported HTTP stack for pinned egress (AI-B decision R4, ADR-0054).

IP pinning with the original TLS name relies on httpcore reading the request
extension `sni_hostname` and passing it to `start_tls()` as `server_hostname`
(`httpcore/_async/connection.py`, verified in 1.0.9). The extension is
documented by httpcore, but it is a behaviour of a specific major line, not a
stable cross-version contract. The strict egress client therefore refuses to
run on an HTTP stack outside the range it was tested against, instead of
silently connecting with different semantics. `pyproject.toml` pins the same
ranges; this check covers installations that bypass the declared bounds.

Widening a range is a reviewed change: run the real-TLS pinning tests
(`tests/infra/egress/test_strict_egress_socket_unit.py`) against the new
version first.
"""

from __future__ import annotations

import httpcore
import httpx

from saas_os.infra.egress.errors import EgressConfigurationError

# (minimum inclusive, maximum exclusive), compared on (major, minor, patch).
SUPPORTED_HTTPX = ((0, 28, 1), (0, 29, 0))
SUPPORTED_HTTPCORE = ((1, 0, 9), (1, 1, 0))


def _version_tuple(version: str) -> tuple[int, int, int]:
    parts: list[int] = []
    for piece in version.split(".")[:3]:
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def _within(version: str, bounds: tuple[tuple[int, int, int], tuple[int, int, int]]) -> bool:
    low, high = bounds
    return low <= _version_tuple(version) < high


def require_supported_http_stack() -> None:
    """Raise `EgressConfigurationError` unless the installed httpx and httpcore
    are within the tested ranges."""
    if not _within(httpx.__version__, SUPPORTED_HTTPX):
        raise EgressConfigurationError("unsupported_httpx_version")
    if not _within(httpcore.__version__, SUPPORTED_HTTPCORE):
        raise EgressConfigurationError("unsupported_httpcore_version")
