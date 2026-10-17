"""Errors of the strict egress client.

Every error carries a short `reason`, the `phase` it happened in, and
`request_may_have_been_sent`: False only when the failure provably happened
before any request byte could reach the destination (destination rejected,
DNS failure, connection or TLS handshake failure). Callers use it to decide
whether a retry could duplicate work the destination already accepted.

Messages name the reason and phase only. They never contain a URL, a header,
a request or response body, or a credential.
"""

from __future__ import annotations


class EgressError(Exception):
    """Base class for strict egress failures."""

    def __init__(self, reason: str, *, phase: str, request_may_have_been_sent: bool) -> None:
        self.reason = reason
        self.phase = phase
        self.request_may_have_been_sent = request_may_have_been_sent
        super().__init__(f"egress {reason} during {phase}")


class EgressConfigurationError(EgressError):
    """The egress client or its environment cannot provide its guarantees
    (an unsupported HTTP stack version, an invalid policy)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, phase="configuration", request_may_have_been_sent=False)


class EgressDestinationError(EgressError):
    """The destination is not allowed by policy: scheme, port, URL form, or a
    resolved or literal address that is not publicly routable. Permanent."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, phase="destination", request_may_have_been_sent=False)


class EgressResolutionError(EgressError):
    """The hostname did not resolve, or resolved to nothing. Transient."""

    def __init__(self) -> None:
        super().__init__("unresolved", phase="resolve", request_may_have_been_sent=False)


class EgressConnectError(EgressError):
    """No validated address accepted a connection. Nothing was sent."""

    def __init__(self) -> None:
        super().__init__("connect_failed", phase="connect", request_may_have_been_sent=False)


class EgressTLSError(EgressError):
    """The TLS handshake or certificate verification failed. Nothing was sent.
    Never retried on another address: a certificate that does not match is a
    reason to stop, not to look elsewhere."""

    def __init__(self) -> None:
        super().__init__("tls_failed", phase="connect", request_may_have_been_sent=False)


class EgressTimeoutError(EgressError):
    """A connect, read-inactivity, write or total deadline expired."""


class EgressRedirectError(EgressError):
    """The destination answered with a redirect. Redirects are never followed:
    their target was never validated."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__("redirect_rejected", phase="response", request_may_have_been_sent=True)


class EgressResponseTooLargeError(EgressError):
    """The response body exceeded the policy's byte limit."""

    def __init__(self) -> None:
        super().__init__("response_too_large", phase="response", request_may_have_been_sent=True)


class EgressProtocolError(EgressError):
    """The exchange failed after the connection was established (reset, protocol
    error, unexpected content encoding). The request may have been sent."""
