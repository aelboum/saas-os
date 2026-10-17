"""The strict egress policy: public destinations over HTTPS only.

This is the policy AI provider calls use (ADR-0054 section 8b; AI-B decision
R1). It has no default values: the caller supplies every limit, so no number
here becomes policy by accident. The AI Control Plane supplies the provisional
values (`saas_os/control_plane/inference/egress_config.py`).

Private destinations are refused unless a `TrustedEndpoint` names the exact
host and port and the resolved address falls inside one of its networks
(ADR-0054 D9; AI-C). Loopback, link-local, metadata, multicast, unspecified
and reserved addresses can never be trusted. There is no global switch.
Webhook delivery does not use this policy; its behaviour is defined by
ADR-0035.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from saas_os.infra.egress.addresses import NEVER_TRUSTABLE_NETWORKS
from saas_os.infra.egress.errors import EgressConfigurationError

DEFAULT_ALLOWED_PORTS: frozenset[int] = frozenset({443})

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class TrustedEndpoint:
    """One exact host and port allowed to resolve into private `networks`."""

    host: str
    port: int
    networks: tuple[Network, ...]

    def __post_init__(self) -> None:
        if not self.host or self.host != self.host.lower() or not self.host.isascii():
            raise EgressConfigurationError("invalid_trusted_host")
        if not 0 < self.port < 65536 or not self.networks:
            raise EgressConfigurationError("invalid_trusted_endpoint")
        for network in self.networks:
            for blocked in NEVER_TRUSTABLE_NETWORKS:
                if blocked.version == network.version and network.overlaps(blocked):  # type: ignore[arg-type]
                    raise EgressConfigurationError("network_never_trustable")


@dataclass(frozen=True)
class StrictEgressPolicy:
    """Limits for one strict egress client.

    - `connect_timeout_seconds`: TCP connect plus TLS handshake, per address.
    - `read_timeout_seconds`: longest wait for the next bytes of the response
      (read inactivity); also bounds each write.
    - `max_response_bytes`: the response body is refused beyond this size.
    - `allowed_ports`: ports a destination URL may name; 443 unless a caller
      configures more explicitly.
    - `max_addresses_tried`: validated addresses tried for one request, in
      resolver order, all within the same total deadline.

    The total deadline is not part of the policy: each call passes a
    `Deadline`, so retries and fallback can share it.
    """

    connect_timeout_seconds: float
    read_timeout_seconds: float
    max_response_bytes: int
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS
    max_addresses_tried: int = 2
    trusted_endpoints: tuple[TrustedEndpoint, ...] = ()

    def __post_init__(self) -> None:
        if not self.connect_timeout_seconds > 0 or not self.read_timeout_seconds > 0:
            raise EgressConfigurationError("timeouts_must_be_positive")
        if self.max_response_bytes <= 0:
            raise EgressConfigurationError("max_response_bytes_must_be_positive")
        if not self.allowed_ports or any(not 0 < port < 65536 for port in self.allowed_ports):
            raise EgressConfigurationError("invalid_allowed_ports")
        if self.max_addresses_tried < 1:
            raise EgressConfigurationError("max_addresses_tried_must_be_positive")
