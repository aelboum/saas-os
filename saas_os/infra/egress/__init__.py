"""Shared outbound HTTP egress primitives (AI-B; ADR-0054 sections 8a, 8b).

- `addresses`: address classification and connection pinning, shared with
  webhook delivery (`saas_os.core.webhooks`), whose behaviour is unchanged
  (ADR-0035).
- `StrictEgressClient` / `StrictEgressPolicy`: the strict policy AI provider
  calls use -- public HTTPS destinations only, pinned, no redirects, no
  environment proxies, bounded in time and size.

Infrastructure: no knowledge of tenants, providers or AI. Imports neither
Core nor the Control Plane (import-linter).
"""

from saas_os.infra.egress.addresses import (
    NAT64_WELL_KNOWN_PREFIX,
    NEVER_TRUSTABLE_NETWORKS,
    IPAddress,
    embedded_ipv4_addresses,
    format_address_for_url,
    is_never_trustable,
    is_non_public_address,
    pin_url_to_address,
)
from saas_os.infra.egress.client import (
    AsyncResolver,
    EgressResponse,
    StrictEgressClient,
    TransportFactory,
    default_resolver,
)
from saas_os.infra.egress.compat import require_supported_http_stack
from saas_os.infra.egress.deadline import Deadline
from saas_os.infra.egress.errors import (
    EgressConfigurationError,
    EgressConnectError,
    EgressDestinationError,
    EgressError,
    EgressProtocolError,
    EgressRedirectError,
    EgressResolutionError,
    EgressResponseTooLargeError,
    EgressTimeoutError,
    EgressTLSError,
)
from saas_os.infra.egress.policy import (
    DEFAULT_ALLOWED_PORTS,
    StrictEgressPolicy,
    TrustedEndpoint,
)

__all__ = [
    "DEFAULT_ALLOWED_PORTS",
    "NAT64_WELL_KNOWN_PREFIX",
    "NEVER_TRUSTABLE_NETWORKS",
    "AsyncResolver",
    "Deadline",
    "EgressConfigurationError",
    "EgressConnectError",
    "EgressDestinationError",
    "EgressError",
    "EgressProtocolError",
    "EgressRedirectError",
    "EgressResolutionError",
    "EgressResponse",
    "EgressResponseTooLargeError",
    "EgressTLSError",
    "EgressTimeoutError",
    "IPAddress",
    "StrictEgressClient",
    "StrictEgressPolicy",
    "TransportFactory",
    "TrustedEndpoint",
    "default_resolver",
    "embedded_ipv4_addresses",
    "format_address_for_url",
    "is_never_trustable",
    "is_non_public_address",
    "pin_url_to_address",
    "require_supported_http_stack",
]
