"""Address classification and connection pinning shared by outbound HTTP
callers (webhook delivery and AI provider calls).

Extracted unchanged from `saas_os/core/webhooks/service.py` (AI-B, ADR-0054
section 8b): the predicate and the pinning helper are pure functions with no
business knowledge. Each caller keeps its own policy (which schemes, ports
and errors apply); only these primitives are shared.

The security question is never "does this hostname/IP string look bad" --
it is "is the address this will actually connect to publicly routable".
`is_non_public_address()` answers it for a real `ipaddress` object, so a
literal address and a resolved one are judged by the same rule.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# RE-4: the IPv6 prefix that carries an IPv4 address in its last 32 bits
# for NAT64 (RFC 6052 well-known prefix). A NAT64 gateway turns
# `64:ff9b::7f00:1` into a connection to 127.0.0.1, so the embedded address
# must pass the same policy.
NAT64_WELL_KNOWN_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")


def embedded_ipv4_addresses(address: IPAddress) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses an IPv6 address carries and may be translated to:
    IPv4-mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4
    (`2002::/16`). Judged explicitly, because whether `ipaddress` treats
    them as global differs between Python versions."""
    if not isinstance(address, ipaddress.IPv6Address):
        return []
    embedded: list[ipaddress.IPv4Address] = []
    if address.ipv4_mapped is not None:
        embedded.append(address.ipv4_mapped)
    if address in NAT64_WELL_KNOWN_PREFIX:
        embedded.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    if address.sixtofour is not None:
        embedded.append(address.sixtofour)
    return embedded


def is_non_public_address(address: IPAddress) -> bool:
    """True unless `address` is a globally routable unicast address.

    RE-4 (audit finding RE-F8): `not address.is_global` is the policy -- it
    covers every IANA special-purpose range, including carrier-grade NAT
    `100.64.0.0/10` (which `is_private` alone missed, so a destination like
    the `100.100.100.200` cloud-metadata address was allowed), documentation,
    benchmarking, `0.0.0.0/8`, `240.0.0.0/4` and their IPv6 counterparts.
    The individual checks are kept for clarity and defense in depth;
    multicast is checked explicitly because some multicast ranges count as
    global; so is the deprecated IPv6 site-local `fec0::/10`, which some
    Python versions still report as global. An IPv4 address embedded in an
    IPv6 one must pass too."""
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
        or address.is_multicast
        or (isinstance(address, ipaddress.IPv6Address) and address.is_site_local)
    ):
        return True
    return any(is_non_public_address(v4) for v4 in embedded_ipv4_addresses(address))


# Ranges no private-endpoint trust entry can ever reach (ADR-0054 D9;
# threat model 3.3, 3.10): unspecified, loopback, link-local (including the
# 169.254.169.254 metadata address), the Alibaba metadata address, multicast,
# reserved, and the AWS IPv6 metadata address.
NEVER_TRUSTABLE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)


def is_never_trustable(address: IPAddress) -> bool:
    """True for an address no trust entry may allow, including through an
    IPv4 address embedded in an IPv6 one."""
    candidates: list[IPAddress] = [address, *embedded_ipv4_addresses(address)]
    for candidate in candidates:
        if candidate.is_loopback or candidate.is_link_local or candidate.is_multicast:
            return True
        if candidate.is_unspecified or candidate.is_reserved:
            return True
        if any(candidate in network for network in NEVER_TRUSTABLE_NETWORKS):
            return True
    return False


def format_address_for_url(address: IPAddress) -> str:
    return f"[{address}]" if address.version == 6 else str(address)


def pin_url_to_address(url: str, address: IPAddress) -> tuple[str, str, str]:
    """Rewrite `url`'s authority to `address` -- an address the caller has
    already validated -- and return `(pinned_url, sni_hostname, host_header)`.

    Connecting to the literal address leaves httpcore no hostname to resolve
    again, so the address that passed the security check is the only address
    the TCP connection can reach (no DNS-rebinding window).
    `httpcore._async.connection.AsyncHTTPConnection._connect()` passes the
    request's `sni_hostname` extension as `server_hostname` to `start_tls()`,
    falling back to the URL host when the extension is absent (verified
    against httpcore 1.0.9). Python's `ssl` module verifies the certificate
    against `server_hostname`, so certificate verification still uses the
    original name. If the extension were ever ignored, the fallback is the
    IP itself, and a certificate issued for a name fails verification:
    the failure mode is closed, not open. The `Host` header is set
    explicitly for HTTP virtual-host routing.

    Raises `ValueError` for a URL with no hostname; callers validate first.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("url has no hostname")
    port = parsed.port
    host_header = f"{hostname}:{port}" if port is not None else hostname
    pinned_netloc = format_address_for_url(address)
    if port is not None:
        pinned_netloc = f"{pinned_netloc}:{port}"
    pinned_url = parsed._replace(netloc=pinned_netloc).geturl()
    return pinned_url, hostname, host_header
