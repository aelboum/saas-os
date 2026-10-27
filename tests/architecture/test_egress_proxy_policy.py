"""ADR-0059: the shipped egress-proxy policy (`deploy/egress-proxy/squid.conf`)
refuses at least everything the application's own check refuses, allows only
`CONNECT` to IP literals on port 443, and logs no URL.

The proxy is the second, independent layer: if the application accepted a
non-public address by mistake, the proxy must still refuse it. Every network
Python itself treats as not globally reachable, and a table of the usual
metadata, private and embedded addresses, must fall in the deny list.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

from saas_os.infra.egress import is_non_public_address

CONFIG = Path(__file__).resolve().parents[2] / "deploy" / "egress-proxy" / "squid.conf"
_TEXT = CONFIG.read_text(encoding="utf-8")
_LINES = [line.strip() for line in _TEXT.splitlines() if line.strip() and not line.startswith("#")]

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _acl_values(name: str, kind: str) -> list[str]:
    values: list[str] = []
    for line in _LINES:
        parts = line.split()
        if parts[:3] == ["acl", name, kind]:
            values.extend(parts[3:])
    return values


_BLOCKED: list[Network] = [ipaddress.ip_network(v) for v in _acl_values("blocked_dst", "dst")]


def _blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Squid judges an IPv4-mapped address by its IPv4 form.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address in net for net in _BLOCKED if net.version == address.version)


def _python_non_global_networks() -> list[Network]:
    networks: list[Network] = []
    for constants in (ipaddress._IPv4Constants, ipaddress._IPv6Constants):  # pyright: ignore[reportPrivateUsage, reportAttributeAccessIssue]
        networks.extend(constants._private_networks)  # type: ignore[attr-defined]
        networks.append(constants._multicast_network)  # type: ignore[attr-defined]
        networks.extend(getattr(constants, "_reserved_networks", []))
    return networks


def test_no_listed_network_overlaps_another() -> None:
    """Squid keeps only one of two overlapping entries, and not always the
    larger (it dropped 0.0.0.0/0 in favour of 0.0.0.0/8)."""
    overlapping = [
        (a, b)
        for i, a in enumerate(_BLOCKED)
        for b in _BLOCKED[i + 1 :]
        if a.version == b.version and a.overlaps(b)  # type: ignore[arg-type]
    ]
    assert overlapping == []


def test_no_ipv6_entry_touches_the_mapped_prefix() -> None:
    """Squid stores IPv4 as `::ffff:0:0/96`, so an IPv6 entry overlapping it
    (`::ffff:0:0/96` itself, or `::/8`) overlaps every IPv4 entry, and Squid
    then drops one of them: it dropped `::/8` in favour of `240.0.0.0/4`."""
    mapped = ipaddress.ip_network("::ffff:0:0/96")
    assert [net for net in _BLOCKED if net.version == 6 and net.overlaps(mapped)] == []


@pytest.mark.parametrize("network", _python_non_global_networks(), ids=str)
def test_every_network_python_treats_as_non_global_is_refused(network: Network) -> None:
    if network == ipaddress.ip_network("::ffff:0:0/96"):
        pytest.skip("IPv4-mapped: judged by its IPv4 form, see the test above")
    for address in (network.network_address, network.broadcast_address):
        if is_non_public_address(address):
            assert _blocked(address), f"{address} (in {network}) is not refused by the proxy"


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",  # AWS, GCP, Azure metadata
        "100.100.100.200",  # Alibaba metadata
        "fd00:ec2::254",  # AWS IPv6 metadata
        "10.0.0.1",
        "172.17.0.1",  # Docker's default bridge gateway
        "192.168.1.1",
        "127.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b::808:808",
        "2002:7f00:1::1",
        "2001:db8::1",
        "224.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
    ],
)
def test_the_usual_non_public_destinations_are_refused(address: str) -> None:
    parsed = ipaddress.ip_address(address)
    assert is_non_public_address(parsed)
    assert _blocked(parsed)


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:1.1.1.1"]
)
def test_public_destinations_are_not_refused(address: str) -> None:
    assert not _blocked(ipaddress.ip_address(address))


def test_only_connect_to_an_ip_literal_on_port_443_is_allowed() -> None:
    assert _acl_values("egress_ports", "port") == ["443"]
    access = [line for line in _LINES if line.startswith("http_access ")]
    assert access == [
        "http_access deny !CONNECT",
        "http_access deny !egress_ports",
        "http_access deny !ip_literal_v4 !ip_literal_v6",
        "http_access deny blocked_dst",
        "http_access allow CONNECT",
        "http_access deny all",
    ]
    assert "cache deny all" in _LINES


def test_the_access_log_records_no_url_and_no_header() -> None:
    [logformat] = [line for line in _LINES if line.startswith("logformat ")]
    assert logformat == "logformat egress %ts.%03tu %>a %rm %<a:%<p %>Hs %Ss"
    for code in ("%ru", "%>ru", "%rp", "%>rp", "%>h", "%<h", "%un", "%ul"):
        assert code not in logformat
    assert re.search(r"^access_log \S+ egress$", _TEXT, re.M)
