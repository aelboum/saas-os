"""Private-endpoint trust of the strict egress client (ADR-0054 D9, AI-C;
threat model 3.10). Hermetic: scripted resolver, mock transport.

A private destination is reachable only through a `TrustedEndpoint` naming
the exact host and port, and only for resolved addresses inside its
networks. All-or-nothing still holds: one resolved address no entry covers
refuses the destination. Loopback, link-local, metadata, multicast,
unspecified and reserved addresses can never be trusted.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx
import pytest

from egress_support import PUBLIC_V4, StaticResolver, mock_transport_factory
from saas_os.infra.egress import (
    Deadline,
    EgressConfigurationError,
    EgressDestinationError,
    StrictEgressClient,
    StrictEgressPolicy,
    TrustedEndpoint,
    is_never_trustable,
)

pytestmark = pytest.mark.anyio

HOST = "llm.internal.example"
URL = f"https://{HOST}/v1/chat/completions"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _entry(host: str = HOST, port: int = 443, *networks: str) -> TrustedEndpoint:
    nets = tuple(ipaddress.ip_network(n) for n in (networks or ("10.20.0.0/16",)))
    return TrustedEndpoint(host=host, port=port, networks=nets)


def _client(answers: list[str], *entries: TrustedEndpoint, **policy: Any):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"{}")

    client = StrictEgressClient(
        StrictEgressPolicy(
            connect_timeout_seconds=5.0,
            read_timeout_seconds=5.0,
            max_response_bytes=1024,
            trusted_endpoints=tuple(entries),
            **policy,
        ),
        resolver=StaticResolver([answers]),
        transport_factory=mock_transport_factory(handler),
    )
    return client, seen


async def _post(client: StrictEgressClient, url: str = URL):
    return await client.post(url, headers={}, content=b"{}", deadline=Deadline.after(5.0))


async def test_a_trusted_private_address_is_reached_and_pinned() -> None:
    client, seen = _client(["10.20.1.5"], _entry())
    response = await _post(client)
    assert response.status_code == 200
    assert len(seen) == 1
    assert seen[0].url.host == "10.20.1.5"  # pinned to the validated address
    assert seen[0].headers["host"] == HOST


async def test_without_an_entry_the_same_address_is_refused() -> None:
    client, seen = _client(["10.20.1.5"])
    with pytest.raises(EgressDestinationError) as caught:
        await _post(client)
    assert caught.value.reason == "non_public_address" and seen == []


@pytest.mark.parametrize(
    ("entry", "url"),
    [
        (_entry(host="other.internal.example"), URL),  # another host
        (_entry(port=8443), URL),  # another port
        (_entry(), "https://sub.llm.internal.example/v1"),  # no suffix matching
    ],
)
async def test_the_entry_must_name_the_exact_host_and_port(
    entry: TrustedEndpoint, url: str
) -> None:
    client, seen = _client(["10.20.1.5"], entry)
    with pytest.raises(EgressDestinationError):
        await _post(client, url)
    assert seen == []


async def test_an_address_outside_the_entry_networks_is_refused() -> None:
    client, seen = _client(["10.30.0.1"], _entry())
    with pytest.raises(EgressDestinationError):
        await _post(client)
    assert seen == []


async def test_all_or_nothing_one_uncovered_private_answer_refuses() -> None:
    client, seen = _client(["10.20.1.5", "192.168.1.1"], _entry())
    with pytest.raises(EgressDestinationError):
        await _post(client)
    assert seen == []


async def test_a_public_answer_alongside_a_trusted_one_is_allowed() -> None:
    client, seen = _client(["10.20.1.5", PUBLIC_V4], _entry())
    assert (await _post(client)).status_code == 200
    assert len(seen) == 1


@pytest.mark.parametrize(
    "network",
    [
        "127.0.0.0/8",
        "127.0.0.1/32",
        "169.254.169.254/32",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "100.100.100.200/32",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
        "fd00:ec2::254/128",
        "0.0.0.0/0",  # overlaps every never-trustable IPv4 range
        "::/0",
    ],
)
def test_a_never_trustable_network_cannot_be_configured(network: str) -> None:
    with pytest.raises(EgressConfigurationError) as caught:
        _entry(HOST, 443, network)
    assert caught.value.reason == "network_never_trustable"


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "169.254.169.254", "::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"],
)
def test_never_trustable_covers_embedded_ipv4(address: str) -> None:
    assert is_never_trustable(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["10.0.0.1", "192.168.1.1", "fd12::1", "100.64.0.1"])
def test_ordinary_private_addresses_are_trustable(address: str) -> None:
    assert not is_never_trustable(ipaddress.ip_address(address))


async def test_a_never_trustable_answer_is_refused_even_for_a_trusted_host() -> None:
    """An IPv4-mapped loopback is inside ::ffff:0:0/96, which overlaps no
    blocked IPv6 range and so passes entry validation; the client's own
    per-address check (embedded IPv4 included) is what refuses it."""
    entry = TrustedEndpoint(host=HOST, port=443, networks=(ipaddress.ip_network("::ffff:0:0/96"),))
    client, seen = _client(["::ffff:127.0.0.1"], entry)
    with pytest.raises(EgressDestinationError):
        await _post(client)
    assert seen == []


@pytest.mark.parametrize(
    ("host", "port"),
    [("", 443), ("LLM.internal.example", 443), ("llm.internal.example", 0), ("ä.example", 443)],
)
def test_an_invalid_entry_is_refused(host: str, port: int) -> None:
    with pytest.raises(EgressConfigurationError):
        TrustedEndpoint(host=host, port=port, networks=(ipaddress.ip_network("10.0.0.0/8"),))


def test_an_entry_needs_at_least_one_network() -> None:
    with pytest.raises(EgressConfigurationError):
        TrustedEndpoint(host=HOST, port=443, networks=())
