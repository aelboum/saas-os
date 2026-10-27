"""ADR-0059 end-to-end driver: runs inside a container placed like the worker
(only `internal` and `worker-dns`, no gateway, `dns:` the resolver) and
exercises the real egress code against the real resolver and proxy.

`python driver.py <phase>` prints one JSON object of outcomes. Phases:
`normal` (everything up), `resolver_down`, `proxy_down`. Nothing here can
reach a real external host: the destinations are local containers on an
internal network with a public-looking subnet.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import sys
import uuid
from typing import Any

import httpx

from saas_os.core.webhooks import config as webhook_config
from saas_os.core.webhooks import service as webhooks
from saas_os.infra.egress import (
    Deadline,
    EgressError,
    StrictEgressClient,
    StrictEgressPolicy,
    get_egress_proxy,
)

CA = "/fixtures/ca.pem"
GOOD = "hooks.e2e.test"


def _context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=CA)


async def _strict(host: str) -> str:
    proxy = get_egress_proxy()
    assert proxy is not None
    client = StrictEgressClient(
        StrictEgressPolicy(
            connect_timeout_seconds=5.0, read_timeout_seconds=5.0, max_response_bytes=4096
        ),
        ssl_context=_context(),
        proxy=proxy,
    )
    try:
        response = await client.post(
            f"https://{host}/strict/PATH-TOKEN?token=QUERY-TOKEN",
            headers={"Content-Type": "application/json"},
            content=b"{}",
            deadline=Deadline.after(15),
        )
    except EgressError as exc:
        return f"{type(exc).__name__}:{exc.reason}"
    return f"status:{response.status_code}"


async def _webhook(host: str, scheme: str = "https") -> str:
    httpx.create_ssl_context = _context  # trust the fixture CA for this run only
    try:
        status = await webhooks._send_signed(  # pyright: ignore[reportPrivateUsage]
            uuid.uuid4(), f"{scheme}://{host}/hook/PATH-TOKEN?token=QUERY-TOKEN", "secret", b"{}"
        )
    except Exception as exc:  # noqa: BLE001 -- the class is the outcome
        reason = getattr(exc, "reason", None)
        return type(exc).__name__ + (f":{reason}" if reason else "")
    return f"status:{status}"


def _resolve(host: str) -> str:
    try:
        return ",".join(sorted({str(i[4][0]) for i in socket.getaddrinfo(host, 443)}))
    except OSError as exc:
        return f"error:{type(exc).__name__}"


def _direct(address: str) -> str:
    try:
        socket.create_connection((address, 443), timeout=3).close()
    except OSError as exc:
        return f"error:{type(exc).__name__}"
    return "connected"


def _raw_connect(target: str) -> str:
    """The proxy's own answer, with the application's check bypassed."""
    proxy = get_egress_proxy()
    assert proxy is not None
    try:
        sock = socket.create_connection((proxy.host, proxy.port), timeout=5)
    except OSError as exc:
        return f"error:{type(exc).__name__}"
    with sock:
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        return sock.recv(256).split(b"\r\n", 1)[0].decode(errors="replace")


async def main(phase: str) -> dict[str, Any]:
    names = {
        "good": GOOD,
        "mixed": "mixed.e2e.test",
        "metadata": "metadata.e2e.test",
        "ula6": "ula6.e2e.test",
        "missing": "missing.e2e.test",
        "outside_zone": "example.com",
        "wrong_cert": "wrong.e2e.test",
    }
    results: dict[str, Any] = {"phase": phase}
    results["resolve"] = {key: _resolve(host) for key, host in names.items()}
    results["direct"] = _direct("11.22.33.10")
    results["strict"] = {key: await _strict(host) for key, host in names.items()}
    results["webhook"] = {key: await _webhook(host) for key, host in names.items()}
    if phase == "normal":
        # WEBHOOK_ALLOW_HTTP=true lets the application accept `http://`, but
        # the proxy still allows port 443 only: the setting cannot widen the
        # network.
        os.environ["WEBHOOK_ALLOW_HTTP"] = "true"
        webhook_config.get_webhook_security_config.cache_clear()
        results["http_opt_in"] = await _webhook(GOOD, scheme="http")
        del os.environ["WEBHOOK_ALLOW_HTTP"]
        webhook_config.get_webhook_security_config.cache_clear()
        results["proxy_policy"] = {
            target: _raw_connect(target)
            for target in (
                "11.22.33.10:443",
                "11.22.33.10:80",
                "10.0.0.5:443",
                "169.254.169.254:443",
                "[fd00:ec2::254]:443",
                f"{GOOD}:443",
            )
        }
    return results


if __name__ == "__main__":
    os.environ.setdefault("ENVIRONMENT", "test")
    print(json.dumps(asyncio.run(main(sys.argv[1])), sort_keys=True))
