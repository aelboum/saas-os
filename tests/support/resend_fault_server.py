"""A local stand-in for Resend's `POST /emails` over real TLS sockets, for
fault injection at the transport boundary (owner decision of 2026-11-01,
ledger row F5).

It models the documented idempotency behaviour
(https://resend.com/docs/dashboard/emails/idempotency-keys, read
2026-11-01): a key is remembered with the body of its first request; the
same key with the same body returns the first result without sending again;
the same key with a different body is `409 invalid_idempotent_request`. A
request the server *processed* counts as a delivery even when its answer is
then lost, which is exactly what makes the outcome ambiguous for the client.

Each request takes the next scripted action (the last one repeats):

- `ok`: process it and answer `200 {"id": ...}`;
- `drop_after_read`: process it, then close without answering;
- `close_before_read`: close the connection before reading the request
  (not processed);
- `stall`: process it, then answer only after `stall_seconds`;
- `garbage_2xx`: process it, then answer `200` with an unreadable body;
- `(status, name)` or `(status, name, headers)`: refuse it with that error
  (not processed).

The provider under test connects through `MappingBackend`, so the pinned
public address of `api.resend.com` reaches this server, and trusts only the
throw-away CA issued here.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any

from egress_support import (
    PUBLIC_V4,
    LocalServer,
    MappingBackend,
    StaticResolver,
    client_context,
    issue_certificates,
    mapped_transport_factory,
    read_request,
    server_context,
)
from saas_os.core.email.config import ResendConfig
from saas_os.core.email.resend_provider import ResendEmailProvider
from saas_os.infra.egress import StrictEgressClient, StrictEgressPolicy

RESEND_HOST = "api.resend.com"


class FakeResend:
    def __init__(self, script: list[Any], tmp_path: Path, *, stall_seconds: float = 2.0) -> None:
        self.script = script
        self.stall_seconds = stall_seconds
        self.certs = issue_certificates(RESEND_HOST)
        self.server = LocalServer(
            self._handle, ssl_context=server_context(self.certs, tmp_path, [])
        )
        self.requests: list[tuple[str | None, bytes]] = []  # (idempotency key, body)
        self.deliveries = 0
        self._first: dict[str, tuple[bytes, str]] = {}

    async def __aenter__(self) -> FakeResend:
        await self.server.__aenter__()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.server.__aexit__(*exc)

    def _next_action(self) -> Any:
        index = min(len(self.requests), len(self.script) - 1)
        return self.script[index]

    def _process(self, key: str | None, body: bytes) -> tuple[int, dict[str, Any]]:
        if key is not None and key in self._first:
            first_body, first_id = self._first[key]
            if first_body != body:
                return 409, {"name": "invalid_idempotent_request", "statusCode": 409}
            return 200, {"id": first_id}
        email_id = str(uuid.uuid4())
        self.deliveries += 1
        if key is not None:
            self._first[key] = (body, email_id)
        return 200, {"id": email_id}

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        action = self._next_action()
        if action == "close_before_read":
            self.requests.append((None, b""))
            return
        body = await read_request(self.server, reader)
        key = None
        for line in self.server.heads[-1].split(b"\r\n"):
            if line.lower().startswith(b"idempotency-key:"):
                key = line.split(b":", 1)[1].strip().decode("ascii")
        self.requests.append((key, body))
        if isinstance(action, tuple):
            status, name, *rest = action
            headers = rest[0] if rest else {}
            await _answer(writer, status, {"name": name, "statusCode": status}, headers)
            return
        status, answer = self._process(key, body)
        if action == "drop_after_read":
            return
        if action == "stall":
            await asyncio.sleep(self.stall_seconds)
        if action == "garbage_2xx":
            await _answer(writer, 200, None, {}, raw=b"not json")
            return
        await _answer(writer, status, answer, {})

    def provider(
        self,
        *,
        read_timeout: float = 2.0,
        total_timeout: int = 5,
        port: int | None = None,
    ) -> ResendEmailProvider:
        backend = MappingBackend(port if port is not None else self.server.port)
        client = StrictEgressClient(
            StrictEgressPolicy(
                connect_timeout_seconds=2,
                read_timeout_seconds=read_timeout,
                max_response_bytes=65536,
            ),
            resolver=StaticResolver([[PUBLIC_V4]]),
            transport_factory=mapped_transport_factory(backend),
            ssl_context=client_context(self.certs.ca_pem),
        )
        return ResendEmailProvider(
            config=ResendConfig(timeout_seconds=total_timeout), client=client
        )


async def _answer(
    writer: asyncio.StreamWriter,
    status: int,
    payload: dict[str, Any] | None,
    headers: dict[str, str],
    *,
    raw: bytes | None = None,
) -> None:
    content = raw if raw is not None else json.dumps(payload).encode("utf-8")
    head = [f"HTTP/1.1 {status} X", "Content-Type: application/json"]
    head += [f"{name}: {value}" for name, value in headers.items()]
    head += [f"Content-Length: {len(content)}", "Connection: close", "", ""]
    writer.write("\r\n".join(head).encode("ascii") + content)
    await writer.drain()
