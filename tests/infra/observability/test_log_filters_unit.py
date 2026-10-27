"""`saas_os/infra/observability/log_filters.py`: no webhook URL path or query
in `httpx`'s request line, and no OIDC `code`/`state` in uvicorn's access
log, whatever logging a product configures."""

from __future__ import annotations

import asyncio
import http.server
import logging
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator

import httpx
import pytest
import uvicorn

from saas_os.infra.observability.log_filters import (
    CallbackQueryFilter,
    OutboundUrlFilter,
    _origin_only,  # pyright: ignore[reportPrivateUsage]
    install_sensitive_log_filters,
)


@pytest.fixture
def httpx_logger_at_debug() -> Iterator[list[logging.LogRecord]]:
    """A product's own logging: the `httpx` logger lowered to `DEBUG` with a
    handler of its own, no `configure_logging()`."""
    logger = logging.getLogger("httpx")
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect()
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


class _NoContent(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def test_an_httpx_request_line_keeps_only_the_origin(
    httpx_logger_at_debug: list[logging.LogRecord],
) -> None:
    install_sensitive_log_filters()
    server = socketserver.TCPServer(("127.0.0.1", 0), _NoContent)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        # A synthetic credential in every part of the URL.
        # pragma: allowlist nextline secret
        url = f"http://user:PASSWORD-TOKEN@127.0.0.1:{port}/hooks/PATH-TOKEN?token=QUERY-TOKEN"
        with httpx.Client(trust_env=False) as client:
            assert client.post(url, content=b"{}").status_code == 204
    finally:
        server.shutdown()
        server.server_close()

    lines = [record.getMessage() for record in httpx_logger_at_debug]
    request_lines = [line for line in lines if line.startswith("HTTP Request:")]
    expected = f'HTTP Request: POST http://127.0.0.1:{port} "HTTP/1.0 204 No Content"'
    assert request_lines == [expected]
    for secret in ("PATH-TOKEN", "QUERY-TOKEN", "PASSWORD-TOKEN", "user:"):
        assert not any(secret in line for line in lines)


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://hooks.example.test/services/T/B/x?token=y", "https://hooks.example.test"),
        ("https://u:p@hooks.example.test:8443/x", "https://hooks.example.test:8443"),
        ("https://[2001:db8::1]:443/x?y=z", "https://[2001:db8::1]:443"),
        ("https://hooks.example.test:99999/x", "<url withheld>"),
        ("https:///no-host", "<url withheld>"),
    ],
)
def test_the_origin_is_the_scheme_host_and_port_only(url: str, origin: str) -> None:
    assert _origin_only(url) == origin


def test_a_preformatted_httpx_message_with_a_url_is_withheld() -> None:
    record = logging.LogRecord(
        "httpx", logging.INFO, __file__, 1, "GET https://h.test/p?q=SECRET", None, None
    )
    assert OutboundUrlFilter().filter(record)
    assert "SECRET" not in record.getMessage()


def test_installing_twice_attaches_each_filter_once() -> None:
    install_sensitive_log_filters()
    install_sensitive_log_filters()
    httpx_filters = logging.getLogger("httpx").filters
    access_filters = logging.getLogger("uvicorn.access").filters
    assert sum(isinstance(f, OutboundUrlFilter) for f in httpx_filters) == 1
    assert sum(isinstance(f, CallbackQueryFilter) for f in access_filters) == 1


@pytest.mark.parametrize("module", ["saas_os.infra.egress.client", "saas_os.core.webhooks.service"])
def test_importing_a_module_that_sends_such_urls_installs_the_filter(module: str) -> None:
    """A product that never calls `configure_logging()` still gets the
    filter as soon as it can send a webhook or a strict-egress request."""
    probe = (
        "import logging, importlib\n"
        f"importlib.import_module({module!r})\n"
        "from saas_os.infra.observability.log_filters import OutboundUrlFilter\n"
        "assert any(isinstance(f, OutboundUrlFilter) for f in logging.getLogger('httpx').filters)\n"
    )
    env = {**os.environ, "ENVIRONMENT": "test", "REDIS_URL": "redis://127.0.0.1:1/0"}
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, env=env, timeout=120
    )
    assert result.returncode == 0, result.stderr[-2000:]


def test_only_the_callback_access_line_loses_its_query(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A real uvicorn server, started as `saas_os/api/server.py` starts it
    (its own access-log configuration), with the filters installed."""

    async def app(scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    install_sensitive_log_filters()
                    await send({"type": "lifespan.startup.complete"})
                else:
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info"))
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.05)
    try:
        for path in ("/auth/callback?code=CODE-TOKEN&state=STATE-TOKEN", "/v1/items?limit=7"):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}") as response:
                assert response.status == 204
    finally:
        server.should_exit = True
        thread.join(10)

    out = capsys.readouterr()
    log = out.out + out.err
    assert '"GET /auth/callback HTTP/1.1" 204' in log
    assert "CODE-TOKEN" not in log
    assert "STATE-TOKEN" not in log
    assert '"GET /v1/items?limit=7 HTTP/1.1" 204' in log
