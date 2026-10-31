"""Local, threaded fixtures for the synchronous outbound clients
(`saas_os/infra/outbound_http.py`): an HTTPS (or plain HTTP) server with
canned routes, a `CONNECT` proxy that records each target, and a listener
that only records that something connected. Everything binds 127.0.0.1;
nothing here reaches another host."""

from __future__ import annotations

import socket
import socketserver
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tests.support.egress_support import Certificates, issue_certificates

# Every variable through which a default-configured client would take its
# routing from the environment.
ENVIRONMENT_PROXY_VARIABLES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


@dataclass(frozen=True)
class Route:
    status: int
    body: bytes = b""
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "application/json"),)


@dataclass
class LocalHTTPServer:
    """Serves `routes` (path -> `Route`) and records each request path."""

    routes: dict[str, Route]
    ssl_context: ssl.SSLContext | None = None
    requests: list[str] = field(default_factory=list)
    port: int = 0

    @property
    def origin(self) -> str:
        if self.ssl_context is not None:
            return f"https://localhost:{self.port}"
        return f"http://127.0.0.1:{self.port}"


@contextmanager
def serve(server: LocalHTTPServer) -> Iterator[LocalHTTPServer]:
    owner = server

    class Handler(BaseHTTPRequestHandler):
        def _answer(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            owner.requests.append(self.path)
            route = owner.routes.get(self.path, Route(404))
            self.send_response(route.status)
            for name, value in route.headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(route.body)))
            self.end_headers()
            self.wfile.write(route.body)

        do_GET = _answer  # noqa: N815 -- the http.server naming convention
        do_POST = _answer  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    if server.ssl_context is not None:
        httpd.socket = server.ssl_context.wrap_socket(httpd.socket, server_side=True)
    server.port = int(httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        httpd.shutdown()
        httpd.server_close()


@dataclass(frozen=True)
class LocalTLS:
    certs: Certificates
    ca_file: Path
    server_context: ssl.SSLContext


def local_tls(directory: Path) -> LocalTLS:
    """A fresh CA and a `localhost` server certificate it signed, written
    under `directory` (which must not exist yet)."""
    certs = issue_certificates("localhost")
    directory.mkdir()
    ca_file = directory / "ca.pem"
    ca_file.write_bytes(certs.ca_pem)
    (directory / "server.pem").write_bytes(certs.cert_pem)
    (directory / "server.key").write_bytes(certs.key_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory / "server.pem"), str(directory / "server.key"))
    return LocalTLS(certs=certs, ca_file=ca_file, server_context=context)


@dataclass
class LocalProxy:
    """`relay=True`: a `CONNECT` proxy relaying every tunnel to 127.0.0.1 at
    the requested port. `relay=False`: records the request and refuses it."""

    relay: bool = True
    heads: list[bytes] = field(default_factory=list)
    connections: int = 0
    port: int = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def _pipe(source: socket.socket, sink: socket.socket) -> None:
    try:
        while data := source.recv(65536):
            sink.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (source, sink):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


@contextmanager
def proxy(state: LocalProxy) -> Iterator[LocalProxy]:
    owner = state

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            owner.connections += 1
            client: socket.socket = self.request
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            owner.heads.append(head.split(b"\r\n\r\n", 1)[0])
            if not owner.relay or not head.startswith(b"CONNECT "):
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            target = head.split(b" ", 2)[1].decode("ascii")
            port = int(target.rsplit(":", 1)[1])
            upstream = socket.create_connection(("127.0.0.1", port), timeout=5)
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            back = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
            back.start()
            _pipe(client, upstream)
            back.join(timeout=5)
            upstream.close()

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Server(("127.0.0.1", 0), Handler)
    state.port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
