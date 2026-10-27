"""ADR-0059 end-to-end fixture: a TLS server standing in for a public webhook
receiver. Logs, one line each, every accepted connection, the SNI name it
was asked for, and every request line and Host header, then answers 204.

`python dest_server.py <cert.pem> <key.pem>`
"""

from __future__ import annotations

import socket
import ssl
import sys
import threading


def log(line: str) -> None:
    print(line, flush=True)


def handle(raw: socket.socket, context: ssl.SSLContext) -> None:
    log("connection")
    try:
        with context.wrap_socket(raw, server_side=True) as tls:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                data += chunk
            head = data.split(b"\r\n\r\n", 1)[0].decode(errors="replace").split("\r\n")
            log(f"request {head[0]}")
            for header in head[1:]:
                if header.lower().startswith("host:"):
                    log(f"host {header.split(':', 1)[1].strip()}")
            tls.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
    except (ssl.SSLError, OSError) as exc:
        log(f"tls-error {type(exc).__name__}")


def main() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[1], sys.argv[2])
    context.sni_callback = lambda _sock, name, _ctx: log(f"sni {name}")
    server = socket.create_server(("0.0.0.0", 443))
    log("listening")
    while True:
        raw, _ = server.accept()
        threading.Thread(target=handle, args=(raw, context), daemon=True).start()


if __name__ == "__main__":
    main()
