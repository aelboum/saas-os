"""A scripted SMTP server on a real local socket, for fault injection at the
transport boundary (owner decision of 2026-11-01, ledger row F5): it
answers like a relay until the scripted point, then refuses, disconnects or
stalls there. Plaintext, unauthenticated, one thread, any number of
sequential connections.

Modes:

- `accept`: a normal conversation; the message is queued (`250`).
- `drop_after_rcpt`: the connection closes right after `250` to RCPT TO.
- `drop_after_354`: the connection closes right after inviting the data.
- `drop_after_data_end`: the whole message is read, then the connection
  closes without a final reply.
- `stall_after_data_end`: the whole message is read and no reply ever comes
  (the client's timeout fires).
- `stall_before_greeting`: the connection is accepted and never greeted.
- `final_4xx` / `final_5xx`: the final reply to the data is `451` / `554`.
- `bad_quit_after_250`: the message is accepted, then QUIT gets `500`.
"""

from __future__ import annotations

import socket
import threading
import time


def closed_port() -> int:
    """A local port nothing listens on (connecting is refused)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


class ScriptedSmtpServer:
    def __init__(self, mode: str, *, stall_seconds: float = 3.0) -> None:
        self.mode = mode
        self.stall_seconds = stall_seconds
        self.connections = 0
        self.messages_received = 0
        self.commands: list[str] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(0.2)
        self.port = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> ScriptedSmtpServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=10)
        self._sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            self.connections += 1
            with conn:
                conn.settimeout(10)
                try:
                    self._converse(conn)
                except OSError:
                    pass

    def _stall(self) -> None:
        deadline = time.monotonic() + self.stall_seconds
        while time.monotonic() < deadline and not self._stop.is_set():
            time.sleep(0.05)

    def _converse(self, conn: socket.socket) -> None:
        if self.mode == "stall_before_greeting":
            self._stall()
            return
        conn.sendall(b"220 scripted.smtp.test ready\r\n")
        buffer = b""
        in_data = False
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buffer += chunk
            while b"\r\n" in buffer:
                line, buffer = buffer.split(b"\r\n", 1)
                if in_data:
                    if line != b".":
                        continue
                    in_data = False
                    self.messages_received += 1
                    if self.mode == "drop_after_data_end":
                        return
                    if self.mode == "stall_after_data_end":
                        self._stall()
                        return
                    if self.mode == "final_4xx":
                        conn.sendall(b"451 4.3.0 try again later\r\n")
                    elif self.mode == "final_5xx":
                        conn.sendall(b"554 5.6.0 message refused\r\n")
                    else:
                        conn.sendall(b"250 2.0.0 queued\r\n")
                    continue
                command = line.decode("ascii", errors="replace").upper()
                self.commands.append(command.split(" ", 1)[0].split(":", 1)[0])
                if command.startswith(("EHLO", "HELO")):
                    conn.sendall(b"250-scripted.smtp.test\r\n250 OK\r\n")
                elif command.startswith("RCPT"):
                    conn.sendall(b"250 OK\r\n")
                    if self.mode == "drop_after_rcpt":
                        return
                elif command.startswith("DATA"):
                    conn.sendall(b"354 go ahead\r\n")
                    if self.mode == "drop_after_354":
                        return
                    in_data = True
                elif command.startswith("QUIT"):
                    if self.mode == "bad_quit_after_250":
                        conn.sendall(b"500 5.0.0 no\r\n")
                    else:
                        conn.sendall(b"221 bye\r\n")
                    return
                elif command.startswith("RSET"):
                    conn.sendall(b"250 OK\r\n")
                else:
                    conn.sendall(b"250 OK\r\n")
