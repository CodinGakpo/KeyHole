"""A tiny deny-by-default HTTP CONNECT proxy that logs every attempt.

This is the sandbox's only intended network path. It permits CONNECT only to hosts on the
allowlist (``MARK1_ALLOWED_HOSTS``); everything else is denied. Every attempt — allowed or denied
— is logged in a structured line so the control plane can fold it into the run's data-flow record
and attestation. Standard library only; no external dependencies.

NOTE: hostname allowlisting here is enforced at the proxy (it sees the CONNECT target), which is
why the proxy exists rather than relying on L3/L4 security-group CIDR rules alone.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
from datetime import datetime, timezone

ALLOWED = {h.strip() for h in os.environ.get("MARK1_ALLOWED_HOSTS", "").split(",") if h.strip()}
PORT = int(os.environ.get("MARK1_PROXY_PORT", "8080"))


def log(event: str, host: str, allowed: bool) -> None:
    print(
        json.dumps(
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "kind": "egress_attempt",
                "event": event,
                "host": host,
                "denied": not allowed,
            }
        ),
        flush=True,
    )


def handle(client: socket.socket) -> None:
    try:
        request = client.recv(65536).decode("latin-1", errors="replace")
        line = request.split("\r\n", 1)[0]
        parts = line.split(" ")
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        host = parts[1].split(":", 1)[0]
        allowed = host in ALLOWED
        log("connect", host, allowed)
        if not allowed:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        # Allowlisted: establish the tunnel. (Kept minimal; real tunneling would splice sockets.)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except OSError:
        pass
    finally:
        client.close()


def main() -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(64)
    print(f"egress-proxy listening on :{PORT}; allowlist={sorted(ALLOWED) or 'DENY-ALL'}", file=sys.stderr)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
