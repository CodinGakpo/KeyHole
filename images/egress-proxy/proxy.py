"""A tiny deny-by-default HTTP CONNECT proxy that logs every attempt.

This is the sandbox's only intended network path. It permits CONNECT only to hosts on the
allowlist (``MARK1_ALLOWED_HOSTS``); everything else is denied with 403. Allowlisted targets are
tunnelled for real (bidirectional splice). Every attempt — allowed or denied — is logged as a
structured JSON line so the control plane can fold it into the run's data-flow record and
attestation.

Hostname allowlisting is enforced here because the proxy sees the CONNECT target host, which
L3/L4 security-group CIDR rules cannot. The decision/parse helpers are pure so they can be unit
tested without a socket.

Standard library only; no external dependencies.
"""

from __future__ import annotations

import json
import os
import select
import socket
import sys
import threading
from datetime import datetime, timezone

DEFAULT_PORT = 8080


def parse_connect(request_line: str) -> tuple[str, int] | None:
    """Parse a ``CONNECT host:port HTTP/1.1`` request line. Returns (host, port) or None."""
    parts = request_line.strip().split(" ")
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        return None
    target = parts[1]
    if ":" in target:
        host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            return None
    else:
        host, port = target, 443
    if not host:
        return None
    return host, port


def is_allowed(host: str, allowed: set[str]) -> bool:
    """Deny-by-default: a host is permitted only if it is explicitly on the allowlist."""
    return host in allowed


def load_allowlist(raw: str) -> set[str]:
    return {h.strip() for h in raw.split(",") if h.strip()}


def _log(event: str, host: str | None, allowed: bool) -> None:
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


def _splice(a: socket.socket, b: socket.socket) -> None:
    """Pump bytes bidirectionally between two sockets until either side closes."""
    conns = [a, b]
    try:
        while True:
            readable, _, errored = select.select(conns, [], conns, 60)
            if errored:
                break
            if not readable:
                break
            for src in readable:
                dst = b if src is a else a
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
    except OSError:
        pass


def handle(client: socket.socket, allowed: set[str]) -> None:
    try:
        request = client.recv(65536).decode("latin-1", errors="replace")
        line = request.split("\r\n", 1)[0]
        parsed = parse_connect(line)
        if parsed is None:
            _log("bad_request", None, False)
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        host, port = parsed
        if not is_allowed(host, allowed):
            _log("connect", host, False)
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return

        _log("connect", host, True)
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        with upstream:
            _splice(client, upstream)
    except OSError:
        pass
    finally:
        client.close()


def main() -> int:
    allowed = load_allowlist(os.environ.get("MARK1_ALLOWED_HOSTS", ""))
    port = int(os.environ.get("MARK1_PROXY_PORT", str(DEFAULT_PORT)))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(64)
    print(
        f"egress-proxy listening on :{port}; allowlist={sorted(allowed) or 'DENY-ALL'}",
        file=sys.stderr,
        flush=True,
    )
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn, allowed), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
