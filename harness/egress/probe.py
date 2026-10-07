"""Containment probe: proves the sandbox has no side exit.

Runs inside a container attached ONLY to an internal (no-internet) Docker network, mirroring the
Fargate sandbox's network posture. Asserts three things:

  1. DIRECT egress fails       - a raw connection to a public IP has no route out.
  2. PROXY denies by default   - CONNECT to a non-allowlisted host returns 403.
  3. PROXY allows the allowlist - CONNECT to the one allowlisted host returns 200.

Exit 0 iff all three hold. Uses literal IPs so it needs no DNS (which the internal net lacks);
the proxy — reachable by service name on the internal net — does the upstream resolution.
"""

from __future__ import annotations

import os
import socket
import sys
import time

PROXY_HOST = os.environ.get("KEYHOLE_PROXY_HOST", "proxy")
PROXY_PORT = int(os.environ.get("KEYHOLE_PROXY_PORT", "8080"))

ALLOWED_IP = "1.1.1.1"  # matches the proxy's KEYHOLE_ALLOWED_HOSTS
DENIED_IP = "9.9.9.9"  # not on the allowlist
PUBLIC_PORT = 443


def direct_egress_blocked() -> bool:
    """A direct connection to a public IP must fail (internal net has no route out)."""
    try:
        socket.create_connection((ALLOWED_IP, PUBLIC_PORT), timeout=5).close()
        return False  # it connected -> containment FAILED
    except OSError:
        return True


def _connect_via_proxy(target_ip: str) -> str:
    """Return the proxy's HTTP status line for a CONNECT to target_ip:443."""
    with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=10) as s:
        s.sendall(f"CONNECT {target_ip}:{PUBLIC_PORT} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode())
        return s.recv(1024).decode("latin-1", errors="replace").split("\r\n", 1)[0]


def _wait_for_proxy(retries: int = 30) -> None:
    for _ in range(retries):
        try:
            socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=2).close()
            return
        except OSError:
            time.sleep(1)
    raise SystemExit("probe: proxy never became reachable")


def main() -> int:
    _wait_for_proxy()

    results = {
        "direct_egress_blocked": direct_egress_blocked(),
        "proxy_denies_unlisted": "403" in _connect_via_proxy(DENIED_IP),
        "proxy_allows_listed": "200" in _connect_via_proxy(ALLOWED_IP),
    }

    for name, ok in results.items():
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")

    all_ok = all(results.values())
    print("CONTAINMENT: " + ("PROVEN" if all_ok else "BROKEN"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
