"""Self-contained, read-only dashboard server (Python standard library only).

No web framework, no CDN, no external requests — the page (``index.html``, a forensic "instrument"
readout whose signature element is the exit-bandwidth aperture) is self-contained and served over
``http.server``. The server is a thin adapter over :mod:`mark1.dashboard.service`; all the logic
(and its tests) live there.
"""

from __future__ import annotations

import json
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from mark1.controlplane.store import Store
from mark1.dashboard import service


def serve(store: Store, pubkey_pem: bytes | None, port: int = 8787,
          host: str = "127.0.0.1") -> None:
    """Run the dashboard until interrupted."""
    handler = _make_handler(store, pubkey_pem)
    httpd = ThreadingHTTPServer((host, port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def _make_handler(store: Store, pubkey_pem: bytes | None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet by default
            pass

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/?"):
                self._send(200, render_index().encode("utf-8"), "text/html; charset=utf-8")
            elif self.path == "/api/runs":
                self._json(200, service.list_summaries(store, pubkey_pem))
            elif self.path.startswith("/api/runs/"):
                run_id = self.path[len("/api/runs/"):]
                detail = service.run_detail(store, run_id, pubkey_pem)
                self._json(200 if detail else 404, detail or {"error": "not found"})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/api/verify":
                self._json(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"valid": False, "error": "body is not valid JSON"})
                return
            self._json(200, service.verify_upload(payload, pubkey_pem))

    return Handler


def render_index() -> str:
    """The dashboard page (index.html), self-contained — no external requests."""
    return _page()


@lru_cache(maxsize=1)
def _page() -> str:
    return resources.files("mark1.dashboard").joinpath("index.html").read_text(encoding="utf-8")
