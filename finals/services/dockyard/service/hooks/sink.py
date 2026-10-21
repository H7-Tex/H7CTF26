#!/usr/bin/env python3
"""Webhook sink: receives POST bodies and stores them for retrieval."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_lock = threading.Lock()
_store: list[dict] = []
MAX_ENTRIES = 500


class SinkHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        with _lock:
            _store.append({"path": self.path, "body": body})
            if len(_store) > MAX_ENTRIES:
                _store.pop(0)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        if self.path == "/dump":
            with _lock:
                data = list(_store)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        elif self.path == "/clear":
            with _lock:
                _store.clear()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"cleared")
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9000))
    server = HTTPServer(("0.0.0.0", port), SinkHandler)
    print(f"sink listening on :{port}", flush=True)
    server.serve_forever()
