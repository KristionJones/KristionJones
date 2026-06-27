"""Zero-dependency web dashboard for the honeypot.

Built on the standard library ``http.server`` so there is nothing to install.
Serves a single-page UI and a small JSON API backed by the same SQLite database
the sensor writes to.

    python -m dashboard.server --port 8000 --data-dir ./data

Then open http://localhost:8000
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from honeypot.storage import Storage


HERE = os.path.dirname(os.path.abspath(__file__))


class DashboardHandler(BaseHTTPRequestHandler):
    storage: Storage  # injected via partial-style subclass below

    # -- helpers ----------------------------------------------------------
    def _send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str, content_type: str) -> None:
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # quieter logging
        return

    # -- routing ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        url = urlparse(self.path)
        route = url.path
        query = parse_qs(url.query)

        if route == "/" or route == "/index.html":
            self._send_file(os.path.join(HERE, "static", "index.html"), "text/html")
        elif route == "/static/app.js":
            self._send_file(os.path.join(HERE, "static", "app.js"),
                            "application/javascript")
        elif route == "/api/stats":
            self._send_json(self.storage.stats())
        elif route == "/api/events":
            limit = int(query.get("limit", ["100"])[0])
            self._send_json(self.storage.recent(min(limit, 1000)))
        elif route == "/api/timeseries":
            bucket = int(query.get("bucket", ["3600"])[0])
            self._send_json(self.storage.timeseries(bucket))
        elif route == "/api/top":
            field_name = query.get("field", ["src_ip"])[0]
            try:
                self._send_json(self.storage.top(field_name,
                                                 int(query.get("limit", ["10"])[0])))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
        else:
            self.send_error(404)


def make_handler(storage: Storage):
    return type("BoundHandler", (DashboardHandler,), {"storage": storage})


def main() -> None:
    parser = argparse.ArgumentParser(description="Honeypot dashboard")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--data-dir", default=os.getcwd())
    args = parser.parse_args()

    storage = Storage(
        db_path=os.path.join(args.data_dir, "honeypot.db"),
        jsonl_path=os.path.join(args.data_dir, "events.jsonl"),
    )
    handler = make_handler(storage)
    httpd = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"  dashboard → http://{args.host}:{args.port}  (data: {args.data_dir})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  dashboard stopped.")
    finally:
        storage.close()


if __name__ == "__main__":
    main()
