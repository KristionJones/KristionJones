"""Flask dashboard and JSON API over the event store."""

from __future__ import annotations

from flask import Flask, Response, jsonify, render_template, request

from . import iocs
from .storage import EventStore


def create_app(store: EventStore) -> Flask:
    """Application factory wiring the dashboard to a given event store."""
    app = Flask(__name__)
    app.config["STORE"] = store

    @app.get("/")
    def index() -> str:
        return render_template("index.html")

    @app.get("/healthz")
    def healthz() -> Response:
        return jsonify({"status": "ok", "events": store.total_events()})

    @app.get("/api/stats")
    def api_stats() -> Response:
        return jsonify(store.stats())

    @app.get("/api/events")
    def api_events() -> Response:
        limit = request.args.get("limit", default=100, type=int)
        return jsonify([e.to_dict() for e in store.recent(limit)])

    @app.get("/api/attackers")
    def api_attackers() -> Response:
        limit = request.args.get("limit", default=10, type=int)
        return jsonify(store.top_attackers(limit))

    @app.get("/api/timeline")
    def api_timeline() -> Response:
        bucket = request.args.get("bucket", default="hour", type=str)
        return jsonify(store.timeline(bucket))

    @app.get("/api/iocs")
    def api_iocs() -> Response:
        fmt = request.args.get("format", default="json", type=str).lower()
        try:
            body = iocs.export(store, fmt)
        except ValueError as exc:
            return Response(str(exc), status=400)
        mimetypes = {
            "csv": "text/csv",
            "json": "application/json",
            "stix": "application/json",
        }
        filename = f"honeypot-iocs.{ 'csv' if fmt == 'csv' else 'json' }"
        return Response(
            body,
            mimetype=mimetypes.get(fmt, "text/plain"),
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    return app
