"""Command-line entry point for the honeypot and dashboard."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from .config import DEFAULT_SERVICES, HoneypotConfig
from .dashboard import create_app
from .sensor import Honeypot
from .storage import EventStore


def _parse_ports(value: str | None) -> list[int]:
    if not value:
        return list(DEFAULT_SERVICES.keys())
    return [int(p) for p in value.split(",") if p.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeypot",
        description="Multi-port network honeypot with live dashboard.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="sensor bind address")
    parser.add_argument(
        "--ports",
        default=None,
        help="comma-separated ports to emulate (default: built-in service set)",
    )
    parser.add_argument("--db", default="honeypot.db", help="SQLite database path")
    parser.add_argument(
        "--dashboard-host", default="0.0.0.0", help="dashboard bind address"
    )
    parser.add_argument(
        "--dashboard-port", type=int, default=8080, help="dashboard port"
    )
    parser.add_argument(
        "--geoip-db", default=None, help="path to GeoLite2-Country.mmdb (optional)"
    )
    parser.add_argument(
        "--no-dashboard", action="store_true", help="run the sensor only"
    )
    parser.add_argument(
        "--no-sensor", action="store_true", help="run the dashboard only"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = HoneypotConfig(
        host=args.host,
        ports=_parse_ports(args.ports),
        db_path=args.db,
        dashboard_host=args.dashboard_host,
        dashboard_port=args.dashboard_port,
        geoip_db=args.geoip_db,
    )
    store = EventStore(config.db_path)

    sensor = None
    if not args.no_sensor:
        sensor = Honeypot(config, store=store)
        sensor.start()

    stop_event = threading.Event()

    def _shutdown(*_a):
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if not args.no_dashboard:
        app = create_app(store)
        # Run Flask in a thread so we can also handle signals cleanly.
        server_thread = threading.Thread(
            target=app.run,
            kwargs={
                "host": config.dashboard_host,
                "port": config.dashboard_port,
                "use_reloader": False,
            },
            daemon=True,
        )
        server_thread.start()
        logging.getLogger("honeypot").info(
            "dashboard at http://%s:%s",
            config.dashboard_host,
            config.dashboard_port,
        )

    stop_event.wait()
    if sensor is not None:
        sensor.stop()
    store.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
