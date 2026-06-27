"""The honeypot sensor: low-interaction multi-port TCP listeners.

Each emulated port runs its own :class:`socketserver.ThreadingTCPServer` in a
background thread. On connect the sensor optionally sends a service banner,
captures a bounded amount of attacker input, records an :class:`Event`, and
closes the connection. It never executes attacker input and never returns a
real shell - it is deliberately *low interaction* so it is safe to expose.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import threading
import uuid
from datetime import datetime, timezone

from .config import HoneypotConfig
from .geo import GeoResolver
from .storage import Event, EventStore

logger = logging.getLogger("honeypot.sensor")


def _make_handler(
    sensor: "Honeypot", dst_port: int
) -> type[socketserver.BaseRequestHandler]:
    service = sensor.config.service_for(dst_port)

    class _Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:  # noqa: D401 - socketserver contract
            sock: socket.socket = self.request
            src_ip, src_port = self.client_address[0], self.client_address[1]
            # Record the port the connection actually landed on. This matches
            # the configured port in normal use and resolves correctly when a
            # listener is bound to an ephemeral port (e.g. port 0 in tests).
            local_port = sock.getsockname()[1]
            session_id = uuid.uuid4().hex[:12]
            try:
                banner = service.get("banner", "")
                if banner:
                    sock.sendall(banner.encode("latin-1", errors="ignore"))
                sock.settimeout(sensor.read_timeout)
                data = b""
                try:
                    while len(data) < sensor.config.max_capture_bytes:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                except (socket.timeout, OSError):
                    pass
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

            payload = data[: sensor.config.max_capture_bytes].decode(
                "latin-1", errors="replace"
            )
            geo = sensor.geo.lookup(src_ip)
            event = Event(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=src_ip,
                src_port=int(src_port),
                dst_port=local_port,
                service=service["name"],
                bytes_received=len(data),
                payload=payload,
                session_id=session_id,
                country=geo.get("country"),
                country_code=geo.get("country_code"),
            )
            sensor.store.record(event)
            logger.info(
                "hit %s:%s -> %s (%s) %dB",
                src_ip,
                src_port,
                dst_port,
                service["name"],
                len(data),
            )

        def log_message(self, *args, **kwargs):  # pragma: no cover - silence base
            pass

    return _Handler


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Honeypot:
    """Owns the per-port listeners and their lifecycle."""

    def __init__(
        self,
        config: HoneypotConfig,
        store: EventStore | None = None,
        read_timeout: float = 2.0,
    ) -> None:
        self.config = config
        self.store = store or EventStore(config.db_path)
        self.geo = GeoResolver(config.geoip_db)
        self.read_timeout = read_timeout
        self._servers: list[_Server] = []
        self._threads: list[threading.Thread] = []
        self.bound_ports: list[int] = []

    def start(self) -> list[int]:
        """Start a listener for each configured port.

        Ports that cannot be bound (already in use, privileged) are skipped with
        a warning rather than aborting the whole sensor. Returns the list of
        ports that were successfully bound.
        """
        for port in self.config.ports:
            try:
                server = _Server(
                    (self.config.host, port), _make_handler(self, port)
                )
            except OSError as exc:
                logger.warning("could not bind port %s: %s", port, exc)
                continue
            thread = threading.Thread(
                target=server.serve_forever, name=f"sensor-{port}", daemon=True
            )
            thread.start()
            self._servers.append(server)
            self._threads.append(thread)
            # Reflect the actually-bound port (relevant when port 0 is used).
            self.bound_ports.append(server.server_address[1])
        logger.info("honeypot listening on ports: %s", self.bound_ports)
        return self.bound_ports

    def stop(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()
        self._servers.clear()
        self._threads.clear()
        self.bound_ports.clear()
