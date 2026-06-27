"""Asyncio multi-port honeypot sensor.

Listens on every configured service port simultaneously. For each connection it
records the source, captures up to ``max_bytes`` of input, attempts to parse
credentials, classifies the payload, and persists an :class:`AttackEvent`.

Run it directly::

    python -m honeypot.sensor --config config.yaml

Default ports are high (2222, 8080, 2323, 2121) so it runs without root. To
catch real scans on 22/80/23/21, redirect with iptables (see the README).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import time

try:  # PyYAML is optional; we fall back to the built-in defaults without it.
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from .enrich import classify_ip
from .services import ServiceProfile, classify_request, parse_credentials
from .storage import AttackEvent, Storage, default_storage


DEFAULT_SERVICES = [
    ServiceProfile("SSH", 2222, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"),
    ServiceProfile("HTTP", 8080, b""),
    ServiceProfile("Telnet", 2323, b"Ubuntu 18.04 LTS\r\nlogin: "),
    ServiceProfile("FTP", 2121, b"220 (vsFTPd 3.0.3)\r\n"),
]

HTTP_RESPONSE = (
    b"HTTP/1.1 401 Unauthorized\r\n"
    b"WWW-Authenticate: Basic realm=\"Admin\"\r\n"
    b"Server: Apache/2.4.41 (Ubuntu)\r\n"
    b"Content-Length: 0\r\n\r\n"
)


class Honeypot:
    def __init__(
        self,
        services: list[ServiceProfile],
        storage: Storage,
        bind_address: str = "0.0.0.0",
        read_timeout: float = 5.0,
        max_bytes: int = 8192,
    ):
        self.services = services
        self.storage = storage
        self.bind_address = bind_address
        self.read_timeout = read_timeout
        self.max_bytes = max_bytes

    async def _handle(self, profile: ServiceProfile, reader, writer) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        src_ip, src_port = peer[0], peer[1]
        start = time.time()
        data = b""
        try:
            if profile.banner:
                writer.write(profile.banner)
                await writer.drain()
            # Read whatever the client sends, bounded by time and size.
            try:
                data = await asyncio.wait_for(
                    reader.read(self.max_bytes), timeout=self.read_timeout
                )
            except asyncio.TimeoutError:
                data = b""

            # A follow-up prompt sometimes coaxes a second credential line.
            if profile.followup and data:
                writer.write(profile.followup)
                await writer.drain()
                try:
                    more = await asyncio.wait_for(
                        reader.read(self.max_bytes), timeout=self.read_timeout
                    )
                    data += more
                except asyncio.TimeoutError:
                    pass

            if profile.name == "HTTP":
                writer.write(HTTP_RESPONSE)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

        username, password = parse_credentials(profile.name, data)
        category = classify_request(profile.name, data)
        preview = data.decode("latin-1", "replace").strip()
        if len(preview) > 280:
            preview = preview[:280] + "…"

        event = AttackEvent(
            service=profile.name,
            src_ip=str(src_ip),
            src_port=int(src_port),
            dst_port=profile.port,
            username=username,
            password=password,
            byte_count=len(data),
            session_ms=int((time.time() - start) * 1000),
            ip_class=classify_ip(str(src_ip)),
            data_preview=f"[{category}] {preview}" if preview else f"[{category}]",
            data_hex=data.hex(),
        )
        self.storage.record(event)
        print(
            f"  ⚑ {event.iso_time}  {profile.name:6s} "
            f"{src_ip}:{src_port} → :{profile.port}  "
            f"{category}"
            + (f"  creds={username!r}:{password!r}" if username else "")
        )

    async def serve(self) -> None:
        servers = []
        for profile in self.services:
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=profile: self._handle(p, r, w),
                    self.bind_address,
                    profile.port,
                )
                servers.append(server)
                print(f"  ● listening  {profile.name:6s} on "
                      f"{self.bind_address}:{profile.port}")
            except OSError as exc:
                print(f"  ✗ could not bind {profile.name} :{profile.port} — {exc}")
        if not servers:
            raise SystemExit("No ports could be bound; aborting.")
        await asyncio.gather(*(s.serve_forever() for s in servers))


def load_services(config_path: str | None) -> tuple[list[ServiceProfile], dict]:
    if not config_path or not os.path.exists(config_path) or yaml is None:
        return DEFAULT_SERVICES, {}
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    services = []
    for item in cfg.get("services", []):
        services.append(
            ServiceProfile(
                name=item["name"],
                port=int(item["port"]),
                banner=item.get("banner", "").encode(),
                followup=item.get("followup", "").encode(),
            )
        )
    return (services or DEFAULT_SERVICES), cfg


def main() -> None:
    parser = argparse.ArgumentParser(description="Low-interaction honeypot sensor")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--bind", default=None)
    parser.add_argument("--data-dir", default=None)
    args = parser.parse_args()

    if args.data_dir:
        os.environ["HONEYPOT_DATA_DIR"] = args.data_dir

    services, cfg = load_services(args.config)
    storage = default_storage()
    hp = Honeypot(
        services=services,
        storage=storage,
        bind_address=args.bind or cfg.get("bind_address", "0.0.0.0"),
        read_timeout=float(cfg.get("read_timeout", 5.0)),
        max_bytes=int(cfg.get("max_bytes", 8192)),
    )

    banner = r"""
   __                            __
  / /  ___  ___  ___ __ _  ___  / /_
 / _ \/ _ \/ _ \/ -_)  ' \/ _ \/ __/   low-interaction honeypot sensor
/_//_/\___/_//_/\__/_/_/_/ .__/\__/    captures · never executes
                        /_/
"""
    print(banner)
    try:
        asyncio.run(hp.serve())
    except KeyboardInterrupt:
        print("\n  stopped. data saved.")
    finally:
        storage.close()


if __name__ == "__main__":
    main()
