"""Configuration for the honeypot sensor and dashboard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


# Default emulated services. Each entry maps a TCP port to a service name and
# the banner the honeypot returns on connect. Banners are deliberately generic
# and version-light so the sensor looks like a plausible target without
# pretending to be a specific patched/unpatched build.
DEFAULT_SERVICES: Dict[int, Dict[str, str]] = {
    21: {"name": "ftp", "banner": "220 (vsFTPd)\r\n"},
    22: {"name": "ssh", "banner": "SSH-2.0-OpenSSH_8.9\r\n"},
    23: {"name": "telnet", "banner": "\xff\xfd\x18\xff\xfd\x20login: "},
    25: {"name": "smtp", "banner": "220 mail ESMTP\r\n"},
    80: {"name": "http", "banner": ""},
    110: {"name": "pop3", "banner": "+OK POP3 ready\r\n"},
    143: {"name": "imap", "banner": "* OK IMAP4 ready\r\n"},
    445: {"name": "smb", "banner": ""},
    3306: {"name": "mysql", "banner": "\x4a\x00\x00\x00\x0a5.7.40\x00"},
    3389: {"name": "rdp", "banner": ""},
    5432: {"name": "postgres", "banner": ""},
    6379: {"name": "redis", "banner": "-NOAUTH Authentication required.\r\n"},
}


@dataclass
class HoneypotConfig:
    """Runtime configuration for the honeypot.

    Attributes:
        host: Interface to bind the sensor listeners to.
        ports: Ports to emulate. Defaults to the keys of ``DEFAULT_SERVICES``.
        db_path: Path to the SQLite event store. ":memory:" for ephemeral runs.
        max_capture_bytes: How many bytes of attacker payload to record.
        services: Per-port service metadata and banners.
        dashboard_host: Interface the Flask dashboard binds to.
        dashboard_port: Port the dashboard serves on.
        geoip_db: Optional path to a MaxMind GeoLite2-Country.mmdb file.
    """

    host: str = "0.0.0.0"
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_SERVICES.keys()))
    db_path: str = "honeypot.db"
    max_capture_bytes: int = 4096
    services: Dict[int, Dict[str, str]] = field(
        default_factory=lambda: dict(DEFAULT_SERVICES)
    )
    dashboard_host: str = "0.0.0.0"
    dashboard_port: int = 8080
    geoip_db: str | None = None

    def service_for(self, port: int) -> Dict[str, str]:
        """Return service metadata for ``port``, falling back to a generic TCP entry."""
        return self.services.get(port, {"name": f"tcp/{port}", "banner": ""})
