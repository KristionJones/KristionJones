"""Emulated service banners and credential parsing.

This is a *low-interaction* honeypot. It presents a believable banner, reads
whatever the client sends, and records it. It NEVER executes attacker input and
NEVER provides a real shell — that keeps the sensor safe to run. The goal is to
collect intelligence (source IPs, credentials sprayed, payloads, scanner
fingerprints), not to let anyone in.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass


@dataclass
class ServiceProfile:
    name: str
    port: int
    banner: bytes = b""
    # A second prompt sent after the client first speaks (e.g. password:).
    followup: bytes = b""


def parse_credentials(service: str, data: bytes) -> tuple[str | None, str | None]:
    """Best-effort extraction of credentials from captured bytes.

    Supports the most common things scanners throw at exposed services:
    HTTP Basic auth, FTP USER/PASS, Telnet/SSH login prompts.
    """
    text = data.decode("latin-1", errors="replace")

    # HTTP Basic auth:  Authorization: Basic base64(user:pass)
    m = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.I)
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode("latin-1", "replace")
            if ":" in decoded:
                user, _, pwd = decoded.partition(":")
                return user, pwd
        except Exception:  # noqa: BLE401 - malformed base64 is expected
            pass

    # FTP:  USER bob\r\n  PASS secret\r\n
    user = None
    pwd = None
    mu = re.search(r"^USER\s+(.+?)\r?$", text, re.I | re.M)
    mp = re.search(r"^PASS\s+(.+?)\r?$", text, re.I | re.M)
    if mu:
        user = mu.group(1).strip()
    if mp:
        pwd = mp.group(1).strip()
    if user or pwd:
        return user, pwd

    # Telnet / generic login: first two lines often "user\r\npassword\r\n"
    if service in {"Telnet", "SSH"}:
        lines = [ln for ln in re.split(r"\r?\n", text) if ln.strip()]
        if len(lines) >= 2 and len(lines[0]) < 64 and len(lines[1]) < 64:
            return lines[0].strip(), lines[1].strip()

    return None, None


def classify_request(service: str, data: bytes) -> str:
    """Tag a payload with a coarse attack category for quick triage."""
    text = data.decode("latin-1", errors="replace").lower()
    signatures = {
        "log4shell": "${jndi:",
        "path_traversal": "../../",
        "shellshock": "() {",
        "sql_injection": "union select",
        "wordpress_scan": "/wp-",
        "phpmyadmin_scan": "phpmyadmin",
        "env_file_probe": "/.env",
        "git_probe": "/.git",
        "shell_upload": "/bin/sh",
        "cmd_injection": ";wget ",
    }
    for label, sig in signatures.items():
        if sig in text:
            return label
    if service == "HTTP" and text.startswith(("get ", "post ", "head ")):
        return "http_recon"
    if service in {"SSH", "Telnet", "FTP"}:
        return "credential_attack"
    return "connection_probe"
