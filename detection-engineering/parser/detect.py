#!/usr/bin/env python3
"""Log-based detection engine (dependency-free).

Reads structured events — the honeypot's ``events.jsonl`` or a Linux
``auth.log`` — and applies a set of detection rules to raise prioritized
alerts mapped to MITRE ATT&CK. This is the "blue team" half of the portfolio:
it turns the raw telemetry the honeypot collects into actionable detections,
the same way a SIEM correlation rule would.

    python detect.py ../../honeypot-dashboard/data/events.jsonl
    python detect.py /var/log/auth.log --format authlog

Outputs a triaged alert list and a summary, optionally as JSON.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict


# --------------------------------------------------------------------------- #
# Input adapters: normalize different log sources into a common event shape
# { ts, src_ip, service, dst_port, username, password, payload }
# --------------------------------------------------------------------------- #
def load_honeypot_jsonl(path: str):
    events = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append({
                "ts": e.get("iso_time", ""),
                "src_ip": e.get("src_ip", ""),
                "service": e.get("service", ""),
                "dst_port": e.get("dst_port"),
                "username": e.get("username"),
                "password": e.get("password"),
                "payload": e.get("data_preview", ""),
            })
    return events


AUTHLOG_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)


def load_authlog(path: str):
    events = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            m = AUTHLOG_FAIL.search(line)
            if m:
                events.append({
                    "ts": line[:15],
                    "src_ip": m.group("ip"),
                    "service": "SSH",
                    "dst_port": 22,
                    "username": m.group("user"),
                    "password": None,
                    "payload": line.strip(),
                })
    return events


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #
DEFAULT_CREDS = {
    ("root", "root"), ("root", "toor"), ("admin", "admin"),
    ("root", "123456"), ("admin", "password"), ("ubuntu", "ubuntu"),
    ("pi", "raspberry"), ("user", "user"),
}

BRUTE_FORCE_THRESHOLD = 5  # credential attempts from one IP


def detect(events: list[dict]) -> list[dict]:
    alerts: list[dict] = []
    attempts_by_ip: dict[str, int] = defaultdict(int)
    services_by_ip: dict[str, set] = defaultdict(set)

    for e in events:
        ip = e["src_ip"]
        payload = (e.get("payload") or "").lower()
        services_by_ip[ip].add(e.get("service"))

        # --- exploitation signatures (per-event) -------------------------
        if "${jndi:" in payload:
            alerts.append(_alert("Log4Shell exploitation attempt", "critical",
                                 ip, e, "T1190 Exploit Public-Facing Application"))
        if "../../" in payload or "/etc/passwd" in payload:
            alerts.append(_alert("Path traversal / LFI attempt", "high",
                                 ip, e, "T1083 File and Directory Discovery"))
        if "union select" in payload:
            alerts.append(_alert("SQL injection attempt", "high",
                                 ip, e, "T1190 Exploit Public-Facing Application"))
        if any(p in payload for p in ("/.env", "/.git", "wp-login", "phpmyadmin")):
            alerts.append(_alert("Sensitive file / admin path probe", "medium",
                                 ip, e, "T1595 Active Scanning"))

        # --- credential rules -------------------------------------------
        if e.get("username") is not None:
            attempts_by_ip[ip] += 1
            if (e.get("username"), e.get("password")) in DEFAULT_CREDS:
                alerts.append(_alert(
                    f"Default credential spray ({e['username']}:{e['password']})",
                    "high", ip, e, "T1110.001 Password Guessing"))

    # --- aggregate rules (across events) --------------------------------
    for ip, count in attempts_by_ip.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "rule": "Credential brute-force / password spraying",
                "severity": "high",
                "src_ip": ip,
                "evidence": f"{count} credential attempts from a single source",
                "mitre": "T1110 Brute Force",
                "ts": "",
            })
        if len(services_by_ip[ip]) >= 3:
            alerts.append({
                "rule": "Multi-service host scanning",
                "severity": "medium",
                "src_ip": ip,
                "evidence": f"touched {len(services_by_ip[ip])} services: "
                            f"{', '.join(sorted(filter(None, services_by_ip[ip])))}",
                "mitre": "T1046 Network Service Discovery",
                "ts": "",
            })
    return alerts


def _alert(rule, severity, ip, event, mitre):
    return {
        "rule": rule,
        "severity": severity,
        "src_ip": ip,
        "evidence": (event.get("payload") or "")[:120],
        "mitre": mitre,
        "ts": event.get("ts", ""),
    }


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def summarize(alerts: list[dict]) -> None:
    by_sev: dict[str, int] = defaultdict(int)
    by_rule: dict[str, int] = defaultdict(int)
    ips: set = set()
    for a in alerts:
        by_sev[a["severity"]] += 1
        by_rule[a["rule"]] += 1
        ips.add(a["src_ip"])

    print("\n" + "═" * 60)
    print("  DETECTION SUMMARY")
    print("═" * 60)
    print(f"  Alerts raised      : {len(alerts)}")
    print(f"  Distinct sources   : {len(ips)}")
    print("  By severity        : " + ", ".join(
        f"{s}={by_sev[s]}" for s in sorted(by_sev, key=lambda x: SEV_ORDER.get(x, 9))))
    print("\n  Top detections:")
    for rule, n in sorted(by_rule.items(), key=lambda kv: -kv[1])[:10]:
        print(f"     {n:4d}  {rule}")
    print("═" * 60 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Log-based detection engine")
    parser.add_argument("logfile", help="events.jsonl (honeypot) or auth.log")
    parser.add_argument("--format", choices=["honeypot", "authlog"],
                        default="honeypot")
    parser.add_argument("--json", help="write full alert list to this JSON file")
    parser.add_argument("--show", type=int, default=15,
                        help="number of individual alerts to print")
    args = parser.parse_args()

    try:
        loader = load_authlog if args.format == "authlog" else load_honeypot_jsonl
        events = loader(args.logfile)
    except FileNotFoundError:
        sys.exit(f"error: log file not found: {args.logfile}")

    alerts = detect(events)
    alerts.sort(key=lambda a: SEV_ORDER.get(a["severity"], 9))

    print(f"\n  parsed {len(events)} events from {args.logfile}")
    for a in alerts[:args.show]:
        print(f"  [{a['severity'].upper():8s}] {a['rule']}")
        print(f"             src={a['src_ip']}  {a['mitre']}")
        if a["evidence"]:
            print(f"             evidence: {a['evidence']}")
    if len(alerts) > args.show:
        print(f"  ... and {len(alerts) - args.show} more")

    summarize(alerts)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2)
        print(f"  full alert list written to {args.json}\n")


if __name__ == "__main__":
    main()
