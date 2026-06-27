# 🍯 Honeypot + Threat Intelligence Dashboard

A **low-interaction honeypot** that emulates exposed services (SSH, HTTP, Telnet,
FTP), captures everything attackers send — source IPs, sprayed credentials,
exploit payloads — and a **live web dashboard** that turns that telemetry into
threat intelligence.

> **Zero third-party dependencies.** The sensor and dashboard run on a clean
> Python 3.10+ install (standard library only). PyYAML is optional, just for the
> config file.

![dashboard](docs/dashboard.png)

## Why this matters (the security concept)
Any host on the public internet is scanned and attacked within *minutes*. A
honeypot is a deliberately exposed decoy with no production value, so **every**
connection to it is suspicious by definition. That makes it one of the cleanest
sources of real-world attack telemetry: which credentials bots spray, which
CVEs are being mass-exploited today, and where attacks originate.

This sensor is **low-interaction by design** — it presents a believable banner,
records what it's sent, and closes the connection. It **never executes attacker
input and never offers a real shell**, which is what makes it safe to run.

## Features
- **Multi-service sensor** — async listener on SSH/HTTP/Telnet/FTP simultaneously (`asyncio`)
- **Credential capture** — parses HTTP Basic auth, FTP USER/PASS, and login prompts
- **Attack classification** — tags payloads (Log4Shell, path traversal, SQLi, WordPress/`.env`/`.git` probes, Shellshock…)
- **Dual storage** — SQLite (for the dashboard) + append-only JSON-lines audit log (for SIEM ingest)
- **Live dashboard** — KPI cards, attack timeline, service breakdown, top attacker IPs / usernames / passwords, and a streaming event feed
- **Offline IP enrichment** — classifies public/private/reserved without leaking IPs to third-party APIs
- **Attack simulator** — seeds realistic demo data for screenshots without exposing anything to the internet
- **Tested** — unit tests for credential parsing, classification, and storage

## Architecture
```
   Attacker / Internet scanners
              │  (connections, creds, payloads)
              ▼
   ┌─────────────────────┐      writes      ┌──────────────────┐
   │  honeypot/sensor.py  │ ───────────────▶ │  honeypot.db      │ (SQLite)
   │  asyncio multi-port  │                  │  events.jsonl     │ (audit log)
   └─────────────────────┘                  └────────┬─────────┘
        services.py  (banners, cred parsing)         │ reads
        enrich.py    (IP classification)             ▼
                                          ┌──────────────────────┐
                                          │ dashboard/server.py   │
                                          │ stdlib HTTP + JSON API │──▶ browser UI
                                          └──────────────────────┘
```

## Quick start
```bash
cd honeypot-dashboard

# 1) (optional) seed demo data so the dashboard isn't empty
python -m tools.simulate_attacks --count 600 --days 3 --data-dir ./data

# 2) launch the dashboard
python -m dashboard.server --port 8000 --data-dir ./data
#    open http://localhost:8000

# 3) run the live sensor (in another terminal) to capture real connections
python -m honeypot.sensor --config config.yaml --data-dir ./data
```

Test the live sensor locally:
```bash
curl -u admin:secret http://localhost:8080/.env     # HTTP basic-auth + probe
printf 'root\ntoor\n' | nc localhost 2222            # fake SSH credential spray
```
…then watch the events appear in the dashboard feed.

## Capturing real attacks (exposing it safely)
Default ports are high (2222/8080/2323/2121) so no root is needed. To catch real
internet scans on the standard ports, redirect them:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```
**Run it on an isolated VM / cloud instance you control** — never on a machine
with production data, and check your hosting provider's acceptable-use policy.

## Run the tests
```bash
python tests/test_honeypot.py        # no dependencies
# or, if you have pytest:  python -m pytest -q
```

## Project layout
```
honeypot/      sensor.py · services.py · storage.py · enrich.py
dashboard/     server.py + static/ (index.html, app.js)
tools/         simulate_attacks.py   (demo data generator)
tests/         test_honeypot.py
config.yaml    service definitions
```

## Ethics & safety
For defensive security research and education. Only deploy on infrastructure you
own or are authorized to test. The sensor intentionally cannot be used to attack
anyone — it only listens and records.
