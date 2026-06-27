# 🛡️ Detection Engineering — Log Parsing & Sigma Rules

The **blue-team** half of the portfolio. This project turns raw security
telemetry into prioritized, ATT&CK-mapped alerts — the core job of a SOC analyst
/ detection engineer. It includes a working detection engine and a set of
[Sigma](https://github.com/SigmaHQ/sigma) rules (the vendor-neutral standard for
SIEM detections).

## What it does
`parser/detect.py` ingests structured logs, correlates events, and raises alerts:

| Detection | Severity | MITRE ATT&CK |
|-----------|----------|--------------|
| Credential brute-force / password spraying | High | T1110 |
| Default-credential spray (root:root, admin:admin…) | High | T1110.001 |
| Log4Shell (JNDI) exploitation | Critical | T1190 |
| Path traversal / LFI | High | T1083 |
| SQL injection | High | T1190 |
| Sensitive file / admin-panel probing (`.env`, `.git`, wp-login) | Medium | T1595 |
| Multi-service host scanning | Medium | T1046 |

It reads two sources out of the box:
- the honeypot's `events.jsonl` (ties the whole portfolio together)
- a standard Linux `auth.log`

## Usage
```bash
cd detection-engineering

# analyze the honeypot's captured telemetry
python parser/detect.py ../honeypot-dashboard/data/events.jsonl --format honeypot

# analyze a Linux auth log for SSH brute force
python parser/detect.py parser/sample_auth.log --format authlog

# export alerts as JSON (e.g. to forward to a ticketing system)
python parser/detect.py ../honeypot-dashboard/data/events.jsonl --json alerts.json
```

Example summary:
```
  DETECTION SUMMARY
  Alerts raised      : 100
  By severity        : critical=12, high=28, medium=60
  Top detections:
       60  Sensitive file / admin path probe
       17  SQL injection attempt
       12  Log4Shell exploitation attempt
```

## Sigma rules
Production-style detections in [`sigma/`](sigma), each with metadata, log source,
detection logic, false-positive notes, and ATT&CK tags:

- [`ssh_bruteforce.yml`](sigma/ssh_bruteforce.yml) — threshold detection for SSH credential attacks
- [`web_exploit_probes.yml`](sigma/web_exploit_probes.yml) — Log4Shell, traversal, SQLi, secret-file probing

Convert Sigma to your SIEM's query language (Splunk SPL, Elastic, Sentinel…) with
[`sigma-cli`](https://github.com/SigmaHQ/sigma-cli):
```bash
pip install sigma-cli
sigma convert -t splunk sigma/ssh_bruteforce.yml
```

## The detection-engineering workflow this demonstrates
1. **Collect** telemetry (honeypot / endpoint / auth logs)
2. **Write** a detection as a portable Sigma rule with an ATT&CK mapping
3. **Test** it against real attack data (here, the honeypot's events)
4. **Tune** for false positives (documented in each rule)
5. **Deploy** by converting to the target SIEM

Together with [`honeypot-dashboard/`](../honeypot-dashboard) (data collection)
and [`malware-analysis/`](../malware-analysis) (IOC generation), this completes a
small end-to-end blue-team pipeline.
