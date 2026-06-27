# Resume & LinkedIn copy

Copy-paste these. Replace bracketed bits with your specifics. Recruiters and ATS
scanners look for the **bolded keywords** — keep them.

---

## Resume — "Projects" section

### Honeypot & Threat Intelligence Dashboard — *Python, asyncio, SQLite*
- Built a **low-interaction honeypot** that emulates SSH, HTTP, Telnet, and FTP
  services and captures attacker source IPs, brute-forced **credentials**, and
  exploit payloads, persisting them to SQLite and an append-only **JSON-lines**
  audit log for SIEM ingestion.
- Developed a real-time **threat-intelligence dashboard** (zero third-party
  dependencies) visualizing attack timelines, top attacker IPs, credential-spray
  trends, and a live event feed.
- Implemented automatic **attack classification** for Log4Shell, path traversal,
  SQL injection, and reconnaissance probes; wrote unit tests for credential
  parsing and storage.

### Static Malware Analysis Toolkit — *Python, PE parsing, YARA*
- Created a static analysis tool that automates first-pass triage: cryptographic
  hashing (MD5/SHA-256), **entropy** analysis to flag packed binaries, **PE
  header** parsing, string and **IOC extraction**, and suspicious-API capability
  detection.
- Authored a **YARA** ruleset and analyst report templates mapped to the
  **MITRE ATT&CK** framework; documented a safe REMnux/FLARE VM analysis lab.

### Phishing Email Analyzer — *Python, Email Security, SPF/DKIM/DMARC*
- Built a tool that parses raw `.eml` emails and produces a weighted **phishing
  risk score** by validating **SPF/DKIM/DMARC**, detecting sender spoofing and
  **look-alike/homoglyph domains**, and flagging malicious links and dangerous
  attachments (executables, double extensions, macro documents).
- Automatically extracts **indicators of compromise** (sender domain, origin IP,
  URLs, attachment hashes) for blocking and threat hunting — replicating SOC
  phishing-triage workflow. Validated against benign and malicious test samples.

### Detection Engineering — Log Parsing & Sigma Rules — *Python, Sigma, MITRE ATT&CK*
- Built a log-based **detection engine** that correlates honeypot and Linux
  `auth.log` events into prioritized, **ATT&CK-mapped** alerts (brute force,
  Log4Shell, SQLi, default-credential spray, host scanning).
- Wrote portable **Sigma** detection rules with documented false-positive tuning,
  convertible to Splunk/Elastic/Sentinel queries.

---

## LinkedIn — "About" / Featured blurb
> I build hands-on **cybersecurity** projects across the blue-team stack: a
> **honeypot** with a live threat-intelligence dashboard, a **static malware
> analysis** toolkit, and **detection-engineering** Sigma rules mapped to MITRE
> ATT&CK. Comfortable with Python, network protocols, SIEM concepts, and the
> attacker techniques these tools are built to catch.

## LinkedIn — Project entries
**Honeypot & Threat Intelligence Dashboard** — Python honeypot capturing live
attacker credentials and exploit payloads, with a real-time dashboard. *Skills:
Python · Network Security · Threat Intelligence · SQLite · asyncio*

**Static Malware Analysis Toolkit** — Automated static triage (hashing, entropy,
PE parsing, IOC + YARA). *Skills: Malware Analysis · Reverse Engineering
(static) · YARA · MITRE ATT&CK*

**Detection Engineering with Sigma** — Log correlation engine + Sigma rules for
SOC detections. *Skills: SIEM · Detection Engineering · Sigma · Incident
Response*

**Phishing Email Analyzer** — `.eml` triage tool scoring phishing risk via
SPF/DKIM/DMARC and link/attachment analysis. *Skills: Email Security · Phishing
Analysis · SPF/DKIM/DMARC · IOC analysis*

---

## Skills keywords to list
`Python` · `Threat Intelligence` · `Honeypots` · `Malware Analysis` ·
`YARA` · `Sigma` · `MITRE ATT&CK` · `SIEM` · `Incident Response` ·
`Network Security` · `Log Analysis` · `Indicators of Compromise (IOC)` ·
`Linux` · `SQL` · `Git`

## Interview talking points (be ready to explain)
- **Why every connection to a honeypot is malicious by definition**, and how that
  makes it clean threat-intel data.
- **Low- vs high-interaction honeypots** and why low-interaction is safe (it never
  executes attacker input or gives a shell).
- **What file entropy tells you** about packing/encryption in malware.
- **What a Sigma rule is** and why detections are written vendor-neutral.
- **The MITRE ATT&CK framework** and how you mapped your detections to it.

## Suggested certifications to pair with this (entry → mid)
CompTIA **Security+** → **CySA+** (analyst) → **Blue Team Level 1 (BTL1)** or
TryHackMe **SOC Level 1** path. These line up directly with what these projects
demonstrate.
