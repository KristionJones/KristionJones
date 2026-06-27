# 🎣 Phishing Email Analyzer

A dependency-free tool that analyzes a raw `.eml` email and scores how likely it
is to be phishing — automating the exact triage an entry-level **SOC analyst**
performs on every user-reported suspicious email.

> **Safe by design:** it only *reads* the email as text. It never opens
> attachments, follows links, or renders HTML.

## What it checks
| Category | Checks |
|----------|--------|
| **Sender spoofing** | From vs Return-Path vs Reply-To mismatch; display-name brand impersonation; fake address in the display name |
| **Email authentication** | SPF / DKIM / DMARC results parsed from `Authentication-Results` |
| **Origin** | Sending IP and `Received` hop chain |
| **URLs** | Anchor-text-vs-real-link mismatch, raw-IP links, URL shorteners, punycode/IDN homoglyphs, risky TLDs, look-alike brand domains (e.g. `micros0ft`) |
| **Attachments** | Dangerous extensions (`.exe`, `.scr`, `.js`…), double extensions (`invoice.pdf.exe`), macro-enabled Office docs, archives; SHA-256 of each |
| **Language** | Urgency / credential-harvesting phrases |

Each finding adds weighted points → a **risk score** and a **verdict**
(BENIGN → LOW RISK → SUSPICIOUS → MALICIOUS), plus a clean list of **IOCs** to
block or hunt.

## Usage
```bash
cd phishing-analyzer

# analyze the included phishing sample
python phishing_analyzer.py samples/phishing_sample.eml

# a known-good email scores 0
python phishing_analyzer.py samples/legitimate_sample.eml

# export a full report (e.g. to attach to a ticket)
python phishing_analyzer.py samples/phishing_sample.eml --json report.json
```

How to get a real `.eml`: in most mail clients choose **"Show original"** /
**"View source"** / **"Save as .eml"** on a suspicious message.

## Example output (abridged)
```
  RISK SCORE: 213   →   MALICIOUS — high-confidence phishing

  FINDINGS:
     [HIGH   +25] Double-extension attachment: Account_Statement.pdf.exe
     [HIGH   +22] DMARC fail — message fails domain alignment policy
     [HIGH   +22] Link text 'https://login.microsoftonline.com' actually points to 185.220.101.42
     [HIGH   +20] Display name mentions 'microsoft' but sender domain is account-secure-mail.top
     [HIGH   +18] URL uses a raw IP address: 185.220.101.42
  IOCs (block/hunt these):
     origin_ip : 185.220.101.42
     url_hosts : ['micros0ft-account.top', '185.220.101.42', ...]
```

## Run the tests
```bash
python tests/test_phishing.py      # no dependencies
```

## The concepts this demonstrates
- **SPF / DKIM / DMARC** — the three email-authentication mechanisms and what a
  `fail` on each actually means.
- **Display-name vs envelope spoofing** — why "Microsoft Account Team" in the
  From line means nothing without checking the real domain.
- **Homoglyph / look-alike domains** (`micros0ft.com`, punycode `xn--`).
- **IOC extraction & triage scoring** — turning one email into actionable,
  blockable indicators.

Pairs with [`detection-engineering/`](../detection-engineering) (write detections
for the IOCs found here) and [`malware-analysis/`](../malware-analysis) (analyze
the attachment a phish drops).
