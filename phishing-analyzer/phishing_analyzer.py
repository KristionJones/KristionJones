#!/usr/bin/env python3
"""Phishing email analyzer (dependency-free).

Parses a raw ``.eml`` email and performs the triage a SOC analyst does on a
reported phish, producing a risk score, a verdict, and ready-to-block IOCs:

  * Header / sender spoofing checks   (From vs Return-Path vs Reply-To, display-name spoof)
  * Email authentication              (SPF / DKIM / DMARC from Authentication-Results)
  * Originating IP / Received hops
  * URL analysis                      (anchor-vs-href mismatch, IP URLs, shorteners,
                                       punycode/IDN homoglyphs, risky TLDs, look-alike brands)
  * Attachment analysis               (dangerous extensions, double extensions, macro docs, hashes)
  * Social-engineering language       (urgency / credential-harvest cues)

Usage:
    python phishing_analyzer.py samples/phishing_sample.eml
    python phishing_analyzer.py message.eml --json report.json

SAFETY: this only *reads* the email as text. It never opens attachments, never
follows links, and never renders HTML. Analyze suspicious mail this way instead
of clicking anything.
"""

from __future__ import annotations

import argparse
import email
import hashlib
import re
import sys
from email import policy
from email.utils import parseaddr, getaddresses


# --------------------------------------------------------------------------- #
# Indicators / reference data
# --------------------------------------------------------------------------- #
DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".jar", ".msi", ".reg", ".lnk",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".gz"}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}
RISKY_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".tk", ".gq", ".ml", ".cf", ".ga",
    ".click", ".country", ".kim", ".work", ".link", ".loan", ".review",
}
BRANDS = ["microsoft", "office365", "outlook", "paypal", "apple", "amazon",
          "netflix", "google", "facebook", "instagram", "docusign", "dhl",
          "fedex", "ups", "chase", "wellsfargo", "bankofamerica", "irs", "usps"]

URGENCY_PHRASES = [
    "verify your account", "verify your identity", "suspended", "unusual activity",
    "click here", "confirm your password", "update your payment", "act now",
    "within 24 hours", "your account will be", "final notice", "reactivate",
    "you have won", "gift card", "wire transfer", "invoice attached", "urgent",
    "immediately", "validate your account", "unlock your account", "re-confirm",
]

URL_RE = re.compile(r"https?://[^\s\"'<>()\]]+", re.I)
HREF_RE = re.compile(r"<a\s[^>]*href\s*=\s*[\"']?(https?://[^\"'>\s]+)[\"']?[^>]*>(.*?)</a>",
                     re.I | re.S)


# --------------------------------------------------------------------------- #
# Scoring helper
# --------------------------------------------------------------------------- #
class Findings:
    def __init__(self):
        self.score = 0
        self.flags: list[dict] = []

    def add(self, severity: str, points: int, message: str):
        self.score += points
        self.flags.append({"severity": severity, "points": points,
                           "message": message})


def domain_of(addr: str) -> str:
    addr = parseaddr(addr)[1]
    return addr.split("@")[-1].lower().strip(">") if "@" in addr else ""


def registered_domain(host: str) -> str:
    """Crude eTLD+1 (good enough for triage without the publicsuffix list)."""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


# --------------------------------------------------------------------------- #
# Analysis stages
# --------------------------------------------------------------------------- #
def analyze_headers(msg, f: Findings) -> dict:
    from_hdr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    display_name, from_addr = parseaddr(from_hdr)
    from_dom = domain_of(from_addr)
    rp_dom = domain_of(return_path)
    reply_dom = domain_of(reply_to)

    # From vs Return-Path (envelope) mismatch — classic spoof signal
    if rp_dom and from_dom and rp_dom != from_dom:
        f.add("high", 25, f"Return-Path domain ({rp_dom}) != From domain ({from_dom})")
    # Reply-To redirect to a different domain
    if reply_dom and from_dom and reply_dom != from_dom:
        f.add("medium", 15, f"Reply-To domain ({reply_dom}) != From domain ({from_dom})")
    # Display-name impersonates a brand/email but the real address is elsewhere
    dn = display_name.lower()
    for brand in BRANDS:
        if brand in dn and brand not in from_dom:
            f.add("high", 20,
                  f"Display name mentions '{brand}' but sender domain is {from_dom}")
            break
    # Display name itself looks like an email that differs from the real one
    m = re.search(r"[\w.+-]+@[\w.-]+", display_name)
    if m and from_addr and m.group(0).lower() != from_addr.lower():
        f.add("medium", 12,
              f"Display name shows '{m.group(0)}' but real sender is {from_addr}")

    return {
        "from": from_hdr, "from_address": from_addr, "from_domain": from_dom,
        "display_name": display_name, "reply_to": reply_to,
        "return_path": return_path, "subject": str(msg.get("Subject", "")),
        "to": str(msg.get("To", "")), "date": str(msg.get("Date", "")),
    }


def analyze_auth(msg, f: Findings) -> dict:
    raw = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    raw += " " + " ".join(str(v) for v in msg.get_all("Received-SPF", []))
    low = raw.lower()
    results = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", low)
        results[mech] = m.group(1) if m else "none"

    if results["spf"] in ("fail", "softfail"):
        f.add("high", 20, f"SPF {results['spf']} — sender not authorized for the domain")
    if results["dkim"] == "fail":
        f.add("high", 18, "DKIM signature failed — message may be altered/forged")
    if results["dmarc"] == "fail":
        f.add("high", 22, "DMARC fail — message fails domain alignment policy")
    if all(v == "none" for v in results.values()):
        f.add("low", 6, "No email authentication results present (SPF/DKIM/DMARC)")
    return results


def get_origin_ip(msg, f: Findings) -> str | None:
    received = msg.get_all("Received", []) or []
    ips: list[str] = []
    for hop in received:
        ips += re.findall(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?", str(hop))
    public = [ip for ip in ips if not ip.startswith(("10.", "192.168.", "127."))]
    return public[-1] if public else (ips[-1] if ips else None)


def extract_bodies(msg) -> tuple[str, str]:
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart" or part.get_filename():
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain":
                text += _safe_content(part)
            elif ctype == "text/html":
                html += _safe_content(part)
    else:
        body = _safe_content(msg)
        if msg.get_content_type() == "text/html":
            html = body
        else:
            text = body
    return text, html


def _safe_content(part) -> str:
    try:
        return part.get_content()
    except Exception:  # noqa: BLE001
        payload = part.get_payload(decode=True)
        if payload:
            return payload.decode("utf-8", "replace")
        return str(part.get_payload())


def analyze_urls(text: str, html: str, from_dom: str, f: Findings) -> list[dict]:
    urls = set(URL_RE.findall(text)) | set(URL_RE.findall(html))
    analyzed = []

    # Anchor text vs real href mismatch (text says paypal.com, link goes elsewhere)
    for href, anchor in HREF_RE.findall(html):
        anchor_text = re.sub(r"<[^>]+>", "", anchor).strip().lower()
        href_host_full = re.sub(r"https?://", "", href).split("/")[0].split(":")[0]
        href_host = registered_domain(href_host_full)
        anchor_host = anchor_text
        if "://" in anchor_text:
            anchor_host = re.sub(r"https?://", "", anchor_text).split("/")[0]
        if "." in anchor_host and href_host and registered_domain(anchor_host) not in href_host:
            f.add("high", 22,
                  f"Link text '{anchor_text}' actually points to {href_host_full}")
        urls.add(href)

    for url in urls:
        host = re.sub(r"https?://", "", url).split("/")[0].split(":")[0].lower()
        reg = registered_domain(host)
        reasons = []
        if re.match(r"\d{1,3}(\.\d{1,3}){3}", host):
            reasons.append("IP-address URL")
            f.add("high", 18, f"URL uses a raw IP address: {host}")
        if reg in URL_SHORTENERS:
            reasons.append("URL shortener (hides destination)")
            f.add("medium", 12, f"Shortened URL: {host}")
        if "xn--" in host:
            reasons.append("punycode/IDN (possible homoglyph)")
            f.add("high", 18, f"Punycode domain (homoglyph attack?): {host}")
        for tld in RISKY_TLDS:
            if host.endswith(tld):
                reasons.append(f"risky TLD {tld}")
                f.add("medium", 10, f"Risky TLD on {host}")
                break
        for brand in BRANDS:
            if brand in host and brand not in reg and (not from_dom or brand not in from_dom):
                reasons.append(f"look-alike of '{brand}'")
                f.add("high", 20, f"Look-alike brand domain: {host} mimics {brand}")
                break
        analyzed.append({"url": url, "host": host, "issues": reasons})
    return analyzed


def analyze_attachments(msg, f: Findings) -> list[dict]:
    out = []
    for part in (msg.walk() if msg.is_multipart() else []):
        fname = part.get_filename()
        if not fname:
            continue
        lower = fname.lower()
        payload = part.get_payload(decode=True) or b""
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        issues = []
        # double extension: invoice.pdf.exe
        if re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.\w{2,4}$", lower):
            issues.append("double extension")
            f.add("high", 25, f"Double-extension attachment: {fname}")
        if ext in DANGEROUS_EXT:
            issues.append("executable/script")
            f.add("high", 25, f"Dangerous attachment type ({ext}): {fname}")
        if ext in MACRO_EXT:
            issues.append("macro-enabled document")
            f.add("high", 20, f"Macro-enabled document: {fname}")
        if ext in ARCHIVE_EXT:
            issues.append("archive (may hide payload)")
            f.add("medium", 10, f"Archive attachment: {fname}")
        out.append({
            "filename": fname,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
            "issues": issues,
        })
    return out


def analyze_language(text: str, html: str, subject: str, f: Findings) -> list[str]:
    blob = (subject + " " + text + " " + re.sub(r"<[^>]+>", " ", html)).lower()
    hits = [p for p in URGENCY_PHRASES if p in blob]
    if hits:
        pts = min(18, 3 * len(hits))
        f.add("medium", pts, f"Social-engineering language: {', '.join(hits[:6])}")
    return hits


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def verdict_for(score: int) -> str:
    if score >= 60:
        return "MALICIOUS — high-confidence phishing"
    if score >= 30:
        return "SUSPICIOUS — likely phishing, review"
    if score >= 12:
        return "LOW RISK — some indicators, probably benign"
    return "BENIGN — no significant indicators"


def analyze(path: str) -> dict:
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)
    f = Findings()
    headers = analyze_headers(msg, f)
    auth = analyze_auth(msg, f)
    origin_ip = get_origin_ip(msg, f)
    text, html = extract_bodies(msg)
    urls = analyze_urls(text, html, headers["from_domain"], f)
    attachments = analyze_attachments(msg, f)
    language = analyze_language(text, html, headers["subject"], f)

    iocs = {
        "sender_domain": headers["from_domain"],
        "from_address": headers["from_address"],
        "origin_ip": origin_ip,
        "urls": sorted({u["url"] for u in urls}),
        "url_hosts": sorted({u["host"] for u in urls}),
        "attachment_hashes": [a["sha256"] for a in attachments if a["sha256"]],
    }
    return {
        "file": path,
        "headers": headers,
        "authentication": auth,
        "origin_ip": origin_ip,
        "urls": urls,
        "attachments": attachments,
        "language_indicators": language,
        "findings": f.flags,
        "risk_score": f.score,
        "verdict": verdict_for(f.score),
        "iocs": iocs,
    }


def print_report(r: dict) -> None:
    line = "─" * 66
    print(f"\n{line}\n  PHISHING EMAIL ANALYSIS\n{line}")
    h = r["headers"]
    print(f"  File     : {r['file']}")
    print(f"  Subject  : {h['subject']}")
    print(f"  From     : {h['from']}")
    print(f"  Reply-To : {h['reply_to'] or '(none)'}")
    print(f"  Origin IP: {r['origin_ip'] or '(not found)'}")
    a = r["authentication"]
    print(f"  Auth     : SPF={a['spf']}  DKIM={a['dkim']}  DMARC={a['dmarc']}")

    print(f"\n  RISK SCORE: {r['risk_score']}   →   {r['verdict']}")

    if r["findings"]:
        print("\n  FINDINGS:")
        for fl in sorted(r["findings"], key=lambda x: -x["points"]):
            print(f"     [{fl['severity'].upper():6s} +{fl['points']:>2}] {fl['message']}")
    else:
        print("\n  FINDINGS: none")

    if r["urls"]:
        print("\n  URLs:")
        for u in r["urls"]:
            tag = f"  ⚠ {', '.join(u['issues'])}" if u["issues"] else ""
            print(f"     {u['url'][:70]}{tag}")
    if r["attachments"]:
        print("\n  ATTACHMENTS:")
        for at in r["attachments"]:
            tag = f"  ⚠ {', '.join(at['issues'])}" if at["issues"] else ""
            print(f"     {at['filename']} ({at['size_bytes']} bytes){tag}")
            if at["sha256"]:
                print(f"        sha256: {at['sha256']}")

    print("\n  IOCs (block/hunt these):")
    for k, v in r["iocs"].items():
        if v:
            print(f"     {k:18s}: {v}")
    print(line + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phishing email (.eml) analyzer")
    parser.add_argument("eml", help="path to the .eml file to analyze")
    parser.add_argument("--json", help="write the full report to this JSON file")
    args = parser.parse_args()
    try:
        report = analyze(args.eml)
    except FileNotFoundError:
        sys.exit(f"error: file not found: {args.eml}")
    print_report(report)
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"  full JSON report written to {args.json}\n")


if __name__ == "__main__":
    main()
