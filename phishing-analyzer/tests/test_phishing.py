"""Tests for the phishing analyzer.
   Run: python tests/test_phishing.py   (or: python -m pytest -q)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishing_analyzer import analyze, registered_domain, domain_of

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "samples")


def test_phishing_sample_flagged_malicious():
    r = analyze(os.path.join(SAMPLES, "phishing_sample.eml"))
    assert r["risk_score"] >= 60
    assert "MALICIOUS" in r["verdict"]
    # auth all fail
    assert r["authentication"]["spf"] == "fail"
    assert r["authentication"]["dmarc"] == "fail"
    # caught the dangerous attachment + origin IP IOC
    messages = " ".join(f["message"] for f in r["findings"])
    assert "Double-extension" in messages or "Dangerous attachment" in messages
    assert r["iocs"]["origin_ip"] == "185.220.101.42"


def test_legitimate_sample_benign():
    r = analyze(os.path.join(SAMPLES, "legitimate_sample.eml"))
    assert r["risk_score"] < 12
    assert "BENIGN" in r["verdict"]
    assert r["authentication"]["dkim"] == "pass"


def test_display_name_brand_spoof_detected():
    r = analyze(os.path.join(SAMPLES, "phishing_sample.eml"))
    messages = " ".join(f["message"] for f in r["findings"])
    assert "microsoft" in messages.lower()


def test_helpers():
    assert registered_domain("login.microsoftonline.com") == "microsoftonline.com"
    assert domain_of('"X" <a@b.co>') == "b.co"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS {name}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"  FAIL {name}: {exc}")
    sys.exit(1 if failures else 0)
