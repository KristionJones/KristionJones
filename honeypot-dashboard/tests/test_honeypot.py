"""Unit tests for the honeypot core. Run with: python -m pytest -q
   (also runnable with no pytest installed: python tests/test_honeypot.py)
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeypot.enrich import classify_ip
from honeypot.services import classify_request, parse_credentials
from honeypot.storage import AttackEvent, Storage


def _storage():
    tmp = tempfile.mkdtemp()
    return Storage(os.path.join(tmp, "t.db"), os.path.join(tmp, "t.jsonl"))


def test_http_basic_auth_parsing():
    # admin:secret -> base64 YWRtaW46c2VjcmV0
    data = b"GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n"
    user, pwd = parse_credentials("HTTP", data)
    assert user == "admin" and pwd == "secret"


def test_ftp_credential_parsing():
    data = b"USER bob\r\nPASS hunter2\r\n"
    user, pwd = parse_credentials("FTP", data)
    assert user == "bob" and pwd == "hunter2"


def test_classify_request_signatures():
    assert classify_request("HTTP", b"GET /?x=${jndi:ldap://x/a}") == "log4shell"
    assert classify_request("HTTP", b"GET /../../etc/passwd") == "path_traversal"
    assert classify_request("SSH", b"root\r\ntoor\r\n") == "credential_attack"


def test_ip_classification():
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("10.0.0.5") == "private"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("not-an-ip") == "unknown"


def test_storage_roundtrip_and_aggregates():
    st = _storage()
    for i in range(5):
        st.record(AttackEvent(service="SSH", src_ip="1.2.3.4",
                              src_port=5000 + i, dst_port=22,
                              username="root", password="123456"))
    st.record(AttackEvent(service="HTTP", src_ip="9.9.9.9",
                          src_port=4000, dst_port=80))
    stats = st.stats()
    assert stats["total_events"] == 6
    assert stats["unique_attackers"] == 2
    assert stats["credential_attempts"] == 5
    top_ip = st.top("src_ip", 5)
    assert top_ip[0]["key"] == "1.2.3.4" and top_ip[0]["count"] == 5
    assert len(st.recent(3)) == 3
    st.close()


def test_top_rejects_unknown_field():
    st = _storage()
    try:
        st.top("evil; DROP TABLE events", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad field")
    st.close()


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
