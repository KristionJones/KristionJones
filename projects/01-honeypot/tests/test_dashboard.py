import json

import pytest

from honeypot.dashboard import create_app


@pytest.fixture
def client(seeded_store):
    app = create_app(seeded_store)
    app.config.update(TESTING=True)
    return app.test_client()


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_index_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"SENTINEL HONEYPOT" in resp.data


def test_api_stats(client):
    data = client.get("/api/stats").get_json()
    assert data["total_events"] == 4
    assert data["unique_attackers"] == 3


def test_api_events_limit(client):
    data = client.get("/api/events?limit=2").get_json()
    assert len(data) == 2
    assert data[0]["id"] > data[1]["id"]


def test_api_attackers(client):
    data = client.get("/api/attackers").get_json()
    assert data[0]["src_ip"] == "203.0.113.5"


def test_api_timeline(client):
    data = client.get("/api/timeline?bucket=hour").get_json()
    assert any(row["bucket"] == "2026-06-27T10" for row in data)


def test_api_iocs_csv_download(client):
    resp = client.get("/api/iocs?format=csv")
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert b"203.0.113.5" in resp.data


def test_api_iocs_stix(client):
    resp = client.get("/api/iocs?format=stix")
    bundle = json.loads(resp.data)
    assert bundle["type"] == "bundle"


def test_api_iocs_bad_format(client):
    assert client.get("/api/iocs?format=nope").status_code == 400
