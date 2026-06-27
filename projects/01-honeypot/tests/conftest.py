import os
import sys

# Make the package importable when tests run from the project directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from honeypot.storage import Event, EventStore


@pytest.fixture
def store():
    s = EventStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def seeded_store(store):
    events = [
        Event("2026-06-27T10:00:00+00:00", "203.0.113.5", 5000, 22, "ssh", 12, "root\n", "a1", "Narnia", "NA"),
        Event("2026-06-27T10:05:00+00:00", "203.0.113.5", 5001, 23, "telnet", 8, "admin", "a2", "Narnia", "NA"),
        Event("2026-06-27T11:00:00+00:00", "198.51.100.9", 6000, 22, "ssh", 0, "", "b1", "Genovia", "GE"),
        Event("2026-06-27T11:30:00+00:00", "192.168.1.10", 7000, 80, "http", 20, "GET / HTTP/1.1", "c1", "Local", "LAN"),
    ]
    for e in events:
        store.record(e)
    return store
