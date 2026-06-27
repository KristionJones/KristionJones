import socket
import time

from honeypot.config import HoneypotConfig
from honeypot.sensor import Honeypot
from honeypot.storage import EventStore


def _wait_for(predicate, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_sensor_records_connection():
    # Bind ephemeral port 0 so the test never collides with a real service.
    store = EventStore(":memory:")
    config = HoneypotConfig(host="127.0.0.1", ports=[0], db_path=":memory:")
    # Give port 0 a known service banner so we can assert on it.
    config.services[0] = {"name": "test", "banner": "HELLO\r\n"}
    sensor = Honeypot(config, store=store, read_timeout=0.3)
    bound = sensor.start()
    try:
        port = bound[0]
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            banner = sock.recv(64)
            assert banner == b"HELLO\r\n"
            sock.sendall(b"malicious-payload")
        assert _wait_for(lambda: store.total_events() == 1)
        event = store.recent(1)[0]
        assert event.dst_port == port
        assert event.service == "test"
        assert "malicious-payload" in event.payload
        assert event.country == "Local"  # 127.0.0.1 classified offline
    finally:
        sensor.stop()
        store.close()
