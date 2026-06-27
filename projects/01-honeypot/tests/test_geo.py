from honeypot.geo import GeoResolver


def test_private_ip_is_local():
    g = GeoResolver()
    res = g.lookup("192.168.1.50")
    assert res["is_private"] is True
    assert res["country"] == "Local"


def test_loopback_is_local():
    assert GeoResolver().lookup("127.0.0.1")["country"] == "Local"


def test_public_ip_unknown_without_db():
    res = GeoResolver().lookup("8.8.8.8")
    assert res["country"] == "Unknown"
    assert res["is_private"] is False


def test_invalid_ip():
    assert GeoResolver().lookup("not-an-ip")["country"] == "Invalid"


def test_missing_geoip_db_degrades_gracefully():
    # A bogus path should not raise; resolver simply has no reader.
    g = GeoResolver("/does/not/exist.mmdb")
    assert g.lookup("8.8.8.8")["country"] == "Unknown"
