import json

import pytest

from honeypot import iocs


def test_csv_export_has_header_and_rows(seeded_store):
    out = iocs.to_csv(seeded_store)
    lines = out.strip().splitlines()
    assert lines[0] == "type,value,hits,last_seen,country"
    assert any("203.0.113.5" in line for line in lines)
    assert len(lines) == 1 + 3  # header + 3 unique IPs


def test_json_export_is_valid(seeded_store):
    data = json.loads(iocs.to_json(seeded_store))
    assert data["count"] == 3
    values = {i["value"] for i in data["indicators"]}
    assert "198.51.100.9" in values


def test_stix_bundle_structure(seeded_store):
    bundle = json.loads(iocs.to_stix(seeded_store))
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert len(bundle["objects"]) == 3
    ind = bundle["objects"][0]
    assert ind["type"] == "indicator"
    assert ind["pattern_type"] == "stix"
    assert ind["pattern"].startswith("[ipv4-addr:value = '")


def test_export_dispatch_and_bad_format(seeded_store):
    assert iocs.export(seeded_store, "csv").startswith("type,value")
    with pytest.raises(ValueError):
        iocs.export(seeded_store, "yaml")
