"""Indicator-of-Compromise (IOC) export.

Turns recorded honeypot activity into shareable indicators in three formats:

* ``csv``   - a flat table, easy to load into a spreadsheet or SIEM.
* ``json``  - a structured list of indicator objects with hit counts.
* ``stix``  - a minimal STIX 2.1 bundle of ``indicator`` SDOs, suitable for
  ingestion by threat-intel platforms.

All three are pure functions of the event store so they are trivial to unit
test and never depend on network access.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .storage import EventStore


def collect_indicators(store: EventStore) -> list[dict[str, Any]]:
    """Aggregate per-source-IP indicators from the event store."""
    indicators = []
    for row in store.top_attackers(limit=10_000):
        indicators.append(
            {
                "type": "ipv4-addr",
                "value": row["src_ip"],
                "hits": row["hits"],
                "last_seen": row["last_seen"],
                "country": row.get("country"),
            }
        )
    return indicators


def to_csv(store: EventStore) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "hits", "last_seen", "country"])
    for ind in collect_indicators(store):
        writer.writerow(
            [
                ind["type"],
                ind["value"],
                ind["hits"],
                ind["last_seen"],
                ind.get("country") or "",
            ]
        )
    return buf.getvalue()


def to_json(store: EventStore) -> str:
    return json.dumps(
        {
            "generated": datetime.now(timezone.utc).isoformat(),
            "count": store.unique_attackers(),
            "indicators": collect_indicators(store),
        },
        indent=2,
    )


def to_stix(store: EventStore) -> str:
    """Build a minimal STIX 2.1 bundle of indicator objects."""
    now = datetime.now(timezone.utc).isoformat()
    objects: list[dict[str, Any]] = []
    for ind in collect_indicators(store):
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"Honeypot source {ind['value']}",
                "description": (
                    f"Observed {ind['hits']} connection(s) to honeypot sensors."
                ),
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{ind['value']}']",
                "pattern_type": "stix",
                "valid_from": now,
            }
        )
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)


def export(store: EventStore, fmt: str = "csv") -> str:
    fmt = fmt.lower()
    if fmt == "csv":
        return to_csv(store)
    if fmt == "json":
        return to_json(store)
    if fmt == "stix":
        return to_stix(store)
    raise ValueError(f"unsupported IOC format: {fmt!r}")
