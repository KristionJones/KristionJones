"""Persistence layer for the honeypot.

Events are written to two places:

* a SQLite database (``honeypot.db``) — queried by the dashboard
* a JSON-lines file (``events.jsonl``) — an append-only audit log that is easy
  to ship to a SIEM / Splunk / the included detection-engineering parser

The module is intentionally dependency-free (stdlib ``sqlite3`` + ``json``) so
the whole project runs with a clean Python install and nothing to ``pip``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,           -- unix epoch seconds
    iso_time    TEXT    NOT NULL,           -- human readable UTC
    service     TEXT    NOT NULL,           -- SSH / HTTP / Telnet / FTP ...
    src_ip      TEXT    NOT NULL,
    src_port    INTEGER NOT NULL,
    dst_port    INTEGER NOT NULL,
    username    TEXT,                       -- parsed credential (if any)
    password    TEXT,                       -- parsed credential (if any)
    byte_count  INTEGER NOT NULL DEFAULT 0,
    session_ms  INTEGER NOT NULL DEFAULT 0,
    ip_class    TEXT,                       -- public / private / loopback
    data_preview TEXT,                      -- decoded, truncated payload
    data_hex    TEXT                        -- full payload, hex encoded
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip  ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
"""


@dataclass
class AttackEvent:
    """A single observed interaction with the honeypot."""

    service: str
    src_ip: str
    src_port: int
    dst_port: int
    ts: float = field(default_factory=time.time)
    iso_time: str = ""
    username: str | None = None
    password: str | None = None
    byte_count: int = 0
    session_ms: int = 0
    ip_class: str | None = None
    data_preview: str = ""
    data_hex: str = ""

    def __post_init__(self) -> None:
        if not self.iso_time:
            self.iso_time = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ts)
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Storage:
    """Thread-safe writer/reader around SQLite + a JSONL audit log."""

    def __init__(self, db_path: str = "honeypot.db", jsonl_path: str = "events.jsonl"):
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self._lock = threading.Lock()
        # ``check_same_thread=False`` because asyncio handlers may run the write
        # from different threads; the lock below serialises access.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------ write
    def record(self, event: AttackEvent) -> int:
        row = event.to_dict()
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO events
                    (ts, iso_time, service, src_ip, src_port, dst_port,
                     username, password, byte_count, session_ms, ip_class,
                     data_preview, data_hex)
                VALUES
                    (:ts, :iso_time, :service, :src_ip, :src_port, :dst_port,
                     :username, :password, :byte_count, :session_ms, :ip_class,
                     :data_preview, :data_hex)
                """,
                row,
            )
            self._conn.commit()
            event_id = cur.lastrowid
            self._append_jsonl(row)
        return event_id

    def _append_jsonl(self, row: dict[str, Any]) -> None:
        with open(self.jsonl_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    # ------------------------------------------------------------------- read
    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            uniq_ip = self._conn.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM events"
            ).fetchone()[0]
            creds = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE username IS NOT NULL"
            ).fetchone()[0]
            services = self._conn.execute(
                "SELECT COUNT(DISTINCT service) FROM events"
            ).fetchone()[0]
            last = self._conn.execute(
                "SELECT iso_time FROM events ORDER BY ts DESC LIMIT 1"
            ).fetchone()
        return {
            "total_events": total,
            "unique_attackers": uniq_ip,
            "credential_attempts": creds,
            "services_targeted": services,
            "last_seen": last[0] if last else None,
        }

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def top(self, field_name: str, limit: int = 10) -> list[dict[str, Any]]:
        allowed = {"src_ip", "dst_port", "service", "username", "password"}
        if field_name not in allowed:
            raise ValueError(f"field must be one of {sorted(allowed)}")
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT {field_name} AS key, COUNT(*) AS count
                FROM events
                WHERE {field_name} IS NOT NULL
                GROUP BY {field_name}
                ORDER BY count DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def timeseries(self, bucket_seconds: int = 3600) -> list[dict[str, Any]]:
        """Attacks per time bucket, oldest first (for the timeline chart)."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, COUNT(*) AS count
                FROM events
                GROUP BY bucket
                ORDER BY bucket ASC
                """,
                (bucket_seconds, bucket_seconds),
            ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "bucket": time.strftime(
                        "%Y-%m-%d %H:%M", time.gmtime(r["bucket"])
                    ),
                    "count": r["count"],
                }
            )
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def default_storage() -> Storage:
    """Storage rooted next to the data directory regardless of CWD."""
    base = os.environ.get("HONEYPOT_DATA_DIR", os.getcwd())
    os.makedirs(base, exist_ok=True)
    return Storage(
        db_path=os.path.join(base, "honeypot.db"),
        jsonl_path=os.path.join(base, "events.jsonl"),
    )
