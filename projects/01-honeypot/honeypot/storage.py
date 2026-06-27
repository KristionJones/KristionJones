"""SQLite-backed event store for honeypot connections.

The store is intentionally small and dependency-free. It is safe to share a
single :class:`EventStore` across the sensor's listener threads and the Flask
dashboard because every write is guarded by a lock and the connection is opened
with ``check_same_thread=False``.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Iterable


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    """A single honeypot interaction."""

    timestamp: str
    src_ip: str
    src_port: int
    dst_port: int
    service: str
    bytes_received: int
    payload: str
    session_id: str
    country: str | None = None
    country_code: str | None = None
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    src_ip          TEXT    NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_port        INTEGER NOT NULL,
    service         TEXT    NOT NULL,
    bytes_received  INTEGER NOT NULL DEFAULT 0,
    payload         TEXT    NOT NULL DEFAULT '',
    session_id      TEXT    NOT NULL,
    country         TEXT,
    country_code    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_port ON events(dst_port);
"""


class EventStore:
    """Thread-safe persistence and aggregation for honeypot events."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # -- writes ---------------------------------------------------------------

    def record(self, event: Event) -> int:
        """Persist an event and return its row id."""
        if not event.timestamp:
            event.timestamp = _utcnow_iso()
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO events
                    (timestamp, src_ip, src_port, dst_port, service,
                     bytes_received, payload, session_id, country, country_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp,
                    event.src_ip,
                    event.src_port,
                    event.dst_port,
                    event.service,
                    event.bytes_received,
                    event.payload,
                    event.session_id,
                    event.country,
                    event.country_code,
                ),
            )
            self._conn.commit()
            event.id = int(cur.lastrowid)
            return event.id

    # -- reads ----------------------------------------------------------------

    def _rows_to_events(self, rows: Iterable[sqlite3.Row]) -> list[Event]:
        return [Event(**dict(row)) for row in rows]

    def recent(self, limit: int = 100) -> list[Event]:
        """Return the most recent events, newest first."""
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return self._rows_to_events(rows)

    def total_events(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def unique_attackers(self) -> int:
        with self._lock:
            return int(
                self._conn.execute(
                    "SELECT COUNT(DISTINCT src_ip) FROM events"
                ).fetchone()[0]
            )

    def top_attackers(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the busiest source IPs with hit counts and last-seen time."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT src_ip,
                       COUNT(*)            AS hits,
                       MAX(timestamp)      AS last_seen,
                       MAX(country)        AS country,
                       MAX(country_code)   AS country_code
                FROM events
                GROUP BY src_ip
                ORDER BY hits DESC, last_seen DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    def hits_by_port(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT dst_port, service, COUNT(*) AS hits
                FROM events GROUP BY dst_port, service ORDER BY hits DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def hits_by_country(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT COALESCE(country, 'Unknown') AS country,
                       COUNT(*) AS hits
                FROM events GROUP BY country ORDER BY hits DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def timeline(self, bucket: str = "hour") -> list[dict[str, Any]]:
        """Return event counts grouped into time buckets.

        ``bucket`` is one of ``"minute"``, ``"hour"`` or ``"day"`` and controls
        how much of the ISO-8601 timestamp is used as the grouping key.
        """
        width = {"minute": 16, "hour": 13, "day": 10}.get(bucket, 13)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT substr(timestamp, 1, ?) AS bucket, COUNT(*) AS hits
                FROM events GROUP BY bucket ORDER BY bucket ASC
                """,
                (width,),
            ).fetchall()
        return [dict(r) for r in rows]

    def distinct_source_ips(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT src_ip FROM events ORDER BY src_ip"
            ).fetchall()
        return [r[0] for r in rows]

    def stats(self) -> dict[str, Any]:
        """Aggregate everything the dashboard needs in one call."""
        return {
            "total_events": self.total_events(),
            "unique_attackers": self.unique_attackers(),
            "top_attackers": self.top_attackers(),
            "hits_by_port": self.hits_by_port(),
            "hits_by_country": self.hits_by_country(),
            "timeline": self.timeline(),
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
