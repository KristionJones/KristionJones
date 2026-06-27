"""IP geolocation with graceful degradation.

If a MaxMind GeoLite2-Country database and the ``geoip2`` package are available
the resolver uses them. Otherwise it still classifies private/reserved address
space (useful for filtering lab noise) and returns ``Unknown`` for the rest, so
the rest of the system never has to care whether a geo database is present.
"""

from __future__ import annotations

import ipaddress
from typing import Any


class GeoResolver:
    def __init__(self, geoip_db: str | None = None) -> None:
        self._reader = None
        if geoip_db:
            try:  # pragma: no cover - exercised only when geoip2 is installed
                import geoip2.database

                self._reader = geoip2.database.Reader(geoip_db)
            except Exception:
                self._reader = None

    @staticmethod
    def _classify_special(ip: str) -> dict[str, Any] | None:
        """Return a result dict for private/reserved IPs, else ``None``."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"country": "Invalid", "country_code": None, "is_private": False}
        if addr.is_private or addr.is_loopback:
            return {"country": "Local", "country_code": "LAN", "is_private": True}
        if addr.is_reserved or addr.is_link_local or addr.is_multicast:
            return {"country": "Reserved", "country_code": None, "is_private": True}
        return None

    def lookup(self, ip: str) -> dict[str, Any]:
        special = self._classify_special(ip)
        if special is not None:
            return special
        if self._reader is not None:  # pragma: no cover - needs geoip2 + db
            try:
                resp = self._reader.country(ip)
                return {
                    "country": resp.country.name or "Unknown",
                    "country_code": resp.country.iso_code,
                    "is_private": False,
                }
            except Exception:
                pass
        return {"country": "Unknown", "country_code": None, "is_private": False}
