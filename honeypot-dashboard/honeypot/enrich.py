"""Lightweight, offline IP enrichment.

By design this does NOT call external geolocation APIs by default — sending every
attacker IP to a third party can leak operational data and rate-limit you. We
classify the address locally (public / private / loopback). A hook is provided
so you can plug in MaxMind GeoLite2 or an API later if you want country data.
"""

from __future__ import annotations

import ipaddress


def classify_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_link_local:
        return "reserved"
    return "public"
