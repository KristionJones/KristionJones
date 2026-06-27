"""sentinel-honeypot: a multi-port network honeypot with a live dashboard.

Project 1 of the Enterprise Security Operations (SOC) Portfolio.
"""

from .storage import EventStore, Event
from .config import HoneypotConfig

__version__ = "1.0.0"

__all__ = ["EventStore", "Event", "HoneypotConfig", "__version__"]
