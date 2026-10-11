"""Network baseline learning - tracks known countries, ASNs, and traffic patterns.

Persists to SQLite via BaselineSnapshot so learned state survives restarts.
"""
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, Set, List, Optional

from sqlalchemy import select, delete

from ueba.database import async_session_factory
from ueba.models import BaselineSnapshot
from ueba.logging_config import get_logger
from ueba.config import get_config

logger = get_logger(__name__)


class NetworkBaseline:
    """Learns and tracks baseline network behavior.

    Flags connections to countries or IPs the network has never communicated with.
    Periodically snapshots state to DB so restarts don't trigger first_seen floods.
    """

    def __init__(self):
        self.config = get_config()
        self.host_connections: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.seen_asns: Dict[str, Set[str]] = defaultdict(set)
        self.seen_countries: Dict[str, Set[str]] = defaultdict(set)
        self.connection_times: Dict[str, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))
        self.window_days: int = self.config.analytics.baseline_window_days
        self._event_count = 0
        self._last_snapshot = datetime.now(timezone.utc)
        self._loaded = False

    async def load_from_db(self):
        """Restore baseline state from DB on startup."""
        try:
            async with async_session_factory() as session:
                result = await session.execute(select(BaselineSnapshot))
                rows = result.scalars().all()
                for snap in rows:
                    ip = snap.host_ip
                    dests = snap.destinations or {}
                    if isinstance(dests, dict):
                        for dst, count in dests.items():
                            self.host_connections[ip][dst] = count
                    if snap.asns:
                        self.seen_asns[ip] = set(snap.asns)
                    if snap.countries:
                        self.seen_countries[ip] = set(snap.countries)
                    self._event_count += snap.event_count or 0
                self._loaded = True
                if rows:
                    logger.info("Baseline restored from DB", extra={
                        "extra_data": {
                            "hosts": len(rows),
                            "total_destinations": sum(len(s.destinations or {}) for s in rows),
                        }
                    })
        except Exception as e:
            logger.warning("Failed to load baseline from DB, starting fresh",
                           extra={"extra_data": {"error": str(e)}})

    async def save_to_db(self):
        """Snapshot current baseline state to DB."""
        try:
            async with async_session_factory() as session:
                await session.execute(delete(BaselineSnapshot))

                now = datetime.now(timezone.utc)
                internal = [ip for ip in self.host_connections
                            if ip.startswith(("192.168.", "172.", "10."))]
                for ip in internal:
                    top_dests = dict(
                        sorted(self.host_connections[ip].items(),
                               key=lambda x: -x[1])[:500]
                    )
                    snap = BaselineSnapshot(
                        host_ip=ip,
                        destinations=top_dests,
                        asns=list(self.seen_asns.get(ip, set())),
                        countries=list(self.seen_countries.get(ip, set())),
                        event_count=sum(top_dests.values()),
                        updated_at=now,
                    )
                    session.add(snap)
                await session.commit()
                self._last_snapshot = now
                logger.info("Baseline snapshot saved", extra={
                    "extra_data": {"hosts": len(internal)}
                })
        except Exception as e:
            logger.error("Failed to save baseline snapshot",
                         extra={"extra_data": {"error": str(e)}})

    async def maybe_snapshot(self):
        """Save snapshot every 10 minutes if there's been activity."""
        now = datetime.now(timezone.utc)
        if (now - self._last_snapshot).total_seconds() > 600 and self._event_count > 0:
            await self.save_to_db()

    def record_connection(self, src_ip: str, dst_ip: str, timestamp: Optional[datetime] = None):
        """Record a connection for baseline learning."""
        if not src_ip or not dst_ip:
            return

        ts = timestamp or datetime.now(timezone.utc)
        self.host_connections[src_ip][dst_ip] += 1
        self.connection_times[src_ip][dst_ip].append(ts)
        self._event_count += 1

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.window_days)
        self.connection_times[src_ip][dst_ip] = [
            t for t in self.connection_times[src_ip][dst_ip] if t > cutoff
        ]

    def is_new_destination(self, src_ip: str, dst_ip: str) -> bool:
        """Check if destination IP is new for this source."""
        return dst_ip not in self.host_connections.get(src_ip, {})

    def is_new_asn(self, src_ip: str, asn: str) -> bool:
        """Check if ASN is new for this source."""
        if not asn:
            return False
        return asn not in self.seen_asns.get(src_ip, set())

    def is_new_country(self, src_ip: str, country: str) -> bool:
        """Check if country is new for this source."""
        if not country:
            return False
        return country not in self.seen_countries.get(src_ip, set())

    def record_asn(self, src_ip: str, asn: str):
        """Record a seen ASN."""
        self.seen_asns[src_ip].add(asn)

    def record_country(self, src_ip: str, country: str):
        """Record a seen country."""
        self.seen_countries[src_ip].add(country)

    def get_host_connections(self, src_ip: str) -> Dict[str, int]:
        """Get connection counts for a host."""
        return dict(self.host_connections.get(src_ip, {}))

    def get_stats(self) -> dict:
        """Get baseline statistics."""
        total_hosts = len(self.host_connections)
        total_destinations = sum(len(dests) for dests in self.host_connections.values())
        return {
            "total_hosts": total_hosts,
            "total_unique_destinations": total_destinations,
            "window_days": self.window_days,
            "event_count": self._event_count,
            "loaded_from_db": self._loaded,
        }
