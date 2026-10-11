"""DNS beaconing detection — timing-regular queries to the same domain.

Connection-level beaconing (detectors.py) sees filterlog flows; malware that
beacons via DNS (TXT/A lookups against attacker-controlled zones, or retrying
a Pi-hole-blocked C2 domain) never shows a stable outbound flow. This detector
tracks query cadence per (client, registered-domain) and flags sustained
low-jitter periodicity.

The dominant false-positive source is TTL-driven re-resolution: a legit client
re-queries a domain every TTL seconds, perfectly periodically. Mitigations:
reputable domains (Tranco rDNS list via feed_manager) are skipped entirely,
regularity must persist for MIN_REPS queries, and each (client, domain) pair
flags at most once per cooldown window.
"""

import math
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from ueba.netconfig import is_own_hostname

from ueba.logging_config import get_logger

logger = get_logger(__name__)

MIN_REPS = 12            # queries needed before cadence is judged
MIN_MEAN_INTERVAL = 15.0     # seconds — faster is burst/retry, not beaconing
MAX_MEAN_INTERVAL = 3600.0   # seconds — slower than hourly isn't measurable here
MAX_CV = 0.15            # coefficient of variation (stddev/mean) ceiling
COOLDOWN = timedelta(hours=1)
PRUNE_EVERY = 500        # calls between stale-entry sweeps
STALE_AFTER = timedelta(hours=2)

_SKIP_SUFFIXES = (
    ".arpa", ".local", ".lan", ".home", ".internal",
    ".plex.direct",  # Plex GDM re-resolves on a fixed cadence
)


def _registered_domain(domain: str) -> str:
    parts = domain.rstrip(".").rsplit(".", 2)
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


class DnsBeaconDetector:
    """Per-(client, domain) DNS query cadence analysis."""

    def __init__(self, feed_manager=None):
        self.feed_manager = feed_manager
        self._timestamps: Dict[Tuple[str, str], Deque[datetime]] = {}
        self._cooldowns: Dict[Tuple[str, str], datetime] = {}
        self._calls = 0

    def analyze_query(
        self,
        client_ip: str,
        domain: str,
        query_type: str = "A",
        blocked: bool = False,
        timestamp: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        if not domain or not client_ip:
            return []

        domain_lower = domain.lower().strip(".")
        if any(domain_lower.endswith(s) for s in _SKIP_SUFFIXES):
            return []
        if is_own_hostname(domain_lower):
            return []

        rdomain = _registered_domain(domain_lower)

        # Reputable (Tranco top-1M) domains re-resolve on TTL expiry — the
        # canonical false positive. Skip them outright, blocked or not:
        # blocked trackers (doubleclick etc.) retry periodically too.
        if self.feed_manager:
            try:
                if self.feed_manager.is_domain_reputable(rdomain):
                    return []
            except Exception:
                pass

        ts = timestamp or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        self._calls += 1
        if self._calls % PRUNE_EVERY == 0:
            self._prune(ts)

        key = (client_ip, rdomain)
        dq = self._timestamps.get(key)
        if dq is None:
            dq = deque(maxlen=40)
            self._timestamps[key] = dq
        # Ignore sub-second duplicates (A + AAAA pairs, retries)
        if dq and (ts - dq[-1]).total_seconds() < 1.0:
            return []
        dq.append(ts)

        if len(dq) < MIN_REPS:
            return []

        cooldown_until = self._cooldowns.get(key)
        if cooldown_until and ts < cooldown_until:
            return []

        recent = list(dq)[-MIN_REPS:]
        intervals = [
            (recent[i] - recent[i - 1]).total_seconds()
            for i in range(1, len(recent))
        ]
        mean = sum(intervals) / len(intervals)
        if not (MIN_MEAN_INTERVAL <= mean <= MAX_MEAN_INTERVAL):
            return []
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        cv = stddev / mean if mean > 0 else 999.0
        if cv > MAX_CV:
            return []

        self._cooldowns[key] = ts + COOLDOWN
        return [{
            "flag_type": "dns_beaconing",
            "details": {
                "rule": "dns_query_beaconing",
                "domain": domain,
                "registered_domain": rdomain,
                "client_ip": client_ip,
                "query_type": query_type,
                "blocked": blocked,
                "mean_interval_seconds": round(mean, 1),
                "stddev_seconds": round(stddev, 2),
                "repetitions": len(recent),
                "description": (
                    f"Periodic DNS queries to {rdomain} every ~{round(mean)}s "
                    f"(jitter {round(cv * 100)}%)"
                    + (" — domain is Pi-hole BLOCKED" if blocked else "")
                ),
            },
            "timestamp": ts,
        }]

    def _prune(self, now: datetime):
        cutoff = now - STALE_AFTER
        for key in list(self._timestamps.keys()):
            dq = self._timestamps[key]
            if not dq or dq[-1] < cutoff:
                del self._timestamps[key]
                self._cooldowns.pop(key, None)
        expired = [k for k, v in self._cooldowns.items() if v < now]
        for k in expired:
            self._cooldowns.pop(k, None)
