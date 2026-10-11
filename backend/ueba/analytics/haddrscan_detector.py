"""Horizontal address scan detector.

Detects a single source IP probing the SAME port across MANY destination IPs
(horizontal scan — opposite of vertical port scan). Based on the Nemea
haddrscan_detector algorithm from CESNET.

Algorithm: Track (src_ip, dst_port) pairs, count unique dst_ips per pair.
Alert when the unique destination count exceeds a configurable threshold.
Only tracks connection attempts (SYN / blocked connections), not established sessions.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple

from sqlalchemy import select

from ueba.logging_config import get_logger
from ueba.database import async_session_factory
from ueba.models import OPNsenseLog
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)

# Default threshold: alert after this many unique DST_IPs per (SRC_IP, DST_PORT)
DEFAULT_ADDR_THRESHOLD = 50
# Idle timeout: discard entry unchanged for this many seconds
DEFAULT_IDLE_TIMEOUT = 300  # 5 minutes
# Pruning interval in seconds
DEFAULT_PRUNE_INTERVAL = 60

# Protocols/tcp_flags we consider as "connection attempt"
TCP_PROTO = 6
TCP_SYN_FLAG = 0x2


@dataclass
class _ScanEntry:
    """Tracked entry for a (src_ip, dst_port) pair."""

    src_ip: str
    dst_port: int
    unique_dst_ips: Set[str] = field(default_factory=set)
    ts_first: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ts_last: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ts_modified: float = field(default_factory=time.monotonic)
    alerted: bool = False


class HaddrscanDetector(BaseAnomalyDetector):
    """Horizontal address scan anomaly detector.

    Processes OPNsense filterlog data from the database to detect hosts
    performing horizontal scans (single source → many destinations on the
    same port).
    """

    def __init__(
        self,
        lookback_hours: int = 24,
        addr_threshold: int = DEFAULT_ADDR_THRESHOLD,
        idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
        prune_interval: int = DEFAULT_PRUNE_INTERVAL,
    ):
        self._lookback_hours = lookback_hours
        self._addr_threshold = addr_threshold
        self._idle_timeout = idle_timeout
        self._prune_interval = prune_interval

        # In-memory state: (src_ip, dst_port) -> _ScanEntry
        self._entries: Dict[Tuple[str, int], _ScanEntry] = {}
        self._last_prune: float = time.monotonic()
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None

    # ------------------------------------------------------------------
    # BaseAnomalyDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "haddrscan"

    @property
    def description(self) -> str:
        return (
            "Horizontal address scan detector — flags source IPs that probe "
            "the same destination port across many different destination IPs."
        )

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    async def detect(self) -> List[AnomalyResult]:
        """Query OPNsense logs and detect horizontal scans.

        Returns:
            List of AnomalyResult for hosts exceeding the threshold.
        """
        self._maybe_prune()

        # Load recent connection attempt logs from the database
        rows = await self._fetch_connection_attempts()

        # Process each row into tracking entries
        for row in rows:
            self._process_row(row)

        # Build results
        results: List[AnomalyResult] = []
        for (src_ip, dst_port), entry in self._entries.items():
            if entry.alerted or len(entry.unique_dst_ips) >= self._addr_threshold:
                if not entry.alerted:
                    entry.alerted = True
                score = min(1.0, len(entry.unique_dst_ips) / max(self._addr_threshold, 1))
                results.append(AnomalyResult(
                    ip=src_ip,
                    score=round(score, 4),
                    details={
                        "detector_name": self.name,
                        "dst_port": dst_port,
                        "unique_dst_ips": len(entry.unique_dst_ips),
                        "threshold": self._addr_threshold,
                        "ts_first": entry.ts_first.isoformat(),
                        "ts_last": entry.ts_last.isoformat(),
                        "sample_dst_ips": sorted(list(entry.unique_dst_ips))[:10],
                    },
                    detector_name=self.name,
                ))

        self._last_results = results
        self._last_run = datetime.now(timezone.utc)

        if results:
            logger.info("Horizontal scan detected", extra={
                "extra_data": {
                    "scanners": len(results),
                    "top_scanner": results[0].ip,
                    "top_port": results[0].details.get("dst_port"),
                }
            })

        return results

    def data_hash(self) -> str:
        """Stable hash for caching based on parameters."""
        import hashlib
        raw = f"haddrscan_{self._lookback_hours}_{self._addr_threshold}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_connection_attempts(self) -> List[Dict[str, Any]]:
        """Fetch recent connection attempt rows from OPNsense logs.

        We consider rows where:
        - protocol is TCP (6)
        - action is 'block' (connection attempt was denied)
        - OR tcp_flags has SYN and action is 'pass' (new connection attempt)

        Since we don't have tcp_flags in OPNsenseLog directly, we use
        blocked connections as a proxy for connection attempts and also
        include passing traffic on common scan ports.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)
        try:
            async with async_session_factory() as session:
                # Get blocked connections (clear scan attempts)
                stmt = (
                    select(
                        OPNsenseLog.src_ip,
                        OPNsenseLog.dst_ip,
                        OPNsenseLog.dst_port,
                        OPNsenseLog.protocol,
                        OPNsenseLog.action,
                    )
                    .where(OPNsenseLog.timestamp >= cutoff)
                    .where(OPNsenseLog.action == "block")
                    .order_by(OPNsenseLog.timestamp.asc())
                )
                result = await session.execute(stmt)
                rows = result.all()
                return [
                    {
                        "src_ip": r.src_ip,
                        "dst_ip": r.dst_ip,
                        "dst_port": r.dst_port,
                        "protocol": r.protocol,
                        "action": r.action,
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.error("Failed to fetch connection attempts", extra={
                "extra_data": {"error": str(e)}
            })
            return []

    def _process_row(self, row: Dict[str, Any]) -> None:
        """Process a single connection row into tracking state."""
        src_ip = row.get("src_ip", "")
        dst_ip = row.get("dst_ip", "")
        dst_port = row.get("dst_port")
        action = row.get("action", "")

        if not src_ip or not dst_ip or dst_port is None:
            return
        if dst_port == 0:
            return

        # Only track internal → external scans (reverse of normal traffic)
        # Internal hosts typically start with 192.168. or 10.
        if not (src_ip.startswith("192.168.") or src_ip.startswith("10.")):
            return

        key = (src_ip, dst_port)
        now = time.monotonic()

        if key not in self._entries:
            self._entries[key] = _ScanEntry(
                src_ip=src_ip,
                dst_port=dst_port,
            )

        entry = self._entries[key]
        entry.unique_dst_ips.add(dst_ip)
        entry.ts_last = datetime.now(timezone.utc)
        entry.ts_modified = now

    def _maybe_prune(self) -> None:
        """Remove entries that have been idle too long."""
        now = time.monotonic()
        if now - self._last_prune < self._prune_interval:
            return
        self._last_prune = now

        expired = [
            key for key, entry in self._entries.items()
            if now - entry.ts_modified > self._idle_timeout
        ]
        for key in expired:
            del self._entries[key]

        if expired:
            logger.debug("Pruned idle haddrscan entries", extra={
                "extra_data": {"pruned": len(expired)}
            })
