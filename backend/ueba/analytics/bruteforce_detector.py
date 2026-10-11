"""Network brute force detection.

Detects SSH/RDP/Telnet brute force attacks from OPNsense filterlog data.
Based on the Nemea brute_force_detector algorithm from CESNET.

Detection modes:
- Simple brute force: single src_ip, single dst_ip, same dst_port (22/23/3389),
  >50 blocked connections in 30 minutes
- Distributed brute force: 5+ distinct src_ips targeting same (dst_ip, dst_port)
  in 30 minutes
- User scan: single src_ip trying same port on 25+ distinct dst_ips in 30 minutes

Operates in both modes:
- Event pipeline: analyze_event() called per-filterlog-event from engine.py
- Ensemble loop: detect() queries OPNsenseLog for blocked brute-force-port
  connections within lookback_hours and runs analyze_event() on each row.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple

from sqlalchemy import select

from ueba.logging_config import get_logger
from ueba.database import async_session_factory
from ueba.models import OPNsenseLog
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)

# Well-known remote access ports
BRUTE_FORCE_PORTS = {22, 23, 3389, 2222, 5900, 5901, 5938}

# Detection thresholds
SIMPLE_BRUTEFORCE_MIN_ATTEMPTS = 50
SIMPLE_BRUTEFORCE_WINDOW_SEC = 1800  # 30 minutes

DISTRIBUTED_BRUTEFORCE_MIN_SOURCES = 5
DISTRIBUTED_BRUTEFORCE_WINDOW_SEC = 1800

USER_SCAN_MIN_TARGETS = 25
USER_SCAN_WINDOW_SEC = 1800


@dataclass
class _BruteForceEntry:
    """Sliding window entry for a connection attempt."""

    src_ip: str
    dst_ip: str
    dst_port: int
    attempts: int = 0
    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    alerted: bool = False


class BruteForceDetector(BaseAnomalyDetector):
    """Per-event and batch brute force detection for remote access protocols.

    Event pipeline: analyze_event() called on each filterlog event in the engine.
    Batch mode: detect() queries OPNsenseLog for blocked connections on brute
    force ports and returns AnomalyResult objects.

    Maintains in-memory sliding windows and returns BehavioralFlag dicts
    when thresholds are exceeded.
    """

    def __init__(
        self,
        lookback_hours: int = 24,
        simple_threshold: int = SIMPLE_BRUTEFORCE_MIN_ATTEMPTS,
        distributed_threshold: int = DISTRIBUTED_BRUTEFORCE_MIN_SOURCES,
        user_scan_threshold: int = USER_SCAN_MIN_TARGETS,
        window_seconds: int = SIMPLE_BRUTEFORCE_WINDOW_SEC,
    ):
        self._lookback_hours = lookback_hours
        self.simple_threshold = simple_threshold
        self.distributed_threshold = distributed_threshold
        self.user_scan_threshold = user_scan_threshold
        self.window_seconds = window_seconds

        # Simple brute force: (src_ip, dst_ip, dst_port) -> _BruteForceEntry
        self._simple_entries: Dict[Tuple[str, str, int], _BruteForceEntry] = {}

        # Distributed brute force: (dst_ip, dst_port) -> set of src_ips
        self._distributed_targets: Dict[Tuple[str, int], Set[str]] = {}
        self._distributed_timestamps: Dict[Tuple[str, int], float] = {}

        # User scan: (src_ip, dst_port) -> set of dst_ips
        self._user_scans: Dict[Tuple[str, int], Set[str]] = {}
        self._user_scan_timestamps: Dict[Tuple[str, int], float] = {}

        # Cooldown to avoid repeated alerts for the same brute force campaign
        self._alert_cooldown: Dict[str, float] = {}
        self._cooldown_seconds = 600  # 10 minutes

        # BaseAnomalyDetector state
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None

    # ------------------------------------------------------------------
    # BaseAnomalyDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "brute_force"

    @property
    def description(self) -> str:
        return (
            "Brute force attack detector for remote access protocols "
            "(SSH, RDP, Telnet, VNC) — flags single-source, distributed, "
            "and user-scan patterns from blocked connection attempts."
        )

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    async def detect(self) -> List[AnomalyResult]:
        """Query OPNsense logs for blocked brute-force-port connections and
        detect brute force patterns.

        Returns:
            List of AnomalyResult objects for detected brute force campaigns.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)

        # Collect behavioral flags from database rows
        all_flags: List[Dict[str, Any]] = []

        try:
            async with async_session_factory() as session:
                stmt = (
                    select(
                        OPNsenseLog.src_ip,
                        OPNsenseLog.dst_ip,
                        OPNsenseLog.dst_port,
                        OPNsenseLog.protocol,
                        OPNsenseLog.action,
                        OPNsenseLog.timestamp,
                    )
                    .where(OPNsenseLog.timestamp >= cutoff)
                    .where(OPNsenseLog.action == "block")
                    .where(OPNsenseLog.dst_port.in_(BRUTE_FORCE_PORTS))
                    .order_by(OPNsenseLog.timestamp.asc())
                )
                result = await session.execute(stmt)
                rows = result.all()
        except Exception as e:
            logger.error("Failed to query OPNsense logs for brute force detection", extra={
                "extra_data": {"error": str(e)}
            })
            self._last_results = []
            self._last_run = datetime.now(timezone.utc)
            return []

        # Feed each row into analyze_event() and collect flags
        for row in rows:
            flags = self.analyze_event(
                src_ip=row.src_ip,
                dst_ip=row.dst_ip,
                dst_port=row.dst_port,
                protocol=row.protocol,
                action=row.action,
                timestamp=row.timestamp,
            )
            all_flags.extend(flags)

        # Convert BehavioralFlag dicts to AnomalyResult objects
        results: List[AnomalyResult] = []
        for flag in all_flags:
            details = flag.get("details", {})
            detection_type = details.get("detection_type", "unknown")

            if detection_type == "simple":
                ip = details.get("src_ip", "")
                attempts = details.get("attempts", 0)
                threshold = details.get("threshold", self.simple_threshold)
                score = min(1.0, attempts / max(threshold, 1))
            elif detection_type == "distributed":
                ip = details.get("dst_ip", "")
                sources = details.get("distinct_sources", 0)
                threshold = details.get("threshold", self.distributed_threshold)
                score = min(1.0, sources / max(threshold, 1))
            elif detection_type == "user_scan":
                ip = details.get("src_ip", "")
                targets = details.get("distinct_targets", 0)
                threshold = details.get("threshold", self.user_scan_threshold)
                score = min(1.0, targets / max(threshold, 1))
            else:
                ip = details.get("src_ip", "")
                score = 0.5

            results.append(AnomalyResult(
                ip=ip,
                score=round(score, 4),
                details=details,
                detector_name=self.name,
            ))

        self._last_results = results
        self._last_run = datetime.now(timezone.utc)

        if results:
            logger.info("Brute force detection completed", extra={
                "extra_data": {
                    "rows_processed": len(rows),
                    "flags_found": len(results),
                    "detection_types": list(set(
                        f.get("details", {}).get("detection_type", "")
                        for f in all_flags
                    )),
                }
            })

        return results

    def analyze_event(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int],
        protocol: Optional[str] = None,
        action: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Analyze a single filterlog event for brute force patterns.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            dst_port: Destination port number.
            protocol: Protocol (tcp, udp, etc.).
            action: Firewall action (pass, block).
            timestamp: Event timestamp.

        Returns:
            List of behavioral flag dicts when thresholds are exceeded.
        """
        flags: List[Dict[str, Any]] = []

        if dst_port is None or dst_port not in BRUTE_FORCE_PORTS:
            return flags
        if not src_ip or not dst_ip:
            return flags

        # Only count connection attempts (blocked or SYN connections)
        # Blocked connections are the strongest signal
        if action and action not in ("block", "pass"):
            return flags

        ts = timestamp or datetime.now(timezone.utc)
        now = time.monotonic()

        # Prune expired entries
        self._prune(now)

        # 1. Simple brute force: single src → single dst on same port
        simple_key = (src_ip, dst_ip, dst_port)
        if simple_key not in self._simple_entries:
            self._simple_entries[simple_key] = _BruteForceEntry(
                src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port
            )
        entry = self._simple_entries[simple_key]
        entry.attempts += 1
        entry.last_seen = now

        cooldown_key = f"simple:{src_ip}:{dst_ip}:{dst_port}"
        if (
            entry.attempts >= self.simple_threshold
            and not entry.alerted
            and cooldown_key not in self._alert_cooldown
        ):
            entry.alerted = True
            self._alert_cooldown[cooldown_key] = now
            flags.append({
                "flag_type": "brute_force",
                "details": {
                    "detection_type": "simple",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "attempts": entry.attempts,
                    "threshold": self.simple_threshold,
                    "window_seconds": self.window_seconds,
                    "description": (
                        f"Simple brute force: {entry.attempts} connection attempts "
                        f"from {src_ip} to {dst_ip}:{dst_port}"
                    ),
                },
                "timestamp": ts,
            })

        # 2. Distributed brute force: many sources → single target:port
        dist_key = (dst_ip, dst_port)
        if dist_key not in self._distributed_targets:
            self._distributed_targets[dist_key] = set()
            self._distributed_timestamps[dist_key] = now
        self._distributed_targets[dist_key].add(src_ip)
        self._distributed_timestamps[dist_key] = now

        dcooldown_key = f"distributed:{dst_ip}:{dst_port}"
        if (
            len(self._distributed_targets[dist_key]) >= self.distributed_threshold
            and dcooldown_key not in self._alert_cooldown
        ):
            self._alert_cooldown[dcooldown_key] = now
            sources = sorted(list(self._distributed_targets[dist_key]))
            flags.append({
                "flag_type": "brute_force",
                "details": {
                    "detection_type": "distributed",
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "distinct_sources": len(sources),
                    "threshold": self.distributed_threshold,
                    "source_ips": sources[:20],
                    "window_seconds": self.window_seconds,
                    "description": (
                        f"Distributed brute force: {len(sources)} distinct sources "
                        f"targeting {dst_ip}:{dst_port}"
                    ),
                },
                "timestamp": ts,
            })
            # Reset to catch new campaigns
            self._distributed_targets[dist_key] = set()

        # 3. User scan: single src → many dsts on same port
        scan_key = (src_ip, dst_port)
        if scan_key not in self._user_scans:
            self._user_scans[scan_key] = set()
            self._user_scan_timestamps[scan_key] = now
        self._user_scans[scan_key].add(dst_ip)
        self._user_scan_timestamps[scan_key] = now

        ucooldown_key = f"userscan:{src_ip}:{dst_port}"
        if (
            len(self._user_scans[scan_key]) >= self.user_scan_threshold
            and ucooldown_key not in self._alert_cooldown
        ):
            self._alert_cooldown[ucooldown_key] = now
            targets = sorted(list(self._user_scans[scan_key]))
            flags.append({
                "flag_type": "brute_force",
                "details": {
                    "detection_type": "user_scan",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "distinct_targets": len(targets),
                    "threshold": self.user_scan_threshold,
                    "sample_targets": targets[:20],
                    "window_seconds": self.window_seconds,
                    "description": (
                        f"User scan: {src_ip} probed port {dst_port} on "
                        f"{len(targets)} distinct hosts"
                    ),
                },
                "timestamp": ts,
            })
            # Reset to catch new campaigns
            self._user_scans[scan_key] = set()

        return flags

    def _prune(self, now: float) -> None:
        """Remove entries outside the sliding window and expired cooldowns."""
        cutoff = now - self.window_seconds
        cooldown_cutoff = now - self._cooldown_seconds

        # Simple brute force entries
        expired_simple = [
            key for key, entry in self._simple_entries.items()
            if entry.last_seen < cutoff
        ]
        for key in expired_simple:
            del self._simple_entries[key]

        # Distributed targets
        expired_dist = [
            key for key, ts in self._distributed_timestamps.items()
            if ts < cutoff
        ]
        for key in expired_dist:
            self._distributed_targets.pop(key, None)
            self._distributed_timestamps.pop(key, None)

        # User scans
        expired_scan = [
            key for key, ts in self._user_scan_timestamps.items()
            if ts < cutoff
        ]
        for key in expired_scan:
            self._user_scans.pop(key, None)
            self._user_scan_timestamps.pop(key, None)

        # Cooldowns
        expired_cooldowns = [
            key for key, ts in self._alert_cooldown.items()
            if ts < cooldown_cutoff
        ]
        for key in expired_cooldowns:
            del self._alert_cooldown[key]

    def get_stats(self) -> Dict[str, Any]:
        """Return current detection statistics."""
        return {
            "active_simple_entries": len(self._simple_entries),
            "active_distributed_targets": len(self._distributed_targets),
            "active_user_scans": len(self._user_scans),
            "alert_cooldowns": len(self._alert_cooldown),
        }
