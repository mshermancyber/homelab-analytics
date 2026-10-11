"""DDoS / Volumetric Flood Detection.

Detects inbound volumetric DDoS attacks by tracking the rate of blocked
inbound events per destination IP over a 60-second sliding window.

MITRE: T1498 (Network Denial of Service)
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional

from ueba.logging_config import get_logger
from ueba.config import get_config
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)


class DDoSDetector(BaseAnomalyDetector):
    """Detects inbound volumetric DDoS floods.

    Maintains a sliding window of blocked-event timestamps per destination IP.
    Flags when the blocked-event rate exceeds the configured threshold within
    a 60-second window.
    """

    def __init__(self):
        # dst_ip -> list of blocked-event datetimes
        self._window: Dict[str, List[datetime]] = defaultdict(list)
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None
        self._config = get_config()

    # ------------------------------------------------------------------
    # BaseAnomalyDetector abstract property implementations
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "ddos_detector"

    @property
    def description(self) -> str:
        return "DDoS / volumetric flood detection via blocked-event rate per destination IP"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    # ------------------------------------------------------------------
    # Per-event analysis
    # ------------------------------------------------------------------

    def analyze_event(
        self,
        src_ip: str,
        dst_ip: str,
        action: Optional[str] = None,
        direction: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> Optional[dict]:
        """Analyze a single filterlog event for DDoS signatures.

        Args:
            src_ip: Source IP of the connection.
            dst_ip: Destination IP of the connection.
            action: Firewall action ('block', 'pass', etc.).
            direction: Traffic direction ('in', 'out').
            timestamp: Event timestamp.

        Returns:
            A behavioral flag dict if a DDoS flood is detected, or None.
        """
        if action != "block":
            return None
        if direction != "in":
            return None
        if not dst_ip:
            return None

        ts = timestamp or datetime.now(timezone.utc)
        self._window[dst_ip].append(ts)

        # Prune timestamps older than 60 seconds
        cutoff = ts - timedelta(seconds=60)
        self._window[dst_ip] = [t for t in self._window[dst_ip] if t > cutoff]

        count = len(self._window[dst_ip])
        threshold = getattr(self._config.analytics, "volumetric_threshold", 200)

        if count >= threshold:
            logger.info("DDoS flood detected", extra={
                "extra_data": {
                    "dst_ip": dst_ip,
                    "blocked_count_60s": count,
                    "threshold": threshold,
                }
            })
            # Clear window to avoid repeated alerts
            self._window[dst_ip] = []
            return {
                "flag_type": "ddos_flood",
                "details": {
                    "dst_ip": dst_ip,
                    "src_ip_sample": src_ip,
                    "blocked_count_60s": count,
                    "threshold": threshold,
                },
                "timestamp": ts,
            }
        return None

    # ------------------------------------------------------------------
    # Batch detection
    # ------------------------------------------------------------------

    async def detect(self) -> List[AnomalyResult]:
        """Run batch DDoS detection across tracked windows.

        Returns AnomalyResult objects for any destination IP whose
        blocked-event rate exceeds the threshold.
        """
        results: List[AnomalyResult] = []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=60)
        threshold = getattr(self._config.analytics, "volumetric_threshold", 200)

        for dst_ip, timestamps in list(self._window.items()):
            # Prune
            fresh = [t for t in timestamps if t > cutoff]
            if not fresh:
                del self._window[dst_ip]
                continue
            self._window[dst_ip] = fresh
            count = len(fresh)
            if count >= threshold:
                results.append(AnomalyResult(
                    ip=dst_ip,
                    score=min(1.0, count / (threshold * 2)),
                    details={
                        "detector": "ddos_flood",
                        "blocked_count_60s": count,
                        "threshold": threshold,
                    },
                    detector_name=self.name,
                ))
                # Clear to avoid repeat alerts in batch mode
                del self._window[dst_ip]

        self._last_results = results
        self._last_run = now
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Return current detection statistics."""
        return {
            "tracked_destinations": len(self._window),
            "total_blocked_events": sum(len(v) for v in self._window.values()),
        }
