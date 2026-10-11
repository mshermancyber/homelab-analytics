"""DNS Amplification Detection.

Detects DNS amplification attacks by tracking DNS queries from external
(non-private) source IPs. A high rate of queries from an external IP to
the local DNS server indicates a reflection/amplification attack.

MITRE: T1498.002 (Reflection Amplification)
Flag type: 'dns_amplification'
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional

from ueba.logging_config import get_logger
from ueba.config import get_config
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)

_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "169.254.", "0.",
)


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private/RFC1918 range."""
    if not ip:
        return True
    if ip in ("::", "::1", "0.0.0.0"):
        return True
    return ip.startswith(_PRIVATE_PREFIXES)


class DNSAmplificationDetector(BaseAnomalyDetector):
    """Detects DNS amplification/reflection attacks.

    Tracks DNS queries from external (non-private) source IPs over a 60-second
    sliding window. A high query rate from an external IP indicates the DNS
    server is being used for a reflection amplification attack.
    """

    def __init__(self):
        # client_ip -> list of query timestamps
        self._external_queries: Dict[str, List[datetime]] = defaultdict(list)
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None
        self._config = get_config()

    # ------------------------------------------------------------------
    # BaseAnomalyDetector abstract property implementations
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "dns_amplification"

    @property
    def description(self) -> str:
        return "DNS amplification/reflection attack detection via external query rate"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    # ------------------------------------------------------------------
    # Per-query analysis
    # ------------------------------------------------------------------

    def analyze_query(
        self,
        client_ip: str,
        domain: str = "",
        timestamp: Optional[datetime] = None,
    ) -> Optional[dict]:
        """Analyze a single DNS query for amplification attack patterns.

        Only tracks queries from external (non-private) IPs.

        Args:
            client_ip: The IP making the DNS query.
            domain: The queried domain (for logging).
            timestamp: Event timestamp.

        Returns:
            A behavioral flag dict if amplification is detected, or None.
        """
        if not client_ip:
            return None
        if _is_private_ip(client_ip):
            return None

        ts = timestamp or datetime.now(timezone.utc)
        self._external_queries[client_ip].append(ts)

        # Prune timestamps older than 60 seconds
        cutoff = ts - timedelta(seconds=60)
        self._external_queries[client_ip] = [
            t for t in self._external_queries[client_ip] if t > cutoff
        ]

        count = len(self._external_queries[client_ip])
        threshold = getattr(
            self._config.analytics, "dns_amplification_threshold", 50
        )

        if count >= threshold:
            logger.info("DNS amplification detected", extra={
                "extra_data": {
                    "external_ip": client_ip,
                    "query_count_60s": count,
                    "threshold": threshold,
                    "sample_domain": domain,
                }
            })
            # Clear window to avoid repeated alerts
            self._external_queries[client_ip] = []
            return {
                "flag_type": "dns_amplification",
                "details": {
                    "external_ip": client_ip,
                    "query_count_60s": count,
                    "threshold": threshold,
                    "sample_domain": domain,
                },
                "timestamp": ts,
            }
        return None

    # ------------------------------------------------------------------
    # Batch detection
    # ------------------------------------------------------------------

    async def detect(self) -> List[AnomalyResult]:
        """Run batch amplification detection across all tracked IPs."""
        results: List[AnomalyResult] = []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=60)
        threshold = getattr(
            self._config.analytics, "dns_amplification_threshold", 50
        )

        for ip, timestamps in list(self._external_queries.items()):
            fresh = [t for t in timestamps if t > cutoff]
            if not fresh:
                del self._external_queries[ip]
                continue
            self._external_queries[ip] = fresh
            count = len(fresh)
            if count >= threshold:
                results.append(AnomalyResult(
                    ip=ip,
                    score=min(1.0, count / (threshold * 2)),
                    details={
                        "detector": "dns_amplification",
                        "query_count_60s": count,
                        "threshold": threshold,
                    },
                    detector_name=self.name,
                ))
                del self._external_queries[ip]

        self._last_results = results
        self._last_run = now
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Return current detection statistics."""
        return {
            "tracked_external_ips": len(self._external_queries),
            "total_tracked_queries": sum(len(v) for v in self._external_queries.values()),
        }
