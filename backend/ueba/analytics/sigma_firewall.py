"""Sigma firewall detection patterns for OPNsense filterlog analysis.

Implements pattern-based firewall detection rules inspired by SigmaHQ
firewall rules:
- Cleartext protocol detection (sensitive ports passed through firewall)
- Outbound SMB to external hosts
- Outbound RDP to external hosts
- DNS on non-standard ports (potential DNS tunneling bypassing Pi-hole)
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy import select

from ueba.logging_config import get_logger
from ueba.database import async_session_factory
from ueba.models import OPNsenseLog
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Sensitive Ports (cleartext protocols commonly targeted)
# ---------------------------------------------------------------------------

SENSITIVE_PORTS = {
    21,      # FTP
    23,      # Telnet
    3306,    # MySQL
    1433,    # MSSQL
    5432,    # PostgreSQL
    27017,   # MongoDB
    5900,    # VNC
    5901,    # VNC
    5902,    # VNC
    5903,    # VNC
    5904,    # VNC
    11211,   # Memcached
    15672,   # RabbitMQ management
    8080,    # HTTP alternate (often unencrypted)
    50000,   # SAP
    1521,    # Oracle
}


# ---------------------------------------------------------------------------
# Helper: IP classification
# ---------------------------------------------------------------------------

def _is_internal_ip(ip: str) -> bool:
    """Check if an IP address is in a private/internal range."""
    if not ip:
        return False
    if ip.startswith(("10.", "192.168.", "127.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False


# ---------------------------------------------------------------------------
# SigmaFirewallDetector
# ---------------------------------------------------------------------------

class SigmaFirewallDetector(BaseAnomalyDetector):
    """Sigma-inspired firewall detection engine for OPNsense filterlog events.

    Runs a set of Sigma-inspired firewall detection rules against each
    OPNsense filterlog event and returns matching BehavioralFlag dicts.
    """

    def __init__(self, lookback_minutes: int = 5):
        self.lookback_minutes = lookback_minutes
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None

    # ------------------------------------------------------------------
    # BaseAnomalyDetector abstract property implementations
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "sigma_firewall"

    @property
    def description(self) -> str:
        return "Sigma-inspired firewall detection rules for OPNsense filterlog events"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    # ------------------------------------------------------------------
    # Batch detection (async, queries OPNsenseLog from database)
    # ------------------------------------------------------------------

    async def detect(self) -> List[AnomalyResult]:
        """Run Sigma firewall detection against recent OPNsenseLog records.

        Queries the database for OPNsense filterlog events in the configured
        lookback window, runs ``analyze_event()`` on each, and returns
        ``AnomalyResult`` objects for any source IPs that triggered one or
        more Sigma firewall rules.
        """
        results: List[AnomalyResult] = []
        try:
            since = datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)

            async with async_session_factory() as session:
                query_result = await session.execute(
                    select(
                        OPNsenseLog.src_ip,
                        OPNsenseLog.dst_ip,
                        OPNsenseLog.dst_port,
                        OPNsenseLog.protocol,
                        OPNsenseLog.action,
                        OPNsenseLog.direction,
                        OPNsenseLog.timestamp,
                    )
                    .where(OPNsenseLog.timestamp >= since)
                    .order_by(OPNsenseLog.timestamp.desc())
                    .limit(5000)
                )
                rows = query_result.all()

            if not rows:
                self._last_results = results
                self._last_run = datetime.now(timezone.utc)
                return results

            # Accumulate flags per source IP
            per_client: Dict[str, List[Dict[str, Any]]] = {}
            for row in rows:
                flags = self.analyze_event(
                    src_ip=row.src_ip,
                    dst_ip=row.dst_ip,
                    dst_port=row.dst_port,
                    protocol=row.protocol,
                    action=row.action,
                    direction=row.direction,
                    timestamp=row.timestamp,
                )
                if flags:
                    if row.src_ip not in per_client:
                        per_client[row.src_ip] = []
                    per_client[row.src_ip].extend(flags)

            # Build AnomalyResult for each flagged client
            for src_ip, flags in per_client.items():
                unique_rules = list({f["details"]["rule"] for f in flags})
                unique_dst_ips = list({f["details"].get("dst_ip", "") for f in flags})
                score = min(1.0, len(flags) / 10.0)

                results.append(AnomalyResult(
                    ip=src_ip,
                    score=round(score, 4),
                    details={
                        "matched_rules": unique_rules,
                        "matched_dst_ips": unique_dst_ips,
                        "total_flags": len(flags),
                        "rule_counts": {r: sum(1 for f in flags if f["details"]["rule"] == r) for r in unique_rules},
                    },
                    detector_name=self.name,
                ))

            self._last_results = results
            self._last_run = datetime.now(timezone.utc)

            if results:
                logger.info("Sigma firewall detection completed", extra={
                    "extra_data": {
                        "events_analyzed": len(rows),
                        "flagged_clients": len(results),
                        "flagged_ips": [r.ip for r in results],
                    }
                })

        except Exception as e:
            logger.error("Sigma firewall detection failed", extra={
                "extra_data": {"error": str(e)}
            })
            self._last_results = results
            self._last_run = datetime.now(timezone.utc)

        return results

    def analyze_event(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int],
        protocol: Optional[str] = None,
        action: Optional[str] = None,
        direction: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Analyze a single OPNsense filterlog event and return any matched flags.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            dst_port: Destination port number.
            protocol: Protocol (tcp, udp, etc.).
            action: Firewall action (pass, block).
            direction: Traffic direction (in, out).
            timestamp: Event timestamp.

        Returns:
            List of behavioral flag dicts, each with flag_type='sigma_firewall'
            and details containing the matched rule name.
        """
        if not src_ip or not dst_ip:
            return []

        ts = timestamp or datetime.now(timezone.utc)
        flags: List[Dict[str, Any]] = []

        # ------------------------------------------------------------------
        # Rule 1: Cleartext Protocol Detection
        # Check if the firewall is passing traffic to cleartext-sensitive ports.
        # ------------------------------------------------------------------
        if (action == "pass" and dst_port is not None and dst_port in SENSITIVE_PORTS
                and not (_is_internal_ip(src_ip) and _is_internal_ip(dst_ip))):
            flags.append({
                "flag_type": "sigma_firewall",
                "details": {
                    "rule": "cleartext_protocol",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol or "unknown",
                    "action": action,
                    "description": f"Cleartext connection to port {dst_port}",
                },
                "timestamp": ts,
            })

        # ------------------------------------------------------------------
        # Rule 2: Outbound SMB Detection
        # Internal host making SMB connections to external IPs.
        # ------------------------------------------------------------------
        if (
            direction != "in"
            and dst_port == 445
            and _is_internal_ip(src_ip)
            and not _is_internal_ip(dst_ip)
        ):
            flags.append({
                "flag_type": "sigma_firewall",
                "details": {
                    "rule": "outbound_smb",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol or "unknown",
                    "action": action,
                    "description": "Outbound SMB to external host",
                },
                "timestamp": ts,
            })

        # ------------------------------------------------------------------
        # Rule 3: Outbound RDP Detection
        # Internal host making RDP connections to external IPs.
        # ------------------------------------------------------------------
        if (
            direction != "in"
            and dst_port == 3389
            and _is_internal_ip(src_ip)
            and not _is_internal_ip(dst_ip)
        ):
            flags.append({
                "flag_type": "sigma_firewall",
                "details": {
                    "rule": "outbound_rdp",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol or "unknown",
                    "action": action,
                    "description": "Outbound RDP to external host",
                },
                "timestamp": ts,
            })

        # ------------------------------------------------------------------
        # Rule 1b: Cleartext internal-to-internal exclusion already handled
        # above (Rule 1 only fires on cleartext ports, not all high ports).
        #
        # NOTE: Rule 4 (dns_nonstandard_port) REMOVED — it flagged ALL
        # TCP/UDP traffic on ports >1024, generating ~1,300 false alerts/week.
        # DNS tunneling is properly covered by dns_tunnel_detector.py and
        # sigma_dns.py (dns_doh_bypass rule).
        # ------------------------------------------------------------------

        return flags

    def get_stats(self) -> Dict[str, Any]:
        """Return current detection statistics."""
        return {
            "last_results_count": len(self._last_results),
        }
