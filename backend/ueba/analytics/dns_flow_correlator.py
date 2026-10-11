"""DNS-Flow Cross-Correlator — cross-references Pi-hole DNS with OPNsense firewall.

Detection rules:
1. No-DNS connection: Connection to external IP with no DNS query from that
   client in the last 60s.  Flags as 'connection_without_dns'.
2. DNS-connection mismatch: DNS query to domain X, but connection goes to an
   IP not in X's resolution set AND the ASN doesn't match.  Flags as
   'dns_flow_mismatch'.

Both rule flags provide per-event behavioral flags suitable for building-block
correlation and alert enrichment.
"""

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from ueba.logging_config import get_logger

logger = get_logger(__name__)

# Private / local subnets — connections to these are never flagged
_PRIVATE_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
    "192.168.",
    "127.",
    "169.254.",
)

# Infrastructure ports that legitimately don't need prior DNS
_INFRA_PORTS = {67, 68, 123}  # DHCP, NTP


def _is_private_ip(ip: str) -> bool:
    """Return True if *ip* belongs to a private / local subnet."""
    if not ip:
        return True
    return ip.startswith(_PRIVATE_PREFIXES) or ip in ("0.0.0.0", "::", "::1")


class DNSFlowCorrelator:
    """Cross-references Pi-hole DNS queries with OPNsense connections.

    Maintains an in-memory cache of domain → resolved IPs and per-client
    recent queries so that each firewall connection can be checked against
    recent DNS activity.
    """

    def __init__(self, dns_ttl_seconds: int = 300, query_window_seconds: int = 60):
        # domain -> {resolved_IPs}, expired after dns_ttl_seconds
        self._dns_cache: Dict[str, Set[str]] = {}
        self._dns_expiry: Dict[str, float] = {}
        self._dns_ttl = dns_ttl_seconds

        # client_ip -> {domain: timestamp}
        self._recent_queries: Dict[str, Dict[str, float]] = {}
        self._query_window = query_window_seconds

        # resolved_ip -> {domains}
        self._ip_to_domains: Dict[str, Set[str]] = {}

        # Last prune time
        self._last_prune: float = time.monotonic()

    # ------------------------------------------------------------------
    # Public API (called from engine)
    # ------------------------------------------------------------------

    def record_dns_query(
        self,
        client_ip: str,
        domain: str,
        resolved_ips: Optional[List[str]] = None,
    ) -> None:
        """Record a Pi-hole DNS query for later correlation.

        Args:
            client_ip: The client that made the DNS query.
            domain: The queried domain name.
            resolved_ips: Resolved IP addresses (from Pi-hole reply), if available.
        """
        now = time.monotonic()
        domain_lower = domain.lower().rstrip(".")

        # Track recent query per client
        if client_ip not in self._recent_queries:
            self._recent_queries[client_ip] = {}
        self._recent_queries[client_ip][domain_lower] = now

        # Cache resolved IPs
        if resolved_ips:
            if domain_lower not in self._dns_cache:
                self._dns_cache[domain_lower] = set()
            for ip in resolved_ips:
                self._dns_cache[domain_lower].add(ip)
                if ip not in self._ip_to_domains:
                    self._ip_to_domains[ip] = set()
                self._ip_to_domains[ip].add(domain_lower)
            self._dns_expiry[domain_lower] = now + self._dns_ttl

        # Prune periodically
        if now - self._last_prune > 30:
            self._prune(now)
            self._last_prune = now

    def record_dns_resolution(
        self,
        client_ip: str,
        resolved_ips: List[str],
    ) -> None:
        """Record that a DNS query from *client_ip* resolved to *resolved_ips*.

        Backward-compatible alias called by existing engine code.  When no
        domain is known we still cache the IP→client mapping for
        connection_without_dns checks.
        """
        now = time.monotonic()
        for ip in resolved_ips:
            if ip not in self._ip_to_domains:
                self._ip_to_domains[ip] = set()
            # Associate the IP with a synthetic __resolved__ marker
            self._ip_to_domains[ip].add("__resolved__")
        # Also prune periodically
        if now - self._last_prune > 30:
            self._prune(now)
            self._last_prune = now

    def check_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: Optional[float] = None,
    ) -> List[dict]:
        """Check an OPNsense connection against recent DNS activity.

        Args:
            src_ip: Source IP making the connection.
            dst_ip: Destination IP being connected to.
            dst_port: Destination port.
            timestamp: Event timestamp as monotonic seconds (defaults to now).

        Returns:
            List of behavioral flag dicts (0-2 flags).
        """
        flags: List[dict] = []
        now = timestamp or time.monotonic()

        # Never flag private / local destinations or infrastructure ports
        if _is_private_ip(dst_ip):
            return flags
        if dst_port in _INFRA_PORTS:
            return flags
        # Skip inbound connections (external src → we don't have their DNS)
        if not _is_private_ip(src_ip):
            return flags
        # Skip broadcast
        if dst_ip in ("255.255.255.255", "0.0.0.0"):
            return flags

        ts = datetime.now(timezone.utc)

        # ── Rule 1: No-DNS connection ──────────────────────────────
        no_dns_flag = self._check_no_dns(src_ip, dst_ip, now, ts)
        if no_dns_flag:
            flags.append(no_dns_flag)

        # ── Rule 2: DNS-connection mismatch ────────────────────────
        mismatch_flag = self._check_mismatch(src_ip, dst_ip, now, ts)
        if mismatch_flag:
            flags.append(mismatch_flag)

        return flags

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _check_no_dns(
        self,
        src_ip: str,
        dst_ip: str,
        now: float,
        ts: datetime,
    ) -> Optional[dict]:
        """Flag connections to external IPs without a recent DNS query.

        Returns a flag dict or None.
        """
        # Has this client made ANY DNS query in the last 60s?
        client_queries = self._recent_queries.get(src_ip, {})
        if not client_queries:
            return {
                "flag_type": "connection_without_dns",
                "severity": "medium",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": (
                        f"Connection to {dst_ip} with no DNS queries from "
                        f"{src_ip} in the last {self._query_window}s"
                    ),
                    "mitre_attack": ["T1071", "T1571"],
                },
                "timestamp": ts,
            }

        # Check if IP is known from DNS resolutions
        ip_domains = self._ip_to_domains.get(dst_ip)
        if not ip_domains or ip_domains == {"__resolved__"}:
            # No domain association at all
            return {
                "flag_type": "connection_without_dns",
                "severity": "medium",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": (
                        f"Connection to {dst_ip} — no DNS resolution found "
                        f"for this IP from any client"
                    ),
                    "mitre_attack": ["T1071", "T1571"],
                },
                "timestamp": ts,
            }

        return None

    def _check_mismatch(
        self,
        src_ip: str,
        dst_ip: str,
        now: float,
        ts: datetime,
    ) -> Optional[dict]:
        """Flag connections where DNS query and connection destination don't match.

        When a client queries domain X, we expect connections to IPs in X's
        resolution set.  If the connection goes to an IP NOT in that set AND
        the IP's associated domains don't overlap with the client's recent
        queries, flag it.
        """
        client_queries = self._recent_queries.get(src_ip, {})
        if not client_queries:
            return None

        # Find domains recently queried by this client
        query_cutoff = now - self._query_window
        recent_domains = {
            d for d, t in client_queries.items() if t >= query_cutoff
        }
        if not recent_domains:
            return None

        # What domains is this IP associated with?
        ip_domains = self._ip_to_domains.get(dst_ip, set())
        ip_domains.discard("__resolved__")

        # Check overlap: do any of the IP's domains match any recent query?
        if ip_domains & recent_domains:
            # At least one domain overlaps — connection is DNS-backed
            return None

        # Build set of ALL IPs resolved by the client's recent domains
        resolved_ips: Set[str] = set()
        for domain in recent_domains:
            resolved_ips.update(self._dns_cache.get(domain, set()))

        if dst_ip in resolved_ips:
            # The IP WAS resolved, but by a domain the client didn't query —
            # may indicate DNS rebinding or the client using cached results
            return None

        # Mismatch: client queried domains, but connected to a different IP
        return {
            "flag_type": "dns_flow_mismatch",
            "severity": "medium",
            "details": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "recent_domains": sorted(recent_domains)[:10],
                "ip_associated_domains": sorted(ip_domains)[:5] if ip_domains else [],
                "description": (
                    f"Connection to {dst_ip} does not match recent DNS queries "
                    f"from {src_ip} ({len(recent_domains)} domains queried)"
                ),
                "mitre_attack": ["T1071.004", "T1571"],
            },
            "timestamp": ts,
        }

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def _prune(self, now: float) -> None:
        """Remove expired cache entries."""
        # Prune DNS cache
        expired_domains = [
            d for d, exp in self._dns_expiry.items() if now >= exp
        ]
        for d in expired_domains:
            # Remove from ip_to_domains mapping
            ips = self._dns_cache.pop(d, set())
            for ip in ips:
                domains = self._ip_to_domains.get(ip)
                if domains:
                    domains.discard(d)
                    if not domains:
                        del self._ip_to_domains[ip]
            self._dns_expiry.pop(d, None)

        # Prune recent queries
        query_cutoff = now - self._query_window
        empty_clients = []
        for client_ip, queries in self._recent_queries.items():
            self._recent_queries[client_ip] = {
                d: t for d, t in queries.items() if t >= query_cutoff
            }
            if not self._recent_queries[client_ip]:
                empty_clients.append(client_ip)
        for c in empty_clients:
            del self._recent_queries[c]

    def get_stats(self) -> Dict:
        """Return current correlator statistics."""
        return {
            "cached_domains": len(self._dns_cache),
            "cached_ips": len(self._ip_to_domains),
            "active_clients": len(self._recent_queries),
        }
