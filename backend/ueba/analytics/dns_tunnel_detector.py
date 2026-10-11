"""DNS tunnel detection.

Detects DNS tunneling (iodine, dns2tcp, dnscat) by analyzing per-source-IP
DNS query patterns. DNS tunneling encodes data into DNS query subdomains,
creating many unique subdomains under a single parent domain.

This is DIFFERENT from DGA detection (which detects random domain NAMES via
entropy). DNS tunneling analyzes query VOLUME, SUBDOMAIN UNIQUENESS, and
PARENT DOMAIN CONCENTRATION.

Algorithm per source IP sliding window (60s):
1. Collect all DNS queries from each client IP
2. Build subdomain analysis per parent domain:
   - Count unique subdomains
   - Compute subdomain length statistics
3. Flag when ALL conditions are met:
   - >150 queries/window
   - >90% unique subdomains
   - >80% concentrated on single parent domain

Based on the Nemea tunnel_detection_dns algorithm.
"""

import time
import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set, Tuple

from sqlalchemy import select

from ueba.logging_config import get_logger
from ueba.database import async_session_factory
from ueba.models import PiHoleQuery
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)

# Detection thresholds
TUNNEL_MIN_QUERIES = 150
TUNNEL_UNIQUE_RATIO = 0.90
TUNNEL_CONCENTRATION_RATIO = 0.80
TUNNEL_WINDOW_SEC = 60

# Minimum subdomain length to consider as encoded data
MIN_ENCODED_SUBDOMAIN_LEN = 8

# Well-known DNS tunnel tools parent domain signatures
KNOWN_TUNNEL_DOMAINS = {
    "iodine", "tunnel.com", "dns2tcp", "dnscat",
}


class DnsTunnelDetector(BaseAnomalyDetector):
    """Per-event DNS tunnel detection.

    Operates in the Pi-hole event pipeline, maintaining per-source-IP
    sliding windows of DNS queries. Also supports batch detection via
    ``detect()`` by querying recent PiHoleQuery records from the database.
    """

    def __init__(
        self,
        min_queries: int = TUNNEL_MIN_QUERIES,
        unique_ratio: float = TUNNEL_UNIQUE_RATIO,
        concentration_ratio: float = TUNNEL_CONCENTRATION_RATIO,
        window_seconds: int = TUNNEL_WINDOW_SEC,
        lookback_hours: int = 1,
    ):
        self.min_queries = min_queries
        self.unique_ratio = unique_ratio
        self.concentration_ratio = concentration_ratio
        self.window_seconds = window_seconds
        self._lookback_hours = lookback_hours

        # Per-source-IP sliding window: src_ip -> list of (timestamp, domain)
        self._windows: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

        # Cooldown per (src_ip, parent_domain) to avoid repeated alerts
        self._alert_cooldown: Dict[Tuple[str, str], float] = {}
        self._cooldown_seconds = 300  # 5 minutes

        self._last_prune: float = time.monotonic()

        # Phase 2a: Query size anomaly tracking per client
        # {client_ip: {"sum_len": float, "sum_len_sq": float, "count": int, "window_start": float}}
        self._query_stats: Dict[str, Dict[str, Any]] = {}
        self._query_size_window_seconds = 3600  # 1 hour
        self._query_size_min_count = 20
        self._query_size_mean_threshold = 30.0  # chars
        self._query_size_var_threshold = 50.0

        # Phase 2b: Character frequency tracking per client
        # {client_ip: {"hex_count": int, "total_chars": int, "unique_chars": set, "batch_queries": int, "window_start": float}}
        self._char_freq_stats: Dict[str, Dict[str, Any]] = {}
        self._char_freq_window_seconds = 300  # 5 min
        self._char_freq_hex_ratio_threshold = 0.7
        self._char_freq_unique_chars_threshold = 20
        self._char_freq_min_queries = 10

        # BaseAnomalyDetector state
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None

    def analyze_query(
        self,
        client_ip: str,
        domain: str,
        query_type: str = "A",
        blocked: bool = False,
        timestamp: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Analyze a single DNS query for tunnel patterns.

        Args:
            client_ip: Client IP making the query.
            domain: Queried domain name.
            query_type: DNS query type.
            blocked: Whether Pi-hole blocked the query.
            timestamp: Event timestamp.

        Returns:
            List of behavioral flag dicts when tunneling is detected.
        """
        if not domain or not client_ip:
            return []
        if query_type.upper() not in ("A", "AAAA", "CNAME", "TXT", "MX", "NS", "NULL"):
            # Non-standard query types can also indicate tunneling
            pass  # Still process, NULL/TXT records are common tunnel vectors

        ts = timestamp or datetime.now(timezone.utc)
        now = time.monotonic()

        # Add query to sliding window
        self._windows[client_ip].append((now, domain))

        # Prune expired entries periodically
        if now - self._last_prune > 10:
            self._prune(now)
            self._last_prune = now

        # Phase 2a: Query size anomaly (runs before window check)
        size_flag = self._check_query_size_anomaly(client_ip, domain)
        if size_flag:
            size_flag["timestamp"] = ts

        # Phase 2b: Character frequency anomaly (runs before window check)
        char_flag = self._check_char_frequency(client_ip, domain)
        if char_flag:
            char_flag["timestamp"] = ts

        # Build result list
        result_flags: List[Dict[str, Any]] = []
        if size_flag:
            result_flags.append(size_flag)
        if char_flag:
            result_flags.append(char_flag)

        # Check if window is large enough for main tunnel detection
        window = self._windows[client_ip]
        if len(window) < self.min_queries:
            return result_flags

        window_flags = self._check_window(client_ip, window, ts)
        return result_flags + window_flags

    def _check_window(
        self,
        client_ip: str,
        window: List[Tuple[float, str]],
        ts: datetime,
    ) -> List[Dict[str, Any]]:
        """Check a source-IP window for DNS tunneling indicators."""
        now = time.monotonic()
        flags: List[Dict[str, Any]] = []

        # Group queries by parent domain (second-level domain + TLD)
        parent_domains: Dict[str, List[str]] = defaultdict(list)
        for _, domain in window:
            parent = self._get_parent_domain(domain)
            parent_domains[parent].append(domain)

        # Need enough parent domains to compute concentration
        if not parent_domains:
            return flags

        total_queries = len(window)
        unique_domains = len(set(d for _, d in window))
        unique_ratio = unique_domains / total_queries if total_queries > 0 else 0

        # Find the most common parent domain
        best_parent = max(parent_domains, key=lambda p: len(parent_domains[p]))
        best_parent_count = len(parent_domains[best_parent])
        concentration = best_parent_count / total_queries if total_queries > 0 else 0

        # Conditions for DNS tunneling:
        # 1. High query volume
        # 2. Mostly unique subdomains (encoded data)
        # 3. Concentrated on a single parent domain
        if (
            total_queries >= self.min_queries
            and unique_ratio >= self.unique_ratio
            and concentration >= self.concentration_ratio
        ):
            # Check cooldown
            cooldown_key = (client_ip, best_parent)
            if cooldown_key in self._alert_cooldown:
                return flags

            # Analyze subdomain characteristics
            subdomains = parent_domains[best_parent]
            subdomain_lengths = [len(s) for s in subdomains]
            avg_len = sum(subdomain_lengths) / len(subdomain_lengths) if subdomain_lengths else 0
            max_len = max(subdomain_lengths) if subdomain_lengths else 0

            # Count subdomains with suspiciously long labels (potential encoded data)
            long_subdomains = sum(
                1 for s in subdomains if len(s) >= MIN_ENCODED_SUBDOMAIN_LEN
            )

            # Entropy check on subdomain characters
            subdomain_entropy = self._subdomain_entropy(subdomains)

            self._alert_cooldown[cooldown_key] = time.monotonic()

            flags.append({
                "flag_type": "dns_tunnel",
                "details": {
                    "client_ip": client_ip,
                    "parent_domain": best_parent,
                    "total_queries": total_queries,
                    "unique_queries": unique_domains,
                    "unique_ratio": round(unique_ratio, 4),
                    "concentration": round(concentration, 4),
                    "avg_subdomain_len": round(avg_len, 2),
                    "max_subdomain_len": max_len,
                    "long_subdomains_count": long_subdomains,
                    "subdomain_entropy": round(subdomain_entropy, 4),
                    "window_seconds": self.window_seconds,
                    "description": (
                        f"DNS tunnel detected: {total_queries} queries in "
                        f"{self.window_seconds}s, {round(unique_ratio*100)}% unique, "
                        f"{round(concentration*100)}% to {best_parent}"
                    ),
                },
                "timestamp": ts,
            })

            # Reset window for this IP to avoid repeated alerts
            self._windows[client_ip] = []

        return flags

    def _prune(self, now: float) -> None:
        """Remove expired entries from all windows."""
        cutoff = now - self.window_seconds

        # Prune query windows
        empty_sources = []
        for src_ip, window in self._windows.items():
            self._windows[src_ip] = [(t, d) for t, d in window if t >= cutoff]
            if not self._windows[src_ip]:
                empty_sources.append(src_ip)
        for src_ip in empty_sources:
            del self._windows[src_ip]

        # Prune alert cooldowns
        cooldown_cutoff = now - self._cooldown_seconds
        expired = [
            key for key, t in self._alert_cooldown.items() if t < cooldown_cutoff
        ]
        for key in expired:
            del self._alert_cooldown[key]

    # ------------------------------------------------------------------
    # Phase 2a: DNS Query Size Anomaly (NEMEA-style)
    # ------------------------------------------------------------------

    def _check_query_size_anomaly(
        self, client_ip: str, domain: str
    ) -> Optional[Dict[str, Any]]:
        """Flag per-client DNS query size anomalies.

        Uses online Welford-style incremental mean/variance over a
        1-hour rolling window.  Tunneled DNS queries are uniformly long
        (encoding data in subdomains), so high mean + low variance
        indicates exfiltration.
        """
        now = time.monotonic()
        query_len = len(domain)

        if client_ip not in self._query_stats:
            self._query_stats[client_ip] = {
                "sum_len": 0.0,
                "sum_len_sq": 0.0,
                "count": 0,
                "window_start": now,
            }

        stats = self._query_stats[client_ip]

        # Reset if window has expired
        if now - stats["window_start"] > self._query_size_window_seconds:
            stats["sum_len"] = 0.0
            stats["sum_len_sq"] = 0.0
            stats["count"] = 0
            stats["window_start"] = now

        # Update running stats
        stats["sum_len"] += query_len
        stats["sum_len_sq"] += query_len * query_len
        stats["count"] += 1

        n = stats["count"]
        if n < self._query_size_min_count:
            return None

        # Mean (EX)
        mean_len = stats["sum_len"] / n

        if mean_len <= self._query_size_mean_threshold:
            return None

        # Variance (VAR = E[X²] - E[X]²)
        mean_sq = stats["sum_len_sq"] / n
        variance = max(0.0, mean_sq - mean_len * mean_len)

        if variance < self._query_size_var_threshold:
            # Reset stats after flagging to avoid repeated alerts
            stats["sum_len"] = 0.0
            stats["sum_len_sq"] = 0.0
            stats["count"] = 0
            stats["window_start"] = now

            return {
                "flag_type": "dns_query_size_anomaly",
                "details": {
                    "client_ip": client_ip,
                    "mean_query_length": round(mean_len, 2),
                    "variance": round(variance, 2),
                    "query_count": n,
                    "threshold_mean": self._query_size_mean_threshold,
                    "threshold_variance": self._query_size_var_threshold,
                    "description": (
                        f"DNS query size anomaly: mean={mean_len:.1f} chars, "
                        f"variance={variance:.1f} over {n} queries "
                        f"(indicates uniformly long tunneled queries)"
                    ),
                },
                "timestamp": datetime.now(timezone.utc),
            }

        return None

    # ------------------------------------------------------------------
    # Phase 2b: Character Frequency Analysis
    # ------------------------------------------------------------------

    def _check_char_frequency(
        self, client_ip: str, domain: str
    ) -> Optional[Dict[str, Any]]:
        """Flag per-client DNS queries with high hex character ratio.

        DNS tunnels that use hex-encoded data produce subdomain labels
        dominated by 0-9,a-f characters with high character diversity.
        """
        now = time.monotonic()

        if client_ip not in self._char_freq_stats:
            self._char_freq_stats[client_ip] = {
                "hex_count": 0,
                "total_chars": 0,
                "unique_chars": set(),
                "batch_queries": 0,
                "window_start": now,
            }

        stats = self._char_freq_stats[client_ip]

        # Reset if window has expired
        if now - stats["window_start"] > self._char_freq_window_seconds:
            stats["hex_count"] = 0
            stats["total_chars"] = 0
            stats["unique_chars"] = set()
            stats["batch_queries"] = 0
            stats["window_start"] = now

        # Extract subdomain labels (ignore TLD)
        parts = domain.rstrip(".").split(".")
        # All parts except the last (TLD) and possibly second-last (SLD)
        subdomain_labels = parts[:-2] if len(parts) > 2 else parts[:-1] if len(parts) > 1 else []

        hex_chars = set("0123456789abcdef")
        for label in subdomain_labels:
            lower = label.lower()
            for ch in lower:
                stats["total_chars"] += 1
                stats["unique_chars"].add(ch)
                if ch in hex_chars:
                    stats["hex_count"] += 1

        stats["batch_queries"] += 1

        if stats["batch_queries"] < self._char_freq_min_queries:
            return None

        total_chars = stats["total_chars"]
        if total_chars == 0:
            return None

        hex_ratio = stats["hex_count"] / total_chars
        unique_chars = len(stats["unique_chars"])

        if (
            hex_ratio > self._char_freq_hex_ratio_threshold
            and unique_chars > self._char_freq_unique_chars_threshold
        ):
            # Reset after flagging
            stats["hex_count"] = 0
            stats["total_chars"] = 0
            stats["unique_chars"] = set()
            stats["batch_queries"] = 0
            stats["window_start"] = now

            return {
                "flag_type": "dns_char_frequency_anomaly",
                "details": {
                    "client_ip": client_ip,
                    "hex_ratio": round(hex_ratio, 4),
                    "unique_chars": unique_chars,
                    "total_chars": total_chars,
                    "query_count": stats["batch_queries"],
                    "threshold_hex_ratio": self._char_freq_hex_ratio_threshold,
                    "threshold_unique_chars": self._char_freq_unique_chars_threshold,
                    "description": (
                        f"DNS character frequency anomaly: {hex_ratio:.2%} hex chars, "
                        f"{unique_chars} unique chars in {stats['batch_queries']} queries "
                        f"(hex-encoded tunnel data suspected)"
                    ),
                },
                "timestamp": datetime.now(timezone.utc),
            }

        return None

    @staticmethod
    def _get_parent_domain(domain: str) -> str:
        """Extract the parent domain (second-level + TLD) from a full domain.

        Examples:
            abc.def.example.com -> example.com
            data.tunnel.server.net -> server.net
            example.co.uk -> example.co.uk
        """
        parts = domain.rstrip(".").split(".")
        if len(parts) <= 2:
            return domain.lower()

        # Common two-part TLDs (country codes + second-level)
        two_part_tlds = {
            "co.uk", "co.jp", "co.kr", "co.in", "com.au", "net.au", "org.au",
            "com.br", "net.br", "org.br", "co.nz", "net.nz", "org.nz",
            "co.za", "web.za", "ac.uk", "gov.uk", "mod.uk", "nhs.uk",
            "com.cn", "net.cn", "org.cn", "com.tw", "net.tw", "org.tw",
        }
        if len(parts) >= 3:
            potential_tld = ".".join(parts[-2:]).lower()
            if potential_tld in two_part_tlds:
                return ".".join(parts[-3:]).lower()

        return ".".join(parts[-2:]).lower()

    @staticmethod
    def _subdomain_entropy(subdomains: List[str]) -> float:
        """Compute character-level Shannon entropy across subdomains."""
        import math
        char_counts: Dict[str, int] = defaultdict(int)
        total_chars = 0
        for s in subdomains:
            for ch in s:
                char_counts[ch] += 1
                total_chars += 1
        if total_chars == 0:
            return 0.0
        entropy = 0.0
        for count in char_counts.values():
            p = count / total_chars
            entropy -= p * math.log2(p)
        return entropy

    # ------------------------------------------------------------------
    # BaseAnomalyDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "dns_tunnel"

    @property
    def description(self) -> str:
        return (
            "DNS tunnel detector — analyzes per-source-IP DNS query patterns "
            "for high-volume, high-unique-subdomain, single-parent-domain "
            "traffic indicative of DNS tunneling tools (iodine, dns2tcp, dnscat)."
        )

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    async def detect(self) -> List[AnomalyResult]:
        """Run batch detection on recent PiHoleQuery records.

        Queries the database for DNS queries within the lookback window,
        feeds them through ``analyze_query()`` in chronological order, and
        returns ``AnomalyResult`` objects for any detected tunnels.

        Returns:
            List of AnomalyResult for source IPs flagged as DNS tunnels.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)

        rows: List[Dict[str, Any]] = []
        try:
            async with async_session_factory() as session:
                stmt = (
                    select(
                        PiHoleQuery.client_ip,
                        PiHoleQuery.queried_domain,
                        PiHoleQuery.query_type,
                        PiHoleQuery.blocked,
                        PiHoleQuery.timestamp,
                    )
                    .where(PiHoleQuery.timestamp >= cutoff)
                    .order_by(PiHoleQuery.timestamp.asc())
                )
                result = await session.execute(stmt)
                raw_rows = result.all()
                rows = [
                    {
                        "client_ip": r.client_ip,
                        "domain": r.queried_domain,
                        "query_type": r.query_type or "A",
                        "blocked": bool(r.blocked),
                        "timestamp": r.timestamp,
                    }
                    for r in raw_rows
                ]
        except Exception as e:
            logger.error("Failed to fetch PiHoleQuery rows for tunnel detection", extra={
                "extra_data": {"error": str(e)}
            })
            return []

        if not rows:
            self._last_results = []
            self._last_run = datetime.now(timezone.utc)
            return []

        # Feed each row through analyze_query in chronological order
        results: List[AnomalyResult] = []
        seen: Set[Tuple[str, str]] = set()  # dedup by (client_ip, parent_domain)

        for row in rows:
            flags = self.analyze_query(
                client_ip=row["client_ip"],
                domain=row["domain"],
                query_type=row["query_type"],
                blocked=row["blocked"],
                timestamp=row["timestamp"],
            )
            for flag in flags:
                details = flag.get("details", {})
                client_ip = details.get("client_ip", "")
                parent_domain = details.get("parent_domain", "")

                # Dedup within this batch run
                dedup_key = (client_ip, parent_domain)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Score: blend of unique_ratio and concentration, clamped to 0-1
                score = min(1.0, (
                    details.get("unique_ratio", 0) * 0.5
                    + details.get("concentration", 0) * 0.3
                    + min(1.0, details.get("total_queries", 0) / self.min_queries) * 0.2
                ))

                results.append(AnomalyResult(
                    ip=client_ip,
                    score=round(score, 4),
                    details={
                        "detector_name": self.name,
                        "flag_type": flag.get("flag_type", "dns_tunnel"),
                        "parent_domain": parent_domain,
                        "total_queries": details.get("total_queries"),
                        "unique_queries": details.get("unique_queries"),
                        "unique_ratio": details.get("unique_ratio"),
                        "concentration": details.get("concentration"),
                        "avg_subdomain_len": details.get("avg_subdomain_len"),
                        "max_subdomain_len": details.get("max_subdomain_len"),
                        "long_subdomains_count": details.get("long_subdomains_count"),
                        "subdomain_entropy": details.get("subdomain_entropy"),
                        "window_seconds": details.get("window_seconds"),
                        "description": details.get("description"),
                    },
                    detector_name=self.name,
                ))

        self._last_results = results
        self._last_run = datetime.now(timezone.utc)

        if results:
            logger.info("DNS tunnel detected (batch)", extra={
                "extra_data": {
                    "tunnels": len(results),
                    "top_client": results[0].ip,
                    "top_domain": results[0].details.get("parent_domain"),
                }
            })

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Return current detection statistics."""
        return {
            "active_sources": len(self._windows),
            "total_queued_queries": sum(len(w) for w in self._windows.values()),
            "alert_cooldowns": len(self._alert_cooldown),
        }
