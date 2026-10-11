"""Behavioral anomaly detectors.

Flags:
- Unusual outbound traffic volume
- New geo/ASN connections
- High-entropy DNS (DGA detection)
- Repeated blocked queries
- Port scanning patterns
- Beaconing behavior
"""
import math
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple

from ueba.logging_config import get_logger
from ueba.config import get_config
from ueba.netconfig import dns_burst_whitelist, gateway_ips, is_internal
from ueba.analytics.baseline import NetworkBaseline

logger = get_logger(__name__)


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


_VOWELS = set("aeiou")


def _dga_score(name: str) -> float:
    """Score how likely a domain label is algorithmically generated (0-1).

    Combines three signals:
    - digit_ratio: DGA domains mix digits with letters
    - consonant_run: DGA has long runs of consonants without vowels
    - bigram_unusualness: DGA lacks common English letter pairs
    """
    if not name:
        return 0.0
    lower = name.lower()
    alpha = [c for c in lower if c.isalpha()]
    digits = sum(1 for c in lower if c.isdigit())

    digit_ratio = digits / len(lower) if lower else 0
    vowel_ratio = sum(1 for c in alpha if c in _VOWELS) / len(alpha) if alpha else 0

    max_consonant_run = 0
    run = 0
    for c in lower:
        if c.isalpha() and c not in _VOWELS:
            run += 1
            max_consonant_run = max(max_consonant_run, run)
        else:
            run = 0

    score = 0.0
    if digit_ratio > 0.2:
        score += 0.4
    if vowel_ratio < 0.15:
        score += 0.3
    if max_consonant_run >= 4:
        score += 0.2
    if len(lower) <= 12 and digit_ratio > 0:
        score += 0.1
    return min(score, 1.0)


def is_high_entropy_domain(domain: str, threshold: float = 3.5) -> bool:
    """Check if a domain looks algorithmically generated (DGA).

    Uses entropy plus structural checks (digit mixing, consonant clusters,
    vowel absence) to distinguish real DGA from long English compound words.
    """
    if not domain:
        return False
    name = domain.rsplit(".", 1)[0] if "." in domain else domain
    if len(name) < 8:
        return False
    entropy = shannon_entropy(name)
    dga = _dga_score(name)
    # High entropy alone isn't enough — require structural DGA indicators
    return (entropy > threshold and dga >= 0.3) or dga >= 0.6




def is_destination_reputable(enrichment: dict, feed_manager=None) -> bool:
    """Check if a destination IP belongs to a known legitimate organization.

    Uses the Tranco top-1M domain list (already loaded) to check the reverse DNS
    hostname. If the rDNS resolves to a domain in Tranco, the destination is a
    known company — not a threat indicator.
    """
    if not enrichment:
        return False
    rdns = enrichment.get("reverse_dns") or ""
    if rdns and feed_manager:
        if feed_manager.is_domain_reputable(rdns):
            return True
    return False


class BehavioralDetector:
    """Detects behavioral anomalies across all events."""

    def __init__(self, baseline: NetworkBaseline):
        self.config = get_config()
        self.baseline = baseline
        
        # Volume tracking: {src_ip: {minute_bucket: byte_count}}
        self.volume_tracker: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # Blocked query tracking: {client_ip: {domain: count}}
        self.blocked_queries: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # Port scan tracking: {(src_ip, dst_ip): (set of novel ports, last_activity)}
        self._port_scan_novel: Dict[Tuple[str, str], Tuple[set, datetime]] = {}
        # Beaconing: tracked via baseline.connection_times
        # Destination fan-out: {src_ip: {minute_bucket: set of unique dst_ips}}
        self.dest_fanout: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
        # Pi-hole: unique domain queries per client per 5-min window
        self.dns_query_burst: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
        # Pi-hole: non-Tranco domain queries per client per 5-min window
        self.dns_unknown_domains: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))

        # Sustained high-frequency connection tracking
        self._sustained_conns: Dict[Tuple[str, str], deque] = {}
        # Cryptominer flow profile tracking
        self._miner_tracking: Dict[Tuple[str, str], dict] = {}
        # Outbound blocked ratio: {src_ip: {bucket: {"pass": n, "block": n}}}
        self._outbound_actions: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: {"pass": 0, "block": 0}))
        # Internal lateral movement: {(src_ip, dst_ip): set of dst_ports}
        self._lateral_ports: Dict[Tuple[str, str], set] = {}

        self.thresholds = self.config.analytics.thresholds
        self._last_prune = datetime.now(timezone.utc)

    def prune_stale_state(self):
        """Remove stale entries from all tracking dicts. Call periodically."""
        now = datetime.now(timezone.utc)
        if (now - self._last_prune).total_seconds() < 300:
            return
        self._last_prune = now

        current_bucket = self._get_minute_bucket(now)
        cutoff_bucket = self._get_minute_bucket(now - timedelta(minutes=10))
        cutoff_5m = self._get_5min_bucket(now - timedelta(minutes=30))

        for tracker in (self.volume_tracker, self.dest_fanout):
            for ip in list(tracker.keys()):
                pruned = {k: v for k, v in tracker[ip].items() if k >= cutoff_bucket}
                tracker[ip].clear()
                tracker[ip].update(pruned)
                if not tracker[ip]:
                    del tracker[ip]

        for tracker in (self.dns_query_burst, self.dns_unknown_domains):
            for ip in list(tracker.keys()):
                pruned = {k: v for k, v in tracker[ip].items() if k >= cutoff_5m}
                tracker[ip].clear()
                tracker[ip].update(pruned)
                if not tracker[ip]:
                    del tracker[ip]

        for ip in list(self.blocked_queries.keys()):
            if len(self.blocked_queries[ip]) > 500:
                top = sorted(self.blocked_queries[ip].items(), key=lambda x: -x[1])[:100]
                self.blocked_queries[ip] = dict(top)

        stale_cutoff = now - timedelta(hours=6)
        for key in list(self._sustained_conns.keys()):
            dq = self._sustained_conns[key]
            if dq and dq[-1][0] < stale_cutoff:
                del self._sustained_conns[key]

        for key in list(self._miner_tracking.keys()):
            entry = self._miner_tracking[key]
            if entry.get("last_seen") and entry["last_seen"] < stale_cutoff:
                del self._miner_tracking[key]

        for ip in list(self._outbound_actions.keys()):
            pruned = {k: v for k, v in self._outbound_actions[ip].items()
                      if k >= cutoff_5m}
            self._outbound_actions[ip].clear()
            self._outbound_actions[ip].update(pruned)
            if not self._outbound_actions[ip]:
                del self._outbound_actions[ip]

        for key in list(self._lateral_ports.keys()):
            if len(self._lateral_ports[key]) == 0:
                del self._lateral_ports[key]

    def _get_minute_bucket(self, timestamp: Optional[datetime] = None) -> str:
        ts = timestamp or datetime.now(timezone.utc)
        return ts.strftime("%Y%m%d%H%M")

    def detect_volume_anomaly(self, src_ip: str, bytes_count: int,
                              timestamp: Optional[datetime] = None) -> Optional[dict]:
        """Flag unusual outbound traffic volume from a single host."""
        if src_ip in gateway_ips():
            return None
        bucket = self._get_minute_bucket(timestamp)
        self.volume_tracker[src_ip][bucket] += bytes_count
        
        total = self.volume_tracker[src_ip][bucket]
        threshold = self.thresholds.outbound_volume_bytes_per_minute
        
        if total > threshold:
            logger.info("Volume anomaly detected", extra={
                "extra_data": {
                    "src_ip": src_ip, "bytes": total, "threshold": threshold
                }
            })
            return {
                "flag_type": "volume",
                "details": {
                    "src_ip": src_ip,
                    "bytes_transferred": total,
                    "threshold": threshold,
                    "minute_bucket": bucket,
                },
                "timestamp": timestamp or datetime.now(timezone.utc),
            }
        return None

    def detect_new_geo_asn(self, src_ip: str, dst_ip: str, asn: Optional[str] = None,
                            country: Optional[str] = None) -> Optional[dict]:
        """Flag connections to new countries or ASNs."""
        flags = []
        
        if asn and self.baseline.is_new_asn(src_ip, asn):
            flags.append(f"new_asn:{asn}")
            self.baseline.record_asn(src_ip, asn)
        
        if country and self.baseline.is_new_country(src_ip, country):
            flags.append(f"new_country:{country}")
            self.baseline.record_country(src_ip, country)
        
        if flags:
            logger.info("New geo/ASN connection", extra={
                "extra_data": {"src_ip": src_ip, "dst_ip": dst_ip, "flags": flags}
            })
            return {
                "flag_type": "geo",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "asn": asn,
                    "country": country,
                    "flags": flags,
                },
                "timestamp": datetime.now(timezone.utc),
            }
        return None

    def detect_high_entropy_dns(self, domain: str, client_ip: str,
                                feed_manager=None) -> Optional[dict]:
        """Flag DNS queries for high-entropy domains (potential DGA).

        Skips domains in Tranco top 1M — high-entropy legitimate domains exist.
        """
        if not domain:
            return None
        if client_ip in dns_burst_whitelist():
            return None
        # RFC 2606/6761 reserved TLDs are guaranteed-NXDOMAIN connectivity/test
        # probes (e.g. "<uuid>.invalid" captive-portal checks) — high entropy by
        # construction, never DGA. The ML classifier already skips .arpa.
        _tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        if _tld in ("invalid", "test", "localhost", "example", "arpa"):
            return None
        if feed_manager and feed_manager.is_domain_reputable(domain):
            return None

        name = domain.rsplit(".", 1)[0] if "." in domain else domain
        if len(name) < 8:
            return None
        entropy = shannon_entropy(name)
        threshold = self.thresholds.high_entropy_shannon_threshold
        dga = _dga_score(name)

        is_dga = (entropy > threshold and dga >= 0.3) or dga >= 0.6
        if is_dga:
            logger.info("DGA domain detected", extra={
                "extra_data": {
                    "domain": domain, "entropy": round(entropy, 2),
                    "dga_score": round(dga, 2), "client_ip": client_ip
                }
            })
            return {
                "flag_type": "dga",
                "details": {
                    "domain": domain,
                    "entropy": round(entropy, 3),
                    "dga_score": round(dga, 2),
                    "threshold": threshold,
                    "client_ip": client_ip,
                },
                "timestamp": datetime.now(timezone.utc),
            }
        return None

    def detect_repeated_blocked_queries(self, client_ip: str, domain: str) -> Optional[dict]:
        """Flag repeated blocked queries to the same domain from the same client."""
        self.blocked_queries[client_ip][domain] += 1
        count = self.blocked_queries[client_ip][domain]
        threshold = self.thresholds.blocked_query_repeat_threshold
        
        if count >= threshold:
            logger.info("Repeated blocked queries detected", extra={
                "extra_data": {
                    "client_ip": client_ip, "domain": domain, "count": count
                }
            })
            return {
                "flag_type": "blocked_repeat",
                "details": {
                    "client_ip": client_ip,
                    "domain": domain,
                    "count": count,
                    "threshold": threshold,
                },
                "timestamp": datetime.now(timezone.utc),
            }
        return None

    def detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int,
                          timestamp: Optional[datetime] = None) -> Optional[dict]:
        """Flag port scanning patterns — novel-only tracking with toggle-on-repeat.

        Only NOVEL (first-seen) ports are tracked. When a dst_port is seen
        AGAIN for the same (src_ip, dst_ip), it's REMOVED from tracking
        (toggle-on-repeat: repeated = legitimate). Threshold is 50 distinct
        tracked ports. Inactive entries are pruned after 5 minutes.
        """
        if dst_port is None:
            return None

        now = timestamp or datetime.now(timezone.utc)
        key = (src_ip, dst_ip)

        # Prune stale entries before processing
        stale_keys = []
        for k, (_ports, last_ts) in self._port_scan_novel.items():
            if (now - last_ts).total_seconds() > 300:
                stale_keys.append(k)
        for k in stale_keys:
            del self._port_scan_novel[k]

        if key in self._port_scan_novel:
            novel_ports, last_ts = self._port_scan_novel[key]
            if dst_port in novel_ports:
                # Toggle-on-repeat: port seen again = legitimate, remove from tracking
                novel_ports.discard(dst_port)
            else:
                # First time seeing this port — add to novel set
                novel_ports.add(dst_port)
            self._port_scan_novel[key] = (novel_ports, now)
        else:
            self._port_scan_novel[key] = ({dst_port}, now)
            novel_ports = self._port_scan_novel[key][0]

        distinct_ports = len(novel_ports)
        threshold = 50  # Raised from 20 to 50 for novel-only tracking

        if distinct_ports >= threshold:
            logger.info("Port scan detected", extra={
                "extra_data": {
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "distinct_novel_ports": distinct_ports
                }
            })
            # Reset tracking after alert to avoid repeated alerts for same scan
            del self._port_scan_novel[key]
            return {
                "flag_type": "port_scan",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "distinct_ports": distinct_ports,
                    "threshold": threshold,
                },
                "timestamp": now,
            }
        return None

    def detect_beaconing(self, src_ip: str, dst_ip: str,
                          timestamp: Optional[datetime] = None,
                          dst_port: Optional[int] = None) -> Optional[dict]:
        """Flag beaconing behavior - regular-interval callbacks to the same external IP."""
        if dst_port == 53:
            return None
        if dst_ip in gateway_ips() or src_ip in gateway_ips():
            return None
        ts = timestamp or datetime.now(timezone.utc)
        self.baseline.record_connection(src_ip, dst_ip, ts)
        
        times = self.baseline.connection_times.get(src_ip, {}).get(dst_ip, [])
        if len(times) < self.thresholds.beaconing_min_repetitions:
            return None
        
        # Check for regular intervals
        sorted_times = sorted(times[-20:])  # Last 20 connections
        intervals = []
        for i in range(1, len(sorted_times)):
            diff = (sorted_times[i] - sorted_times[i - 1]).total_seconds()
            intervals.append(diff)
        
        if not intervals:
            return None
        
        # Calculate variance of intervals
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 1:  # Too frequent to be meaningful beaconing
            return None
        
        variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        
        tolerance = self.thresholds.beaconing_interval_tolerance_seconds
        
        cv = stddev / mean_interval if mean_interval > 0 else 999
        if cv < 0.5 and stddev < tolerance and len(intervals) >= self.thresholds.beaconing_min_repetitions - 1:
            logger.info("Beaconing detected", extra={
                "extra_data": {
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "mean_interval": round(mean_interval, 1),
                    "stddev": round(stddev, 1),
                    "repetitions": len(intervals),
                }
            })
            return {
                "flag_type": "beaconing",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "mean_interval_seconds": round(mean_interval, 1),
                    "stddev_seconds": round(stddev, 1),
                    "repetitions": len(sorted_times),
                },
                "timestamp": ts,
            }
        return None

    _PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.", "127.", "169.254.")

    def _is_private(self, ip: str) -> bool:
        return ip.startswith(self._PRIVATE_PREFIXES) or ip in ("0.0.0.0", "::", "::1")

    def _get_5min_bucket(self, timestamp: Optional[datetime] = None) -> str:
        ts = timestamp or datetime.now(timezone.utc)
        minute = (ts.minute // 5) * 5
        return ts.strftime(f"%Y%m%d%H{minute:02d}")

    def detect_destination_fanout(self, src_ip: str, dst_ip: str,
                                  timestamp: Optional[datetime] = None) -> Optional[dict]:
        """Flag a host connecting to many unique destinations in a short window.

        Catches data exfil, worm propagation, or compromised hosts scanning outbound.
        """
        if not dst_ip or self._is_private(dst_ip):
            return None
        if src_ip in gateway_ips():
            return None
        bucket = self._get_minute_bucket(timestamp)
        self.dest_fanout[src_ip][bucket].add(dst_ip)
        count = len(self.dest_fanout[src_ip][bucket])
        threshold = getattr(self.thresholds, "dest_fanout_per_minute", 30)
        if count >= threshold:
            return {
                "flag_type": "dest_fanout",
                "details": {
                    "src_ip": src_ip,
                    "unique_destinations": count,
                    "threshold": threshold,
                    "minute_bucket": bucket,
                },
                "timestamp": timestamp or datetime.now(timezone.utc),
            }
        return None

    def detect_outbound_blocked_ratio(self, src_ip: str, action: str,
                                       timestamp: Optional[datetime] = None) -> Optional[dict]:
        """Flag internal hosts with high ratio of blocked outbound connections.

        A compromised host trying to reach C2 will generate many blocked
        outbound attempts when firewall rules deny the traffic.
        """
        if not is_internal(src_ip):
            return None
        if src_ip in gateway_ips():
            return None
        bucket = self._get_5min_bucket(timestamp)
        self._outbound_actions[src_ip][bucket][action] += 1
        counts = self._outbound_actions[src_ip][bucket]
        total = counts["pass"] + counts["block"]
        if total < 20:
            return None
        block_ratio = counts["block"] / total
        if block_ratio > 0.6:
            return {
                "flag_type": "outbound_blocked_ratio",
                "details": {
                    "src_ip": src_ip,
                    "block_ratio": round(block_ratio, 2),
                    "blocked": counts["block"],
                    "passed": counts["pass"],
                    "window": bucket,
                },
                "timestamp": timestamp or datetime.now(timezone.utc),
            }
        return None

    def detect_lateral_movement(self, src_ip: str, dst_ip: str,
                                 dst_port: Optional[int] = None,
                                 timestamp: Optional[datetime] = None) -> Optional[dict]:
        """Flag internal-to-internal connections on many distinct ports.

        Lateral movement (post-compromise host discovery) shows as one internal
        host probing another on many ports — distinct from normal LAN traffic
        which uses a small set of service ports.
        """
        if not src_ip or not dst_ip or dst_port is None:
            return None
        if not (is_internal(src_ip) and is_internal(dst_ip)):
            return None
        if src_ip == dst_ip:
            return None
        key = (src_ip, dst_ip)
        if key not in self._lateral_ports:
            self._lateral_ports[key] = set()
        self._lateral_ports[key].add(dst_port)
        if len(self._lateral_ports[key]) >= 15:
            ports = sorted(self._lateral_ports[key])
            self._lateral_ports[key] = set()
            return {
                "flag_type": "lateral_movement",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "distinct_ports": len(ports),
                    "sample_ports": ports[:20],
                },
                "timestamp": timestamp or datetime.now(timezone.utc),
            }
        return None

    def detect_dns_query_burst(self, client_ip: str, domain: str,
                                timestamp: Optional[datetime] = None) -> Optional[dict]:
        """Flag a client making a burst of unique DNS queries."""
        if client_ip in dns_burst_whitelist():
            return None
        bucket = self._get_5min_bucket(timestamp)
        self.dns_query_burst[client_ip][bucket].add(domain)
        count = len(self.dns_query_burst[client_ip][bucket])
        threshold = getattr(self.thresholds, "dns_query_burst_per_5min", 100)
        if count >= threshold:
            return {
                "flag_type": "dns_query_burst",
                "details": {
                    "client_ip": client_ip,
                    "unique_domains": count,
                    "threshold": threshold,
                    "window": "5min",
                    "sample_domains": list(self.dns_query_burst[client_ip][bucket])[:10],
                },
                "timestamp": timestamp or datetime.now(timezone.utc),
            }
        return None

    def detect_dns_unknown_domains(self, client_ip: str, domain: str,
                                    feed_manager=None,
                                    timestamp: Optional[datetime] = None) -> Optional[dict]:
        """Flag a client querying many domains not in Tranco top 1M."""
        if client_ip in dns_burst_whitelist():
            return None
        if feed_manager and feed_manager.is_domain_reputable(domain):
            return None
        bucket = self._get_5min_bucket(timestamp)
        self.dns_unknown_domains[client_ip][bucket].add(domain)
        count = len(self.dns_unknown_domains[client_ip][bucket])
        threshold = getattr(self.thresholds, "dns_unknown_domains_per_5min", 20)
        if count >= threshold:
            return {
                "flag_type": "dns_unknown_burst",
                "details": {
                    "client_ip": client_ip,
                    "unknown_domain_count": count,
                    "threshold": threshold,
                    "window": "5min",
                    "sample_domains": list(self.dns_unknown_domains[client_ip][bucket])[:10],
                },
                "timestamp": timestamp or datetime.now(timezone.utc),
            }
        return None

    def detect_unknown_source(self, src_ip: str, dst_ip: str,
                               dst_port: Optional[int] = None) -> Optional[dict]:
        """Flag inbound connections from unknown external sources."""
        if not src_ip or self._is_private(src_ip):
            return None
        if src_ip not in self.baseline.host_connections:
            return {
                "flag_type": "unknown_source",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                },
                "timestamp": datetime.now(timezone.utc),
            }
        return None

    def analyze_event(self, event: dict, feed_manager=None) -> List[dict]:
        """Run all behavioral detectors on a normalized event.

        Returns list of behavioral flag dicts.
        """
        flags = []
        event_type = event.get("event_type", "")
        src_ip = event.get("source_ip", "")
        parsed = event.get("parsed_fields") or {}

        # OPNsense filterlog events
        if event_type == "opnsense" and parsed:
            p_src_ip = parsed.get("src_ip", src_ip)
            p_dst_ip = parsed.get("dst_ip", "")
            p_dst_port = parsed.get("dst_port")

            # Unknown external source connecting in
            flag = self.detect_unknown_source(p_src_ip, p_dst_ip, p_dst_port)
            if flag:
                flags.append(flag)

            # Volume — use actual packet length from filterlog if available
            pkt_len = parsed.get("length") or 1500
            flag = self.detect_volume_anomaly(p_src_ip, pkt_len)
            if flag:
                flags.append(flag)

            # Port scan
            if p_dst_port:
                flag = self.detect_port_scan(p_src_ip, p_dst_ip, p_dst_port)
                if flag:
                    flags.append(flag)

            # Beaconing (skip DNS — resolver traffic is inherently periodic)
            flag = self.detect_beaconing(p_src_ip, p_dst_ip, dst_port=p_dst_port)
            if flag:
                flags.append(flag)

            # Destination fan-out (host hitting many unique external IPs)
            flag = self.detect_destination_fanout(p_src_ip, p_dst_ip)
            if flag:
                flags.append(flag)

            # New destination (geo/ASN - we flag on new destination IP as proxy)
            if self.baseline.is_new_destination(p_src_ip, p_dst_ip):
                flag = self.detect_new_geo_asn(p_src_ip, p_dst_ip, asn=None, country=None)
                if flag:
                    flags.append(flag)

            # Outbound blocked ratio
            action = parsed.get("action")
            if action in ("pass", "block"):
                flag = self.detect_outbound_blocked_ratio(p_src_ip, action)
                if flag:
                    flags.append(flag)

            # Internal lateral movement
            flag = self.detect_lateral_movement(p_src_ip, p_dst_ip, p_dst_port)
            if flag:
                flags.append(flag)

            # Phase 3a: Sustained high-frequency connection
            sf_flag = self._check_sustained_high_freq(p_src_ip, p_dst_ip, event.get("timestamp"))
            if sf_flag:
                flags.append(sf_flag)

            # Phase 3b: Cryptominer flow profile
            miner_flag = self._check_miner_profile(event)
            if miner_flag:
                flags.append(miner_flag)

        # Pi-hole DNS events
        elif event_type == "pihole" and parsed:
            domain = parsed.get("queried_domain", "")
            client_ip = parsed.get("client_ip", src_ip)
            blocked = parsed.get("blocked", False)

            if domain:
                # High-entropy DNS (potential DGA, skip Tranco top-1M)
                flag = self.detect_high_entropy_dns(domain, client_ip, feed_manager)
                if flag:
                    flags.append(flag)

                # Burst of unique domain queries from one client (DGA cycling, DNS exfil)
                flag = self.detect_dns_query_burst(client_ip, domain)
                if flag:
                    flags.append(flag)

                # Burst of queries to domains not in Tranco (C2, tunneling)
                flag = self.detect_dns_unknown_domains(client_ip, domain, feed_manager)
                if flag:
                    flags.append(flag)

            # Repeated blocked queries
            if blocked and domain:
                flag = self.detect_repeated_blocked_queries(client_ip, domain)
                if flag:
                    flags.append(flag)

        # Generic events - check raw message for any IPs
        elif event_type == "generic":
            raw = event.get("raw_message", "")
            import re
            ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw)
            for ip in ips:
                if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255") and ip != src_ip:
                    if self.baseline.is_new_destination(src_ip, ip):
                        flag = self.detect_new_geo_asn(src_ip, ip)
                        if flag:
                            flags.append(flag)

        if flags:
            logger.debug("Behavioral flags detected", extra={
                "extra_data": {
                    "event_type": event_type,
                    "flag_count": len(flags),
                    "flag_types": [f["flag_type"] for f in flags],
                }
            })

        return flags

    # ------------------------------------------------------------------
    # Phase 3a: Sustained High-Frequency Connection Detection
    # ------------------------------------------------------------------

    def _check_sustained_high_freq(
        self,
        src_ip: str,
        dst_ip: str,
        timestamp: Optional[datetime] = None,
    ) -> Optional[dict]:
        """Flag sustained high-frequency connections to a single destination.

        Threshold: 120+ connections/hour for 4+ consecutive hours.
        """
        if not src_ip or not dst_ip:
            return None
        if self._is_private(dst_ip):
            return None

        ts = timestamp or datetime.now(timezone.utc)
        key = (src_ip, dst_ip)

        # Truncate timestamp to hour bucket
        hour_bucket = ts.replace(minute=0, second=0, microsecond=0)

        if key not in self._sustained_conns:
            self._sustained_conns[key] = deque()

        dq = self._sustained_conns[key]

        # Count this event in the current hour bucket
        if dq and dq[-1][0] == hour_bucket:
            dq[-1] = (hour_bucket, dq[-1][1] + 1)
        else:
            dq.append((hour_bucket, 1))

        # Prune entries older than 6 hours
        cutoff = hour_bucket - timedelta(hours=6)
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        if not dq:
            return None

        CONSECUTIVE_HOURS = 4
        MIN_PER_HOUR = 120

        if len(dq) < CONSECUTIVE_HOURS:
            return None

        # Check the last 4 hours
        last_four = list(dq)[-CONSECUTIVE_HOURS:]

        # Verify they are consecutive hours
        for i in range(1, len(last_four)):
            expected = last_four[i - 1][0] + timedelta(hours=1)
            if last_four[i][0] != expected:
                return None

        # Verify each has sufficient count
        if all(count >= MIN_PER_HOUR for _, count in last_four):
            total_conns = sum(count for _, count in last_four)
            return {
                "flag_type": "sustained_high_frequency",
                "severity": "medium",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "consecutive_hours": CONSECUTIVE_HOURS,
                    "total_connections": total_conns,
                    "hourly_counts": [c for _, c in last_four],
                    "threshold_per_hour": MIN_PER_HOUR,
                    "description": (
                        f"Sustained high-frequency: {total_conns} connections over "
                        f"{CONSECUTIVE_HOURS} consecutive hours to {dst_ip}"
                    ),
                    "mitre_attack": ["T1071", "T1041"],
                },
                "timestamp": ts,
            }

        return None

    # ------------------------------------------------------------------
    # Phase 3b: Cryptominer Flow Profile
    # ------------------------------------------------------------------

    def _check_miner_profile(self, event_data: dict) -> Optional[dict]:
        """Multi-factor scoring for cryptominer traffic patterns.

        Scoring (max 8 points):
        - Bytes/packet in range [50, 130]: +2
        - Sustained activity > 5 min to single dest: +2
        - Non-standard port (not 80/443/53/22): +1
        - Connection frequency 8-30 packets/min: +2
        Score >= 6: flag as potential cryptominer.
        """
        import time as _time

        parsed = event_data.get("parsed_fields", {})
        if not isinstance(parsed, dict):
            return None

        src_ip = parsed.get("src_ip", "") or event_data.get("source_ip", "")
        dst_ip = parsed.get("dst_ip", "")
        dst_port = parsed.get("dst_port")
        pkt_len = parsed.get("length", 0)
        ts = event_data.get("timestamp") or datetime.now(timezone.utc)

        if not src_ip or not dst_ip:
            return None
        if self._is_private(dst_ip):
            return None

        score = 0
        breakdown: Dict[str, Any] = {}

        # 1. Bytes/packet in range [50, 130]
        try:
            pkt_len_int = int(pkt_len) if pkt_len else 0
        except (ValueError, TypeError):
            pkt_len_int = 0
        if 50 <= pkt_len_int <= 130:
            score += 2
            breakdown["packet_size"] = {"score": 2, "value": pkt_len_int}
        else:
            breakdown["packet_size"] = {"score": 0, "value": pkt_len_int}

        # 2. Sustained activity > 5 min to single dest
        key = (src_ip, dst_ip)
        now_mono = _time.monotonic()
        if key not in self._miner_tracking:
            self._miner_tracking[key] = {
                "first_seen": now_mono,
                "last_seen": now_mono,
                "count": 1,
            }
        else:
            tracker = self._miner_tracking[key]
            tracker["last_seen"] = now_mono
            tracker["count"] += 1

        tracker = self._miner_tracking[key]
        duration_min = (tracker["last_seen"] - tracker["first_seen"]) / 60.0
        if duration_min > 5:
            score += 2
            breakdown["duration"] = {"score": 2, "value": round(duration_min, 1)}
        else:
            breakdown["duration"] = {"score": 0, "value": round(duration_min, 1)}

        # 3. Non-standard port
        STANDARD_PORTS = {80, 443, 53, 22}
        try:
            port_int = int(dst_port) if dst_port is not None else None
        except (ValueError, TypeError):
            port_int = None
        if port_int is not None and port_int not in STANDARD_PORTS:
            score += 1
            breakdown["nonstandard_port"] = {"score": 1, "value": port_int}
        else:
            breakdown["nonstandard_port"] = {"score": 0, "value": port_int}

        # 4. Connection frequency 8-30 packets/min
        if duration_min > 0 and tracker["count"] > 1:
            ppm = tracker["count"] / duration_min
            if 8 <= ppm <= 30:
                score += 2
                breakdown["frequency"] = {"score": 2, "value": round(ppm, 1)}
            else:
                breakdown["frequency"] = {"score": 0, "value": round(ppm, 1)}
        else:
            breakdown["frequency"] = {"score": 0, "value": 0}

        if score >= 6:
            # Save values before resetting
            pkt_count = tracker["count"]
            del self._miner_tracking[key]

            return {
                "flag_type": "cryptominer_profile",
                "severity": "medium",
                "details": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": port_int,
                    "total_score": score,
                    "max_score": 8,
                    "score_breakdown": breakdown,
                    "packet_count": pkt_count,
                    "description": (
                        f"Cryptominer flow profile detected: score={score}/8 "
                        f"({pkt_count} packets to {dst_ip})"
                    ),
                    "mitre_attack": ["T1496"],
                },
                "timestamp": ts,
            }

        return None

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Check if IP is in a private network range."""
        if not ip:
            return True
        if ip.startswith(("10.", "192.168.", "127.")):
            return True
        if ip.startswith("172."):
            try:
                second = int(ip.split(".")[1])
                return 16 <= second <= 31
            except (ValueError, IndexError):
                return False
        return False
