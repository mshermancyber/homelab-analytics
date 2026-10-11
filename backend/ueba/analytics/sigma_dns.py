"""Sigma DNS detection patterns for Pi-hole query analysis.

Implements pattern-based DNS detection rules inspired by SigmaHQ DNS rules:
- Cobalt Strike DNS beaconing
- DNS Base64 exfiltration
- Suspicious TLD queries
- Cryptocurrency mining pool DNS
- Dynamic DNS resolution
- Known DoH bypass
"""

import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Set, Tuple, Optional

from sqlalchemy import select

from ueba.logging_config import get_logger
from ueba.database import async_session_factory
from ueba.netconfig import gateway_ips, is_own_hostname
from ueba.models import PiHoleQuery
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Pattern Definitions
# ---------------------------------------------------------------------------

# Cobalt Strike DNS beaconing patterns
COBALT_STRIKE_PATTERNS = [
    re.compile(r"^aaa\.stage\..*", re.IGNORECASE),
    re.compile(r"^post\.1.*", re.IGNORECASE),
    re.compile(r".*\.stage\.123456\..*", re.IGNORECASE),
]

# DNS Base64 exfiltration: padding sequences in domain labels
BASE64_EXFIL_PATTERNS = [
    re.compile(r".*==\..*"),  # base64 padding in labels
    re.compile(r".*[A-Za-z0-9+/]{30,}\..*"),  # long base64-like labels
]

# Suspicious free TLDs commonly used by malware
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".work", ".date",
    ".loan", ".win", ".bid", ".trade", ".webcam",
    ".stream", ".download", ".review", ".country", ".racing",
}

# Cryptocurrency mining pool DNS patterns
# NOTE: generic "pool." excluded — it matches NTP pools (*.pool.ntp.org).
# Only match mining-specific pool domains.
MINING_POOL_PATTERNS = [
    re.compile(r".*miningpool\..*", re.IGNORECASE),
    re.compile(r".*mining\..*", re.IGNORECASE),
    re.compile(r".*miner\..*", re.IGNORECASE),
    re.compile(r".*xmr\..*", re.IGNORECASE),
    re.compile(r".*cryptonight\..*", re.IGNORECASE),
    re.compile(r".*stratum\..*", re.IGNORECASE),
    re.compile(r".*nicehash\..*", re.IGNORECASE),
    re.compile(r".*ethermine\..*", re.IGNORECASE),
    re.compile(r".*f2pool\..*", re.IGNORECASE),
    re.compile(r".*antpool\..*", re.IGNORECASE),
    re.compile(r".*slushpool\..*", re.IGNORECASE),
    re.compile(r".*nanopool\..*", re.IGNORECASE),
    re.compile(r".*hiveon\..*", re.IGNORECASE),
    re.compile(r".*flexpool\..*", re.IGNORECASE),
    re.compile(r".*2miners\..*", re.IGNORECASE),
]

# Dynamic DNS providers (30+ providers)
DYNDNS_DOMAINS = {
    # Major DynDNS providers
    "dyndns.org", "no-ip.org", "no-ip.com", "noip.com",
    "hopto.org", "ddns.net", "afraid.org", "freedns.afraid.org",
    "dyn.com", "dynserv.com", "dyndns.biz", "dyndns.info",
    "dyndns.ws", "dyndns.tv",
    # Additional DynDNS providers
    "duckdns.org", "changeip.com", "changeip.org",
    "dnsdynamic.org", "dynu.com", "dynu.net",
    "zapto.org", "myftp.org", "myftp.biz",
    "servehttp.com", "serveftp.com", "serveftp.net",
    "servegame.com", "servegame.org",
    "selfip.com", "selfip.net", "selfip.biz",
    "bounceme.net", "bouncepad.org",
    "redirectme.net", "webhop.org", "webhop.net",
    "myvnc.com", "myddns.me",
    "dlinkddns.com", "dlinkddns.org",
    "tplinkdns.com", "tplogin.cn",
    "asustor.com", "myqnapcloud.com",
    "synology.me", "quickconnect.to",
    "mynetgear.com", "routerlogin.net",
    # Free subdomain providers
    "nip.io", "sslip.io", "xip.io",
    "nip.io", "sslip.io",
}

# Known DoH (DNS-over-HTTPS) bypass domains
DOH_DOMAINS = {
    "dns.google", "dns.google.com",
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net",
    "doh.opendns.com", "doh.familyshield.opendns.com",
    "doh.cleanbrowsing.org",
    "doh.dns.sb", "doh.libredns.gr",
    "doh.securedns.eu", "doh.powerdns.org",
    "dns.nextdns.io", "doh.nextdns.io",
    "doh.42l.fr", "doh.appliedprivacy.net",
    "doh.tiar.app", "doh.tiarap.org",
    "doh.mullvad.net", "doh.dnscrypt.ca",
    "dnsforge.de", "doh.dnswarden.com",
    "doh.centraleu.pi-dns.com",
}


# ---------------------------------------------------------------------------
# Compile all patterns
# ---------------------------------------------------------------------------

def _compile_dyndns_suffix_patterns() -> List[re.Pattern]:
    """Compile regex patterns to match any DynDNS domain suffix."""
    patterns = []
    for domain in sorted(DYNDNS_DOMAINS, key=len, reverse=True):
        escaped = re.escape(domain)
        patterns.append(re.compile(rf".*\.{escaped}$", re.IGNORECASE))
    return patterns


_DYNDNS_PATTERNS = _compile_dyndns_suffix_patterns()


def _matches_any(domain: str, patterns: List[re.Pattern]) -> bool:
    """Check if domain matches any compiled regex pattern."""
    for pat in patterns:
        if pat.search(domain):
            return True
    return False


def _get_sld(domain: str) -> str:
    """Extract the second-level domain + TLD."""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]).lower()
    return domain.lower()


# ---------------------------------------------------------------------------
# Detection Rules
# ---------------------------------------------------------------------------

# ── Phase 1: Low-reputation eTLDs ──────────────────────────────────
_BAD_ETLDS = (
    '.top', '.icu', '.sbs', '.click', '.buzz', '.surf', '.rest',
    '.quest', '.fit', '.beauty', '.hair', '.skin', '.makeup',
    '.boats', '.bond', '.cam', '.cfd', '.cyou',
    '.duckdns.org', '.zapto.org', '.hopto.org', '.sytes.net',
    '.portmap.io', '.serveo.net', '.loca.lt', '.localhost.run',
    '.pgrok.com',
)
# Own dynamic-DNS hostnames come from network.own_hostnames (see config.yaml)
# and are matched with netconfig.is_own_hostname().

# ── Phase 1: Abused web services (C2 / data exfil) ──────────────────
_ABUSED_SERVICES = (
    'pastebin.com', 'paste.ee', 'hastebin.com', 'dpaste.com',
    'file.io', 'transfer.sh', 'filedropper.com', 'gofile.io',
    'webhook.site', 'requestbin.com', 'pipedream.com',
    'raw.githubusercontent.com',
    'ipify.org', 'icanhazip.com', 'ifconfig.me', 'checkip.amazonaws.com',
    'wtfismyip.com', 'ipinfo.io', 'api.ipify.org',
)
_ABUSED_SUFFIXES = (
    '.ngrok.io', '.ngrok-free.app', '.trycloudflare.com',
    '.devtunnels.ms', '.serveo.net', '.loca.lt',
    '.localhost.run', '.portmap.io',
)

# ── Phase 1: External IP lookup services ────────────────────────────
_IP_LOOKUP_DOMAINS = (
    'ipify.org', 'api.ipify.org', 'icanhazip.com', 'ifconfig.me',
    'checkip.amazonaws.com', 'wtfismyip.com', 'ipinfo.io',
    'myexternalip.com', 'ip-api.com', 'ipecho.net',
    'checkip.dyndns.org', 'whatismyipaddress.com',
)
# Hosts that legitimately query external IP services (DDNS updaters) — the
# router/firewall refreshes its own dynamic-DNS record this way.


class SigmaDnsDetector(BaseAnomalyDetector):
    """Pattern-based DNS detection engine for Pi-hole query data.

    Runs a set of Sigma-inspired DNS detection rules against each
    Pi-hole query event and returns matching BehavioralFlag dicts.
    """

    def __init__(self, lookback_minutes: int = 5):
        self.lookback_minutes = lookback_minutes
        self._seen_mining_domains: Set[str] = set()
        self._seen_dyndns: Dict[str, datetime] = {}
        self._seen_doh: Dict[str, datetime] = {}
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None
        # External IP whitelist can be extended at runtime
        self._external_ip_whitelist: Set[str] = gateway_ips()

    # ------------------------------------------------------------------
    # BaseAnomalyDetector abstract property implementations
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "sigma_dns"

    @property
    def description(self) -> str:
        return "Sigma-inspired pattern-based DNS detection rules for Pi-hole query analysis"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    # ------------------------------------------------------------------
    # Batch detection (async, queries PiHoleQuery from database)
    # ------------------------------------------------------------------

    async def detect(self) -> List[AnomalyResult]:
        """Run Sigma DNS detection against recent PiHoleQuery records.

        Queries the database for Pi-hole queries in the configured
        lookback window, runs ``analyze_query()`` on each, and returns
        ``AnomalyResult`` objects for any clients that triggered one or
        more Sigma DNS rules.
        """
        results: List[AnomalyResult] = []
        try:
            since = datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)

            async with async_session_factory() as session:
                query_result = await session.execute(
                    select(
                        PiHoleQuery.client_ip,
                        PiHoleQuery.queried_domain,
                        PiHoleQuery.query_type,
                        PiHoleQuery.blocked,
                        PiHoleQuery.timestamp,
                    )
                    .where(PiHoleQuery.timestamp >= since)
                    .order_by(PiHoleQuery.timestamp.desc())
                    .limit(5000)
                )
                rows = query_result.all()

            if not rows:
                self._last_results = results
                self._last_run = datetime.now(timezone.utc)
                return results

            # Accumulate flags per client IP
            per_client: Dict[str, List[Dict[str, Any]]] = {}
            for row in rows:
                flags = self.analyze_query(
                    client_ip=row.client_ip,
                    domain=row.queried_domain,
                    query_type=row.query_type or "A",
                    blocked=bool(row.blocked),
                    timestamp=row.timestamp,
                )
                if flags:
                    if row.client_ip not in per_client:
                        per_client[row.client_ip] = []
                    per_client[row.client_ip].extend(flags)

            # Build AnomalyResult for each flagged client
            for client_ip, flags in per_client.items():
                unique_rules = list({f["details"]["rule"] for f in flags})
                unique_domains = list({f["details"]["domain"] for f in flags})
                score = min(1.0, len(flags) / 10.0)

                results.append(AnomalyResult(
                    ip=client_ip,
                    score=round(score, 4),
                    details={
                        "matched_rules": unique_rules,
                        "matched_domains": unique_domains,
                        "total_flags": len(flags),
                        "rule_counts": {r: sum(1 for f in flags if f["details"]["rule"] == r) for r in unique_rules},
                    },
                    detector_name=self.name,
                ))

            self._last_results = results
            self._last_run = datetime.now(timezone.utc)

            if results:
                logger.info("Sigma DNS detection completed", extra={
                    "extra_data": {
                        "queries_analyzed": len(rows),
                        "flagged_clients": len(results),
                        "flagged_ips": [r.ip for r in results],
                    }
                })

        except Exception as e:
            logger.error("Sigma DNS detection failed", extra={
                "extra_data": {"error": str(e)}
            })
            self._last_results = results
            self._last_run = datetime.now(timezone.utc)

        return results

    def analyze_query(
        self,
        client_ip: str,
        domain: str,
        query_type: str = "A",
        blocked: bool = False,
        timestamp: datetime | None = None,
    ) -> List[Dict[str, Any]]:
        """Analyze a single Pi-hole DNS query and return any matched flags.

        Args:
            client_ip: The client IP making the query.
            domain: The queried domain name.
            query_type: DNS query type (A, AAAA, etc.).
            blocked: Whether Pi-hole blocked the query.
            timestamp: Event timestamp.

        Returns:
            List of behavioral flag dicts, each with flag_type='sigma_dns'
            and details containing the matched rule name.
        """
        if not domain:
            return []

        ts = timestamp or datetime.now(timezone.utc)
        flags: List[Dict[str, Any]] = []
        domain_lower = domain.lower().strip(".")

        # Rule 1: Cobalt Strike DNS beaconing
        if _matches_any(domain_lower, COBALT_STRIKE_PATTERNS):
            flags.append({
                "flag_type": "sigma_dns",
                "details": {
                    "rule": "cobalt_strike_dns_beaconing",
                    "domain": domain,
                    "client_ip": client_ip,
                    "query_type": query_type,
                    "blocked": blocked,
                    "description": "Cobalt Strike DNS beaconing pattern detected",
                },
                "timestamp": ts,
            })

        # Rule 2: DNS Base64 exfiltration.
        # Excluded suffixes: subdomain-encoded data is only an exfil channel
        # when the zone's authoritative NS is attacker-controlled. Plex GDM
        # and Amazon device infra (a2z.com — Alexa/Echo device-ID hashes,
        # amazon.com — AVS endpoints) are first-party authoritative zones.
        _exfil_excluded = (".plex.direct", ".a2z.com", ".amazon.com")
        if (_matches_any(domain_lower, BASE64_EXFIL_PATTERNS)
                and not any(domain_lower.endswith(s) for s in _exfil_excluded)):
            flags.append({
                "flag_type": "sigma_dns",
                "details": {
                    "rule": "dns_base64_exfil",
                    "domain": domain,
                    "client_ip": client_ip,
                    "query_type": query_type,
                    "blocked": blocked,
                    "description": "DNS query contains base64-encoded data (potential exfiltration)",
                },
                "timestamp": ts,
            })

        # Rule 3: Suspicious TLD queries
        sld = _get_sld(domain_lower)
        for tld in SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                flags.append({
                    "flag_type": "sigma_dns",
                    "details": {
                        "rule": "suspicious_tld",
                        "domain": domain,
                        "tld": tld,
                        "client_ip": client_ip,
                        "query_type": query_type,
                        "blocked": blocked,
                        "description": f"Query to suspicious TLD: {tld}",
                    },
                    "timestamp": ts,
                })
                break  # one flag per TLD match

        # Rule 4: Cryptocurrency mining pool DNS
        if _matches_any(domain_lower, MINING_POOL_PATTERNS) and not domain_lower.endswith(".ntp.org"):
            self._seen_mining_domains.add(domain_lower)
            flags.append({
                "flag_type": "sigma_dns",
                "details": {
                    "rule": "cryptomining_pool_dns",
                    "domain": domain,
                    "client_ip": client_ip,
                    "query_type": query_type,
                    "blocked": blocked,
                    "description": "DNS query to suspected cryptocurrency mining pool",
                },
                "timestamp": ts,
            })

        # Rule 5: Dynamic DNS resolution (exclude own DDNS hostname)
        if _matches_any(domain_lower, _DYNDNS_PATTERNS) and not is_own_hostname(domain_lower):
            self._seen_dyndns.setdefault(domain_lower, ts)
            flags.append({
                "flag_type": "sigma_dns",
                "details": {
                    "rule": "dynamic_dns_resolution",
                    "domain": domain,
                    "client_ip": client_ip,
                    "query_type": query_type,
                    "blocked": blocked,
                    "description": "DNS query to Dynamic DNS provider domain",
                },
                "timestamp": ts,
            })

        # Rule 6: Known DoH bypass
        doh_check = domain_lower
        # Strip www prefix if present
        if doh_check.startswith("www."):
            doh_check = doh_check[4:]
        if doh_check in DOH_DOMAINS:
            self._seen_doh.setdefault(doh_check, ts)
            flags.append({
                "flag_type": "sigma_dns",
                "details": {
                    "rule": "doh_bypass",
                    "domain": domain,
                    "client_ip": client_ip,
                    "query_type": query_type,
                    "blocked": blocked,
                    "description": "DNS query to known DoH provider (DNS-over-HTTPS bypass)",
                },
                "timestamp": ts,
            })

        # Rule 7: Low-reputation eTLD
        etld_flag = self._check_low_reputation_etld(domain_lower, client_ip, query_type, blocked, ts)
        if etld_flag:
            flags.append(etld_flag)

        # Rule 8: Abused web service
        abused_flag = self._check_abused_web_service(domain_lower, client_ip, query_type, blocked, ts)
        if abused_flag:
            flags.append(abused_flag)

        # Rule 9: External IP lookup
        iplookup_flag = self._check_external_ip_lookup(domain_lower, client_ip, query_type, blocked, ts)
        if iplookup_flag:
            flags.append(iplookup_flag)

        # Rule 10: Punycode (IDN homoglyph) domain — common phishing vector.
        # Any DNS label starting with xn-- is an internationalized name that
        # can visually impersonate a legitimate domain (аpple.com etc.).
        if any(label.startswith("xn--") for label in domain_lower.split(".")):
            flags.append({
                "flag_type": "sigma_dns",
                "details": {
                    "rule": "punycode_idn_domain",
                    "domain": domain,
                    "client_ip": client_ip,
                    "query_type": query_type,
                    "blocked": blocked,
                    "description": "Punycode (xn--) internationalized domain — possible homoglyph phishing",
                },
                "timestamp": ts,
            })

        return flags

    # ------------------------------------------------------------------
    # Phase 1: New Sigma-inspired detection rules
    # ------------------------------------------------------------------

    def _check_low_reputation_etld(
        self,
        domain: str,
        client_ip: str,
        query_type: str,
        blocked: bool,
        ts: datetime,
    ) -> Optional[Dict[str, Any]]:
        """Flag DNS queries to known-bad eTLDs associated with phishing/C2/malware."""
        # Exclude our own dynamic-DNS hostnames
        if is_own_hostname(domain):
            return None

        for etld in _BAD_ETLDS:
            if domain.endswith(etld):
                return {
                    "flag_type": "low_reputation_etld",
                    "severity": "medium",
                    "details": {
                        "rule": "low_reputation_etld",
                        "domain": domain,
                        "matched_etld": etld,
                        "client_ip": client_ip,
                        "query_type": query_type,
                        "blocked": blocked,
                        "description": f"DNS query to low-reputation eTLD: {etld}",
                        "mitre_attack": ["T1071.004", "T1568"],
                    },
                    "timestamp": ts,
                }
        return None

    def _check_abused_web_service(
        self,
        domain: str,
        client_ip: str,
        query_type: str,
        blocked: bool,
        ts: datetime,
    ) -> Optional[Dict[str, Any]]:
        """Flag DNS queries to commonly abused C2/exfil services.

        These are legitimate services frequently abused by attackers for
        data exfiltration, command-and-control, and staging payloads.
        Returns low-severity building blocks — severity escalates when
        correlated with other signals.
        """
        # Check exact domain matches
        for svc in _ABUSED_SERVICES:
            if domain == svc or domain.endswith("." + svc):
                return {
                    "flag_type": "abused_web_service",
                    "severity": "low",
                    "details": {
                        "rule": "abused_web_service",
                        "domain": domain,
                        "matched_service": svc,
                        "match_type": "exact",
                        "client_ip": client_ip,
                        "query_type": query_type,
                        "blocked": blocked,
                        "description": f"DNS query to commonly abused service: {svc}",
                        "mitre_attack": ["T1102", "T1567", "T1572"],
                    },
                    "timestamp": ts,
                }

        # Check suffix matches (ngrok, cloudflare tunnels, etc.)
        for suffix in _ABUSED_SUFFIXES:
            if domain.endswith(suffix):
                return {
                    "flag_type": "abused_web_service",
                    "severity": "low",
                    "details": {
                        "rule": "abused_web_service",
                        "domain": domain,
                        "matched_suffix": suffix,
                        "match_type": "suffix",
                        "client_ip": client_ip,
                        "query_type": query_type,
                        "blocked": blocked,
                        "description": f"DNS query to tunnelling/exfil suffix: {suffix}",
                        "mitre_attack": ["T1102", "T1567", "T1572"],
                    },
                    "timestamp": ts,
                }

        return None

    def _check_external_ip_lookup(
        self,
        domain: str,
        client_ip: str,
        query_type: str,
        blocked: bool,
        ts: datetime,
    ) -> Optional[Dict[str, Any]]:
        """Flag DNS queries to external IP lookup services.

        Post-exploitation recon: attackers often query ifconfig-like
        services to determine the victim's public IP address.
        """
        # Exclude gateway and DDNS updater hosts
        if client_ip in self._external_ip_whitelist:
            return None

        for svc in _IP_LOOKUP_DOMAINS:
            if domain == svc or domain.endswith("." + svc):
                return {
                    "flag_type": "external_ip_lookup",
                    "severity": "low",
                    "details": {
                        "rule": "external_ip_lookup",
                        "domain": domain,
                        "matched_service": svc,
                        "client_ip": client_ip,
                        "query_type": query_type,
                        "blocked": blocked,
                        "description": f"DNS query to external IP lookup service: {svc}",
                        "mitre_attack": ["T1016.001", "T1614"],
                    },
                    "timestamp": ts,
                }
        return None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return current detection statistics."""
        return {
            "unique_mining_domains": len(self._seen_mining_domains),
            "unique_dyndns_domains": len(self._seen_dyndns),
            "unique_doh_domains": len(self._seen_doh),
        }
