"""Threat intelligence feed loader - pulls from public feeds.

Loads real public threat intelligence feeds from multiple categories:
- Malware/C2: abuse.ch URLhaus, ThreatFox (recent), Feodo Tracker, SSL Blacklist
- Ransomware: ransomware.live API
- Botnet/DDoS: Spamhaus DROP/EDROP, DShield top attackers
- Phishing: OpenPhish, PhishTank
- APT/Nation-state: Emerging Threats compromised IPs, CISA KEV, MITRE ATT&CK
- DNS-specific: newly registered domains
- General reputation: Blocklist.de
- EPSS enrichment: FIRST EPSS scores for CISA KEV vulnerabilities

All IOCs stored in-memory as sets/dicts for instant lookup.
Uses SSRF-hardened HTTP client with response-size caps.
"""
import asyncio
import csv
import io
import ipaddress
import json
import os
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, Optional, List, Tuple
from urllib.parse import urlparse

import httpx

from pathlib import Path

from ueba.logging_config import get_logger
from ueba.config import get_config, AppConfig
from ueba.models import ThreatFeed

logger = get_logger(__name__)

def _local_feeds_db() -> Optional[str]:
    """Path to the optional local SQLite mirror of CVE/EPSS/Tranco data.

    Set ``feeds.local_db_path`` in config.yaml (or ``FEEDS_LOCAL_DB_PATH``) to
    enable the local loaders; unset, those feeds fall back to their public APIs.
    See docs/FEEDS.md for the expected schema.
    """
    path = get_config().feeds.local_db_path
    if not path:
        return None
    if not Path(path).is_file():
        logger.warning("Local feeds database not found", extra={
            "extra_data": {"path": path}
        })
        return None
    return path


# Category to severity hint mapping
CATEGORY_SEVERITY = {
    "malware": "high",
    "ransomware": "critical",
    "botnet": "high",
    "phishing": "medium",
    "apt": "critical",
    "dns": "medium",
    "spam": "low",
    "reputation": "medium",
    "ddos": "high",
    "generic": "medium",
}

# Maximum response size in bytes (32 MB)
MAX_RESPONSE_SIZE = 32 * 1024 * 1024
# Blocked IP ranges for SSRF protection (localhost, private, link-local)
SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_ssrf_safe(url: str) -> bool:
    """Validate that a URL does not point to internal/private networks."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Resolve hostname
        addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for addr_info in addrs:
            ip_str = addr_info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            for blocked in SSRF_BLOCKED_NETWORKS:
                if ip in blocked:
                    logger.warning("SSRF blocked", extra={
                        "extra_data": {"url": url, "resolved_ip": ip_str, "blocked_network": str(blocked)}
                    })
                    return False
        return True
    except Exception as e:
        logger.warning("SSRF check failed", extra={"extra_data": {"url": url, "error": str(e)}})
        return False


class SafeHttpClient:
    """SSRF-hardened, response-size-capped HTTP client."""

    def __init__(self, timeout: float = 60.0, max_response_size: int = MAX_RESPONSE_SIZE):
        self.timeout = timeout
        self.max_response_size = max_response_size
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Use a transport that blocks SSRF targets
            limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                limits=limits,
                headers={"User-Agent": "UEBA-ThreatIntel/0.1"},
            )
        return self._client

    async def fetch_text(self, url: str) -> Optional[str]:
        """Fetch URL and return text, with SSRF check and size cap."""
        if not _is_ssrf_safe(url):
            return None
        client = await self._get_client()
        try:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                total = 0
                chunks = []
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self.max_response_size:
                        logger.warning("Response size exceeded cap", extra={
                            "extra_data": {"url": url, "cap": self.max_response_size}
                        })
                        return None
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning("Safe HTTP fetch failed", extra={
                "extra_data": {"url": url, "error": str(e)}
            })
            return None

    async def fetch_json(self, url: str) -> Optional[dict]:
        """Fetch URL and return JSON, with SSRF check and size cap."""
        if not _is_ssrf_safe(url):
            return None
        client = await self._get_client()
        try:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                total = 0
                chunks = []
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self.max_response_size:
                        logger.warning("Response size exceeded cap", extra={
                            "extra_data": {"url": url, "cap": self.max_response_size}
                        })
                        return None
                    chunks.append(chunk)
                body = b"".join(chunks).decode("utf-8", errors="replace")
                return json.loads(body)
        except Exception as e:
            logger.warning("Safe JSON fetch failed", extra={
                "extra_data": {"url": url, "error": str(e)}
            })
            return None

    async def fetch_json_post(self, url: str, body: dict) -> Optional[dict]:
        """POST JSON to URL and return parsed JSON response, with SSRF check and size cap."""
        if not _is_ssrf_safe(url):
            return None
        client = await self._get_client()
        try:
            async with client.stream("POST", url, json=body) as response:
                response.raise_for_status()
                total = 0
                chunks = []
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self.max_response_size:
                        logger.warning("Response size exceeded cap", extra={
                            "extra_data": {"url": url, "cap": self.max_response_size}
                        })
                        return None
                    chunks.append(chunk)
                body_bytes = b"".join(chunks).decode("utf-8", errors="replace")
                return json.loads(body_bytes)
        except Exception as e:
            logger.warning("Safe JSON POST failed", extra={
                "extra_data": {"url": url, "error": str(e)}
            })
            return None

    async def fetch_json_post_form(self, url: str, data: dict) -> Optional[dict]:
        """POST form-encoded data to URL and return parsed JSON, with SSRF check and size cap."""
        if not _is_ssrf_safe(url):
            return None
        client = await self._get_client()
        try:
            async with client.stream("POST", url, data=data) as response:
                response.raise_for_status()
                total = 0
                chunks = []
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self.max_response_size:
                        logger.warning("Response size exceeded cap", extra={
                            "extra_data": {"url": url, "cap": self.max_response_size}
                        })
                        return None
                    chunks.append(chunk)
                body_bytes = b"".join(chunks).decode("utf-8", errors="replace")
                return json.loads(body_bytes)
        except Exception as e:
            logger.warning("Safe JSON POST (form) failed", extra={
                "extra_data": {"url": url, "error": str(e)}
            })
            return None

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


class ThreatFeedManager:
    """Manages threat intelligence feeds - loading, TTL, and in-memory storage."""

    def __init__(self):
        self.config = get_config()
        self.http = SafeHttpClient(timeout=60.0)

        # In-memory IOC storage: {feed_name: {set of IOCs}}
        self.iocs: Dict[str, Set[str]] = {}
        # Feed metadata: {feed_name: {category, severity, last_refresh, ...}}
        self.feed_meta: Dict[str, dict] = {}
        # Global set of all IOCs for fast lookup
        self.global_iocs: Dict[str, dict] = {}  # ioc_value -> {feed, category, severity}
        # EPSS scores: {cve_id: epss_score}
        self.epss_scores: Dict[str, float] = {}
        # Tranco top-1M domain whitelist for reputation scoring
        self.tranco_domains: Set[str] = set()

        self._running = False
        self._refresh_task: Optional[asyncio.Task] = None
        self._file_watcher_task: Optional[asyncio.Task] = None
        self._initialized = asyncio.Event()

        # File watcher state
        self._feed_cache_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "data", "feed_cache"
        )
        self._watched_mtimes: Dict[str, float] = {}

    def _parse_csv_lines(self, text: str, ioc_column: int = 0, delimiter: str = ",", skip_header: int = 1) -> Set[str]:
        """Parse IOCs from CSV text."""
        iocs = set()
        try:
            reader = csv.reader(io.StringIO(text), delimiter=delimiter)
            for i, row in enumerate(reader):
                if i < skip_header:
                    continue
                if row and len(row) > ioc_column:
                    val = row[ioc_column].strip()
                    if val and not val.startswith("#"):
                        iocs.add(val)
        except Exception as e:
            logger.debug("CSV parse error", extra={"extra_data": {"error": str(e)}})
        return iocs

    def _parse_line_list(self, text: str) -> Set[str]:
        """Parse IOCs from line-delimited text (one per line)."""
        iocs = set()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith(";"):
                # Extract IP or domain from line (may contain comments)
                # Try to get the first non-comment token
                parts = line.split("#")[0].split(";")[0].strip()
                if parts:
                    iocs.add(parts.split()[0] if " " in parts else parts)
        return iocs

    def _parse_json_iocs(self, data: dict, key_path: Optional[List[str]] = None) -> Set[str]:
        """Extract IOCs from JSON response."""
        iocs = set()
        if key_path:
            current = data
            for key in key_path:
                if isinstance(current, dict):
                    current = current.get(key, [])
                elif isinstance(current, list):
                    break
            items = current if isinstance(current, list) else []
        elif isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("data", data.get("indicators", []))
        else:
            return iocs

        for item in items:
            if isinstance(item, str):
                iocs.add(item)
            elif isinstance(item, dict):
                for val in item.values():
                    if isinstance(val, str) and (re.match(r'^\d+\.\d+\.\d+\.\d+', val) or '.' in val):
                        iocs.add(val)
        return iocs

    # ------------------------------------------------------------------
    # Feed loaders
    # ------------------------------------------------------------------

    async def load_urlhaus(self, url: str) -> Tuple[Set[str], str]:
        """Load abuse.ch URLhaus - malware URLs."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_csv_lines(text, ioc_column=2, skip_header=9)  # URL is column 2
            return iocs, "malware"
        return set(), "malware"

    async def load_threatfox(self, url: str) -> Tuple[Set[str], str]:
        """Load ThreatFox IOCs - malware IOCs (recent endpoint).

        Response format: {"<numeric_id>": [{"ioc_value": ..., ...}], ...}
        """
        data = await self.http.fetch_json(url)
        if data and isinstance(data, dict):
            iocs = set()
            for key, items in data.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    ioc = item.get("ioc_value", "") if isinstance(item, dict) else ""
                    if ioc:
                        iocs.add(ioc)
            return iocs, "malware"
        return set(), "malware"

    async def load_feodo_tracker(self, url: str) -> Tuple[Set[str], str]:
        """Load Feodo Tracker - C2 IPs."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_csv_lines(text, ioc_column=1, skip_header=7)
            return iocs, "malware"
        return set(), "malware"

    async def load_ssl_blacklist(self, url: str) -> Tuple[Set[str], str]:
        """Load SSL Blacklist - malicious SSL cert IPs."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_csv_lines(text, ioc_column=1, skip_header=7)
            return iocs, "malware"
        return set(), "malware"

    async def load_ransomware_live(self, url: str) -> Tuple[Set[str], str]:
        """Load ransomware.live API - recent ransomware victims.
        
        Extracts victim domains/IPs from the ransomware.live victims feed.
        Reference: /data/security-hub/backend/app/ingest/ransomwatch.py
        """
        data = await self.http.fetch_json(url)
        if data:
            iocs = set()
            victims = data if isinstance(data, list) else data.get("data", data.get("victims", []))
            for victim in victims:
                if isinstance(victim, dict):
                    # Extract domain/website from victim entry
                    domain = victim.get("domain") or victim.get("website") or victim.get("url")
                    if domain:
                        # Clean up protocol and trailing slashes
                        domain = re.sub(r'^https?://', '', domain)
                        domain = domain.rstrip('/')
                        if domain:
                            iocs.add(domain)
                    # Also extract IP if available
                    ip = victim.get("ip") or victim.get("ip_address")
                    if ip and re.match(r'^\d+\.\d+\.\d+\.\d+', str(ip)):
                        iocs.add(ip)
                    # Extract group name as IOC for group tracking
                    group = victim.get("group") or victim.get("ransomware_group") or victim.get("group_name")
                    if group:
                        iocs.add(f"ransomware_group:{group}")
            return iocs, "ransomware"
        return set(), "ransomware"

    async def load_spamhaus_drop(self, url: str) -> Tuple[Set[str], str]:
        """Load Spamhaus DROP list - botnet/DDoS IPs (CIDR notation)."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = set()
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(";"):
                    parts = line.split()
                    if parts:
                        iocs.add(parts[0])  # CIDR range
            return iocs, "botnet"
        return set(), "botnet"

    async def load_spamhaus_edrop(self, url: str) -> Tuple[Set[str], str]:
        """Load Spamhaus EDROP list.
        
        EDROP format: semicolon-delimited with subnet;netmask;country fields.
        Previously failed because the parser only split on whitespace.
        """
        text = await self.http.fetch_text(url)
        if text:
            iocs = set()
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(";") or line.startswith("#"):
                    continue
                # EDROP format: S<CIDR> ; netmask ; country
                # Remove comments and extract the CIDR
                line = line.split(";")[0].strip()
                if line:
                    # Take first non-empty token
                    parts = line.split()
                    for part in parts:
                        if "/" in part or re.match(r'^\d+\.\d+\.\d+\.\d+', part):
                            iocs.add(part)
                            break
            return iocs, "botnet"
        return set(), "botnet"

    async def load_dshield_top(self, url: str) -> Tuple[Set[str], str]:
        """Load DShield top attackers."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = set()
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Format: IP\tnetmask\t...
                    parts = line.split("\t")
                    if parts:
                        iocs.add(parts[0])
            return iocs, "ddos"
        return set(), "ddos"

    async def load_openphish(self, url: str) -> Tuple[Set[str], str]:
        """Load OpenPhish phishing URLs."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_line_list(text)
            return iocs, "phishing"
        return set(), "phishing"

    async def load_phishtank(self, url: str) -> Tuple[Set[str], str]:
        """Load PhishTank CSV."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_csv_lines(text, ioc_column=1, skip_header=1)
            return iocs, "phishing"
        return set(), "phishing"

    async def load_emerging_threats(self, url: str) -> Tuple[Set[str], str]:
        """Load Emerging Threats compromised IPs."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_line_list(text)
            return iocs, "apt"
        return set(), "apt"

    async def load_cisa_kev(self, url: str) -> Tuple[Set[str], str]:
        """Load CISA Known Exploited Vulnerabilities from the local feeds database."""
        import sqlite3 as _sqlite3
        db_path = _local_feeds_db()
        iocs = set()
        try:
            conn = _sqlite3.connect(db_path)
            cursor = conn.execute("SELECT cve FROM kev")
            for (cve_id,) in cursor:
                if cve_id:
                    iocs.add(cve_id)
            conn.close()
        except Exception as e:
            logger.warning("Failed to load KEV from the local database, falling back to API", extra={
                "extra_data": {"error": str(e)}
            })
            data = await self.http.fetch_json(url)
            if data:
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cveID", "")
                    if cve:
                        iocs.add(cve)
        return iocs, "apt"

    async def load_nrd_domains(self, url: str) -> Tuple[Set[str], str]:
        """Load newly registered domains."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_line_list(text)
            return iocs, "dns"
        return set(), "dns"

    async def load_blocklist_de(self, url: str) -> Tuple[Set[str], str]:
        """Load Blocklist.de all IPs."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_line_list(text)
            return iocs, "reputation"
        return set(), "reputation"

    async def load_tor_exits(self, url: str) -> Tuple[Set[str], str]:
        """Load Tor exit node IPs (official torproject bulk list).

        An internal host talking to a Tor exit is either running Tor or
        proxied through one — high-signal on a homelab with no expected Tor use.
        """
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_line_list(text)
            return iocs, "reputation"
        return set(), "reputation"

    async def load_cins_army(self, url: str) -> Tuple[Set[str], str]:
        """Load CINS Army list — IPs with poor CINS Sentinel reputation."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_line_list(text)
            return iocs, "reputation"
        return set(), "reputation"

    async def load_blackbook(self, url: str) -> Tuple[Set[str], str]:
        """Load stamparm/blackbook — curated daily list of malicious domains."""
        text = await self.http.fetch_text(url)
        if text:
            iocs = self._parse_line_list(text)
            return iocs, "dns"
        return set(), "dns"

    # ------------------------------------------------------------------
    # New: MalwareBazaar (abuse.ch)
    # ------------------------------------------------------------------

    async def load_malwarebazaar(self, url: str) -> Tuple[Set[str], str]:
        """Load MalwareBazaar recent samples via CSV export.

        CSV columns: first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter,
        file_name, file_type_guess, mime_type, signature, clamav, vtpercent,
        imphash, ssdeep, tlsh
        """
        text = await self.http.fetch_text(url)
        if not text:
            return set(), "malware"
        iocs = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip(' "') for p in line.split(",")]
            if len(parts) < 14:
                continue
            sha256, md5, sha1 = parts[1], parts[2], parts[3]
            signature = parts[8]
            for h in (sha256, md5, sha1):
                if h and h != "n/a":
                    iocs.add(h)
            if signature and signature != "n/a":
                iocs.add(f"malware_signature:{signature}")
        return iocs, "malware"

    # ------------------------------------------------------------------
    # New: NVD (NIST National Vulnerability Database)
    # ------------------------------------------------------------------

    async def load_nvd_recent(self, url: str) -> Tuple[Set[str], str]:
        """Load high-severity CVEs from the local feeds database.

        Reads the local feeds database when one is configured.
        Loads CVEs with CVSS >= 7.0 as IOCs for correlation.
        """
        import sqlite3 as _sqlite3
        db_path = _local_feeds_db()
        iocs = set()
        try:
            conn = _sqlite3.connect(db_path)
            cursor = conn.execute(
                "SELECT cve, score, severity FROM nvd WHERE score >= 7.0"
            )
            for cve_id, score, severity in cursor:
                if cve_id:
                    iocs.add(cve_id)
                    if score is not None:
                        iocs.add(f"{cve_id}:cvss={score}")
            conn.close()
        except Exception as e:
            logger.warning("Failed to load NVD from the local database", extra={
                "extra_data": {"db": db_path, "error": str(e)}
            })
            return set(), "apt"

        logger.info("NVD CVEs loaded from local DB", extra={
            "extra_data": {"cve_count": len([i for i in iocs if ":cvss=" not in i])}
        })
        return iocs, "apt"

    # ------------------------------------------------------------------
    # New: MITRE ATT&CK
    # ------------------------------------------------------------------

    async def load_mitre_attack(self, url: str) -> Tuple[Set[str], str]:
        """Load MITRE ATT&CK STIX bundle from GitHub.

        Extracts:
        - Threat group names (APT groups)
        - Malware family names
        - Tool names

        Reference: /data/security-hub/backend/app/ingest/mitre.py
        """
        # STIX bundle is ~47MB, needs a larger cap than the default 32MB
        mitre_client = SafeHttpClient(timeout=120.0, max_response_size=64 * 1024 * 1024)
        data = await mitre_client.fetch_json(url)
        await mitre_client.close()
        if not data:
            return set(), "apt"

        iocs = set()
        objects = data.get("objects", []) if isinstance(data, dict) else []

        for obj in objects:
            obj_type = obj.get("type", "") if isinstance(obj, dict) else ""
            obj_name = obj.get("name", "") if isinstance(obj, dict) else ""

            if obj_type == "intrusion-set" and obj_name:
                # Threat actor / APT group
                iocs.add(f"mitre_group:{obj_name}")
                # Also add aliases
                for alias in obj.get("aliases", []) if isinstance(obj, dict) else []:
                    iocs.add(f"mitre_group:{alias}")

            elif obj_type == "malware" and obj_name:
                # Malware family
                iocs.add(f"mitre_malware:{obj_name}")

            elif obj_type == "tool" and obj_name:
                # Tool
                iocs.add(f"mitre_tool:{obj_name}")

            elif obj_type == "campaign" and obj_name:
                # Campaign
                iocs.add(f"mitre_campaign:{obj_name}")

        logger.info("MITRE ATT&CK loaded", extra={
            "extra_data": {"iocs": len(iocs), "objects": len(objects)}
        })
        return iocs, "apt"

    # ------------------------------------------------------------------
    # New: EPSS scoring
    # ------------------------------------------------------------------

    async def load_epss_scores(self) -> Dict[str, float]:
        """Load EPSS scores from the local feeds database ."""
        import sqlite3 as _sqlite3
        db_path = _local_feeds_db()
        scores = {}
        try:
            conn = _sqlite3.connect(db_path)
            cursor = conn.execute("SELECT cve, epss FROM epss WHERE epss > 0")
            for cve_id, epss_score in cursor:
                if cve_id:
                    scores[cve_id] = float(epss_score)
            conn.close()
            logger.info("EPSS scores loaded from local DB", extra={
                "extra_data": {"cve_count": len(scores)}
            })
        except Exception as e:
            logger.warning("EPSS local load failed, falling back to API", extra={
                "extra_data": {"error": str(e)}
            })
            url = "https://api.first.org/data/v1/epss"
            try:
                data = await self.http.fetch_json(url)
                if data and isinstance(data, dict):
                    for entry in data.get("data", []):
                        cve = entry.get("cve", "")
                        epss = entry.get("epss", "0")
                        if cve:
                            try:
                                scores[cve] = float(epss)
                            except (ValueError, TypeError):
                                pass
            except Exception:
                pass
        return scores

    def get_epss_score(self, cve_id: str) -> Optional[float]:
        """Get EPSS score for a CVE ID. Returns None if not found."""
        return self.epss_scores.get(cve_id)

    async def _load_tranco_domains(self) -> None:
        """Load Tranco top-1M domain whitelist from the local feeds database."""
        import sqlite3 as _sqlite3
        db_path = _local_feeds_db()
        if not db_path:
            return  # no local mirror configured — reputability checks stay off
        try:
            conn = _sqlite3.connect(db_path)
            cursor = conn.execute("SELECT domain FROM tranco")
            self.tranco_domains = {row[0] for row in cursor}
            conn.close()
            logger.info("Tranco domains loaded from local DB", extra={
                "extra_data": {"domain_count": len(self.tranco_domains)}
            })
        except Exception as e:
            logger.warning("Tranco load failed", extra={"extra_data": {"error": str(e)}})

    def is_domain_reputable(self, domain: str) -> bool:
        """Check if a domain is in the Tranco top-1M (likely legitimate)."""
        if not self.tranco_domains:
            return False
        parts = domain.lower().split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.tranco_domains:
                return True
        return False

    # ------------------------------------------------------------------
    # Optional: API-key-gated enrichment
    # ------------------------------------------------------------------

    async def enrich_virustotal(self, ioc: str) -> Optional[dict]:
        """Look up an IOC (IP/domain/hash) in VirusTotal.

        Requires VIRUSTOTAL_API_KEY environment variable.
        Reference: /data/security-hub/backend/app/integrations/
        """
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            return None

        # Determine IOC type for endpoint selection
        if re.match(r'^\d+\.\d+\.\d+\.\d+', ioc):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif re.match(r'^[a-fA-F0-9]{32}$', ioc):
            endpoint = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc):
            endpoint = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
            endpoint = f"https://www.virustotal.com/api/v3/files/{ioc}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc}"

        try:
            client = httpx.AsyncClient(timeout=30.0)
            response = await client.get(
                endpoint,
                headers={"x-apikey": api_key, "Accept": "application/json"},
            )
            await client.aclose()
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "harmless": attrs.get("last_analysis_stats", {}).get("harmless", 0),
                    "total": sum(attrs.get("last_analysis_stats", {}).values()),
                    "reputation": attrs.get("reputation", 0),
                }
            elif response.status_code == 404:
                return {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0, "reputation": 0, "not_found": True}
        except Exception as e:
            logger.debug("VirusTotal enrichment failed", extra={"extra_data": {"ioc": ioc, "error": str(e)}})
        return None

    async def enrich_shodan(self, ip: str) -> Optional[dict]:
        """Look up an IP in Shodan.

        Requires SHODAN_API_KEY environment variable.
        Reference: /data/security-hub/backend/app/integrations/
        """
        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            return None

        endpoint = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            client = httpx.AsyncClient(timeout=30.0)
            response = await client.get(endpoint)
            await client.aclose()
            if response.status_code == 200:
                data = response.json()
                return {
                    "ports": data.get("ports", []),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "country": data.get("country_name", ""),
                    "os": data.get("os", ""),
                    "vulns": list(data.get("vulns", [])),
                    "last_update": data.get("last_update", ""),
                }
        except Exception as e:
            logger.debug("Shodan enrichment failed", extra={"extra_data": {"ip": ip, "error": str(e)}})
        return None

    async def enrich_hibp(self, email: str) -> Optional[dict]:
        """Check an email address against Have I Been Pwned.

        Requires HIBP_API_KEY environment variable.
        Reference: /data/security-hub/backend/app/integrations/
        """
        api_key = os.environ.get("HIBP_API_KEY", "")
        if not api_key:
            return None

        endpoint = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        try:
            client = httpx.AsyncClient(timeout=30.0)
            response = await client.get(
                endpoint,
                headers={"hibp-api-key": api_key, "user-agent": "UEBA-ThreatIntel/0.1"},
                params={"truncateResponse": "false"},
            )
            await client.aclose()
            if response.status_code == 200:
                breaches = response.json()
                return {
                    "breach_count": len(breaches),
                    "breaches": [
                        {"name": b.get("Name"), "date": b.get("BreachDate"), "data_classes": b.get("DataClasses", [])}
                        for b in breaches
                    ],
                }
            elif response.status_code == 404:
                return {"breach_count": 0, "breaches": []}
        except Exception as e:
            logger.debug("HIBP enrichment failed", extra={"extra_data": {"email": email, "error": str(e)}})
        return None

    # ------------------------------------------------------------------
    # New: CIRCL Passive DNS enrichment
    # ------------------------------------------------------------------

    async def enrich_domain_passive_dns(self, domain: str) -> Optional[dict]:
        """Query CIRCL Passive DNS for historical DNS data on a domain.

        Returns NDJSON-parsed records with rrname, rdata, rrtype,
        time_first, time_last for each historical DNS entry.
        Reference: /data/osint/server/src/collectors/passivdns-collector.ts
        """
        url = f"https://www.circl.lu/pdns/query/{domain}"
        text = await self.http.fetch_text(url)
        if not text:
            return None

        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append({
                        "rrname": record.get("rrname", ""),
                        "rdata": record.get("rdata", ""),
                        "rrtype": record.get("rrtype", ""),
                        "time_first": record.get("time_first", ""),
                        "time_last": record.get("time_last", ""),
                    })
            except json.JSONDecodeError:
                continue

        logger.debug("Passive DNS enrichment", extra={
            "extra_data": {"domain": domain, "records": len(records)}
        })
        return {
            "domain": domain,
            "record_count": len(records),
            "records": records,
        }

    # ------------------------------------------------------------------
    # New: BGP Ranking (CIRCL) enrichment
    # ------------------------------------------------------------------

    async def enrich_asn_reputation(self, asn: str) -> Optional[dict]:
        """Query BGP Ranking for ASN reputation score.

        POSTs to bgpranking-ng.circl.lu with the ASN.
        Returns ranking score (0-1, higher = more malicious),
        country, description, and prefix count.
        Reference: /data/osint/server/src/collectors/bgpranking-collector.ts
        """
        # Normalize ASN: accept both 'AS1234' and '1234'
        if isinstance(asn, int) or asn.isdigit():
            asn = f"AS{asn}"
        asn = asn.upper().strip()
        if not asn.startswith("AS"):
            asn = f"AS{asn}"

        url = "https://bgpranking-ng.circl.lu/json/asn"
        data = await self.http.fetch_json_post(url, {"asn": asn})
        if not data:
            return None

        response_data = data.get("response", data)
        ranking = response_data.get("ranking", {})
        return {
            "asn": asn,
            "rank": ranking.get("rank"),
            "score": ranking.get("score"),
            "description": ranking.get("description", ""),
            "country": ranking.get("country", ""),
            "prefix_count": ranking.get("prefixes", 0),
            "raw": response_data,
        }

    # ------------------------------------------------------------------
    # New: crt.sh Certificate Transparency enrichment
    # ------------------------------------------------------------------

    async def enrich_domain_certificates(self, domain: str) -> Optional[dict]:
        """Query crt.sh for SSL/TLS certificates issued for a domain.

        Returns discovered subdomains, common names, and SAN entries
        with issuer and validity dates.
        Reference: /data/osint/server/src/collectors/crtsh-collector.ts
        """
        url = f"https://crt.sh/?q={domain}&output=json"
        data = await self.http.fetch_json(url)
        if not data or not isinstance(data, list):
            return None

        certs = []
        seen_names = set()
        for entry in data:
            if not isinstance(entry, dict):
                continue
            common_name = entry.get("common_name", "")
            name_value = entry.get("name_value", "")
            issuer = entry.get("issuer_name", "")
            not_before = entry.get("not_before", "")
            not_after = entry.get("not_after", "")

            cert_info = {
                "common_name": common_name,
                "name_value": name_value,
                "issuer_name": issuer,
                "not_before": not_before,
                "not_after": not_after,
            }
            certs.append(cert_info)

            # Collect all unique SAN domains
            if name_value:
                for san in name_value.split("\n"):
                    san = san.strip()
                    if san and san not in seen_names:
                        seen_names.add(san)

        logger.debug("crt.sh enrichment", extra={
            "extra_data": {"domain": domain, "certificates": len(certs), "unique_names": len(seen_names)}
        })
        return {
            "domain": domain,
            "certificate_count": len(certs),
            "certificates": certs,
            "discovered_names": sorted(seen_names),
        }

    # ------------------------------------------------------------------
    # Feed management
    # ------------------------------------------------------------------

    def _get_feed_loader(self, name: str):
        """Map feed name to loader function."""
        loaders = {
            "urlhaus": self.load_urlhaus,
            "threatfox": self.load_threatfox,
            "feodo_tracker": self.load_feodo_tracker,
            "ssl_blacklist": self.load_ssl_blacklist,
            "ransomware_live": self.load_ransomware_live,
            "spamhaus_drop": self.load_spamhaus_drop,
            "spamhaus_edrop": self.load_spamhaus_edrop,
            "dshield_top": self.load_dshield_top,
            "openphish": self.load_openphish,
            "phishtank": self.load_phishtank,
            "emerging_threats_compromised": self.load_emerging_threats,
            "cisa_kev": self.load_cisa_kev,
            "mitre_attack": self.load_mitre_attack,
            "nrd_domains": self.load_nrd_domains,
            "blocklist_de": self.load_blocklist_de,
            "tor_exits": self.load_tor_exits,
            "cins_army": self.load_cins_army,
            "blackbook": self.load_blackbook,
            "malwarebazaar": self.load_malwarebazaar,
            "nvd_recent": self.load_nvd_recent,
        }
        return loaders.get(name)

    async def load_feed(self, name: str, url: str) -> bool:
        """Load a single feed by name."""
        loader = self._get_feed_loader(name)
        if not loader:
            logger.warning("No loader for feed", extra={"extra_data": {"feed": name}})
            return False

        try:
            iocs, category = await loader(url)
            if iocs:
                self.iocs[name] = iocs
                self.feed_meta[name] = {
                    "category": category,
                    "severity": CATEGORY_SEVERITY.get(category, "medium"),
                    "last_refresh": datetime.now(timezone.utc),
                    "ioc_count": len(iocs),
                    "status": "active",
                    "error": None,
                }

                # Add to global lookup
                severity = CATEGORY_SEVERITY.get(category, "medium")
                for ioc in iocs:
                    self.global_iocs[ioc] = {
                        "feed": name,
                        "category": category,
                        "severity": severity,
                    }

                logger.info("Feed loaded", extra={
                    "extra_data": {
                        "feed": name, "category": category, "ioc_count": len(iocs)
                    }
                })
                return True
            else:
                self.feed_meta[name] = {
                    "category": "unknown",
                    "severity": "info",
                    "last_refresh": datetime.now(timezone.utc),
                    "ioc_count": 0,
                    "status": "failed",
                    "error": "No IOCs returned",
                }
                return False
        except Exception as e:
            self.feed_meta[name] = {
                "category": "unknown",
                "severity": "info",
                "last_refresh": datetime.now(timezone.utc),
                "ioc_count": 0,
                "status": "failed",
                "error": str(e),
            }
            logger.error("Feed load error", extra={
                "extra_data": {"feed": name, "error": str(e)}
            })
            return False

    async def load_all_feeds(self) -> None:
        """Load all configured feeds in parallel, plus EPSS enrichment."""
        feed_urls = self.config.feeds.urls
        if not feed_urls:
            logger.warning("No feeds configured")
            return

        tasks = []
        for name, url in feed_urls.items():
            tasks.append(self.load_feed(name, url))

        # Also load EPSS scores and Tranco whitelist in parallel
        tasks.append(self._load_epss_and_store())
        tasks.append(self._load_tranco_domains())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        success = sum(1 for r in results if r is True)
        failed = sum(1 for r in results if r is False)
        errors = sum(1 for r in results if isinstance(r, Exception))

        logger.info("All feeds loaded", extra={
            "extra_data": {
                "total": len(feed_urls) + 1,  # +1 for EPSS
                "success": success,
                "failed": failed,
                "errors": errors,
                "total_iocs": len(self.global_iocs),
                "epss_scores": len(self.epss_scores),
            }
        })

    async def _load_epss_and_store(self) -> bool:
        """Load EPSS scores and store in-memory. Returns True on success."""
        scores = await self.load_epss_scores()
        if scores:
            self.epss_scores = scores
            return True
        return False

    async def refresh_loop(self):
        """Periodic refresh of all feeds."""
        self._running = True
        interval = self.config.feeds.refresh_interval_seconds

        while self._running:
            try:
                await self.load_all_feeds()
                self._initialized.set()
            except Exception as e:
                logger.error("Feed refresh cycle failed", extra={"extra_data": {"error": str(e)}})
                self._initialized.set()  # Don't block startup

            await asyncio.sleep(interval)

    async def _file_watcher_loop(self):
        """Periodically check feed cache directory for changed files and reload them."""
        interval = 60  # Check every 60 seconds

        while self._running:
            try:
                await self._check_feed_cache_files()
            except Exception as e:
                logger.error("File watcher cycle failed", extra={
                    "extra_data": {"error": str(e)}
                })
            await asyncio.sleep(interval)

    async def _check_feed_cache_files(self):
        """Scan the feed cache directory and reload any files whose mtime changed."""
        if not os.path.isdir(self._feed_cache_dir):
            return

        try:
            entries = os.listdir(self._feed_cache_dir)
        except OSError:
            return

        for filename in entries:
            filepath = os.path.join(self._feed_cache_dir, filename)
            if not os.path.isfile(filepath):
                continue

            # Only watch text-based IOC files
            _, ext = os.path.splitext(filename)
            if ext.lower() not in (".txt", ".csv", ".json", ".list", ".feeds"):
                continue

            try:
                current_mtime = os.path.getmtime(filepath)
            except OSError:
                continue

            previous_mtime = self._watched_mtimes.get(filepath)
            if previous_mtime is not None and current_mtime <= previous_mtime:
                continue  # No change

            # File is new or modified — reload it
            feed_name = os.path.splitext(filename)[0]
            logger.info("Feed cache file changed, reloading", extra={
                "extra_data": {"file": filename, "feed_name": feed_name}
            })

            try:
                success = await self._load_feed_from_file(feed_name, filepath)
                if success:
                    self._watched_mtimes[filepath] = current_mtime
                    logger.info("Feed cache file reloaded successfully", extra={
                        "extra_data": {"feed_name": feed_name, "file": filename}
                    })
                else:
                    logger.warning("Feed cache file reload failed", extra={
                        "extra_data": {"feed_name": feed_name, "file": filename}
                    })
            except Exception as e:
                logger.error("Error reloading feed cache file", extra={
                    "extra_data": {"file": filename, "error": str(e)}
                })

    async def _load_feed_from_file(self, feed_name: str, filepath: str) -> bool:
        """Load IOCs from a local file and update in-memory storage.

        Supports line-delimited text files (one IOC per line) and simple JSON
        arrays of IOC strings.  Assigns a 'generic' category by default.
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()

            _, ext = os.path.splitext(filepath)
            iocs: Set[str] = set()

            if ext.lower() == ".json":
                try:
                    data = json.loads(raw)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                iocs.add(item.strip())
                            elif isinstance(item, dict):
                                for val in item.values():
                                    if isinstance(val, str):
                                        iocs.add(val.strip())
                except json.JSONDecodeError:
                    # Fall through to line-delimited parsing
                    iocs = self._parse_line_list(raw)
            else:
                iocs = self._parse_line_list(raw)

            if not iocs:
                self.feed_meta[feed_name] = {
                    "category": "generic",
                    "severity": "medium",
                    "last_refresh": datetime.now(timezone.utc),
                    "ioc_count": 0,
                    "status": "failed",
                    "error": "No IOCs found in file",
                }
                return False

            # Remove old IOCs for this feed from global lookup
            if feed_name in self.iocs:
                old_iocs = self.iocs[feed_name]
                for old_ioc in old_iocs:
                    self.global_iocs.pop(old_ioc, None)

            # Store new IOCs
            self.iocs[feed_name] = iocs
            category = "generic"
            severity = CATEGORY_SEVERITY.get(category, "medium")
            self.feed_meta[feed_name] = {
                "category": category,
                "severity": severity,
                "last_refresh": datetime.now(timezone.utc),
                "ioc_count": len(iocs),
                "status": "active",
                "error": None,
            }

            # Add to global lookup
            for ioc in iocs:
                self.global_iocs[ioc] = {
                    "feed": feed_name,
                    "category": category,
                    "severity": severity,
                }

            return True
        except Exception as e:
            logger.error("Failed to load feed from file", extra={
                "extra_data": {"feed_name": feed_name, "filepath": filepath, "error": str(e)}
            })
            return False

    def start_file_watcher(self):
        """Start the file watcher background task for feed cache hot-reload."""
        if self._file_watcher_task is not None:
            return
        # Ensure cache directory exists
        os.makedirs(self._feed_cache_dir, exist_ok=True)
        self._file_watcher_task = asyncio.create_task(self._file_watcher_loop())
        logger.info("Feed cache file watcher started", extra={
            "extra_data": {"directory": self._feed_cache_dir}
        })

    async def start(self):
        """Start feed manager - initial load + periodic refresh + file watcher."""
        self._refresh_task = asyncio.create_task(self.refresh_loop())
        self.start_file_watcher()
        # Wait for initial load (with timeout)
        try:
            await asyncio.wait_for(self._initialized.wait(), timeout=120.0)
        except asyncio.TimeoutError:
            logger.warning("Initial feed load timed out, continuing anyway")
            self._initialized.set()
        logger.info("Threat feed manager started")

    async def stop(self):
        """Stop feed manager."""
        self._running = False
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
        if self._file_watcher_task:
            self._file_watcher_task.cancel()
            try:
                await self._file_watcher_task
            except asyncio.CancelledError:
                pass
        await self.http.close()
        logger.info("Threat feed manager stopped")

    def lookup(self, value: str) -> Optional[dict]:
        """Look up a value in all threat feeds. Returns match info or None."""
        if value in self.global_iocs:
            result = dict(self.global_iocs[value])
            # Enrich with EPSS score for CVEs
            if value.startswith("CVE-"):
                epss = self.get_epss_score(value)
                if epss is not None:
                    result["epss_score"] = epss
            return result
        # Also check if value is contained in any IOC (substring match for domains)
        for ioc, meta in self.global_iocs.items():
            if ioc in value or value in ioc:
                return dict(meta)
        return None

    def lookup_ip(self, ip: str) -> Optional[dict]:
        """Look up an IP in threat feeds."""
        return self.lookup(ip)

    def lookup_domain(self, domain: str) -> Optional[dict]:
        """Look up a domain in threat feeds."""
        if domain in self.global_iocs:
            return dict(self.global_iocs[domain])
        # Also check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.global_iocs:
                return dict(self.global_iocs[parent])
        return None

    def get_feed_status(self) -> List[dict]:
        """Get status of all feeds."""
        result = []
        for name, meta in self.feed_meta.items():
            result.append({
                "name": name,
                "category": meta["category"],
                "url": self.config.feeds.urls.get(name, ""),
                "last_refresh": meta["last_refresh"].isoformat() if meta["last_refresh"] else None,
                "status": meta["status"],
                "ioc_count": meta["ioc_count"],
                "error": meta.get("error"),
                "staleness_seconds": (
                    (datetime.now(timezone.utc) - meta["last_refresh"]).total_seconds()
                    if meta["last_refresh"] else None
                ),
            })
        return result

    @property
    def is_ready(self) -> bool:
        return self._initialized.is_set()

    @property
    def total_ioc_count(self) -> int:
        return len(self.global_iocs)
