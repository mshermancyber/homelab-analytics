"""Threat intelligence matcher - cross-references events against feeds."""
from datetime import datetime, timezone
from typing import Optional, List

from ueba.logging_config import get_logger
from ueba.intelligence.feeds import ThreatFeedManager

logger = get_logger(__name__)


class ThreatMatcher:
    """Cross-references events against all loaded threat feeds."""

    # RFC1918, loopback, link-local — never flag these
    _PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.", "127.", "169.254.")

    def __init__(self, feed_manager: ThreatFeedManager):
        self.feed_manager = feed_manager

    def _is_private_ip(self, ip: str) -> bool:
        return ip.startswith(self._PRIVATE_PREFIXES) or ip in ("0.0.0.0", "::", "::1")

    def match_event(self, event: dict) -> List[dict]:
        """Match a normalized event against threat feeds.

        Skips domains in Tranco top-1M (likely legitimate) and private IPs.
        """
        matches = []
        parsed = event.get("parsed_fields") or {}

        # Check IPs (only public)
        for field in ["src_ip", "dst_ip", "source_ip", "client_ip"]:
            ip = event.get(field) or parsed.get(field)
            if not ip or self._is_private_ip(ip):
                continue
            match = self.feed_manager.lookup_ip(ip)
            if match and not any(m["ioc_value"] == ip for m in matches):
                matches.append({
                    "ioc_value": ip,
                    "field": field,
                    "feed": match["feed"],
                    "threat_category": match["category"],
                    "severity_hint": match["severity"],
                    "first_seen": datetime.now(timezone.utc),
                })

        # Check domains — skip if in Tranco top 1M
        for field in ["queried_domain"]:
            domain = parsed.get(field) or event.get(field)
            if not domain or "." not in str(domain):
                continue
            domain = str(domain).lower()
            if self.feed_manager.is_domain_reputable(domain):
                continue
            match = self.feed_manager.lookup_domain(domain)
            if match and not any(m["ioc_value"] == domain for m in matches):
                matches.append({
                    "ioc_value": domain,
                    "field": field,
                    "feed": match["feed"],
                    "threat_category": match["category"],
                    "severity_hint": match["severity"],
                    "first_seen": datetime.now(timezone.utc),
                })

        if matches:
            logger.info("Threat matches found", extra={
                "extra_data": {
                    "match_count": len(matches),
                    "feeds": [m["feed"] for m in matches],
                }
            })

        return matches
