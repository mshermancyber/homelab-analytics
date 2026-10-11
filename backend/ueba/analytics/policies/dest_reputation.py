"""Destination Reputation Profile Policy — per-host set of destination characteristics.

Scores weighted novelty: residential/hosting ASNs score higher than CDN/cloud.
Uses existing MMDB enrichment for (ASN, country_code, org_category) tuples.

Data source: OPNsense dst_ip + MMDB lookup.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple

from sqlalchemy import select

from ueba.analytics.policy_base import BehavioralPolicy, PolicyScore
from ueba.database import async_session_factory, submit_write
from ueba.intelligence.enrichment import enrich_ip
from ueba.logging_config import get_logger
from ueba.models import OPNsenseLog

logger = get_logger(__name__)

# Org categories based on ASN name heuristics
def _classify_org(org_name: Optional[str]) -> str:
    """Classify an org name into a category."""
    if not org_name:
        return "unknown"
    name_lower = org_name.lower()
    if any(kw in name_lower for kw in ("google", "cloudflare", "akamai", "fastly", "aws", "azure", "microsoft", "apple", "facebook", "netflix", "cdn", "edgecast", "stackpath")):
        return "cdn_cloud"
    if any(kw in name_lower for kw in ("comcast", "verizon", "at&t", "t-mobile", "sprint", "charter", "spectrum", "cox", "bt ", "vodafone", "orange", "deutsche telekom", "telefonica", "china telecom", "china mobile", "ntt", "kddi", "telstra", "rogers", "bell ", "sky ", "virgin media", "centurylink", "frontier", "windstream")):
        return "isp_residential"
    if any(kw in name_lower for kw in ("ovh", "hetzner", "digitalocean", "linode", "vultr", "host", "dedicated", "server", "colo", "datacenter", "data center", "leaseweb", "softlayer", "rackspace")):
        return "hosting"
    if any(kw in name_lower for kw in ("university", "college", "edu", "school", "research", "institute")):
        return "education"
    if any(kw in name_lower for kw in ("government", "gov", "municipal")):
        return "government"
    return "other"


# Novelty weights per org category: higher = more suspicious when novel
_CATEGORY_NOVELTY_WEIGHTS: Dict[str, float] = {
    "hosting": 2.0,
    "isp_residential": 1.5,
    "unknown": 1.5,
    "other": 1.0,
    "education": 0.7,
    "government": 0.5,
    "cdn_cloud": 0.3,
}


class DestReputationPolicy(BehavioralPolicy):
    """Scores hosts based on novelty of destination (ASN, country, org category).

    Residential/hosting destinations are weighted higher than CDN/cloud when
    they first appear in a host's profile.
    """

    def __init__(self, lookback_hours: int = 1, learning_rate: float = 0.1):
        self._lookback_hours = lookback_hours
        self._learning_rate = learning_rate
        # Per-host baselines: host_ip -> {destinations: [(asn, cc, org_cat), ...], days_learned, sensitivity}
        self._baselines: Dict[str, Dict[str, Any]] = {}
        # Enrichment cache: ip -> {asn, country_code, org}
        self._enrichment_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "dest_reputation"

    @property
    def description(self) -> str:
        return (
            "Per-host set of destination (ASN, country, org) tuples with "
            "weighted novelty scoring.  Residential/hosting ASNs score "
            "higher than CDN/cloud."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(
        self, host_ip: str, event_data: Optional[Dict[str, Any]] = None
    ) -> PolicyScore:
        """Evaluate destination reputation for a host."""
        try:
            current_dests = await self._extract_current_destinations(host_ip)
            if not current_dests:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No destination data available in lookback window.",
                    baseline_days=0,
                )

            baseline = self._baselines.get(host_ip)
            if baseline is None:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No baseline established — cold start.",
                    baseline_days=0,
                    details={"current_dest_count": len(current_dests)},
                )

            known_tuples: Set[Tuple[str, str, str]] = set(
                baseline.get("destinations", [])
            )
            days = baseline.get("days_learned", 0)
            sensitivity = baseline.get("sensitivity", 1.0)

            if not known_tuples:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="Baseline has no destination data yet.",
                    baseline_days=days,
                )

            # Compute weighted novelty
            total_weight = 0.0
            novel_weight = 0.0
            novel_items: List[Tuple[str, str, str]] = []

            for asn, cc, org_cat in current_dests:
                w = _CATEGORY_NOVELTY_WEIGHTS.get(org_cat, 1.0)
                total_weight += w
                if (asn, cc, org_cat) not in known_tuples:
                    novel_weight += w
                    novel_items.append((asn, cc, org_cat))

            fraction_novel = novel_weight / total_weight if total_weight > 0 else 0.0
            score = min(fraction_novel * sensitivity * 2.0, 1.0)
            score = self._cold_start_cap(score, days)

            return PolicyScore(
                score=round(score, 4),
                policy_name=self.name,
                reason=(
                    f"Weighted novelty {fraction_novel:.1%} — "
                    f"{len(novel_items)} novel destinations."
                ),
                details={
                    "novel_destinations": [
                        {"asn": a, "country": c, "category": o}
                        for a, c, o in novel_items[:10]
                    ],
                    "total_destinations": len(current_dests),
                    "known_destination_count": len(known_tuples),
                },
                baseline_days=days,
            )
        except Exception:
            logger.error(
                "Destination reputation evaluation failed",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )
            return PolicyScore(score=0.0, policy_name=self.name, reason="Evaluation error.")

    async def update_baseline(
        self,
        host_ip: str,
        features: Dict[str, Any],
        feedback: Optional[str] = None,
    ) -> None:
        """Update the learned destination reputation baseline for a host."""
        try:
            current = features.get("destinations")
            if current is None:
                current = await self._extract_current_destinations(host_ip)
            if not current:
                return

            if host_ip not in self._baselines:
                self._baselines[host_ip] = {
                    "destinations": list(current),
                    "days_learned": 1,
                    "sensitivity": 1.0,
                }
                await self._persist_baseline(host_ip)
                return

            bl = self._baselines[host_ip]
            known = set(bl["destinations"])
            known.update(current)
            bl["destinations"] = list(known)
            bl["days_learned"] = min(bl["days_learned"] + 1, 365)

            if feedback == "false_positive":
                bl["sensitivity"] = max(0.5, bl["sensitivity"] * 0.9)
            elif feedback == "true_positive":
                bl["sensitivity"] = min(2.0, bl["sensitivity"] * 1.1)

            await self._persist_baseline(host_ip)
        except Exception:
            logger.error(
                "Destination reputation baseline update failed",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )

    async def get_baseline(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Return the current baseline for a host."""
        return self._baselines.get(host_ip)

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    async def _extract_current_destinations(
        self, host_ip: str
    ) -> List[Tuple[str, str, str]]:
        """Extract (ASN, country_code, org_category) tuples for current destinations."""
        since = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)

        async with async_session_factory() as session:
            result = await session.execute(
                select(OPNsenseLog.dst_ip)
                .where(
                    OPNsenseLog.src_ip == host_ip,
                    OPNsenseLog.timestamp >= since,
                )
                .distinct()
                .limit(100)
            )
            rows = result.all()

        destinations: List[Tuple[str, str, str]] = []
        seen = set()
        for row in rows:
            dst_ip = row.dst_ip
            if not dst_ip or dst_ip in seen:
                continue
            seen.add(dst_ip)

            # Enrich
            if dst_ip not in self._enrichment_cache:
                try:
                    enriched = await enrich_ip(dst_ip)
                    self._enrichment_cache[dst_ip] = enriched
                except Exception:
                    self._enrichment_cache[dst_ip] = {}
            enriched = self._enrichment_cache.get(dst_ip, {})

            asn = enriched.get("asn") or "unknown"
            cc = enriched.get("country_code") or "??"
            org_cat = _classify_org(enriched.get("org") or enriched.get("isp"))

            destinations.append((asn, cc, org_cat))

            # Limit cache size
            if len(self._enrichment_cache) > 2000:
                # Remove oldest entries
                keys = list(self._enrichment_cache.keys())
                for k in keys[:500]:
                    del self._enrichment_cache[k]

        return destinations

    async def _persist_baseline(self, host_ip: str) -> None:
        """Persist the in-memory baseline to the database."""
        bl = self._baselines.get(host_ip)
        if not bl:
            return

        async def _do_write():
            from ueba.models import PolicyBaseline
            async with async_session_factory() as session:
                result = await session.execute(
                    select(PolicyBaseline).where(
                        PolicyBaseline.policy_name == self.name,
                        PolicyBaseline.host_ip == host_ip,
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    row.baseline_data = bl
                    row.sensitivity = bl.get("sensitivity", 1.0)
                    row.days_learned = bl.get("days_learned", 0)
                else:
                    session.add(PolicyBaseline(
                        policy_name=self.name,
                        host_ip=host_ip,
                        baseline_data=bl,
                        sensitivity=bl.get("sensitivity", 1.0),
                        days_learned=bl.get("days_learned", 0),
                    ))
                await session.commit()

        try:
            await submit_write(_do_write)
        except Exception:
            logger.warning(
                "Failed to persist destination reputation baseline",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )

    async def load_baselines_from_db(self) -> None:
        """Restore in-memory baselines from the database on startup."""
        try:
            from ueba.models import PolicyBaseline
            async with async_session_factory() as session:
                result = await session.execute(
                    select(PolicyBaseline).where(
                        PolicyBaseline.policy_name == self.name
                    )
                )
                rows = result.scalars().all()
                for row in rows:
                    bd = row.baseline_data
                    if isinstance(bd, str):
                        import json
                        bd = json.loads(bd)
                    # Convert destinations back to tuples
                    if "destinations" in bd:
                        bd["destinations"] = [tuple(d) for d in bd["destinations"]]
                    self._baselines[row.host_ip] = bd
                logger.info(
                    "Loaded destination reputation baselines from DB",
                    extra={"extra_data": {"count": len(rows)}},
                )
        except Exception:
            logger.warning("Could not load destination reputation baselines", exc_info=True)
