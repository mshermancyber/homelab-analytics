"""DNS Diversity Profile Policy — replaces static DNS burst + first_seen for behavioral scoring.

Learns per-host hourly DNS query profiles and scores deviation from 7-day
rolling baseline.  Device role provides prior expectations.

Data source: Pi-hole queries from pihole_queries table.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy import select, func

from ueba.analytics.policy_base import BehavioralPolicy, PolicyScore
from ueba.database import async_session_factory, submit_write
from ueba.logging_config import get_logger

logger = get_logger(__name__)

# Tranco TLD list — well-known reputable TLDs that users commonly visit.
# In a full deployment this would be loaded from a file; here we hard-code
# a representative set.
_TRANCO_TLD_SET: set = {
    "com", "org", "net", "gov", "edu", "mil",
    "co.uk", "co.jp", "de", "fr", "ca", "au",
    "io", "dev", "app", "cloud", "tech",
}

# Device role prior for expected hourly unique domains (normalized against overall)
_ROLE_PRIORS: Dict[str, Dict[str, float]] = {
    "iot": {
        "expected_unique_domains": 5,
        "expected_tranco_pct": 0.95,
        "expected_first_seen_pct": 0.05,
        "sensitivity_multiplier": 0.5,  # Tighter — less variance expected
    },
    "server": {
        "expected_unique_domains": 20,
        "expected_tranco_pct": 0.60,
        "expected_first_seen_pct": 0.20,
        "sensitivity_multiplier": 1.0,
    },
    "workstation": {
        "expected_unique_domains": 50,
        "expected_tranco_pct": 0.75,
        "expected_first_seen_pct": 0.10,
        "sensitivity_multiplier": 1.0,
    },
    "infrastructure": {
        "expected_unique_domains": 10,
        "expected_tranco_pct": 0.50,
        "expected_first_seen_pct": 0.30,
        "sensitivity_multiplier": 0.7,
    },
}

_FEATURE_KEYS = [
    "unique_domains",
    "unique_tlds",
    "pct_tranco_domains",
    "pct_first_seen_domains",
    "mean_domain_length",
    "max_subdomain_depth",
]


class DnsDiversityPolicy(BehavioralPolicy):
    """Scores hosts based on deviation from learned DNS query diversity.

    Per-host hourly features are compared against a rolling 7-day EMA baseline.
    Device role priors adjust baseline expectations.
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        device_roles: Optional[Dict[str, str]] = None,
    ):
        self._learning_rate = learning_rate
        self._device_roles = device_roles or {}
        # Per-host baselines: host_ip -> {features, days_learned, sensitivity}
        self._baselines: Dict[str, Dict[str, Any]] = {}
        # Network-wide average features (cold start)
        self._network_baseline: Optional[Dict[str, float]] = None
        self._network_days: int = 0
        # First-seen domain cache: domain -> first_seen_timestamp
        self._first_seen_cache: Dict[str, datetime] = {}

    @property
    def name(self) -> str:
        return "dns_diversity"

    @property
    def description(self) -> str:
        return (
            "Per-host hourly DNS query diversity profiling with 7-day rolling "
            "baseline.  Device role provides prior expectations for IoT vs "
            "workstation behavior."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(
        self, host_ip: str, event_data: Optional[Dict[str, Any]] = None
    ) -> PolicyScore:
        """Evaluate DNS diversity for a host."""
        try:
            features = await self._extract_features(host_ip)
            if features is None:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No DNS query data available in lookback window.",
                    baseline_days=0,
                )

            role = self._device_roles.get(host_ip, "workstation")
            role_prior = _ROLE_PRIORS.get(role, _ROLE_PRIORS["workstation"])
            sensitivity_mult = role_prior.get("sensitivity_multiplier", 1.0)

            baseline = self._baselines.get(host_ip)
            if baseline is None:
                net = await self._get_network_baseline()
                if net is None:
                    return PolicyScore(
                        score=0.0,
                        policy_name=self.name,
                        reason="Insufficient data — cold start period.",
                        baseline_days=0,
                        details={"features": features, "device_role": role},
                    )

                deviation = self._compute_deviation(features, net, role_prior)
                score = self._sigmoid(deviation, midpoint=1.5, steepness=1.0)
                score = self._cold_start_cap(score, self._network_days)
                return PolicyScore(
                    score=round(min(score * sensitivity_mult, 1.0), 4),
                    policy_name=self.name,
                    reason=f"Cold-start: feature deviation {deviation:.3f} from network baseline (role={role}).",
                    details={
                        "features": features,
                        "network_baseline": net,
                        "deviation": round(deviation, 4),
                        "device_role": role,
                    },
                    baseline_days=self._network_days,
                )

            baseline_features = baseline.get("features", {})
            days = baseline.get("days_learned", 0)
            sensitivity = baseline.get("sensitivity", 1.0)

            deviation = self._compute_deviation(features, baseline_features, role_prior)
            score = self._sigmoid(deviation, midpoint=1.5 / max(sensitivity, 0.1), steepness=1.0)
            score = self._cold_start_cap(score, days)

            return PolicyScore(
                score=round(min(score * sensitivity_mult, 1.0), 4),
                policy_name=self.name,
                reason=f"Feature deviation {deviation:.3f} from learned DNS profile (role={role}).",
                details={
                    "features": features,
                    "baseline_features": baseline_features,
                    "deviation": round(deviation, 4),
                    "device_role": role,
                    "sensitivity": sensitivity,
                },
                baseline_days=days,
            )
        except Exception:
            logger.error(
                "DNS diversity evaluation failed",
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
        """Update the learned DNS diversity baseline for a host."""
        try:
            current = features if features else await self._extract_features(host_ip)
            if current is None:
                return

            if host_ip not in self._baselines:
                self._baselines[host_ip] = {
                    "features": dict(current),
                    "days_learned": 1,
                    "sensitivity": 1.0,
                }
                await self._persist_baseline(host_ip)
                return

            bl = self._baselines[host_ip]
            bl["features"] = self._ema_update_dict(
                bl["features"], current, self._learning_rate, feedback
            )
            bl["days_learned"] = min(bl["days_learned"] + 1, 365)

            if feedback == "false_positive":
                bl["sensitivity"] = max(0.5, bl["sensitivity"] * 0.9)
            elif feedback == "true_positive":
                bl["sensitivity"] = min(2.0, bl["sensitivity"] * 1.1)

            await self._persist_baseline(host_ip)
        except Exception:
            logger.error(
                "DNS diversity baseline update failed",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )

    async def get_baseline(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Return the current baseline for a host."""
        return self._baselines.get(host_ip)

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    async def _extract_features(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Extract hourly DNS diversity features for a host."""
        since = datetime.now(timezone.utc) - timedelta(hours=1)

        async with async_session_factory() as session:
            result = await session.execute(
                select(
                    PiHoleQuery.queried_domain,
                    PiHoleQuery.timestamp,
                ).where(
                    PiHoleQuery.client_ip == host_ip,
                    PiHoleQuery.timestamp >= since,
                )
            )
            rows = result.all()

        if not rows:
            return None

        domains = [row.queried_domain for row in rows if row.queried_domain]
        if not domains:
            return None

        unique_domains = len(set(domains))
        tlds = set()
        tranco_count = 0
        first_seen_count = 0
        total_length = 0
        max_subdomain_depth = 0

        for d in domains:
            # TLD extraction (last segment after final dot)
            parts = d.lower().rstrip(".").split(".")
            if len(parts) >= 2:
                tld = parts[-1]
                tlds.add(tld)
                # Check against Tranco TLDs ± second-level
                if tld in _TRANCO_TLD_SET or (
                    len(parts) >= 3
                    and f"{parts[-2]}.{parts[-1]}" in _TRANCO_TLD_SET
                ):
                    tranco_count += 1
            else:
                tlds.add(parts[-1] if parts else d)

            # First-seen check
            if d not in self._first_seen_cache:
                self._first_seen_cache[d] = datetime.now(timezone.utc)
                first_seen_count += 1

            total_length += len(d)
            max_subdomain_depth = max(max_subdomain_depth, len(parts) - 2)

        return {
            "unique_domains": float(unique_domains),
            "unique_tlds": float(len(tlds)),
            "pct_tranco_domains": round(tranco_count / len(domains), 4) if domains else 0.0,
            "pct_first_seen_domains": round(first_seen_count / len(domains), 4) if domains else 0.0,
            "mean_domain_length": round(total_length / len(domains), 2) if domains else 0.0,
            "max_subdomain_depth": float(max_subdomain_depth),
        }

    def _compute_deviation(
        self,
        current: Dict[str, Any],
        baseline: Dict[str, Any],
        role_prior: Dict[str, float],
    ) -> float:
        """Compute weighted deviation between current features and baseline."""
        total_deviation = 0.0
        weight_sum = 0.0
        weights = {
            "unique_domains": 1.0,
            "unique_tlds": 1.5,
            "pct_tranco_domains": 2.0,
            "pct_first_seen_domains": 2.0,
            "mean_domain_length": 0.5,
            "max_subdomain_depth": 1.0,
        }
        for key in _FEATURE_KEYS:
            cv = float(current.get(key, 0))
            bv = float(baseline.get(key, 0))
            if bv > 0:
                dev = abs(cv - bv) / bv
            else:
                dev = cv if cv > 0 else 0.0
            w = weights.get(key, 1.0)
            total_deviation += dev * w
            weight_sum += w

        return total_deviation / weight_sum if weight_sum > 0 else 0.0

    async def _get_network_baseline(self) -> Optional[Dict[str, float]]:
        """Compute network-wide average DNS diversity features."""
        if self._network_baseline is not None:
            return self._network_baseline

        since = datetime.now(timezone.utc) - timedelta(hours=1)
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(
                        PiHoleQuery.client_ip,
                        func.count(func.distinct(PiHoleQuery.queried_domain)).label("ud"),
                    ).where(PiHoleQuery.timestamp >= since)
                    .group_by(PiHoleQuery.client_ip)
                    .limit(200)
                )
                rows = result.all()

            if not rows:
                return None

            total_ud = sum(row.ud for row in rows)

            # Compute network average as a rough proxy
            self._network_baseline = {
                "unique_domains": round(total_ud / len(rows), 2) if rows else 0.0,
                "unique_tlds": 5.0,
                "pct_tranco_domains": 0.75,
                "pct_first_seen_domains": 0.10,
                "mean_domain_length": 15.0,
                "max_subdomain_depth": 2.0,
            }

            async with async_session_factory() as session:
                day_result = await session.execute(
                    select(func.count(func.distinct(func.date(PiHoleQuery.timestamp)))).where(
                        PiHoleQuery.timestamp >= since
                    )
                )
                day_row = day_result.first()
                self._network_days = day_row[0] if day_row and day_row[0] else 0

            return self._network_baseline
        except Exception:
            logger.warning("Network DNS baseline query failed", exc_info=True)
            return None

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
                "Failed to persist DNS diversity baseline",
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
                    self._baselines[row.host_ip] = bd
                logger.info(
                    "Loaded DNS diversity baselines from DB",
                    extra={"extra_data": {"count": len(rows)}},
                )
        except Exception:
            logger.warning("Could not load DNS diversity baselines", exc_info=True)


# Late import to avoid circular dependency
from ueba.models import PiHoleQuery  # noqa: E402
