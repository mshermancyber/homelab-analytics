"""DNS-Flow Coherence Policy — tracks ratio of DNS-backed connections to total.

Measures the fraction of OPNsense connections that were preceded by a Pi-hole
DNS query for the same destination.  A drop in this ratio suggests the host
is connecting to IPs without DNS resolution (e.g., hard-coded C2 addresses).

Requires a DNSFlowCorrelator data structure that cross-references Pi-hole
queries with OPNsense connections.  The correlator is injected via constructor.

Data source: both Pi-hole and OPNsense.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy import select, func

from ueba.analytics.policy_base import BehavioralPolicy, PolicyScore
from ueba.database import async_session_factory, submit_write
from ueba.logging_config import get_logger

logger = get_logger(__name__)


class DNSFlowCorrelator:
    """Cross-references Pi-hole DNS queries with OPNsense connections.

    Maintains an in-memory mapping of recently resolved domains to IPs,
    allowing queries about whether a given destination IP was resolved
    via DNS by a given host.
    """

    def __init__(self, ttl_seconds: int = 300):
        # host_ip -> {dst_ip -> expiry_monotonic}
        self._resolutions: Dict[str, Dict[str, float]] = {}
        self._ttl = ttl_seconds

    def record_dns_resolution(self, client_ip: str, resolved_ips: List[str]) -> None:
        """Record that a DNS query from *client_ip* resolved to *resolved_ips*."""
        import time as _time
        now = _time.monotonic()
        if client_ip not in self._resolutions:
            self._resolutions[client_ip] = {}
        for ip in resolved_ips:
            self._resolutions[client_ip][ip] = now + self._ttl

    def is_dns_backed(self, host_ip: str, dst_ip: str) -> bool:
        """Check if *dst_ip* was recently resolved by *host_ip* via DNS."""
        import time as _time
        now = _time.monotonic()
        host_resolutions = self._resolutions.get(host_ip, {})
        expiry = host_resolutions.get(dst_ip, 0)
        return now < expiry

    def get_coherence_ratio(self, host_ip: str, recent_connections: List[str]) -> float:
        """Compute fraction of recent connections that are DNS-backed."""
        if not recent_connections:
            return 1.0
        backed = sum(1 for ip in recent_connections if self.is_dns_backed(host_ip, ip))
        return backed / len(recent_connections)

    def prune(self) -> None:
        """Remove expired entries."""
        import time as _time
        now = _time.monotonic()
        for host_ip in list(self._resolutions.keys()):
            self._resolutions[host_ip] = {
                ip: exp for ip, exp in self._resolutions[host_ip].items()
                if now < exp
            }
            if not self._resolutions[host_ip]:
                del self._resolutions[host_ip]


class DnsFlowCoherencePolicy(BehavioralPolicy):
    """Scores hosts when their DNS-flow coherence ratio drops below baseline.

    A host normally resolves most destinations via DNS.  A drop in this
    ratio suggests C2 or proxy behavior where IPs are hard-coded.
    """

    def __init__(
        self,
        lookback_hours: int = 1,
        learning_rate: float = 0.1,
        correlator: Optional[DNSFlowCorrelator] = None,
    ):
        self._lookback_hours = lookback_hours
        self._learning_rate = learning_rate
        self._correlator = correlator or DNSFlowCorrelator()
        # Per-host baselines: host_ip -> {coherence_ratio, days_learned, sensitivity}
        self._baselines: Dict[str, Dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "dns_flow_coherence"

    @property
    def description(self) -> str:
        return (
            "Tracks ratio of DNS-backed connections to total connections.  "
            "Scores drops below host baseline as potential C2/proxy behavior."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(
        self, host_ip: str, event_data: Optional[Dict[str, Any]] = None
    ) -> PolicyScore:
        """Evaluate DNS-flow coherence for a host."""
        try:
            connections = await self._extract_recent_connections(host_ip)
            if not connections:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No connection data available in lookback window.",
                    baseline_days=0,
                )

            current_ratio = self._correlator.get_coherence_ratio(host_ip, connections)

            baseline = self._baselines.get(host_ip)
            if baseline is None:
                # Cold start: assume default coherence of 0.7
                default_baseline = 0.7
                deviation = max(0.0, default_baseline - current_ratio)
                score = self._sigmoid(deviation, midpoint=0.2, steepness=0.15)
                score = self._cold_start_cap(score, 0)
                return PolicyScore(
                    score=round(score, 4),
                    policy_name=self.name,
                    reason=(
                        f"Cold-start: coherence ratio {current_ratio:.3f} vs "
                        f"default {default_baseline:.3f}."
                    ),
                    details={
                        "coherence_ratio": round(current_ratio, 4),
                        "connections": len(connections),
                    },
                    baseline_days=0,
                )

            baseline_ratio = baseline.get("coherence_ratio", 0.7)
            days = baseline.get("days_learned", 0)
            sensitivity = baseline.get("sensitivity", 1.0)

            deviation = max(0.0, baseline_ratio - current_ratio)
            score = self._sigmoid(deviation, midpoint=0.2 / max(sensitivity, 0.1), steepness=0.15)
            score = self._cold_start_cap(score, days)

            return PolicyScore(
                score=round(score, 4),
                policy_name=self.name,
                reason=(
                    f"Coherence ratio {current_ratio:.3f} below baseline "
                    f"{baseline_ratio:.3f} (deviation={deviation:.3f})."
                ),
                details={
                    "coherence_ratio": round(current_ratio, 4),
                    "baseline_ratio": round(baseline_ratio, 4),
                    "deviation": round(deviation, 4),
                    "connections": len(connections),
                },
                baseline_days=days,
            )
        except Exception:
            logger.error(
                "DNS-flow coherence evaluation failed",
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
        """Update the learned coherence baseline for a host."""
        try:
            current_ratio = features.get("coherence_ratio")
            if current_ratio is None:
                connections = await self._extract_recent_connections(host_ip)
                if not connections:
                    return
                current_ratio = self._correlator.get_coherence_ratio(host_ip, connections)

            if host_ip not in self._baselines:
                self._baselines[host_ip] = {
                    "coherence_ratio": current_ratio,
                    "days_learned": 1,
                    "sensitivity": 1.0,
                }
                await self._persist_baseline(host_ip)
                return

            bl = self._baselines[host_ip]
            bl["coherence_ratio"] = self._ema_update(
                bl["coherence_ratio"], current_ratio, self._learning_rate, feedback
            )
            bl["days_learned"] = min(bl["days_learned"] + 1, 365)

            if feedback == "false_positive":
                bl["sensitivity"] = max(0.5, bl["sensitivity"] * 0.9)
            elif feedback == "true_positive":
                bl["sensitivity"] = min(2.0, bl["sensitivity"] * 1.1)

            await self._persist_baseline(host_ip)
        except Exception:
            logger.error(
                "DNS-flow coherence baseline update failed",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )

    async def get_baseline(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Return the current baseline for a host."""
        return self._baselines.get(host_ip)

    @property
    def correlator(self) -> DNSFlowCorrelator:
        return self._correlator

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    async def _extract_recent_connections(self, host_ip: str) -> List[str]:
        """Extract distinct dst_ips from recent OPNsense connections."""
        since = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)

        async with async_session_factory() as session:
            result = await session.execute(
                select(OPNsenseLog.dst_ip)
                .where(
                    OPNsenseLog.src_ip == host_ip,
                    OPNsenseLog.timestamp >= since,
                )
                .distinct()
                .limit(200)
            )
            rows = result.all()

        return [row.dst_ip for row in rows if row.dst_ip]

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
                "Failed to persist DNS-flow coherence baseline",
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
                    "Loaded DNS-flow coherence baselines from DB",
                    extra={"extra_data": {"count": len(rows)}},
                )
        except Exception:
            logger.warning("Could not load DNS-flow coherence baselines", exc_info=True)


# Late import to avoid circular dependency
from ueba.models import OPNsenseLog  # noqa: E402
