"""Port Usage Profile Policy — per-host set of observed destination ports.

Score = fraction of current connections going to ports NOT in baseline set.
Proxy/C2 behaviors often use unusual ports not in the host's normal profile.

Data source: OPNsense dst_port.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set

from sqlalchemy import select, func

from ueba.analytics.policy_base import BehavioralPolicy, PolicyScore
from ueba.database import async_session_factory, submit_write
from ueba.logging_config import get_logger
from ueba.models import OPNsenseLog

logger = get_logger(__name__)


class PortUsagePolicy(BehavioralPolicy):
    """Scores hosts based on connections to ports outside their known set.

    Maintains a per-host set of observed dst_ports with frequency counts.
    Anomaly score = fraction of current connections to novel ports.
    """

    def __init__(self, lookback_hours: int = 1, learning_rate: float = 0.1):
        self._lookback_hours = lookback_hours
        self._learning_rate = learning_rate
        # Per-host baselines: host_ip -> {ports: {port: count}, days_learned, sensitivity}
        self._baselines: Dict[str, Dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "port_usage"

    @property
    def description(self) -> str:
        return (
            "Per-host set of observed destination ports.  Scores connections "
            "to ports outside the host's normal profile."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(
        self, host_ip: str, event_data: Optional[Dict[str, Any]] = None
    ) -> PolicyScore:
        """Evaluate port usage for a host."""
        try:
            current_ports = await self._extract_current_ports(host_ip)
            if not current_ports:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No connection data available in lookback window.",
                    baseline_days=0,
                )

            baseline = self._baselines.get(host_ip)
            if baseline is None:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No baseline established — cold start.",
                    baseline_days=0,
                    details={"current_ports": list(current_ports)[:50]},
                )

            known_ports: Dict[int, int] = baseline.get("ports", {})
            days = baseline.get("days_learned", 0)
            sensitivity = baseline.get("sensitivity", 1.0)

            if not known_ports:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="Baseline has no port data yet.",
                    baseline_days=days,
                )

            # Count novel ports
            known_set = set(known_ports.keys())
            novel = sum(1 for p in current_ports if p not in known_set)
            total = len(current_ports)
            fraction_novel = novel / total if total > 0 else 0.0

            score = min(fraction_novel * sensitivity * 2.0, 1.0)
            score = self._cold_start_cap(score, days)

            return PolicyScore(
                score=round(score, 4),
                policy_name=self.name,
                reason=(
                    f"{novel}/{total} connections to novel ports "
                    f"({fraction_novel:.1%} of current)."
                ),
                details={
                    "novel_ports": sorted(list(set(current_ports) - known_set))[:20],
                    "total_connections": total,
                    "novel_count": novel,
                    "known_port_count": len(known_set),
                },
                baseline_days=days,
            )
        except Exception:
            logger.error(
                "Port usage evaluation failed",
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
        """Update the learned port usage baseline for a host."""
        try:
            current_ports = features.get("ports")
            if current_ports is None:
                current_ports = await self._extract_current_ports(host_ip)
            if not current_ports:
                return

            if host_ip not in self._baselines:
                port_counts: Dict[int, int] = {}
                for p in current_ports:
                    port_counts[p] = port_counts.get(p, 0) + 1
                self._baselines[host_ip] = {
                    "ports": port_counts,
                    "days_learned": 1,
                    "sensitivity": 1.0,
                }
                await self._persist_baseline(host_ip)
                return

            bl = self._baselines[host_ip]
            # Merge new ports with EMA-style decay
            rate = self._learning_rate
            if feedback == "false_positive":
                rate *= 1.2
            elif feedback == "true_positive":
                rate *= 0.8

            # Increment counts for observed ports
            known = bl["ports"]
            for p in current_ports:
                known[p] = known.get(p, 0) + 1

            # Decay all counts slightly to forget stale ports
            for p in list(known.keys()):
                known[p] = max(known[p] * (1.0 - rate * 0.1), 0.5)
                if known[p] < 1.0:
                    del known[p]

            bl["days_learned"] = min(bl["days_learned"] + 1, 365)

            if feedback == "false_positive":
                bl["sensitivity"] = max(0.5, bl["sensitivity"] * 0.9)
            elif feedback == "true_positive":
                bl["sensitivity"] = min(2.0, bl["sensitivity"] * 1.1)

            await self._persist_baseline(host_ip)
        except Exception:
            logger.error(
                "Port usage baseline update failed",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )

    async def get_baseline(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Return the current baseline for a host."""
        return self._baselines.get(host_ip)

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    async def _extract_current_ports(self, host_ip: str) -> List[int]:
        """Extract list of dst_ports for a host in the lookback window."""
        since = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)

        async with async_session_factory() as session:
            result = await session.execute(
                select(OPNsenseLog.dst_port)
                .where(
                    OPNsenseLog.src_ip == host_ip,
                    OPNsenseLog.timestamp >= since,
                    OPNsenseLog.dst_port.isnot(None),
                )
                .limit(500)
            )
            rows = result.all()

        return [row.dst_port for row in rows if row.dst_port is not None]

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
                "Failed to persist port usage baseline",
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
                    # Convert port keys back to int
                    if "ports" in bd:
                        bd["ports"] = {int(k): v for k, v in bd["ports"].items()}
                    self._baselines[row.host_ip] = bd
                logger.info(
                    "Loaded port usage baselines from DB",
                    extra={"extra_data": {"count": len(rows)}},
                )
        except Exception:
            logger.warning("Could not load port usage baselines", exc_info=True)
