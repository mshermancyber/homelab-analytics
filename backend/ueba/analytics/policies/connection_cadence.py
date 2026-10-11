"""Connection Cadence Policy — replaces static beaconing detector with behavioral scoring.

Learns a per-host histogram of inter-connection intervals and scores hosts
based on KL divergence from their learned baseline.

Data source: OPNsense timestamps from opnsense_logs table.
"""

import math
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy import select, func, text, cast, Integer

from ueba.analytics.policy_base import BehavioralPolicy, PolicyScore
from ueba.database import async_session_factory, submit_write
from ueba.logging_config import get_logger

logger = get_logger(__name__)

# 10-bin cadence histogram edges (seconds)
_CADENCE_BINS = [
    (0, 1),          # 0-1s
    (1, 5),          # 1-5s
    (5, 15),         # 5-15s
    (15, 30),        # 15-30s
    (30, 60),        # 30-60s
    (60, 300),       # 1-5m
    (300, 900),      # 5-15m
    (900, 3600),     # 15-60m
    (3600, 21600),   # 1-6h
    (21600, 86400),  # 6h+
]

_BIN_LABELS = [
    "0-1s", "1-5s", "5-15s", "15-30s", "30-60s",
    "1-5m", "5-15m", "15-60m", "1-6h", "6h+",
]


class ConnectionCadencePolicy(BehavioralPolicy):
    """Scores hosts based on deviation from learned inter-connection cadence.

    Computes a 10-bin histogram of inter-connection intervals, compares it
    to the host's EMA-baselined histogram via KL divergence, and maps the
    result to a 0-1 anomaly score via sigmoid.
    """

    def __init__(self, lookback_hours: int = 6, learning_rate: float = 0.1):
        self._lookback_hours = lookback_hours
        self._learning_rate = learning_rate
        # Per-host baseline: Dict[str, Dict] where Dict = {histogram, days_learned, sensitivity}
        self._baselines: Dict[str, Dict[str, Any]] = {}
        # Network-wide average cadence histogram (for cold start)
        self._network_baseline: Optional[List[float]] = None
        self._network_days: int = 0

    @property
    def name(self) -> str:
        return "connection_cadence"

    @property
    def description(self) -> str:
        return (
            "Scores hosts based on KL divergence between current and learned "
            "inter-connection interval histograms.  Replaces static beaconing "
            "detection with behavioral profiling."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(
        self, host_ip: str, event_data: Optional[Dict[str, Any]] = None
    ) -> PolicyScore:
        """Evaluate connection cadence for a host.

        Extracts inter-connection intervals from OPNsense logs, builds a
        10-bin histogram, and computes KL divergence from the learned baseline.
        """
        try:
            current_hist = await self._extract_histogram(host_ip)
            if not current_hist or sum(current_hist) == 0:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No connection data available in lookback window.",
                    baseline_days=0,
                )

            baseline = self._baselines.get(host_ip)
            if baseline is None:
                # Cold start: use network-wide average
                net = await self._get_network_baseline()
                if net is None:
                    return PolicyScore(
                        score=0.0,
                        policy_name=self.name,
                        reason="Insufficient data — cold start period.",
                        baseline_days=0,
                        details={"histogram": current_hist},
                    )
                kl = self._kl_divergence(current_hist, net)
                score = self._sigmoid(kl, midpoint=0.5, steepness=0.5)
                score = self._cold_start_cap(score, self._network_days)
                return PolicyScore(
                    score=round(score, 4),
                    policy_name=self.name,
                    reason=f"Cold-start: KL divergence {kl:.3f} from network baseline.",
                    details={
                        "histogram": current_hist,
                        "kl_divergence": round(kl, 4),
                        "network_baseline": net,
                    },
                    baseline_days=self._network_days,
                )

            baseline_hist = baseline.get("histogram", [1.0] * 10)
            days = baseline.get("days_learned", 0)
            sensitivity = baseline.get("sensitivity", 1.0)

            kl = self._kl_divergence(current_hist, baseline_hist)
            # Adjust sigmoid midpoint by sensitivity: higher sensitivity = lower midpoint
            score = self._sigmoid(kl, midpoint=0.5 / max(sensitivity, 0.1), steepness=0.5)
            score = self._cold_start_cap(score, days)

            return PolicyScore(
                score=round(score, 4),
                policy_name=self.name,
                reason=f"KL divergence {kl:.3f} from learned cadence baseline.",
                details={
                    "histogram": current_hist,
                    "baseline_histogram": baseline_hist,
                    "kl_divergence": round(kl, 4),
                    "sensitivity": sensitivity,
                },
                baseline_days=days,
            )
        except Exception:
            logger.error(
                "Connection cadence evaluation failed",
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
        """Update the learned cadence histogram for a host via EMA."""
        try:
            current_hist = features.get("histogram")
            if current_hist is None:
                current_hist = await self._extract_histogram(host_ip)
            if not current_hist or sum(current_hist) == 0:
                return

            if host_ip not in self._baselines:
                self._baselines[host_ip] = {
                    "histogram": [float(x) for x in current_hist],
                    "days_learned": 1,
                    "sensitivity": 1.0,
                }
                await self._persist_baseline(host_ip)
                return

            bl = self._baselines[host_ip]
            # EMA update each bin
            rate = self._learning_rate
            if feedback == "false_positive":
                rate *= 1.2
            elif feedback == "true_positive":
                rate *= 0.8

            new_hist = []
            for i in range(len(current_hist)):
                prev = bl["histogram"][i] if i < len(bl["histogram"]) else current_hist[i]
                new_hist.append(prev + rate * (current_hist[i] - prev))
            bl["histogram"] = new_hist
            bl["days_learned"] = min(bl["days_learned"] + 1, 365)

            # Adjust sensitivity from feedback
            if feedback == "false_positive":
                bl["sensitivity"] = max(0.5, bl["sensitivity"] * 0.9)
            elif feedback == "true_positive":
                bl["sensitivity"] = min(2.0, bl["sensitivity"] * 1.1)

            await self._persist_baseline(host_ip)
        except Exception:
            logger.error(
                "Connection cadence baseline update failed",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )

    async def get_baseline(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Return the current baseline for a host."""
        return self._baselines.get(host_ip)

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    async def _extract_histogram(self, host_ip: str) -> List[float]:
        """Build a 10-bin inter-connection interval histogram for a host."""
        since = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)

        async with async_session_factory() as session:
            result = await session.execute(
                select(
                    cast(func.strftime("%s", OPNsenseLog.timestamp), Integer).label("ts"),
                )
                .where(
                    OPNsenseLog.src_ip == host_ip,
                    OPNsenseLog.timestamp >= since,
                )
                .order_by(OPNsenseLog.timestamp.asc())
            )
            rows = result.all()

        if len(rows) < 2:
            return [0.0] * 10

        timestamps = [row.ts for row in rows]
        intervals = []
        for i in range(1, len(timestamps)):
            delta = timestamps[i] - timestamps[i - 1]
            if delta >= 0:
                intervals.append(delta)
            if len(intervals) >= 1000:  # Cap for performance
                break

        histogram = [0.0] * 10
        for delta in intervals:
            for bi, (lo, hi) in enumerate(_CADENCE_BINS):
                if lo <= delta < hi:
                    histogram[bi] += 1.0
                    break

        return histogram

    async def _get_network_baseline(self) -> Optional[List[float]]:
        """Get or compute the network-wide average cadence histogram."""
        if self._network_baseline is not None:
            return self._network_baseline

        # Compute from all hosts in the lookback window
        since = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)
        try:
            async with async_session_factory() as session:
                # Use a window function to compute intervals per host
                result = await session.execute(
                    text(
                        """
                        WITH ordered AS (
                            SELECT src_ip,
                                   cast(strftime('%s', timestamp) as integer) as ts,
                                   cast(strftime('%s', timestamp) as integer) -
                                     LAG(cast(strftime('%s', timestamp) as integer)) OVER (
                                       PARTITION BY src_ip ORDER BY timestamp
                                     ) as delta
                            FROM opnsense_logs
                            WHERE timestamp >= :since
                        )
                        SELECT delta FROM ordered WHERE delta IS NOT NULL AND delta >= 0
                        LIMIT 5000
                        """
                    ),
                    {"since": since},
                )
                rows = result.all()
        except Exception:
            logger.warning("Network baseline query failed", exc_info=True)
            return None

        if len(rows) < 10:
            return None

        histogram = [0.0] * 10
        for row in rows:
            delta = row.delta
            if delta is not None:
                for bi, (lo, hi) in enumerate(_CADENCE_BINS):
                    if lo <= delta < hi:
                        histogram[bi] += 1.0
                        break

        # Normalize
        total = sum(histogram)
        if total > 0:
            histogram = [h / total for h in histogram]

        self._network_baseline = histogram
        # Count distinct days
        try:
            async with async_session_factory() as session:
                day_result = await session.execute(
                    text(
                        """
                        SELECT COUNT(DISTINCT date(timestamp)) as days
                        FROM opnsense_logs
                        WHERE timestamp >= :since
                        """
                    ),
                    {"since": since},
                )
                day_row = day_result.first()
                self._network_days = day_row.days if day_row else 0
        except Exception:
            self._network_days = 0

        return self._network_baseline

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
                "Failed to persist connection cadence baseline",
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
                    "Loaded connection cadence baselines from DB",
                    extra={"extra_data": {"count": len(rows)}},
                )
        except Exception:
            logger.warning("Could not load connection cadence baselines", exc_info=True)


# Late import to avoid circular dependency
from ueba.models import OPNsenseLog  # noqa: E402
