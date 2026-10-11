"""Temporal Activity Policy — learns 24-hour activity profiles per host.

Scores activity outside a device's normal hours, weighted by how unusual
that hour is.  A laptop at 3 AM scores high; a server at 3 AM scores 0.0.

Data source: timestamps from both opnsense_logs and pihole_queries.
"""

import math
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy import select, func, text

from ueba.analytics.policy_base import BehavioralPolicy, PolicyScore
from ueba.database import async_session_factory, submit_write
from ueba.logging_config import get_logger

logger = get_logger(__name__)

_HOURS = list(range(24))


class TemporalActivityPolicy(BehavioralPolicy):
    """Scores hosts based on activity outside their learned hourly profile.

    Maintains a 24-bin histogram of event counts per hour-of-day.  Scores
    deviation from the baseline, weighted by the baseline's "unusualness"
    of the current hour.
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        device_roles: Optional[Dict[str, str]] = None,
    ):
        self._learning_rate = learning_rate
        self._device_roles = device_roles or {}
        # Per-host baselines: host_ip -> {histogram (24 floats), days_learned, sensitivity}
        self._baselines: Dict[str, Dict[str, Any]] = {}
        # Network-wide average (cold start)
        self._network_baseline: Optional[List[float]] = None
        self._network_days: int = 0

    @property
    def name(self) -> str:
        return "temporal_activity"

    @property
    def description(self) -> str:
        return (
            "Learns 24-hour activity profiles per host and scores events "
            "outside normal hours, weighted by hour unusualness."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(
        self, host_ip: str, event_data: Optional[Dict[str, Any]] = None
    ) -> PolicyScore:
        """Evaluate temporal activity for a host."""
        try:
            current_hist = await self._extract_histogram(host_ip)
            if current_hist is None or sum(current_hist) == 0:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No activity data available in lookback window.",
                    baseline_days=0,
                )

            role = self._device_roles.get(host_ip, "workstation")
            baseline = self._baselines.get(host_ip)

            if baseline is None:
                net = await self._get_network_baseline()
                if net is None:
                    return PolicyScore(
                        score=0.0,
                        policy_name=self.name,
                        reason="Insufficient data — cold start period.",
                        baseline_days=0,
                        details={"histogram": current_hist, "device_role": role},
                    )

                score = self._score_hour_weighted(current_hist, net, role)
                score = self._cold_start_cap(score, self._network_days)
                return PolicyScore(
                    score=round(score, 4),
                    policy_name=self.name,
                    reason=f"Cold-start: hour-weighted activity deviation from network baseline (role={role}).",
                    details={
                        "histogram": current_hist,
                        "network_baseline": net,
                        "device_role": role,
                    },
                    baseline_days=self._network_days,
                )

            baseline_hist = baseline.get("histogram", [1.0] * 24)
            days = baseline.get("days_learned", 0)
            sensitivity = baseline.get("sensitivity", 1.0)

            score = self._score_hour_weighted(current_hist, baseline_hist, role)
            # Adjust with sensitivity
            score = min(score * sensitivity, 1.0)
            score = self._cold_start_cap(score, days)

            return PolicyScore(
                score=round(score, 4),
                policy_name=self.name,
                reason=f"Hour-weighted activity score {score:.3f} (role={role}, {days}d baseline).",
                details={
                    "histogram": current_hist,
                    "baseline_histogram": baseline_hist,
                    "device_role": role,
                    "sensitivity": sensitivity,
                },
                baseline_days=days,
            )
        except Exception:
            logger.error(
                "Temporal activity evaluation failed",
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
        """Update the learned hourly activity profile for a host."""
        try:
            current = features.get("histogram")
            if current is None:
                current = await self._extract_histogram(host_ip)
            if current is None or sum(current) == 0:
                return

            if host_ip not in self._baselines:
                self._baselines[host_ip] = {
                    "histogram": [float(x) for x in current],
                    "days_learned": 1,
                    "sensitivity": 1.0,
                }
                await self._persist_baseline(host_ip)
                return

            bl = self._baselines[host_ip]
            rate = self._learning_rate
            if feedback == "false_positive":
                rate *= 1.2
            elif feedback == "true_positive":
                rate *= 0.8

            new_hist = []
            for i in range(24):
                prev = bl["histogram"][i] if i < len(bl["histogram"]) else current[i]
                new_hist.append(prev + rate * (current[i] - prev))
            bl["histogram"] = new_hist
            bl["days_learned"] = min(bl["days_learned"] + 1, 365)

            if feedback == "false_positive":
                bl["sensitivity"] = max(0.5, bl["sensitivity"] * 0.9)
            elif feedback == "true_positive":
                bl["sensitivity"] = min(2.0, bl["sensitivity"] * 1.1)

            await self._persist_baseline(host_ip)
        except Exception:
            logger.error(
                "Temporal activity baseline update failed",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )

    async def get_baseline(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Return the current baseline for a host."""
        return self._baselines.get(host_ip)

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    async def _extract_histogram(self, host_ip: str) -> Optional[List[float]]:
        """Build 24-hour activity histogram from OPNsense and Pi-hole logs."""
        since = datetime.now(timezone.utc) - timedelta(hours=24)

        histogram = [0.0] * 24

        # OPNsense events
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    text(
                        """
                        SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                               COUNT(*) as cnt
                        FROM opnsense_logs
                        WHERE src_ip = :host_ip AND timestamp >= :since
                        GROUP BY hour
                        """
                    ),
                    {"host_ip": host_ip, "since": since},
                )
                for row in result:
                    if 0 <= row.hour < 24:
                        histogram[row.hour] += row.cnt
        except Exception:
            logger.debug("OPNsense temporal query failed", exc_info=True)

        # Pi-hole events
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    text(
                        """
                        SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                               COUNT(*) as cnt
                        FROM pihole_queries
                        WHERE client_ip = :host_ip AND timestamp >= :since
                        GROUP BY hour
                        """
                    ),
                    {"host_ip": host_ip, "since": since},
                )
                for row in result:
                    if 0 <= row.hour < 24:
                        histogram[row.hour] += row.cnt
        except Exception:
            logger.debug("Pi-hole temporal query failed", exc_info=True)

        if sum(histogram) == 0:
            return None
        return histogram

    def _score_hour_weighted(
        self,
        current: List[float],
        baseline: List[float],
        role: str,
    ) -> float:
        """Score based on how unusual the current hour's activity is.

        The idea: multiply the deviation at each hour by the rarity of that
        hour in the baseline.  A server active at 3 AM (where baseline has
        significant 3 AM activity) gets low score.  A laptop active at 3 AM
        (where baseline has near-zero) gets high score.
        """
        total_current = sum(current)
        total_baseline = sum(baseline)
        if total_current == 0 or total_baseline == 0:
            return 0.0

        # Normalize baseline to get expected probabilities
        baseline_prob = [max(b / total_baseline, 1e-10) for b in baseline]

        # "Unusualness" of each hour = 1 / (baseline_prob normalized)
        # Hours the host never uses are most unusual
        max_prob = max(baseline_prob) if baseline_prob else 1.0
        unusualness = [1.0 - (p / max_prob) for p in baseline_prob]

        # Weight current activity by unusualness
        score = 0.0
        for h in range(24):
            current_frac = current[h] / total_current if total_current > 0 else 0.0
            score += current_frac * unusualness[h]

        # Role-based adjustments
        if role == "server":
            score *= 0.3  # Servers expected to be active at odd hours
        elif role == "infrastructure":
            score *= 0.2
        elif role == "iot":
            score *= 1.2  # IoT devices shouldn't vary their hours

        return min(score, 1.0)

    async def _get_network_baseline(self) -> Optional[List[float]]:
        """Compute network-wide average hourly activity profile."""
        if self._network_baseline is not None:
            return self._network_baseline

        since = datetime.now(timezone.utc) - timedelta(hours=24)
        histogram = [0.0] * 24

        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    text(
                        """
                        SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                               COUNT(*) as cnt
                        FROM (
                            SELECT timestamp FROM opnsense_logs WHERE timestamp >= :since
                            UNION ALL
                            SELECT timestamp FROM pihole_queries WHERE timestamp >= :since
                        )
                        GROUP BY hour
                        """
                    ),
                    {"since": since},
                )
                for row in result:
                    if 0 <= row.hour < 24:
                        histogram[row.hour] += row.cnt
        except Exception:
            logger.warning("Network temporal baseline query failed", exc_info=True)
            return None

        total = sum(histogram)
        if total == 0:
            return None

        self._network_baseline = [h / total for h in histogram]
        self._network_days = 1  # 24h window ≈ 1 day
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
                "Failed to persist temporal activity baseline",
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
                    "Loaded temporal activity baselines from DB",
                    extra={"extra_data": {"count": len(rows)}},
                )
        except Exception:
            logger.warning("Could not load temporal activity baselines", exc_info=True)
