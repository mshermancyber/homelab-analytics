"""Outbound Symmetry Policy — measures inbound-followed-by-outbound relay behavior.

Measures the ratio of outbound connections that were preceded by an inbound
connection to the same port within 5 seconds.  Proxy exit nodes show elevated
relay ratios while most devices have near-zero.

Data source: OPNsense direction + timestamps.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

from sqlalchemy import select, func, text

from ueba.analytics.policy_base import BehavioralPolicy, PolicyScore
from ueba.database import async_session_factory, submit_write
from ueba.logging_config import get_logger

logger = get_logger(__name__)

_RELAY_WINDOW_SECONDS = 5


class OutboundSymmetryPolicy(BehavioralPolicy):
    """Scores hosts based on relay behavior (inbound→outbound pairs).

    A relay is detected when an inbound connection to (host, port) is followed
    by an outbound connection from (host, same/similar port) within 5 seconds.
    Normal devices have near-zero relay ratios; proxy exit nodes show elevated
    ratios.
    """

    def __init__(self, lookback_hours: int = 1, learning_rate: float = 0.1):
        self._lookback_hours = lookback_hours
        self._learning_rate = learning_rate
        # Per-host baselines: host_ip -> {relay_ratio, days_learned, sensitivity}
        self._baselines: Dict[str, Dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "outbound_symmetry"

    @property
    def description(self) -> str:
        return (
            "Measures inbound-followed-by-outbound relay pairs within 5 seconds.  "
            "Elevated relay ratios indicate potential proxy exit node behavior."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(
        self, host_ip: str, event_data: Optional[Dict[str, Any]] = None
    ) -> PolicyScore:
        """Evaluate outbound symmetry for a host."""
        try:
            relay_ratio, total_out, relay_count = await self._compute_relay_ratio(host_ip)
            if total_out == 0:
                return PolicyScore(
                    score=0.0,
                    policy_name=self.name,
                    reason="No outbound connections in lookback window.",
                    baseline_days=0,
                )

            baseline = self._baselines.get(host_ip)
            if baseline is None:
                # Cold start: assume baseline relay ratio is 0
                score = self._sigmoid(relay_ratio, midpoint=0.05, steepness=0.05)
                score = self._cold_start_cap(score, 0)
                return PolicyScore(
                    score=round(score, 4),
                    policy_name=self.name,
                    reason=(
                        f"Cold-start: relay ratio {relay_ratio:.4f} "
                        f"({relay_count}/{total_out})."
                    ),
                    details={
                        "relay_ratio": round(relay_ratio, 4),
                        "total_outbound": total_out,
                        "relay_count": relay_count,
                    },
                    baseline_days=0,
                )

            baseline_ratio = baseline.get("relay_ratio", 0.0)
            days = baseline.get("days_learned", 0)
            sensitivity = baseline.get("sensitivity", 1.0)

            # Score based on how much relay ratio exceeds baseline
            excess = max(0.0, relay_ratio - baseline_ratio)
            score = self._sigmoid(excess, midpoint=0.03 / max(sensitivity, 0.1), steepness=0.03)
            score = self._cold_start_cap(score, days)

            return PolicyScore(
                score=round(score, 4),
                policy_name=self.name,
                reason=(
                    f"Relay ratio {relay_ratio:.4f} (baseline {baseline_ratio:.4f}), "
                    f"{relay_count}/{total_out} outbound connections are relays."
                ),
                details={
                    "relay_ratio": round(relay_ratio, 4),
                    "baseline_ratio": round(baseline_ratio, 4),
                    "total_outbound": total_out,
                    "relay_count": relay_count,
                },
                baseline_days=days,
            )
        except Exception:
            logger.error(
                "Outbound symmetry evaluation failed",
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
        """Update the learned relay ratio baseline for a host."""
        try:
            current_ratio = features.get("relay_ratio")
            if current_ratio is None:
                current_ratio, _, _ = await self._compute_relay_ratio(host_ip)
                if current_ratio == 0.0:
                    return

            if host_ip not in self._baselines:
                self._baselines[host_ip] = {
                    "relay_ratio": current_ratio,
                    "days_learned": 1,
                    "sensitivity": 1.0,
                }
                await self._persist_baseline(host_ip)
                return

            bl = self._baselines[host_ip]
            bl["relay_ratio"] = self._ema_update(
                bl["relay_ratio"], current_ratio, self._learning_rate, feedback
            )
            bl["days_learned"] = min(bl["days_learned"] + 1, 365)

            if feedback == "false_positive":
                bl["sensitivity"] = max(0.5, bl["sensitivity"] * 0.9)
            elif feedback == "true_positive":
                bl["sensitivity"] = min(2.0, bl["sensitivity"] * 1.1)

            await self._persist_baseline(host_ip)
        except Exception:
            logger.error(
                "Outbound symmetry baseline update failed",
                extra={"extra_data": {"host": host_ip}},
                exc_info=True,
            )

    async def get_baseline(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Return the current baseline for a host."""
        return self._baselines.get(host_ip)

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    async def _compute_relay_ratio(self, host_ip: str) -> Tuple[float, int, int]:
        """Compute relay ratio: outbound connections paired with recent inbound.

        Returns:
            (relay_ratio, total_outbound, relay_count)
        """
        since = datetime.now(timezone.utc) - timedelta(hours=self._lookback_hours)

        async with async_session_factory() as session:
            # Get all connections for this host in the window, ordered by time
            result = await session.execute(
                text(
                    """
                    SELECT id, direction, dst_port, src_port,
                           cast(strftime('%s', timestamp) as integer) as ts
                    FROM opnsense_logs
                    WHERE (src_ip = :host_ip OR dst_ip = :host_ip2)
                      AND timestamp >= :since
                    ORDER BY timestamp ASC
                    """
                ),
                {"host_ip": host_ip, "host_ip2": host_ip, "since": since},
            )
            rows = result.fetchall()

        if len(rows) < 2:
            return (0.0, 0, 0)

        # Build lists of inbound events (to this host) and outbound events (from this host)
        # We track (timestamp, port) for inbound and outbound
        inbound_events: List[Tuple[float, int]] = []  # (unix_ts, dst_port)
        outbound_events: List[Tuple[float, int]] = []  # (unix_ts, dst_port)

        for row in rows:
            direction = row.direction
            ts = float(row.ts)
            dst_port = row.dst_port
            src_port = row.src_port

            if direction == "in":
                # Inbound TO this host: dst_port is the host's port
                inbound_events.append((ts, dst_port or 0))
            elif direction == "out":
                # Outbound FROM this host: dst_port is remote port
                outbound_events.append((ts, dst_port or 0))

        total_outbound = len(outbound_events)
        if total_outbound == 0:
            return (0.0, 0, 0)

        # Use a sliding-window approach: for each outbound, check if there's
        # an inbound within the last RELAY_WINDOW_SECONDS on the same port
        relay_count = 0
        inbound_idx = 0

        for out_ts, out_port in outbound_events:
            # Advance inbound pointer to within window
            while (
                inbound_idx < len(inbound_events)
                and inbound_events[inbound_idx][0] < out_ts - _RELAY_WINDOW_SECONDS
            ):
                inbound_idx += 1

            # Check inbounds within the window
            for i in range(inbound_idx, len(inbound_events)):
                in_ts, in_port = inbound_events[i]
                if in_ts > out_ts:
                    break
                # If same port within 5 seconds, count as relay
                if in_port > 0 and in_port == out_port:
                    relay_count += 1
                    break

        relay_ratio = relay_count / total_outbound if total_outbound > 0 else 0.0
        return (relay_ratio, total_outbound, relay_count)

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
                "Failed to persist outbound symmetry baseline",
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
                    "Loaded outbound symmetry baselines from DB",
                    extra={"extra_data": {"count": len(rows)}},
                )
        except Exception:
            logger.warning("Could not load outbound symmetry baselines", exc_info=True)
