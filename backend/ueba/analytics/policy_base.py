"""Behavioral policy framework for the UEBA platform.

Provides the base classes and ensemble for host-level behavioral policies
that score hosts based on learned baselines rather than static thresholds.
"""

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

from ueba.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class PolicyScore:
    """Result from a behavioral policy evaluation.

    Attributes:
        score: Normalized anomaly score (0.0 = normal, 1.0 = highly anomalous).
        policy_name: Name of the policy that produced this score.
        reason: Human-readable explanation of why the score was assigned.
        details: Arbitrary per-policy context (feature values, baselines, etc.).
        baseline_days: How many days of baseline data were available.
    """

    score: float
    policy_name: str
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    baseline_days: int = 0


class BehavioralPolicy(ABC):
    """Abstract base class for per-host behavioral policies.

    Subclasses must implement:

    * ``name`` — short unique name (e.g. 'connection_cadence')
    * ``description`` — human-readable description
    * ``evaluate(host_ip, event_data)`` — return a PolicyScore
    * ``update_baseline(host_ip, features, feedback)`` — update learned baseline
    * ``get_baseline(host_ip)`` — return current baseline dict
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short unique name for this policy."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what the policy measures."""
        ...

    @abstractmethod
    async def evaluate(self, host_ip: str, event_data: Optional[Dict[str, Any]] = None) -> PolicyScore:
        """Evaluate the policy for a given host.

        Args:
            host_ip: The host IP to score.
            event_data: Optional event context (current event being processed).

        Returns:
            A PolicyScore with the normalized anomaly score.
        """
        ...

    @abstractmethod
    async def update_baseline(
        self,
        host_ip: str,
        features: Dict[str, Any],
        feedback: Optional[str] = None,
    ) -> None:
        """Update the learned baseline for a host.

        Args:
            host_ip: The host IP.
            features: Feature vector to incorporate into baseline.
            feedback: Optional feedback — 'false_positive' widens sensitivity
                (multiplies effective learning rate by 1.2), 'true_positive'
                narrows it (multiplies by 0.8).
        """
        ...

    @abstractmethod
    async def get_baseline(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Return the current baseline for a host, or None if no baseline exists."""
        ...

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ema_update(
        current: float,
        new_value: float,
        learning_rate: float = 0.1,
        feedback: Optional[str] = None,
    ) -> float:
        """Exponential moving average update with optional feedback adjustment.

        Args:
            current: Current EMA value.
            new_value: New observation.
            learning_rate: Base learning rate (default 0.1).
            feedback: 'false_positive' → 1.2x rate (wider), 'true_positive' → 0.8x (narrower).

        Returns:
            Updated EMA value.
        """
        rate = learning_rate
        if feedback == "false_positive":
            rate *= 1.2  # Widen — adapt faster to incorporate legitimate behavior
        elif feedback == "true_positive":
            rate *= 0.8  # Narrow — adapt slower to preserve anomaly signal
        return current + rate * (new_value - current)

    @staticmethod
    def _ema_update_dict(
        current: Dict[str, float],
        new_values: Dict[str, float],
        learning_rate: float = 0.1,
        feedback: Optional[str] = None,
    ) -> Dict[str, float]:
        """EMA update for a dictionary of values."""
        rate = learning_rate
        if feedback == "false_positive":
            rate *= 1.2
        elif feedback == "true_positive":
            rate *= 0.8
        result = dict(current)
        for k, v in new_values.items():
            result[k] = result.get(k, v) + rate * (v - result.get(k, v))
        return result

    @staticmethod
    def _kl_divergence(p: List[float], q: List[float]) -> float:
        """Kullback-Leibler divergence from p to q (smoothed).

        Both lists are normalised to sum to 1 and a small epsilon is added
        to avoid log(0).
        """
        eps = 1e-10
        p_arr = [max(x, 0) for x in p]
        q_arr = [max(x, 0) for x in q]
        p_sum = sum(p_arr)
        q_sum = sum(q_arr)
        n = len(p_arr)
        kl = 0.0
        for i in range(n):
            pi = (p_arr[i] / p_sum if p_sum > 0 else 1.0 / n) + eps
            qi = (q_arr[i] / q_sum if q_sum > 0 else 1.0 / n) + eps
            kl += pi * math.log2(pi / qi)
        return max(kl, 0.0)

    @staticmethod
    def _sigmoid(x: float, midpoint: float = 1.0, steepness: float = 2.0) -> float:
        """Sigmoid function mapping a value to (0, 1).

        score = 1 / (1 + exp(-(x - midpoint) / steepness))
        """
        if steepness <= 0:
            steepness = 1.0
        return 1.0 / (1.0 + math.exp(-(x - midpoint) / steepness))

    @staticmethod
    def _cold_start_cap(
        score: float,
        days_learned: int,
        cap_days: int = 3,
        max_cold_score: float = 0.5,
    ) -> float:
        """Cap anomaly scores during cold-start period.

        During the first *cap_days* days, scores are linearly interpolated
        between 0 and *max_cold_score* based on how many days have been learned.

        Args:
            score: Raw anomaly score.
            days_learned: Number of days of baseline data.
            cap_days: Number of days over which to phase in full scoring.
            max_cold_score: Maximum score allowed on day 0.

        Returns:
            Capped score.
        """
        if days_learned >= cap_days:
            return score
        # Linear ramp: day 0 → max_cold_score, day cap_days → 1.0
        ramp = max_cold_score + (1.0 - max_cold_score) * (days_learned / cap_days)
        return min(score, ramp)


class PolicyEnsemble:
    """Runs a collection of behavioral policies and produces composite scores.

    Composite score per host = weighted_avg * (1 + 0.2 * (consensus_count - 1))
    where weighted_avg is the weight-adjusted mean of individual policy scores
    and consensus_count is how many distinct policies produced a score > 0.

    This matches the consensus bonus math in ModelEnsemble.
    """

    def __init__(
        self,
        policies: List[BehavioralPolicy],
        weights: Optional[Dict[str, float]] = None,
    ):
        self.policies = policies
        self.weights = weights or {}  # policy_name -> weight, defaults to 1.0
        self._last_results: List[Dict[str, Any]] = []
        self._last_run: Optional[datetime] = None

    @property
    def last_results(self) -> List[Dict[str, Any]]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    async def score_host(
        self,
        host_ip: str,
        event_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluate all policies for a single host and compute composite score.

        Returns:
            Dict with keys: ip, composite_score, consensus_count, policies,
            active_policies.
        """
        scores: List[Tuple[float, str, str, Dict[str, Any], int]] = []
        for policy in self.policies:
            try:
                result = await policy.evaluate(host_ip, event_data)
                if result.score > 0:
                    scores.append((
                        result.score,
                        result.policy_name,
                        result.reason,
                        result.details,
                        result.baseline_days,
                    ))
            except Exception:
                logger.error(
                    "Policy evaluation failed",
                    extra={
                        "extra_data": {
                            "policy": policy.name,
                            "host": host_ip,
                        }
                    },
                    exc_info=True,
                )

        if not scores:
            return {
                "ip": host_ip,
                "composite_score": 0.0,
                "consensus_count": 0,
                "active_policies": 0,
                "policies": [],
            }

        # Count distinct policies that contributed
        policy_names = set(s[1] for s in scores)
        consensus_count = len(policy_names)

        # Weighted average
        total_weighted_score = 0.0
        total_weight = 0.0
        for score, pol_name, reason, details, baseline_days in scores:
            w = self.weights.get(pol_name, 1.0)
            total_weighted_score += score * w
            total_weight += w

        weighted_avg = total_weighted_score / total_weight if total_weight > 0 else 0.0

        # Consensus bonus: +20% for each additional policy beyond the first
        composite_score = weighted_avg * (1.0 + 0.2 * (consensus_count - 1))

        policies_list = [
            {
                "name": s[1],
                "score": round(s[0], 4),
                "reason": s[2],
                "details": s[3],
                "baseline_days": s[4],
            }
            for s in scores
        ]

        result = {
            "ip": host_ip,
            "composite_score": round(composite_score, 4),
            "consensus_count": consensus_count,
            "active_policies": len(scores),
            "policies": policies_list,
        }

        self._last_results.append(result)
        self._last_run = datetime.now(timezone.utc)

        return result

    async def propagate_feedback(
        self,
        host_ip: str,
        feedback: str,
        contributing_policies: Optional[List[str]] = None,
    ) -> None:
        """Propagate FP/TP feedback to contributing policies.

        Args:
            host_ip: The host IP.
            feedback: 'false_positive' or 'true_positive'.
            contributing_policies: Optional list of policy names that contributed
                to the alert. If None, propagates to all policies.
        """
        for policy in self.policies:
            if contributing_policies and policy.name not in contributing_policies:
                continue
            try:
                # Update baseline with empty features — just adjust sensitivity
                await policy.update_baseline(host_ip, {}, feedback=feedback)
            except Exception:
                logger.error(
                    "Failed to propagate feedback to policy",
                    extra={
                        "extra_data": {
                            "policy": policy.name,
                            "host": host_ip,
                            "feedback": feedback,
                        }
                    },
                    exc_info=True,
                )
