"""Multi-model ensemble scoring.

Runs all registered detectors concurrently, groups results by host IP,
and computes a composite score per host using weighted average with
consensus bonus.
"""

import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from collections import defaultdict

from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult
from ueba.logging_config import get_logger

logger = get_logger(__name__)


class ModelEnsemble:
    """Runs a collection of anomaly detectors and produces composite scores.

    Composite score per host = weighted_avg * (1 + 0.2 * (consensus_count - 1))
    where weighted_avg is the weight-adjusted mean of individual detector scores
    and consensus_count is how many distinct detectors flagged the host.

    Feature weights (from config) are applied to individual detector details
    to produce security-weighted anomaly scores.
    """

    def __init__(
        self,
        detectors: List[BaseAnomalyDetector],
        weights: Optional[Dict[str, float]] = None,
        feature_weights: Optional[Dict[str, float]] = None,
    ):
        self.detectors = detectors
        self.weights = weights or {}  # detector_name -> weight, defaults to 1.0
        self.feature_weights = feature_weights or {}  # feature_name -> weight
        self._last_results: List[Dict[str, Any]] = []
        self._last_run: Optional[datetime] = None

    @property
    def last_results(self) -> List[Dict[str, Any]]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    async def run_all(self) -> List[Dict[str, Any]]:
        """Run all detectors concurrently and compute composite scores.

        Returns:
            List of host dicts sorted by composite_score descending.
            Each dict has keys: ip, composite_score, consensus_count, detectors.
        """
        # 1. Run all detectors concurrently
        results = await asyncio.gather(
            *[d.detect() for d in self.detectors],
            return_exceptions=True,
        )

        # 2. Collect results by host
        #    by_host[ip] = [(score, detector_name, details), ...]
        by_host: Dict[str, List[tuple]] = defaultdict(list)

        for i, result in enumerate(results):
            detector = self.detectors[i]
            if isinstance(result, Exception):
                logger.error(
                    "Detector raised exception during ensemble run",
                    extra={
                        "extra_data": {
                            "detector": detector.name,
                            "error": str(result),
                        }
                    },
                )
                continue
            # result should be List[AnomalyResult]
            for anomaly in result:
                if isinstance(anomaly, AnomalyResult):
                    by_host[anomaly.ip].append(
                        (anomaly.score, anomaly.detector_name, anomaly.details)
                    )

        # 3. Compute composite score per host
        composite: List[Dict[str, Any]] = []
        for ip, entries in by_host.items():
            # Determine which detectors flagged this host
            detector_names = set(entry[1] for entry in entries)
            consensus_count = len(detector_names)

            # Weighted average: sum(score * weight) / sum(weights)
            total_weighted_score = 0.0
            total_weight = 0.0
            for score, det_name, details in entries:
                w = self.weights.get(det_name, 1.0)
                # Apply feature weight bonus: if a detector flagged a feature
                # that has a high security weight, boost its contribution
                feature_bonus = self._compute_feature_bonus(details)
                total_weighted_score += score * w * feature_bonus
                total_weight += w

            weighted_avg = total_weighted_score / total_weight if total_weight > 0 else 0.0

            # Consensus bonus: +20% for each additional detector beyond the first
            composite_score = weighted_avg * (1.0 + 0.2 * (consensus_count - 1))

            # Collect detector details
            detectors_list = [
                {"name": entry[1], "score": entry[0], "details": entry[2]}
                for entry in entries
            ]

            composite.append({
                "ip": ip,
                "composite_score": round(composite_score, 4),
                "consensus_count": consensus_count,
                "detectors": detectors_list,
            })

        # 4. Sort by composite_score descending
        composite.sort(key=lambda h: h["composite_score"], reverse=True)

        self._last_results = composite
        self._last_run = datetime.now(timezone.utc)

        if composite:
            logger.info(
                "Model ensemble run complete",
                extra={
                    "extra_data": {
                        "hosts_scored": len(composite),
                        "top_score": composite[0]["composite_score"],
                        "top_ip": composite[0]["ip"],
                    }
                },
            )

        return composite

    def _compute_feature_bonus(self, details: Dict[str, Any]) -> float:
        """Compute a multiplicative bonus based on feature weights.

        If the details contain features that have high security weights in
        self.feature_weights, the score is boosted. Returns a multiplier
        >= 1.0 (capped at 2.0).
        """
        if not self.feature_weights or not details:
            return 1.0

        bonus = 1.0
        matched_features = 0
        for feature_name, weight in self.feature_weights.items():
            # Check if this feature is present in details with a notable value
            value = details.get(feature_name, 0)
            if isinstance(value, (int, float)) and value > 0:
                # Boost based on feature weight (weights > 1.0 increase score)
                if weight > 1.0:
                    bonus += 0.05 * (weight - 1.0)
                    matched_features += 1

        return min(bonus, 2.0)
