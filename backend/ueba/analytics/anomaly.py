"""IsolationForest per-host anomaly detection.

Extracts behavioral features from OPNsense logs per internal IP over a
configurable window (default 24h), fits an IsolationForest, and returns
hosts flagged as anomalous along with their feature profiles.
"""
import asyncio
import joblib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from ueba.logging_config import get_logger
from ueba.database import async_session_factory
from ueba.models import OPNsenseLog
from ueba.netconfig import lan_filter
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)


class AnomalyDetector(BaseAnomalyDetector):
    """Statistical anomaly detector using IsolationForest on per-host features."""

    def __init__(self, contamination: float = 0.1, lookback_hours: int = 24,
                 feature_weights: Optional[Dict[str, float]] = None):
        self.contamination = contamination
        self.lookback_hours = lookback_hours
        self._feature_weights = feature_weights or {}
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None
        self._model: Optional[IsolationForest] = None
        self._model_hash: Optional[str] = None

    @property
    def name(self) -> str:
        return "isolation_forest"

    @property
    def description(self) -> str:
        return "IsolationForest statistical anomaly detection on per-host OPNsense features"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    async def detect(self) -> List[AnomalyResult]:
        """Run anomaly detection on internal hosts.

        Extracts features per internal IP from OPNsense logs, fits
        IsolationForest (or uses cached model if available), and
        returns anomalous hosts with scores.
        """
        try:
            features = await self._extract_features()
            if len(features) < 5:
                logger.debug("Not enough hosts for anomaly detection", extra={
                    "extra_data": {"host_count": len(features)}
                })
                self._last_results = []
                self._last_run = datetime.now(timezone.utc)
                return []

            results = self._run_isolation_forest(features)
            self._last_results = results
            self._last_run = datetime.now(timezone.utc)

            if results:
                logger.info("Anomaly detection completed", extra={
                    "extra_data": {
                        "hosts_analyzed": len(features),
                        "anomalies_found": len(results),
                        "anomalous_ips": [r.ip for r in results],
                    }
                })
            else:
                logger.debug("Anomaly detection completed, no anomalies", extra={
                    "extra_data": {"hosts_analyzed": len(features)}
                })

            return results

        except Exception as e:
            logger.error("Anomaly detection failed", extra={
                "extra_data": {"error": str(e)}
            })
            return []

    async def _extract_features(self) -> List[Dict[str, Any]]:
        """Extract per-host feature vectors from OPNsense logs."""
        since = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)

        async with async_session_factory() as session:
            # Query per-host aggregated features for internal IPs
            result = await session.execute(
                select(
                    OPNsenseLog.src_ip,
                    func.count(OPNsenseLog.id).label("total_connections"),
                    func.count(func.distinct(OPNsenseLog.dst_ip)).label("unique_destinations"),
                    func.count(func.distinct(OPNsenseLog.dst_port)).label("unique_ports"),
                    func.sum(
                        case(
                            (OPNsenseLog.action == "block", 1),
                            else_=0,
                        )
                    ).label("blocked_count"),
                    func.count(func.distinct(OPNsenseLog.protocol)).label("unique_protocols"),
                )
                .where(
                    OPNsenseLog.timestamp >= since,
                    lan_filter(OPNsenseLog.src_ip),
                )
                .group_by(OPNsenseLog.src_ip)
            )
            rows = result.all()

        features = []
        for row in rows:
            total = row.total_connections or 0
            blocked = row.blocked_count or 0
            blocked_ratio = blocked / total if total > 0 else 0.0

            features.append({
                "ip": row.src_ip,
                "unique_destinations": row.unique_destinations or 0,
                "unique_ports": row.unique_ports or 0,
                "total_connections": total,
                "blocked_ratio": round(blocked_ratio, 4),
                "unique_protocols": row.unique_protocols or 0,
            })

        return features

    def _run_isolation_forest(self, features: List[Dict[str, Any]]) -> List[AnomalyResult]:
        """Fit IsolationForest (or use cached model) and return anomalous hosts."""
        feature_keys = [
            "unique_destinations", "unique_ports", "total_connections",
            "blocked_ratio", "unique_protocols",
        ]

        X = np.array([[f[k] for k in feature_keys] for f in features], dtype=np.float64)

        # Apply feature weights before training (security-weighted scoring)
        if self._feature_weights:
            weight_vector = np.array([
                self._feature_weights.get(k, 1.0) for k in feature_keys
            ], dtype=np.float64)
            X = X * weight_vector

        # Reuse the in-memory model only while its cache key (which includes
        # the UTC date) is current — otherwise retrain on fresh traffic.
        current_hash = self.data_hash()
        if self._model is not None and self._model_hash == current_hash:
            clf = self._model
            logger.debug("Using cached IsolationForest model")
        else:
            clf = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            clf.fit(X)
            self._model = clf
            self._model_hash = current_hash
            logger.debug("Trained new IsolationForest model")

        predictions = clf.predict(X)
        scores = clf.decision_function(X)

        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            # contamination=0.1 makes predict() flag the top ~10% of hosts on
            # EVERY run, even on a quiet day. Require the decision score to be
            # meaningfully negative too, so ordinary days can yield zero
            # anomalies instead of a guaranteed quota.
            if pred == -1 and float(-score) >= 0.02:
                host = features[i].copy()
                # Lower (more negative) decision_function = more anomalous.
                # Scale to 0-1: decision scores live in roughly [-0.2, 0.2].
                host["anomaly_score"] = round(min(1.0, float(-score) * 5.0), 4)
                anomalies.append(host)

        # Sort by anomaly score descending (most anomalous first)
        anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        return [
            AnomalyResult(
                ip=a["ip"],
                score=a["anomaly_score"],
                details={k: v for k, v in a.items() if k != "ip"},
                detector_name=self.name,
            )
            for a in anomalies
        ]

    # ------------------------------------------------------------------
    # Model persistence
    # ------------------------------------------------------------------

    def save_model(self, path: str) -> None:
        """Save the trained IsolationForest model to disk."""
        if self._model is not None:
            joblib.dump(self._model, path)
            logger.debug("Saved IsolationForest model", extra={
                "extra_data": {"path": path}
            })

    def load_model(self, path: str) -> bool:
        """Load a previously saved IsolationForest model from disk."""
        try:
            self._model = joblib.load(path)
            # Engine only loads a cache file matching the current hash
            self._model_hash = self.data_hash()
            logger.debug("Loaded IsolationForest model from cache", extra={
                "extra_data": {"path": path}
            })
            return True
        except Exception as e:
            logger.warning("Failed to load cached IsolationForest model", extra={
                "extra_data": {"path": path, "error": str(e)}
            })
            return False

    def data_hash(self) -> str:
        """Return a hash based on detector parameters for cache keying.

        Includes the current UTC date so the model retrains daily on fresh
        traffic instead of scoring forever against a stale snapshot (the
        engine prunes old cache files automatically).
        """
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"if_{self.lookback_hours}_{self.contamination}_{today}"
