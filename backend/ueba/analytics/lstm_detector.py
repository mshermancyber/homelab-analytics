"""LSTM autoencoder temporal sequence anomaly detection.

Builds hourly feature sequences for internal hosts (see network.lan_cidrs) over
7 days (168 hours), trains an LSTM autoencoder to reconstruct normal
temporal behavior patterns, and flags hosts with high reconstruction error.

Features per hour per host (7):
- unique_destinations, unique_ports, total_connections, blocked_ratio,
  unique_protocols, protocol_entropy, hour_of_day
"""
import math
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

import numpy as np
from sqlalchemy import select, func, case

from ueba.logging_config import get_logger
from ueba.database import async_session_factory
from ueba.models import OPNsenseLog
from ueba.netconfig import lan_filter
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)

# Suppress TensorFlow C++ log messages (must be set before import)
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

try:
    import tensorflow as tf
    from tensorflow import keras

    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False
    tf = None  # type: ignore
    keras = None  # type: ignore

# Feature keys in column order for the LSTM input matrix
_FEATURE_KEYS = [
    "unique_destinations",
    "unique_ports",
    "total_connections",
    "blocked_ratio",
    "unique_protocols",
    "protocol_entropy",
    "hour_of_day",
]

_SEQUENCE_LENGTH = 168  # 7 days × 24 hours


def _distribution_entropy(counts: List[int]) -> float:
    """Shannon entropy of a count distribution.

    Args:
        counts: List of integer counts per category.

    Returns:
        Entropy in bits.  0 if the list is empty or sums to zero.
    """
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


class LSTMAnomalyDetector(BaseAnomalyDetector):
    """LSTM autoencoder temporal sequence anomaly detector.

    Builds 168-hour sequences of 7 behavioral features per internal host,
    trains an LSTM autoencoder to reconstruct the sequences, and flags
    hosts whose temporal patterns cannot be reconstructed accurately
    (MSE > mean + 2·std).
    """

    def __init__(self, lookback_hours: int = 168):
        self.lookback_hours = lookback_hours
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None
        self.model: Optional["keras.Model"] = None

    # ------------------------------------------------------------------
    # BaseAnomalyDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "lstm_temporal"

    @property
    def description(self) -> str:
        return "LSTM autoencoder temporal sequence anomaly detection"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    async def detect(self) -> List[AnomalyResult]:
        """Run LSTM temporal anomaly detection.

        Returns:
            List of AnomalyResult for hosts flagged as anomalous.
        """
        if not HAS_TENSORFLOW:
            logger.warning(
                "TensorFlow not available, skipping LSTM temporal detection"
            )
            self._last_results = []
            self._last_run = datetime.now(timezone.utc)
            return []

        try:
            sequences, hosts, num_timesteps_map = await self._extract_sequences()

            if len(hosts) < 5:
                logger.debug(
                    "Not enough hosts for LSTM temporal detection",
                    extra={"extra_data": {"host_count": len(hosts)}},
                )
                self._last_results = []
                self._last_run = datetime.now(timezone.utc)
                return []

            results = self._train_and_detect(sequences, hosts, num_timesteps_map)
            self._last_results = results
            self._last_run = datetime.now(timezone.utc)

            if results:
                logger.info(
                    "LSTM temporal anomaly detection completed",
                    extra={
                        "extra_data": {
                            "hosts_analyzed": len(hosts),
                            "anomalies_found": len(results),
                            "anomalous_ips": [r.ip for r in results],
                        }
                    },
                )
            else:
                logger.debug(
                    "LSTM temporal detection completed, no anomalies",
                    extra={"extra_data": {"hosts_analyzed": len(hosts)}},
                )

            return results

        except Exception:
            logger.error(
                "LSTM temporal detection failed",
                exc_info=True,
            )
            return []

    # ------------------------------------------------------------------
    # Sequence extraction
    # ------------------------------------------------------------------

    async def _extract_sequences(
        self,
    ) -> Tuple[np.ndarray, List[str], Dict[str, int]]:
        """Extract hourly feature sequences per internal host.

        Queries OPNsense logs over *lookback_hours* (default 168),
        buckets events into hourly slots (0 … 167), and builds a
        (num_hosts × 168 × 7) feature tensor.  Missing hours are
        zero-padded.

        Returns:
            Tuple of:
            - sequences: float32 array of shape (num_hosts, 168, 7)
            - hosts: list of src_ip strings in the same order
            - num_timesteps_map: dict src_ip → count of non-empty hours
        """
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=self.lookback_hours)

        async with async_session_factory() as session:
            # ── Hourly aggregated features per (src_ip, hour_slot) ─────
            # hour_slot = integer 0..167 representing hours since *since*
            hour_slot_expr = func.cast(
                (func.julianday(OPNsenseLog.timestamp) - func.julianday(since))
                * 24,
                func.Integer,
            ).label("hour_slot")

            result = await session.execute(
                select(
                    OPNsenseLog.src_ip,
                    hour_slot_expr,
                    func.count(OPNsenseLog.id).label("total_connections"),
                    func.count(func.distinct(OPNsenseLog.dst_ip)).label(
                        "unique_destinations"
                    ),
                    func.count(func.distinct(OPNsenseLog.dst_port)).label(
                        "unique_ports"
                    ),
                    func.sum(
                        case(
                            (OPNsenseLog.action == "block", 1),
                            else_=0,
                        )
                    ).label("blocked_count"),
                    func.count(func.distinct(OPNsenseLog.protocol)).label(
                        "unique_protocols"
                    ),
                )
                .where(
                    OPNsenseLog.timestamp >= since,
                    lan_filter(OPNsenseLog.src_ip),
                )
                .group_by(OPNsenseLog.src_ip, "hour_slot")
                .order_by(OPNsenseLog.src_ip, "hour_slot")
            )
            rows = result.all()

            # ── Protocol distribution per (src_ip, hour_slot) ──────────
            proto_result = await session.execute(
                select(
                    OPNsenseLog.src_ip,
                    hour_slot_expr,
                    OPNsenseLog.protocol,
                    func.count(OPNsenseLog.id).label("cnt"),
                )
                .where(
                    OPNsenseLog.timestamp >= since,
                    lan_filter(OPNsenseLog.src_ip),
                )
                .group_by(OPNsenseLog.src_ip, "hour_slot", OPNsenseLog.protocol)
            )
            proto_rows = proto_result.all()

        if not rows:
            return (
                np.empty((0, _SEQUENCE_LENGTH, len(_FEATURE_KEYS)), dtype=np.float32),
                [],
                {},
            )

        # ── Build protocol entropy lookup ──────────────────────────────
        # Key: (src_ip, hour_slot) → list of protocol counts
        proto_map: Dict[Tuple[str, int], List[int]] = {}
        for pr in proto_rows:
            key = (pr.src_ip, pr.hour_slot)
            if key not in proto_map:
                proto_map[key] = []
            proto_map[key].append(pr.cnt or 0)

        # ── Organise by host ───────────────────────────────────────────
        hosts_set: Dict[str, Dict[int, Dict[str, Any]]] = {}
        for row in rows:
            ip = row.src_ip
            slot = row.hour_slot
            # Clamp slot to valid range (safety against edge cases)
            if slot < 0 or slot >= _SEQUENCE_LENGTH:
                continue

            if ip not in hosts_set:
                hosts_set[ip] = {}

            total = row.total_connections or 0
            blocked = row.blocked_count or 0
            blocked_ratio = blocked / total if total > 0 else 0.0

            proto_key = (ip, slot)
            proto_entropy = _distribution_entropy(
                proto_map.get(proto_key, [])
            )

            hosts_set[ip][slot] = {
                "unique_destinations": row.unique_destinations or 0,
                "unique_ports": row.unique_ports or 0,
                "total_connections": total,
                "blocked_ratio": round(blocked_ratio, 4),
                "unique_protocols": row.unique_protocols or 0,
                "protocol_entropy": round(proto_entropy, 4),
                "hour_of_day": slot % 24,
            }

        # ── Build numpy tensor ─────────────────────────────────────────
        hosts = sorted(hosts_set.keys())
        num_hosts = len(hosts)
        sequences = np.zeros(
            (num_hosts, _SEQUENCE_LENGTH, len(_FEATURE_KEYS)),
            dtype=np.float32,
        )
        num_timesteps_map: Dict[str, int] = {}

        for i, ip in enumerate(hosts):
            slots = hosts_set[ip]
            num_timesteps_map[ip] = len(slots)
            for slot, feats in slots.items():
                for j, key in enumerate(_FEATURE_KEYS):
                    sequences[i, slot, j] = feats[key]

        logger.debug(
            "Extracted LSTM sequences",
            extra={
                "extra_data": {
                    "hosts": num_hosts,
                    "total_hour_slots": len(rows),
                    "lookback_hours": self.lookback_hours,
                }
            },
        )

        return sequences, hosts, num_timesteps_map

    # ------------------------------------------------------------------
    # Training & detection
    # ------------------------------------------------------------------

    def _train_and_detect(
        self,
        sequences: np.ndarray,
        hosts: List[str],
        num_timesteps_map: Dict[str, int],
    ) -> List[AnomalyResult]:
        """Train LSTM autoencoder and flag hosts with high reconstruction error.

        Args:
            sequences: float32 array (num_hosts, 168, 7).
            hosts: src_ip strings parallel to axis 0.
            num_timesteps_map: dict src_ip → count of non-empty hours.

        Returns:
            List of AnomalyResult for flagged hosts, sorted by score desc.
        """
        num_hosts, num_timesteps, num_features = sequences.shape

        if num_hosts < 5:
            return []

        # ── Normalise per feature across all (host, timestep) ──────────
        # Reshape to 2-D for scaling, then reshape back
        flat = sequences.reshape(-1, num_features)
        flat_min = flat.min(axis=0)
        flat_max = flat.max(axis=0)
        # Avoid division by zero for constant features
        denom = flat_max - flat_min
        denom[denom == 0] = 1.0
        flat_scaled = (flat - flat_min) / denom
        sequences_scaled = flat_scaled.reshape(num_hosts, num_timesteps, num_features)

        # ── Build LSTM autoencoder ─────────────────────────────────────
        model = keras.Sequential(
            [
                keras.layers.LSTM(
                    64,
                    activation="relu",
                    return_sequences=False,
                    input_shape=(num_timesteps, num_features),
                ),
                keras.layers.RepeatVector(num_timesteps),
                keras.layers.LSTM(
                    64,
                    activation="relu",
                    return_sequences=True,
                ),
                keras.layers.TimeDistributed(
                    keras.layers.Dense(num_features)
                ),
            ]
        )
        model.compile(optimizer="adam", loss="mse")
        self.model = model

        # ── Train ──────────────────────────────────────────────────────
        history = model.fit(
            sequences_scaled,
            sequences_scaled,
            epochs=50,
            batch_size=16,
            validation_split=0.1,
            verbose=0,
        )

        final_loss = float(history.history["loss"][-1])
        val_loss = (
            float(history.history["val_loss"][-1])
            if history.history.get("val_loss")
            else None
        )

        logger.debug(
            "LSTM autoencoder training complete",
            extra={
                "extra_data": {
                    "samples": num_hosts,
                    "final_loss": round(final_loss, 6),
                    "val_loss": round(val_loss, 6) if val_loss is not None else None,
                }
            },
        )

        # ── Reconstruction error ───────────────────────────────────────
        reconstructed = model.predict(sequences_scaled, verbose=0)
        # Per-sample MSE: mean over (timesteps × features)
        mse_per_host = np.mean(
            (sequences_scaled - reconstructed) ** 2, axis=(1, 2)
        )

        mean_mse = float(np.mean(mse_per_host))
        std_mse = float(np.std(mse_per_host))
        threshold = mean_mse + 2.0 * std_mse

        # ── Flag anomalous hosts ───────────────────────────────────────
        results: List[AnomalyResult] = []
        for i, mse in enumerate(mse_per_host):
            mse_val = float(mse)
            if mse_val > threshold:
                ip = hosts[i]
                # Normalised score: 0 at mean, 0.5 at threshold, → 1.0
                if std_mse > 0:
                    score = min(1.0, (mse_val - mean_mse) / (4.0 * std_mse))
                else:
                    score = 0.0

                results.append(
                    AnomalyResult(
                        ip=ip,
                        score=round(score, 6),
                        details={
                            "mse": round(mse_val, 6),
                            "mean_mse": round(mean_mse, 6),
                            "std_mse": round(std_mse, 6),
                            "num_timesteps": num_timesteps_map.get(ip, 0),
                        },
                        detector_name=self.name,
                    )
                )

        # Sort by score descending (most anomalous first)
        results.sort(key=lambda r: r.score, reverse=True)
        return results
