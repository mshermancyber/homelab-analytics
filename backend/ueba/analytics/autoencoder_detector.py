"""MLPRegressor autoencoder anomaly detection.

Trains a bottlenecked MLPRegressor to reconstruct per-host feature vectors.
Hosts whose feature vectors cannot be reconstructed accurately (MSE > mean + 2*std)
are flagged as anomalous.

Extended features (11):
- unique_destinations, unique_ports, total_connections, blocked_ratio,
  unique_protocols (inherited from anomaly.py)
- protocol_entropy: Shannon entropy of the protocol distribution
- hour_entropy: Shannon entropy of the hour-of-day connection distribution
- after_hours_connections: connections between 00:00-06:00 ET
- novel_port_count: dst_ports not seen in host's previous 7-day history
- unique_countries: distinct country codes from MMDB enrichment
- denied_to_allowed_ratio: blocked_count / max(total_connections, 1)

Per-device behavioral profiling:
- Each host's features are snapshotted daily to the device_profiles table.
- WDD (Weighted Deviation Distance) scores compare each host to its OWN
  7-day rolling average using security-weighted feature importance.
- Hosts without history fall back to network-wide comparison.
- Role-based peer group deviation also computed when device_roles is provided.
"""
import json
import math
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sqlalchemy import Integer, select, func, case, delete

from ueba.logging_config import get_logger
from ueba.database import async_session_factory, submit_write
from ueba.models import OPNsenseLog, DeviceProfile
from ueba.netconfig import lan_filter
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)

# Feature keys used for the autoencoder (order must match X matrix columns)
_FEATURE_KEYS = [
    "unique_destinations",
    "unique_ports",
    "total_connections",
    "blocked_ratio",
    "unique_protocols",
    "protocol_entropy",
    "hour_entropy",
    "after_hours_connections",
    "novel_port_count",
    "unique_countries",
    "denied_to_allowed_ratio",
]

# ── Phase 4b: WDD security weights (UEBA-DL adapted to network) ────
_WDD_WEIGHTS = [
    1.2,  # unique_destinations
    1.0,  # unique_ports
    1.2,  # total_connections
    0.5,  # blocked_ratio
    0.8,  # unique_protocols
    1.0,  # protocol_entropy
    0.7,  # hour_entropy
    1.5,  # after_hours_connections
    2.0,  # novel_port_count (highest — like USB insert)
    1.5,  # unique_countries
    1.8,  # denied_to_allowed_ratio
]
_WDD_THRESHOLD = 3.0  # ~3 sigma equivalent for WDD

_PROFILE_LOOKBACK_DAYS = 7
_PROFILE_RETENTION_DAYS = 30


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


class AutoencoderDetector(BaseAnomalyDetector):
    """Autoencoder anomaly detector using sklearn's MLPRegressor.

    Trains a neural network with a 5-neuron bottleneck layer to reconstruct
    11-dimensional per-host feature vectors.  Hosts that cannot be reconstructed
    well are flagged.

    Also computes Weighted Deviation Distance (WDD) against per-host 7-day
    profiles and against role-based peer groups when device roles are provided.

    Parameters:
        lookback_hours: How many hours of OPNsense data to train on.
        contamination: Not used in the autoencoder (threshold is mean + 2*std).
            Kept for interface compatibility with other detectors.
        feature_weights: Optional per-feature weights for reconstruction weighting.
        device_roles: Optional dict mapping IP -> role name for peer group deviation.
    """

    def __init__(self, lookback_hours: int = 24, contamination: float = 0.1,
                 feature_weights: Optional[Dict[str, float]] = None,
                 device_roles: Optional[Dict[str, str]] = None):
        self.lookback_hours = lookback_hours
        self.contamination = contamination
        self._feature_weights = feature_weights or {}
        self._device_roles = device_roles or {}
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None
        self.model: Optional[MLPRegressor] = None

    # ------------------------------------------------------------------
    # BaseAnomalyDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "autoencoder"

    @property
    def description(self) -> str:
        return (
            "MLPRegressor autoencoder with WDD scoring using 11 extended host "
            "features including after-hours activity, novel ports, unique countries, "
            "and denied-to-allowed ratio, with per-device behavioral profiling "
            "and role-based peer group deviation"
        )

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    def data_hash(self) -> str:
        """Return a hash based on lookback hours for cache keying."""
        return f"ae_{self.lookback_hours}"

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    async def detect(
        self,
        enrichment_data: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[AnomalyResult]:
        """Run autoencoder anomaly detection.

        Args:
            enrichment_data: Optional mapping of IP -> enrichment dict (country_code, asn, etc.)

        Returns:
            List of AnomalyResult for hosts flagged as anomalous.
        """
        try:
            features = await self._extract_features(enrichment_data)
            if len(features) < 5:
                logger.debug(
                    "Not enough hosts for autoencoder detection",
                    extra={"extra_data": {"host_count": len(features)}},
                )
                self._last_results = []
                self._last_run = datetime.now(timezone.utc)
                return []

            profiles = await self._load_device_profiles()
            results = self._train_and_detect(features, profiles)

            await self._save_device_profiles(features)

            self._last_results = results
            self._last_run = datetime.now(timezone.utc)

            if results:
                logger.info(
                    "Autoencoder anomaly detection completed",
                    extra={
                        "extra_data": {
                            "hosts_analyzed": len(features),
                            "anomalies_found": len(results),
                            "anomalous_ips": [r.ip for r in results],
                            "hosts_with_profiles": sum(
                                1 for f in features if f["ip"] in profiles
                            ),
                        }
                    },
                )
            else:
                logger.debug(
                    "Autoencoder detection completed, no anomalies",
                    extra={"extra_data": {"hosts_analyzed": len(features)}},
                )

            return results

        except Exception:
            logger.error(
                "Autoencoder detection failed",
                exc_info=True,
            )
            return []

    # ------------------------------------------------------------------
    # Device profile persistence
    # ------------------------------------------------------------------

    async def _load_device_profiles(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load the last 7 days of feature profiles per host."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=_PROFILE_LOOKBACK_DAYS)
        ).strftime("%Y-%m-%d")

        async with async_session_factory() as session:
            result = await session.execute(
                select(DeviceProfile)
                .where(DeviceProfile.date >= cutoff)
                .order_by(DeviceProfile.ip, DeviceProfile.date)
            )
            rows = result.scalars().all()

        profiles: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            fv = row.feature_vector
            if isinstance(fv, str):
                fv = json.loads(fv)
            profiles.setdefault(row.ip, []).append(fv)

        return profiles

    async def _save_device_profiles(
        self, features: List[Dict[str, Any]]
    ) -> None:
        """Upsert today's feature snapshot for each host."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=_PROFILE_RETENTION_DAYS)
        ).strftime("%Y-%m-%d")

        async def _do_write():
            async with async_session_factory() as session:
                # Prune old profiles
                await session.execute(
                    delete(DeviceProfile).where(DeviceProfile.date < cutoff)
                )
                for host in features:
                    ip = host["ip"]
                    fv = {k: host[k] for k in _FEATURE_KEYS}
                    existing = await session.execute(
                        select(DeviceProfile).where(
                            DeviceProfile.ip == ip,
                            DeviceProfile.date == today,
                        )
                    )
                    row = existing.scalar_one_or_none()
                    if row:
                        row.feature_vector = fv
                        row.event_count = host.get("total_connections", 0)
                    else:
                        session.add(DeviceProfile(
                            ip=ip,
                            date=today,
                            feature_vector=fv,
                            event_count=host.get("total_connections", 0),
                        ))
                await session.commit()

        try:
            await submit_write(_do_write)
        except Exception:
            logger.warning("Failed to save device profiles", exc_info=True)

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    async def _extract_features(
        self,
        enrichment_data: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Extract 11-feature vectors per internal host from OPNsense logs."""
        since = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
        enrichment_data = enrichment_data or {}

        async with async_session_factory() as session:
            # ── aggregated features per internal host ──────────────────
            result = await session.execute(
                select(
                    OPNsenseLog.src_ip,
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
                .group_by(OPNsenseLog.src_ip)
            )
            rows = result.all()

            features: List[Dict[str, Any]] = []
            for row in rows:
                ip = row.src_ip
                total = row.total_connections or 0
                blocked = row.blocked_count or 0
                blocked_ratio = blocked / total if total > 0 else 0.0

                # Per-host distribution queries (within the same session)
                proto_entropy = await self._query_protocol_entropy(
                    session, ip, since
                )
                hour_entropy = await self._query_hour_entropy(
                    session, ip, since
                )

                # Phase 4a: After-hours connections (00:00-06:00 ET ~ 05:00-11:00 UTC)
                after_hours = await self._query_after_hours_connections(
                    session, ip, since
                )

                # Phase 4a: Novel port count (ports not seen in 7-day history)
                novel_ports = await self._query_novel_port_count(
                    session, ip, since
                )

                # Phase 4a: Unique countries from enrichment
                unique_countries = self._query_unique_countries(
                    ip, enrichment_data
                )

                # Phase 4a: Denied-to-allowed ratio
                denied_ratio = round(blocked / max(total, 1), 4)

                features.append(
                    {
                        "ip": ip,
                        "unique_destinations": row.unique_destinations or 0,
                        "unique_ports": row.unique_ports or 0,
                        "total_connections": total,
                        "blocked_ratio": round(blocked_ratio, 4),
                        "unique_protocols": row.unique_protocols or 0,
                        "protocol_entropy": round(proto_entropy, 4),
                        "hour_entropy": round(hour_entropy, 4),
                        "after_hours_connections": after_hours,
                        "novel_port_count": novel_ports,
                        "unique_countries": unique_countries,
                        "denied_to_allowed_ratio": denied_ratio,
                    }
                )

        return features

    async def _query_protocol_entropy(
        self, session, src_ip: str, since: datetime
    ) -> float:
        """Compute Shannon entropy of the protocol distribution for *src_ip*."""
        result = await session.execute(
            select(
                OPNsenseLog.protocol,
                func.count(OPNsenseLog.id).label("cnt"),
            )
            .where(
                OPNsenseLog.src_ip == src_ip,
                OPNsenseLog.timestamp >= since,
            )
            .group_by(OPNsenseLog.protocol)
        )
        counts = [row.cnt for row in result.all() if row.cnt is not None]
        return _distribution_entropy(counts)

    async def _query_hour_entropy(
        self, session, src_ip: str, since: datetime
    ) -> float:
        """Compute Shannon entropy of the hour-of-day distribution for *src_ip*.

        Normalized by log2(24) so the result is in [0, 1].
        """
        result = await session.execute(
            select(
                func.cast(func.strftime("%H", OPNsenseLog.timestamp), Integer).label("hour"),
                func.count(OPNsenseLog.id).label("cnt"),
            )
            .where(
                OPNsenseLog.src_ip == src_ip,
                OPNsenseLog.timestamp >= since,
            )
            .group_by("hour")
        )
        counts = [row.cnt for row in result.all() if row.cnt is not None]
        raw_entropy = _distribution_entropy(counts)
        max_entropy = math.log2(24)  # ~4.585 bits
        if max_entropy > 0:
            return raw_entropy / max_entropy
        return 0.0

    async def _query_after_hours_connections(
        self, session, src_ip: str, since: datetime
    ) -> int:
        """Count connections between 00:00-06:00 ET (05:00-11:00 UTC)."""
        result = await session.execute(
            select(func.count(OPNsenseLog.id))
            .where(
                OPNsenseLog.src_ip == src_ip,
                OPNsenseLog.timestamp >= since,
                func.cast(func.strftime("%H", OPNsenseLog.timestamp), Integer) >= 5,
                func.cast(func.strftime("%H", OPNsenseLog.timestamp), Integer) < 11,
            )
        )
        count = result.scalar()
        return int(count) if count else 0

    async def _query_novel_port_count(
        self, session, src_ip: str, since: datetime
    ) -> int:
        """Count destination ports not seen in the host's 7-day history."""
        # All ports in the current window
        result = await session.execute(
            select(func.distinct(OPNsenseLog.dst_port))
            .where(
                OPNsenseLog.src_ip == src_ip,
                OPNsenseLog.timestamp >= since,
                OPNsenseLog.dst_port.isnot(None),
            )
        )
        current_ports = {row[0] for row in result.all() if row[0] is not None}

        if not current_ports:
            return 0

        # Ports in previous 7 days (excluding current window)
        history_since = since - timedelta(days=7)
        result = await session.execute(
            select(func.distinct(OPNsenseLog.dst_port))
            .where(
                OPNsenseLog.src_ip == src_ip,
                OPNsenseLog.timestamp >= history_since,
                OPNsenseLog.timestamp < since,
                OPNsenseLog.dst_port.isnot(None),
            )
        )
        history_ports = {row[0] for row in result.all() if row[0] is not None}

        novel = current_ports - history_ports
        return len(novel)

    @staticmethod
    def _query_unique_countries(
        src_ip: str,
        enrichment_data: Dict[str, Dict[str, Any]],
    ) -> int:
        """Count unique country codes from MMDB enrichment for this host's destinations."""
        # enrichment_data maps dst_ip -> enrichment dict
        # This is a simplified approach: we count unique countries across
        # all enrichments associated with *src_ip*.
        # In practice, the engine would pass a mapping of src_ip -> set of country codes.
        enrich = enrichment_data.get(src_ip, {})
        countries = enrich.get("unique_countries", 0)
        if isinstance(countries, (list, set)):
            return len(countries)
        if isinstance(countries, int):
            return countries
        return 0

    # ------------------------------------------------------------------
    # Phase 4b: WDD computation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_wdd(
        current_features: np.ndarray,
        baseline_features: np.ndarray,  # (n_samples, n_features)
    ) -> float:
        """Compute Weighted Deviation Distance between current and baseline.

        WDD = sqrt(sum(w_i * (x_i - mean_i)^2 / max(var_i, epsilon)))

        Uses security weights from _WDD_WEIGHTS.  Returns a single scalar
        representing how many weighted sigmas the current sample deviates
        from the baseline mean.
        """
        if baseline_features.size == 0:
            return 0.0

        epsilon = 1e-9
        mean = np.mean(baseline_features, axis=0)
        var = np.var(baseline_features, axis=0)

        sq_diff = (current_features - mean) ** 2
        weighted = np.array(_WDD_WEIGHTS, dtype=np.float64) * sq_diff
        # Relative variance floor: with only 3-7 daily samples, a feature that
        # barely moved has near-zero variance and a small absolute change
        # explodes the WDD. Floor the denominator at (15% of mean)^2 so scores
        # reflect meaningful deviation, not sampling noise.
        var_floor = (0.15 * np.abs(mean)) ** 2 + epsilon
        denom = np.maximum(var, var_floor)

        wdd = float(np.sqrt(np.sum(weighted / denom)))
        return wdd

    @staticmethod
    def _wdd_feature_contributions(
        current_features: np.ndarray,
        baseline_features: np.ndarray,
    ) -> Dict[str, float]:
        """Return per-feature WDD contributions for explainability."""
        if baseline_features.size == 0:
            return {}

        epsilon = 1e-9
        mean = np.mean(baseline_features, axis=0)
        var = np.var(baseline_features, axis=0)

        sq_diff = (current_features - mean) ** 2
        weighted = np.array(_WDD_WEIGHTS, dtype=np.float64) * sq_diff
        var_floor = (0.15 * np.abs(mean)) ** 2 + epsilon
        denom = np.maximum(var, var_floor)
        contribs = weighted / denom

        return {_FEATURE_KEYS[i]: round(float(contribs[i]), 4) for i in range(len(_FEATURE_KEYS))}

    # ------------------------------------------------------------------
    # Phase 6a: Role-based peer group deviation
    # ------------------------------------------------------------------

    def _check_role_deviation(
        self,
        host_ip: str,
        features: Dict[str, Any],
        all_features: List[Dict[str, Any]],
        device_roles: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Flag hosts that deviate from their role peer group.

        Computes WDD between the host's feature vector and the role's
        average feature vector.  Flags when WDD > 2.5 (strong signal).
        """
        roles = device_roles or self._device_roles
        if not roles:
            return None

        role = roles.get(host_ip)
        if not role:
            return None

        # Build role peer feature matrix
        peer_vectors = []
        for f in all_features:
            ip = f.get("ip", "")
            if ip != host_ip and roles.get(ip) == role:
                vec = np.array([f[k] for k in _FEATURE_KEYS], dtype=np.float64)
                peer_vectors.append(vec)

        if len(peer_vectors) < 2:
            # Not enough peers for reliable comparison
            return None

        peers = np.stack(peer_vectors)
        current = np.array([features[k] for k in _FEATURE_KEYS], dtype=np.float64)

        wdd = self._compute_wdd(current, peers)

        if wdd > 2.5:
            contributions = self._wdd_feature_contributions(current, peers)
            # Find top deviating features
            sorted_contribs = sorted(
                contributions.items(), key=lambda x: x[1], reverse=True
            )[:3]

            return {
                "flag_type": "role_deviation",
                "severity": "medium",
                "details": {
                    "host_ip": host_ip,
                    "role": role,
                    "wdd_score": round(wdd, 4),
                    "peer_count": len(peer_vectors),
                    "top_deviating_features": [f[0] for f in sorted_contribs],
                    "feature_contributions": {
                        k: v for k, v in sorted_contribs
                    },
                    "description": (
                        f"Host {host_ip} (role={role}) deviates from {len(peer_vectors)} "
                        f"peers: WDD={wdd:.2f}"
                    ),
                    "mitre_attack": ["TA0011"],
                },
                "timestamp": datetime.now(timezone.utc),
            }

        return None

    # ------------------------------------------------------------------
    # Training & detection
    # ------------------------------------------------------------------

    def _train_and_detect(
        self,
        features: List[Dict[str, Any]],
        profiles: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> List[AnomalyResult]:
        """Train MLPRegressor autoencoder and flag hosts with high WDD.

        Uses per-device profiles via WDD (Weighted Deviation Distance):
        a host is anomalous if its security-weighted WDD > 3.0 from its
        own 7-day rolling profile.  Hosts without profile history fall
        back to the network-wide autoencoder reconstruction error.

        Also checks role-based peer group deviation for hosts with
        known device roles.

        Args:
            features: Per-host feature dicts (must have >= 5 entries).
            profiles: Per-IP list of historical feature vectors (from device_profiles).

        Returns:
            List of AnomalyResult for flagged hosts.
        """
        if len(features) < 5:
            return []

        profiles = profiles or {}

        # Build feature matrix
        X = np.array(
            [[f[k] for k in _FEATURE_KEYS] for f in features],
            dtype=np.float64,
        )

        # Apply feature weights before normalization (security-weighted scoring)
        if self._feature_weights:
            weight_vector = np.array([
                self._feature_weights.get(k, 1.0) for k in _FEATURE_KEYS
            ], dtype=np.float64)
            X = X * weight_vector

        # Normalize
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Train bottlenecked autoencoder (identity reconstruction)
        model = MLPRegressor(
            hidden_layer_sizes=(5,),
            activation="relu",
            max_iter=2000,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
        )
        model.fit(X_scaled, X_scaled)
        self.model = model

        # Reconstruction error (network-wide fallback)
        X_pred = model.predict(X_scaled)
        mse_per_sample = np.mean((X_scaled - X_pred) ** 2, axis=1)

        mean_mse = float(np.mean(mse_per_sample))
        std_mse = float(np.std(mse_per_sample))
        network_threshold = mean_mse + 2.0 * std_mse

        logger.debug(
            "Autoencoder training complete",
            extra={
                "extra_data": {
                    "samples": len(features),
                    "features": len(_FEATURE_KEYS),
                    "mean_mse": round(mean_mse, 6),
                    "std_mse": round(std_mse, 6),
                    "threshold": round(network_threshold, 6),
                    "hosts_with_profiles": sum(
                        1 for f in features if f["ip"] in profiles
                    ),
                    "final_loss": (
                        round(float(model.loss_), 6)
                        if model.loss_ is not None
                        else None
                    ),
                }
            },
        )

        results: List[AnomalyResult] = []
        for i, host in enumerate(features):
            ip = host["ip"]
            host_profiles = profiles.get(ip)

            if host_profiles and len(host_profiles) >= 3:
                # ── Per-device WDD comparison ─────────────────────────
                current_vec = np.array(
                    [host[k] for k in _FEATURE_KEYS], dtype=np.float64
                )
                history_vecs = np.array([
                    [p.get(k, 0) for k in _FEATURE_KEYS] for p in host_profiles
                ], dtype=np.float64)

                wdd = self._compute_wdd(current_vec, history_vecs)

                if wdd > _WDD_THRESHOLD:
                    contributions = self._wdd_feature_contributions(
                        current_vec, history_vecs
                    )
                    sorted_contribs = sorted(
                        contributions.items(), key=lambda x: x[1], reverse=True
                    )[:3]

                    details = {k: host[k] for k in _FEATURE_KEYS}
                    details["comparison"] = "per_device_wdd"
                    details["wdd_score"] = round(wdd, 4)
                    details["profile_days"] = len(host_profiles)
                    details["threshold"] = _WDD_THRESHOLD
                    details["top_deviating_features"] = [f[0] for f in sorted_contribs]
                    details["feature_contributions"] = {
                        k: v for k, v in sorted_contribs
                    }

                    # Normalize to 0-1 so ensemble composites stay comparable
                    # across detectors: threshold maps to 0.5, 3x threshold → 1.0.
                    norm_score = min(1.0, 0.5 * wdd / _WDD_THRESHOLD)
                    results.append(
                        AnomalyResult(
                            ip=ip,
                            score=round(norm_score, 4),
                            details=details,
                            detector_name=self.name,
                        )
                    )

            else:
                # ── Network-wide fallback ──────────────────────────────
                mse = float(mse_per_sample[i])
                if mse > network_threshold:
                    details = {k: host[k] for k in _FEATURE_KEYS}
                    details["reconstruction_mse"] = round(mse, 6)
                    details["threshold"] = round(network_threshold, 6)
                    details["comparison"] = "network_wide"
                    # Normalize like the WDD path: threshold → 0.5, 3x → 1.0
                    norm_score = min(1.0, 0.5 * mse / max(network_threshold, 1e-9))
                    results.append(
                        AnomalyResult(
                            ip=ip,
                            score=round(norm_score, 4),
                            details=details,
                            detector_name=self.name,
                        )
                    )

        # ── Phase 6a: Role-based peer group deviation ──────────────────
        for host in features:
            ip = host["ip"]
            if self._device_roles and ip in self._device_roles:
                role_flag = self._check_role_deviation(
                    ip, host, features, self._device_roles
                )
                if role_flag:
                    d = dict(role_flag["details"])
                    # WDD > 2.5 fires the check; map 2.5→0.5, 7.5→1.0
                    norm = min(1.0, 0.5 * d["wdd_score"] / 2.5)
                    results.append(AnomalyResult(
                        ip=ip,
                        score=round(norm, 4),
                        details=d,
                        detector_name=self.name,
                    ))

        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def _check_device_deviation(
        self,
        current: Dict[str, Any],
        history: List[Dict[str, Any]],
    ) -> Optional[AnomalyResult]:
        """Compare a host's current features to its own historical profile.

        Returns an AnomalyResult if any feature deviates by more than 2σ from
        the host's rolling average, weighted by the magnitude of deviation.
        """
        deviations: Dict[str, float] = {}
        max_sigma = 0.0

        for key in _FEATURE_KEYS:
            hist_values = [p.get(key, 0) for p in history]
            mean = np.mean(hist_values)
            std = np.std(hist_values)

            if std < 1e-9:
                # No variance in history — flag if current is significantly
                # different from the constant value
                if mean > 0 and abs(current[key] - mean) > mean * 0.5:
                    sigma = 3.0
                elif mean == 0 and current[key] > 0:
                    sigma = 3.0
                else:
                    continue
            else:
                sigma = abs(current[key] - mean) / std

            if sigma > 2.0:
                deviations[key] = round(sigma, 2)
                max_sigma = max(max_sigma, sigma)

        if not deviations:
            return None

        details = {k: current[k] for k in _FEATURE_KEYS}
        details["comparison"] = "per_device"
        details["profile_days"] = len(history)
        details["deviating_features"] = deviations
        details["max_sigma"] = round(max_sigma, 2)

        return AnomalyResult(
            ip=current["ip"],
            score=round(max_sigma, 4),
            details=details,
            detector_name=self.name,
        )
