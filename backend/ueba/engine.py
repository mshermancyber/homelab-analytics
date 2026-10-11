"""UEBA engine - orchestrates ingestion, intelligence, analytics, triage, and escalation."""
import asyncio
import glob
import json
import math
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ueba.logging_config import get_logger, setup_logging
from ueba.config import get_config, reload_config
from ueba.credentials import get_secret
from ueba.netconfig import (
    excluded_building_block_ips,
    network_name,
    infra_hosts,
    is_internal,
    lan_filter,
    reputable_orgs,
    static_wan_ips,
)
from ueba.database import DB_PATH, init_db, shutdown_db, async_session_factory, submit_write
from ueba.models import (
SyslogEvent, OPNsenseLog, PiHoleQuery, ThreatMatch, ThreatFeed,
BehavioralFlag, Alert, NetworkBaseline as NBaselineModel, CustomRule,
AnomalySuppression, FalsePositivePattern, ShadowResult, BuildingBlock,
DeviceRole, ModelRun,
)
from ueba.ingestion.syslog import SyslogListener
from ueba.ingestion.pihole import PiHoleAPIPoller
from ueba.intelligence.feeds import ThreatFeedManager
from ueba.intelligence.matcher import ThreatMatcher
from ueba.analytics.baseline import NetworkBaseline
from ueba.analytics.detectors import BehavioralDetector
from ueba.triage import LLMTriage
from ueba.escalation import send_escalation
from ueba.websocket_manager import WebSocketManager
from ueba.intelligence.enrichment import enrich_ip, enrich_domain
from ueba.analytics.detectors import is_destination_reputable
from ueba.analytics.attack_mapping import get_mitre_mapping
from ueba.analytics.playbooks import get_playbook
from ueba.analytics.anomaly import AnomalyDetector
from ueba.analytics.graph_detector import GraphAnomalyDetector
from ueba.analytics.autoencoder_detector import AutoencoderDetector
from ueba.analytics.lstm_detector import LSTMAnomalyDetector
from ueba.analytics.ensemble import ModelEnsemble
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult
from ueba.analytics.haddrscan_detector import HaddrscanDetector
from ueba.analytics.sigma_dns import SigmaDnsDetector
from ueba.analytics.sigma_firewall import SigmaFirewallDetector
from ueba.analytics.bruteforce_detector import BruteForceDetector
from ueba.analytics.dns_tunnel_detector import DnsTunnelDetector
from ueba.analytics.dns_beacon_detector import DnsBeaconDetector
from ueba.analytics.first_seen import FirstSeenDetector, FirstSeenHistory
from ueba.analytics.ddos_detector import DDoSDetector
from ueba.analytics.dga_classifier import DGAClassifier
from ueba.analytics.biflow import BiflowCorrelator
from ueba.analytics.dns_amplification import DNSAmplificationDetector
from ueba.analytics.dns_flow_correlator import DNSFlowCorrelator as DNSFlowCrossCorrelator
from ueba.analytics.dns_profile import DNSProfileDetector
from ueba.analytics.policy_base import PolicyEnsemble
from ueba.analytics.policies import (
    ConnectionCadencePolicy,
    DnsDiversityPolicy,
    TemporalActivityPolicy,
    PortUsagePolicy,
    DestReputationPolicy,
    DnsFlowCoherencePolicy,
    OutboundSymmetryPolicy,
)

logger = get_logger(__name__)



def _parse_created_at(created_at, fallback):
    """Parse a created_at value that may be ISO string, float, or datetime."""
    if isinstance(created_at, str):
        try:
            return datetime.fromisoformat(created_at)
        except ValueError:
            return fallback
    if isinstance(created_at, (int, float)):
        return datetime.fromtimestamp(created_at, tz=timezone.utc)
    if isinstance(created_at, datetime):
        return created_at
    return fallback

def _is_private(ip):
    """Check if an IP address is in a private/reserved range."""
    if not ip:
        return True
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False

# ── CTI tuning allowlists (2026-07-16 review) ───────────────────────────────
# These strip SPECIFIC benign behavioral flag types toward known-benign
# destinations. Real IOC / threat-feed matches (threat_matches) are NOT affected
# by any of these — they still alert. Tor exits are deliberately NOT listed so
# they stay alertable.
# Own public/WAN addresses (NAT egress + inbound scan target).  Normally left
# empty in config: _wan_ip_discovery() learns the current address at runtime.
# Shared cloud/CDN & app backends — beaconing/correlated_threat here is app telemetry, not C2.
CLOUD_CDN_PREFIXES = (
    "17.", "20.", "3.171.", "47.246.", "43.152.", "163.181.", "8.25.82.",
    "71.18.123.", "199.232.", "216.239.", "203.107.", "92.38.145.",
)
# Apple Private Relay / iCloud egress + encrypted DNS — connection_without_dns & dga are FPs here.
PRIVATE_RELAY_PREFIXES = ("17.", "172.224.", "104.28.")
# Telemetry endpoints pihole sinkholes — outbound_blocked_ratio here is a pihole artifact, not a threat.
TELEMETRY_PREFIXES = ("17.", "17.248.", "17.57.", "20.", "3.171.", "199.232.")


def _dst_prefix(dst_ip, prefixes):
    """True if dst_ip starts with any of the given prefixes (str.startswith takes a tuple)."""
    return bool(dst_ip) and dst_ip.startswith(prefixes)


class UEBAEngine:
    """Central engine that coordinates all UEBA subsystems."""

    def __init__(self):
        self.config = get_config()
        self.websocket: Optional[WebSocketManager] = None
        self.syslog_listener: Optional[SyslogListener] = None
        self.pihole_poller: Optional[PiHoleAPIPoller] = None
        self.feed_manager: Optional[ThreatFeedManager] = None
        self.threat_matcher: Optional[ThreatMatcher] = None
        self.baseline: Optional[NetworkBaseline] = None
        self.behavioral_detector: Optional[BehavioralDetector] = None
        self.llm_triage: Optional[LLMTriage] = None
        self._detectors: List[BaseAnomalyDetector] = []
        self.ensemble: Optional[ModelEnsemble] = None
        self.policy_ensemble: Optional[PolicyEnsemble] = None

        # ML ensemble host scores (updated every 30 min by anomaly loop)
        self._ensemble_host_scores: Dict[str, float] = {}

        # Feature 10: Shadow mode for detectors
        self._shadow_mode: Dict[str, bool] = {}

        # Feature 17: Building blocks for alert correlation
        self._building_blocks: Dict[str, List[dict]] = {}
        self._bb_reputable_cache: Dict[str, bool] = {}

        # Feature 18: Device roles
        self._device_roles: Dict[str, str] = {}

        # Shutdown event
        self._shutdown_event = asyncio.Event()
        self._running = False
        self._tasks: List[asyncio.Task] = []

    @property
    def anomaly_detector(self) -> Optional[AnomalyDetector]:
        """Backward-compatible accessor for the first detector (IsolationForest)."""
        if self._detectors:
            first = self._detectors[0]
            if isinstance(first, AnomalyDetector):
                return first
        return None

    async def startup(self):
        """Initialize all subsystems."""
        logger.info("Starting UEBA Engine")

        # Initialize database
        await init_db()

        # Load baseline from DB (uses BaselineSnapshot table)
        self.baseline = NetworkBaseline()
        await self.baseline.load_from_db()

        # Initialize subsystems
        self.websocket = WebSocketManager()
        self.feed_manager = ThreatFeedManager()
        self.threat_matcher = ThreatMatcher(self.feed_manager)
        self.behavioral_detector = BehavioralDetector(self.baseline)
        self.llm_triage = LLMTriage()

        # Get feature weights from config for security-weighted scoring
        feature_weights = getattr(self.config.analytics, 'feature_weights', {})

        anomaly_detector = AnomalyDetector(feature_weights=feature_weights)
        self._detectors.append(anomaly_detector)

        graph_detector = GraphAnomalyDetector(lookback_hours=24, feed_manager=self.feed_manager)
        self._detectors.append(graph_detector)

        autoencoder_detector = AutoencoderDetector(lookback_hours=24,
                                                    feature_weights=feature_weights)
        self._detectors.append(autoencoder_detector)

        lstm_detector = LSTMAnomalyDetector(lookback_hours=168)
        self._detectors.append(lstm_detector)

        haddrscan_detector = HaddrscanDetector(lookback_hours=24)
        self._detectors.append(haddrscan_detector)

        # Detector weights: pagerank/dns_profile are precision-filtered (Tranco,
        # MMDB org), isolation_forest is the noisiest of the pool.
        _detector_weights = {
            "pagerank_graph": 1.5,
            "dns_profile": 1.3,
            "autoencoder": 1.0,
            "isolation_forest": 0.6,
        }
        self.ensemble = ModelEnsemble(self._detectors, weights=_detector_weights,
                                      feature_weights=feature_weights)

        # Event-pipeline detectors (run on each event, not in ensemble loop)
        self.sigma_dns = SigmaDnsDetector()
        self._detectors.append(self.sigma_dns)
        self.sigma_firewall = SigmaFirewallDetector()
        self._detectors.append(self.sigma_firewall)
        self.bruteforce_detector = BruteForceDetector(lookback_hours=24)
        self._detectors.append(self.bruteforce_detector)
        self.dns_tunnel_detector = DnsTunnelDetector()
        self._detectors.append(self.dns_tunnel_detector)
        self.dns_beacon_detector = DnsBeaconDetector(feed_manager=self.feed_manager)
        self.ddos_detector = DDoSDetector()
        self._detectors.append(self.ddos_detector)
        self.dga_classifier = DGAClassifier()
        self._detectors.append(self.dga_classifier)
        self.biflow_correlator = BiflowCorrelator()
        self.dns_amplification_detector = DNSAmplificationDetector()
        self._detectors.append(self.dns_amplification_detector)
        self.dns_profile_detector = DNSProfileDetector(lookback_hours=24)
        self._detectors.append(self.dns_profile_detector)
        self.first_seen = None  # Initialized after baseline threshold is set

        # Event counter for baseline learning period
        self._event_count = 0
        self._baseline_learning_threshold = 500
        self._own_wan_ips: set = static_wan_ips()  # seeded from config; WAN discovery adds more

        # Initialize first-seen detector (needs baseline threshold)
        self.first_seen = FirstSeenDetector(
            history_days=5,
            learning_event_threshold=self._baseline_learning_threshold,
        )
        self._detectors.append(self.first_seen)

        # Alert dedup: (src_ip, dst_ip) -> expiry timestamp
        self._alert_dedup: dict = {}
        self._alert_dedup_seconds = 1800  # 30 min cooldown per pair

        # Custom rules engine
        self._custom_rules: List[dict] = []
        # Aggregate counters: (rule_id, src_ip) -> [(monotonic_time, value), ...]
        self._rule_aggregates: dict = {}

        # DNS resolution cache: IP -> (domain, expiry_monotonic)
        self._dns_cache: dict = {}
        self._dns_cache_ttl = 1800  # 30 min
        self._dns_resolved: dict = {}  # domain -> expiry (avoid re-resolving)

        # Load false positive patterns from DB
        self._fp_patterns: set = set()  # (src_ip, dst_network, classification)
        await self._load_false_positives()

        # Retrain DGA classifier with analyst-labeled domains
        await self._retrain_dga_with_labels()

        # Load custom rules from DB
        await self._load_rules()

        # Load anomaly suppressions from DB
        self._anomaly_suppressions: set = set()  # (ip, detector_name)
        await self._load_anomaly_suppressions()

        # Load device roles
        await self._load_device_roles()

        # Initialize behavioral policy ensemble
        dns_correlator = DnsFlowCoherencePolicy.DNSFlowCorrelator if hasattr(
            DnsFlowCoherencePolicy, 'DNSFlowCorrelator'
        ) else None
        if dns_correlator is None:
            from ueba.analytics.policies.dns_flow_coherence import DNSFlowCorrelator
        else:
            DNSFlowCorrelator = dns_correlator

        correlator = DNSFlowCorrelator()
        policies = [
            ConnectionCadencePolicy(lookback_hours=6),
            DnsDiversityPolicy(device_roles=self._device_roles),
            TemporalActivityPolicy(device_roles=self._device_roles),
            PortUsagePolicy(lookback_hours=1),
            DestReputationPolicy(lookback_hours=1),
            DnsFlowCoherencePolicy(lookback_hours=1, correlator=correlator),
            OutboundSymmetryPolicy(lookback_hours=1),
        ]
        self._dns_flow_correlator = correlator
        self._policies = policies
        self.policy_ensemble = PolicyEnsemble(policies)

        # Phase 5: DNS-Flow Cross-Correlator for connection-without-DNS
        # and DNS-connection mismatch detection
        self._dns_cross_correlator = DNSFlowCrossCorrelator()

        # Load policy baselines from DB
        for p in policies:
            if hasattr(p, 'load_baselines_from_db'):
                await p.load_baselines_from_db()

        logger.info("Behavioral policy ensemble initialized", extra={
            "extra_data": {"policy_count": len(policies)}
        })

        # Wire up callbacks
        self.syslog_listener = SyslogListener(event_callback=self._on_syslog_event)
        self.llm_triage.result_callback = self._on_triage_result

        # Start subsystems
        await self.websocket.start()
        await self.syslog_listener.start()
        await self.feed_manager.start()
        if self.config.llm.enabled:
            await self.llm_triage.start()
        else:
            logger.info("LLM triage disabled (set llm.enabled / LLM_ENABLED=true to turn it on)")

        # Start Pi-hole pollers (supports multiple, comma-separated)
        pihole_urls = get_secret("PIHOLE_URL") or ""
        pihole_password = get_secret("PIHOLE_PASSWORD") or ""
        self._pihole_pollers = []
        for url in [u.strip() for u in pihole_urls.split(",") if u.strip()]:
            poller = PiHoleAPIPoller(url, pihole_password)
            poller.event_callback = self._on_pihole_event
            await poller.start()
            self._pihole_pollers.append(poller)

        self._running = True

        # Create model cache directory for anomaly detector persistence
        self._model_cache_dir = str(Path(DB_PATH).parent / "model_cache")
        os.makedirs(self._model_cache_dir, exist_ok=True)
        logger.info("Model cache directory ready", extra={
            "extra_data": {"path": self._model_cache_dir}
        })

        logger.info("UEBA Engine started")

        # Track background tasks
        self._tasks = []

        # Start storage pruner (30GB cap)
        self._tasks.append(asyncio.create_task(self._storage_pruner()))

        # Start WAN IP discovery (learns own public IP to suppress self-traffic)
        self._tasks.append(asyncio.create_task(self._wan_ip_discovery()))

        # Start periodic anomaly detection (every 30 minutes)
        self._tasks.append(asyncio.create_task(self._anomaly_detection_loop()))

        # Start building block correlator (every 5 minutes)
        self._tasks.append(asyncio.create_task(self._building_block_correlator()))

        # Start feed file watcher (polling every 30 seconds)
        self._tasks.append(asyncio.create_task(self._feed_file_watcher()))

        # Start syslog watchdog (restarts listener if OPNsense goes stale)
        self._tasks.append(asyncio.create_task(self._syslog_watchdog()))

        # Start daily policy baseline learning (policies persist per-host baselines)
        self._tasks.append(asyncio.create_task(self._policy_learning_loop()))

    async def shutdown(self):
        """Graceful shutdown with state flush."""
        logger.info("Shutting down UEBA Engine")
        self._running = False
        self._shutdown_event.set()

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()

        # Stop subsystems in reverse order
        if self.llm_triage:
            await self.llm_triage.stop()
        for poller in getattr(self, '_pihole_pollers', []):
            await poller.stop()
        if self.feed_manager:
            await self.feed_manager.stop()
        if self.syslog_listener:
            await self.syslog_listener.stop()
        if self.websocket:
            await self.websocket.stop()

        if self.baseline:
            await self.baseline.save_to_db()

        await shutdown_db()
        logger.info("UEBA Engine shutdown complete")

    async def _load_baseline(self):
        """Legacy shim — baseline loads itself via baseline.load_from_db()."""
        pass

    async def _load_false_positives(self):
        """Load false positive patterns from previously marked alerts.

        Extracts (src_ip, dst_/16 network, classification) tuples so future
        alerts matching the same pattern are auto-suppressed.
        """
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(Alert).where(Alert.status == "false_positive")
                )
                rows = result.scalars().all()
                for row in rows:
                    dst_net = self._ip_to_16(row.dst_ip) if row.dst_ip else ""
                    self._fp_patterns.add((row.src_ip, dst_net, row.classification))
                if self._fp_patterns:
                    logger.info("Loaded false positive patterns", extra={
                        "extra_data": {"count": len(self._fp_patterns),
                                       "patterns": [f"{s}->{d} [{c}]" for s, d, c in self._fp_patterns]}
                    })
        except Exception as e:
            logger.warning("Could not load false positives", extra={"extra_data": {"error": str(e)}})

    async def _retrain_dga_with_labels(self):
        """Retrain DGA classifier with analyst-labeled domains from DB."""
        try:
            from ueba.models import DGATrainingLabel
            async with async_session_factory() as session:
                result = await session.execute(select(DGATrainingLabel))
                rows = result.scalars().all()
                if rows:
                    labels = [{"domain": r.domain, "label": r.label} for r in rows]
                    self.dga_classifier._train(analyst_labels=labels)
                    logger.info("DGA classifier retrained with analyst labels", extra={
                        "extra_data": {"analyst_labels": len(labels)}
                    })
        except Exception as e:
            logger.warning("Could not retrain DGA classifier", extra={"extra_data": {"error": str(e)}})

    async def _load_rules(self):
        """Load all enabled custom rules from the database."""
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(CustomRule).where(CustomRule.enabled == True)
                )
                rows = result.scalars().all()
                self._custom_rules = []
                for row in rows:
                    try:
                        rule_json = json.loads(row.rule_json)
                    except (json.JSONDecodeError, TypeError):
                        logger.warning("Invalid rule JSON, skipping", extra={
                            "extra_data": {"rule_id": row.id, "rule_name": row.name}
                        })
                        continue
                    self._custom_rules.append({
                        "id": row.id,
                        "name": row.name,
                        "rule_json": rule_json,
                        "severity": row.severity,
                    })
                logger.info("Custom rules loaded", extra={
                    "extra_data": {"count": len(self._custom_rules)}
                })
        except Exception as e:
            logger.warning("Could not load custom rules", extra={"extra_data": {"error": str(e)}})

    async def reload_rules(self):
        """Reload custom rules from the database (called after CRUD changes)."""
        await self._load_rules()
        # Clear aggregate counters since rules may have changed
        self._rule_aggregates.clear()

    def evaluate_rules(self, event_data: dict, enrichment: dict) -> List[dict]:
        """Evaluate custom rules against an event. Returns list of match dicts.

        Each match dict contains:
          - rule_id, rule_name, severity, classification

        Non-aggregate rules check field conditions directly against the event.
        Aggregate rules maintain in-memory counters per (rule_id, src_ip) with
        windowed expiry and fire when the threshold is exceeded.
        """
        import time as _time
        import json as _json

        parsed = event_data.get("parsed_fields") or {}
        if not isinstance(parsed, dict):
            parsed = {}
        src_ip = parsed.get("src_ip") or parsed.get("client_ip") or event_data.get("source_ip", "")
        dst_ip = parsed.get("dst_ip", "")

        matches: List[dict] = []
        now_mono = _time.monotonic()

        for rule in self._custom_rules:
            rule_json = rule.get("rule_json")
            if not isinstance(rule_json, dict):
                continue

            field = rule_json.get("field", "")
            op = rule_json.get("op", "eq")
            value = rule_json.get("value")
            aggregate = rule_json.get("aggregate")
            threshold = rule_json.get("threshold")

            # Resolve the field value from event or enrichment
            field_value = self._resolve_field_value(field, parsed, enrichment, src_ip, dst_ip)

            if aggregate:
                # ---- Aggregate rule ----
                agg_field = aggregate.get("field", "")
                agg_op = aggregate.get("op", "count")
                agg_window = aggregate.get("window", "5m")

                # Parse window duration
                window_seconds = self._parse_window(agg_window)
                if not window_seconds:
                    continue

                # Resolve the aggregate field value from this event
                agg_value = self._resolve_field_value(agg_field, parsed, enrichment, src_ip, dst_ip)
                if agg_value is None:
                    continue

                # Build counter key: (rule_id, src_ip)
                counter_key = (rule["id"], src_ip)
                if counter_key not in self._rule_aggregates:
                    self._rule_aggregates[counter_key] = []

                # Prune expired entries
                cutoff = now_mono - window_seconds
                self._rule_aggregates[counter_key] = [
                    (t, v) for t, v in self._rule_aggregates[counter_key] if t > cutoff
                ]

                # Add this event's value
                self._rule_aggregates[counter_key].append((now_mono, agg_value))

                # Evaluate based on aggregate operator
                window_entries = self._rule_aggregates[counter_key]
                if agg_op == "count":
                    current_count = len(window_entries)
                elif agg_op == "count_distinct":
                    current_count = len(set(v for _, v in window_entries))
                else:
                    continue

                if threshold and current_count >= threshold:
                    matches.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "classification": f"custom_rule:{rule['name']}",
                        "match_type": "aggregate",
                        "match_detail": f"{agg_op} of {agg_field} = {current_count} (threshold: {threshold})",
                    })
            else:
                # ---- Non-aggregate rule ----
                if field_value is None:
                    continue

                matched = self._evaluate_condition(field_value, op, value)
                if matched:
                    matches.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "classification": f"custom_rule:{rule['name']}",
                        "match_type": "condition",
                        "match_detail": f"{field} {op} {value}",
                    })

        # Periodic cleanup of aggregate counters
        if len(self._rule_aggregates) > 10000:
            self._rule_aggregates = {
                k: [(t, v) for t, v in entries if t > now_mono - 3600]
                for k, entries in self._rule_aggregates.items()
                if entries
            }

        return matches

    def _resolve_field_value(
        self, field: str, parsed: dict, enrichment: dict, src_ip: str, dst_ip: str
    ):
        """Resolve a rule field name to its value from event data or enrichment."""
        # Fields from parsed_fields
        if field in ("src_ip", "dst_ip", "dst_port", "protocol", "action"):
            if field == "src_ip":
                return src_ip or None
            if field == "dst_ip":
                return dst_ip or None
            if field == "dst_port":
                val = parsed.get("dst_port")
                return str(val) if val is not None else None
            if field == "protocol":
                return parsed.get("protocol") or None
            if field == "action":
                return parsed.get("action") or None

        # Domain field (from Pi-hole events)
        if field == "domain":
            return parsed.get("queried_domain") or None

        # Fields from enrichment — look up by dst_ip
        if field in ("dst_country", "dst_org"):
            ip_to_check = dst_ip or src_ip
            enrich_data = enrichment.get(ip_to_check, {})
            if not isinstance(enrich_data, dict):
                enrich_data = {}
            if field == "dst_country":
                return enrich_data.get("country") or enrich_data.get("country_code") or None
            if field == "dst_org":
                return enrich_data.get("org") or enrich_data.get("isp") or None

        return None

    @staticmethod
    def _evaluate_condition(field_value: str, op: str, rule_value) -> bool:
        """Evaluate a single condition: field_value op rule_value."""
        if rule_value is None:
            return False

        fv = str(field_value).lower() if field_value else ""
        rv = str(rule_value).lower()

        if op == "eq":
            return fv == rv
        elif op == "neq":
            return fv != rv
        elif op == "contains":
            return rv in fv
        elif op == "startswith":
            return fv.startswith(rv)
        elif op == "gt":
            try:
                return float(fv) > float(rv)
            except (ValueError, TypeError):
                return False
        elif op == "lt":
            try:
                return float(fv) < float(rv)
            except (ValueError, TypeError):
                return False
        return False

    @staticmethod
    def _parse_window(window: str) -> Optional[int]:
        """Parse a window string like '1m', '5m', '15m', '1h' to seconds."""
        if not window:
            return None
        window = window.strip().lower()
        if window.endswith("m"):
            try:
                return int(window[:-1]) * 60
            except ValueError:
                return None
        elif window.endswith("h"):
            try:
                return int(window[:-1]) * 3600
            except ValueError:
                return None
        elif window.endswith("s"):
            try:
                return int(window[:-1])
            except ValueError:
                return None
        return None

    async def _load_anomaly_suppressions(self):
        """Load anomaly suppressions from database into in-memory set."""
        try:
            async with async_session_factory() as session:
                result = await session.execute(select(AnomalySuppression))
                rows = result.scalars().all()
                for row in rows:
                    self._anomaly_suppressions.add((row.ip, row.detector_name))
                if self._anomaly_suppressions:
                    logger.info("Loaded anomaly suppressions", extra={
                        "extra_data": {"count": len(self._anomaly_suppressions)}
                    })
        except Exception as e:
            logger.warning("Could not load anomaly suppressions", extra={"extra_data": {"error": str(e)}})

    async def _load_device_roles(self):
        """Load device roles from database into in-memory dict."""
        try:
            async with async_session_factory() as session:
                result = await session.execute(select(DeviceRole))
                rows = result.scalars().all()
                for row in rows:
                    self._device_roles[row.ip] = row.role
                if self._device_roles:
                    logger.info("Loaded device roles", extra={
                        "extra_data": {"count": len(self._device_roles)}
                    })
        except Exception as e:
            logger.warning("Could not load device roles", extra={"extra_data": {"error": str(e)}})

    @staticmethod
    def _ip_to_16(ip: str) -> str:
        """Convert IP to /16 network prefix for fuzzy matching."""
        if not ip:
            return ""
        parts = ip.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return ip

    async def _cache_dns_resolution(self, domain: str):
        """Forward-resolve a domain and cache IP -> domain for firewall correlation."""
        import socket as _sock
        import time
        now = time.monotonic()
        if domain in self._dns_resolved and now < self._dns_resolved[domain]:
            return
        try:
            results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _sock.getaddrinfo(domain, None, _sock.AF_UNSPEC, _sock.SOCK_STREAM)
            )
            expiry = now + self._dns_cache_ttl
            for result in results:
                ip = result[4][0]
                self._dns_cache[ip] = (domain, expiry)
            self._dns_resolved[domain] = expiry
            if len(self._dns_cache) > 10000:
                self._dns_cache = {k: v for k, v in self._dns_cache.items() if v[1] > now}
            if len(self._dns_resolved) > 5000:
                self._dns_resolved = {k: v for k, v in self._dns_resolved.items() if v > now}
        except Exception:
            pass

    async def _feed_dns_correlator(self, client_ip: str, domain: str) -> None:
        """Resolve a domain and feed resolved IPs to the DNS-flow correlator."""
        if not hasattr(self, '_dns_flow_correlator') or not self._dns_flow_correlator:
            return
        import socket as _sock
        try:
            results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _sock.getaddrinfo(domain, None, _sock.AF_UNSPEC, _sock.SOCK_STREAM)
            )
            ips = [r[4][0] for r in results]
            if ips:
                self._dns_flow_correlator.record_dns_resolution(client_ip, ips)
        except Exception:
            pass

    def _lookup_dns_cache(self, ip: str) -> Optional[str]:
        """Look up an IP in the DNS cache, return domain or None."""
        import time
        entry = self._dns_cache.get(ip)
        if entry:
            domain, expiry = entry
            if time.monotonic() < expiry:
                return domain
        return None

    def _is_false_positive(self, src_ip: str, dst_ip: str, classification: str) -> bool:
        """Check if an alert matches a learned false positive pattern."""
        dst_net = self._ip_to_16(dst_ip)
        if (src_ip, dst_net, classification) in self._fp_patterns:
            return True
        # Also check with broader classification matching
        for fp_src, fp_dst, fp_cls in self._fp_patterns:
            if fp_src == src_ip and fp_dst == dst_net:
                # Same source and destination network — likely same FP
                if fp_cls in classification or classification in fp_cls:
                    return True
                # beaconing and C2 callback are the same class of FP
                if {fp_cls, classification} <= {"beaconing", "C2 callback", "C2_callback"}:
                    return True
        return False

    async def _save_syslog_event(self, event_data: dict) -> Optional[int]:
        """Save a syslog event to the database. Returns event ID.

        For parsed events (opnsense/pihole), we skip raw_message and parsed_fields
        since the structured data goes into opnsense_logs/pihole_queries instead.
        Only generic (unparsed) events keep the raw message.
        """
        try:
            event_type = event_data.get("event_type", "generic")
            is_parsed = event_type in ("opnsense", "pihole") and event_data.get("parsed_fields")

            async def _do_write():
                async with async_session_factory() as session:
                    event = SyslogEvent(
                        timestamp=event_data.get("timestamp", datetime.now(timezone.utc)),
                        source_ip=event_data.get("source_ip", "0.0.0.0"),
                        source_device=event_data.get("source_device", event_data.get("source_ip", "")),
                        raw_message="" if is_parsed else event_data.get("raw_message", ""),
                        parsed_fields=None if is_parsed else event_data.get("parsed_fields"),
                        event_type=event_type,
                        received_at=datetime.now(timezone.utc),
                    )
                    session.add(event)
                    await session.flush()

                    parsed = event_data.get("parsed_fields") or {}

                    if event_type == "opnsense" and parsed:
                        opsense_log = OPNsenseLog(
                            syslog_event_id=event.id,
                            timestamp=event.timestamp,
                            interface=parsed.get("interface"),
                            src_ip=parsed.get("src_ip", event.source_ip),
                            dst_ip=parsed.get("dst_ip", "0.0.0.0"),
                            src_port=parsed.get("src_port"),
                            dst_port=parsed.get("dst_port"),
                            protocol=parsed.get("protocol"),
                            action=parsed.get("action"),
                            direction=parsed.get("direction"),
                            rule_id=parsed.get("rule_id"),
                        )
                        session.add(opsense_log)

                    elif event_type == "pihole" and parsed:
                        pihole_query = PiHoleQuery(
                            syslog_event_id=event.id,
                            timestamp=event.timestamp,
                            client_ip=parsed.get("client_ip", event.source_ip),
                            queried_domain=parsed.get("queried_domain", ""),
                            query_type=parsed.get("query_type", "A"),
                            blocked=parsed.get("blocked", False),
                            reply_type=parsed.get("reply_type"),
                        )
                        session.add(pihole_query)

                    await session.commit()
                    return event.id

            return await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to save syslog event", extra={"extra_data": {"error": str(e)}})
            return None

    async def _save_threat_matches(self, event_id: int, matches: List[dict]):
        """Save threat matches to database."""
        if not matches:
            return
        try:
            async def _do_write():
                async with async_session_factory() as session:
                    for m in matches:
                        # Find feed by name
                        feed_name = m.get("feed", "")
                        feed_result = await session.execute(
                            select(ThreatFeed).where(ThreatFeed.name == feed_name)
                        )
                        feed = feed_result.scalar_one_or_none()

                        threat_match = ThreatMatch(
                            event_id=event_id,
                            feed_id=feed.id if feed else None,
                            ioc_value=m.get("ioc_value", ""),
                            threat_category=m.get("threat_category", "unknown"),
                            severity_hint=m.get("severity_hint", "info"),
                            first_seen=m.get("first_seen", datetime.now(timezone.utc)),
                        )
                        session.add(threat_match)
                    await session.commit()
            await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to save threat matches", extra={"extra_data": {"error": str(e)}})

    # Need this import in scope
    async def _save_behavioral_flags(self, event_id: int, flags: List[dict]):
        """Save behavioral flags to database."""
        if not flags:
            return
        try:
            async def _do_write():
                async with async_session_factory() as session:
                    for f in flags:
                        bf = BehavioralFlag(
                            event_id=event_id,
                            flag_type=f.get("flag_type", "unknown"),
                            details=f.get("details"),
                            timestamp=f.get("timestamp", datetime.now(timezone.utc)),
                        )
                        session.add(bf)
                    await session.commit()
            await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to save behavioral flags", extra={"extra_data": {"error": str(e)}})

    async def _save_alert(self, event_data: dict, event_id: int, threat_matches: List[dict],
                           behavioral_flags: List[dict], triage_result: dict):
        """Save an alert to database."""
        try:
            analysis = triage_result.get("analysis", {})
            normalized = triage_result.get("normalized", {})

            severity = normalized.get("severity", "info")
            if threat_matches:
                # Escalate severity based on threat intel
                max_sev = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                if max_sev.get(normalized.get("severity", "info"), 1) < 4:
                    for tm in threat_matches:
                        if max_sev.get(tm.get("severity_hint", "info"), 1) >= 3:
                            severity = tm["severity_hint"]
                            break

            def _serialize(items):
                return [{k: (v.isoformat() if isinstance(v, datetime) else v)
                         for k, v in m.items()} for m in items] if items else None

            src_ip = normalized.get("offending_host", event_data.get("source_ip", ""))
            dst_ip = (event_data.get("parsed_fields", {}).get("dst_ip", "")
                      if isinstance(event_data.get("parsed_fields"), dict) else "")
            classification = normalized.get("threat_classification", "unknown")

            # Auto-mark as false_positive if it matches a learned pattern
            status = "open"
            if self._is_false_positive(src_ip, dst_ip, classification):
                status = "false_positive"
                logger.info("LLM alert auto-marked FP by learned pattern", extra={
                    "extra_data": {"src": src_ip, "dst": dst_ip, "class": classification}
                })

            async def _do_write():
                async with async_session_factory() as session:
                    # Determine investigation playbook from behavioral flags
                    _guide = ""
                    if behavioral_flags:
                        _first_ft = behavioral_flags[0].get("flag_type", "") if isinstance(behavioral_flags[0], dict) else ""
                        _guide = get_playbook(_first_ft)

                    alert = Alert(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        event_ids=[event_id],
                        threat_matches=_serialize(threat_matches),
                        behavioral_flags=_serialize(behavioral_flags),
                        llm_analysis=analysis,
                        escalate=False if status == "false_positive" else normalized.get("escalate", False),
                        severity=severity,
                        classification=classification,
                        confidence=normalized.get("confidence", 0),
                        status=status,
                        investigation_guide=_guide,
                        created_at=datetime.now(timezone.utc),
                    )
                    session.add(alert)
                    await session.commit()
            await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to save alert", extra={"extra_data": {"error": str(e)}})

    @staticmethod
    def _sigmoid_confidence(raw_score: float, midpoint: float = None, steepness: float = None) -> float:
        """Apply sigmoid calibration to raw detection scores.

        confidence = 1 / (1 + exp(-(raw_score - midpoint) / steepness)) * 100

        Args:
            raw_score: Raw detection score (e.g., number of matching feeds, count of flags)
            midpoint: Sigmoid midpoint (default from config: analytics.sigmoid_midpoint)
            steepness: Sigmoid steepness (default from config: analytics.sigmoid_steepness)

        Returns:
            Calibrated confidence percentage (0-100).
        """
        config = get_config()
        m = midpoint if midpoint is not None else config.analytics.sigmoid_midpoint
        s = steepness if steepness is not None else config.analytics.sigmoid_steepness
        # Clamp s to avoid division by zero
        if s <= 0:
            s = 1.0
        return round(1.0 / (1.0 + math.exp(-(raw_score - m) / s)) * 100, 1)

    async def _create_local_alert(self, event_data: dict, event_id: int,
                                    threat_matches: list, behavioral_flags: list,
                                    enrichment: dict) -> Optional[int]:
        """Create an alert from local detection rules. Returns alert ID."""
        parsed = event_data.get("parsed_fields") or {}
        if isinstance(parsed, dict) and parsed.get("src_ip"):
            src_ip = parsed["src_ip"]
            dst_ip = parsed.get("dst_ip", "")
        else:
            src_ip = event_data.get("source_ip", "")
            dst_ip = parsed.get("dst_ip", "") if isinstance(parsed, dict) else ""

        firewall_action = parsed.get("action") if isinstance(parsed, dict) else None

        # Determine severity from rule matches
        if threat_matches:
            sev_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            max_sev = max(sev_map.get(m.get("severity_hint", "info"), 1) for m in threat_matches)
            severity = {5: "critical", 4: "high", 3: "medium", 2: "low"}.get(max_sev, "info")
        elif any(f["flag_type"] in ("dga", "port_scan") for f in behavioral_flags):
            severity = "high"
        elif any(f["flag_type"] in ("beaconing", "volume", "dest_fanout",
                                      "brute_force", "dns_tunnel", "sigma_dns",
                                      "haddrscan", "connection_without_dns",
                                      "outbound_blocked_ratio", "lateral_movement") for f in behavioral_flags):
            severity = "medium"
        else:
            severity = "low"

        # Blocked traffic: firewall already handled it, cap severity at medium
        if firewall_action == "block":
            sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            if sev_rank.get(severity, 1) > 3:
                severity = "medium"

        # DNS correlation: look up dst_ip domain from Pi-hole cache
        dst_domain = self._lookup_dns_cache(dst_ip) if dst_ip else None

        # Build classification from top flag/match
        if threat_matches:
            classification = threat_matches[0].get("threat_category", "ioc_match")
        elif behavioral_flags:
            classification = behavioral_flags[0].get("flag_type", "behavioral")
        else:
            classification = "unknown"

        # Build summary
        parts = []
        for m in threat_matches[:3]:
            parts.append(f"IOC: {m.get('ioc_value', '?')} ({m.get('feed', 'unknown')})")
        for f in behavioral_flags[:3]:
            parts.append(f"{f['flag_type']}: {f.get('details', '')}"[:120])
        summary = "; ".join(parts) if parts else "Detection rule triggered"

        # Append enrichment to summary
        enrich_parts = []
        for key, data in enrichment.items():
            if isinstance(data, dict):
                if data.get("country"):
                    enrich_parts.append(f"{key}: {data.get('org') or data.get('isp') or '?'}, {data['country']}")
                    if data.get("asn"):
                        enrich_parts[-1] += f" ({data['asn']})"
        if enrich_parts:
            summary += " | " + "; ".join(enrich_parts)

        # Populate MITRE ATT&CK mapping from behavioral flags
        attack_technique = None
        attack_tactic = None
        if behavioral_flags:
            first_flag_type = behavioral_flags[0].get("flag_type", "")
            attack_technique, attack_tactic = get_mitre_mapping(first_flag_type)
        if not attack_technique and threat_matches:
            attack_technique = "T1204"
            attack_tactic = "Execution"

        # Compute sigmoid-calibrated confidence
        if threat_matches:
            raw_score = len(threat_matches)
        elif behavioral_flags:
            raw_score = len(behavioral_flags)
        else:
            raw_score = 1
        confidence = self._sigmoid_confidence(raw_score)

        # Ensemble ML boost: if the host has a high composite anomaly score
        # from the 30-min ensemble cycle, upgrade confidence and severity
        ensemble_score = self._ensemble_host_scores.get(src_ip, 0.0)
        if ensemble_score > 0.7:
            confidence = min(confidence * (1.0 + ensemble_score), 100.0)
            if behavioral_flags and severity in ("low", "medium"):
                _sev_upgrade = {"low": "medium", "medium": "high"}
                severity = _sev_upgrade[severity]

        # Behavioral policy ensemble evaluation
        policy_result = None
        if self.policy_ensemble and src_ip:
            try:
                policy_result = await self.policy_ensemble.score_host(src_ip)
                composite = policy_result.get("composite_score", 0.0)
                active = policy_result.get("active_policies", 0)
                # If composite > 0.7 AND active_policies >= 2, boost alert confidence
                if composite > 0.7 and active >= 2:
                    confidence = min(confidence * (1.0 + composite * 0.5), 100.0)
                    if severity in ("low", "medium"):
                        _sev_upgrade = {"low": "medium", "medium": "high"}
                        severity = _sev_upgrade[severity]
                    logger.info(
                        "Policy ensemble boosted alert",
                        extra={
                            "extra_data": {
                                "host": src_ip,
                                "composite": composite,
                                "active_policies": active,
                            }
                        },
                    )
            except Exception:
                logger.error(
                    "Policy ensemble evaluation failed in alert creation",
                    exc_info=True,
                )

        try:
            async def _do_write():
                async with async_session_factory() as session:
                    # Determine investigation playbook from behavioral flags
                    _guide = ""
                    if behavioral_flags:
                        _first_ft = behavioral_flags[0].get("flag_type", "") if isinstance(behavioral_flags[0], dict) else ""
                        _guide = get_playbook(_first_ft)

                    _analysis = {
                            "enrichment": enrichment,
                            "source": "local_rules",
                            "firewall_action": firewall_action,
                            "protocol": parsed.get("protocol") if isinstance(parsed, dict) else None,
                            "dst_port": parsed.get("dst_port") if isinstance(parsed, dict) else None,
                            "dst_domain": dst_domain,
                        }
                    if ensemble_score > 0.0:
                        _analysis["ensemble_score"] = ensemble_score
                    if policy_result:
                        _analysis["policy_scores"] = policy_result

                    alert = Alert(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        event_ids=[event_id],
                        threat_matches=[{k: (v.isoformat() if isinstance(v, datetime) else v)
                                         for k, v in m.items()} for m in threat_matches] if threat_matches else None,
                        behavioral_flags=[{k: (v.isoformat() if isinstance(v, datetime) else v)
                                           for k, v in f.items()} for f in behavioral_flags] if behavioral_flags else None,
                        llm_analysis=_analysis,
                        escalate=False,
                        severity=severity,
                        classification=classification,
                        confidence=confidence,
                        firewall_action=firewall_action,
                        dst_domain=dst_domain,
                        attack_technique=attack_technique,
                        attack_tactic=attack_tactic,
                        investigation_guide=_guide,
                        created_at=datetime.now(timezone.utc),
                    )
                    session.add(alert)
                    await session.commit()
                    await session.refresh(alert)
                    return alert.id

            alert_id = await submit_write(_do_write)

            if self.websocket:
                await self.websocket.broadcast("alert", {
                    "alert_id": alert_id,
                    "severity": severity,
                    "classification": classification,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_domain": dst_domain,
                    "action": firewall_action,
                    "protocol": parsed.get("protocol") if isinstance(parsed, dict) else None,
                    "dst_port": parsed.get("dst_port") if isinstance(parsed, dict) else None,
                    "summary": summary,
                    "enrichment": enrichment,
                    "escalated": False,
                    "source": "local_rules",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

            return alert_id
        except Exception as e:
            logger.error("Failed to create local alert", extra={"extra_data": {"error": str(e)}})
        return None

    async def _create_custom_rule_alert(self, event_data: dict, event_id: int,
                                         rule_match: dict, enrichment: dict) -> Optional[int]:
        """Create an alert from a custom rule match. Returns alert ID."""
        parsed = event_data.get("parsed_fields") or {}
        if isinstance(parsed, dict) and parsed.get("src_ip"):
            src_ip = parsed["src_ip"]
            dst_ip = parsed.get("dst_ip", "")
        else:
            src_ip = event_data.get("source_ip", "")
            dst_ip = parsed.get("dst_ip", "") if isinstance(parsed, dict) else ""

        firewall_action = parsed.get("action") if isinstance(parsed, dict) else None
        severity = rule_match.get("severity", "medium")
        classification = rule_match.get("classification", "custom_rule")
        rule_name = rule_match.get("rule_name", "unknown")

        # DNS correlation: look up dst_ip domain from Pi-hole cache
        dst_domain = self._lookup_dns_cache(dst_ip) if dst_ip else None

        # Behavioral policy ensemble evaluation
        policy_result = None
        if self.policy_ensemble and src_ip:
            try:
                policy_result = await self.policy_ensemble.score_host(src_ip)
            except Exception:
                logger.error(
                    "Policy ensemble evaluation failed in custom rule alert",
                    exc_info=True,
                )

        # Build summary
        summary = f"Custom rule '{rule_name}' matched: {rule_match.get('match_detail', 'condition met')}"

        # Append enrichment to summary
        enrich_parts = []
        for key, data in enrichment.items():
            if isinstance(data, dict):
                if data.get("country"):
                    enrich_parts.append(f"{key}: {data.get('org') or data.get('isp') or '?'}, {data['country']}")
        if enrich_parts:
            summary += " | " + "; ".join(enrich_parts)

        try:
            async def _do_write():
                async with async_session_factory() as session:
                    # Determine investigation playbook from classification or rule name
                    _guide = get_playbook(classification) or get_playbook(rule_name)
                    alert = Alert(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        event_ids=[event_id],
                        threat_matches=None,
                        behavioral_flags=None,
                        llm_analysis={
                            "enrichment": enrichment,
                            "source": "custom_rule",
                            "rule_name": rule_name,
                            "rule_id": rule_match.get("rule_id"),
                            "match_detail": rule_match.get("match_detail"),
                            "firewall_action": firewall_action,
                            "protocol": parsed.get("protocol") if isinstance(parsed, dict) else None,
                            "dst_port": parsed.get("dst_port") if isinstance(parsed, dict) else None,
                            "dst_domain": dst_domain,
                            "policy_scores": policy_result,
                        },
                        escalate=False,
                        severity=severity,
                        classification=classification,
                        confidence=self._sigmoid_confidence(2.0),
                        firewall_action=firewall_action,
                        dst_domain=dst_domain,
                        investigation_guide=_guide,
                        created_at=datetime.now(timezone.utc),
                    )
                    session.add(alert)
                    await session.commit()
                    await session.refresh(alert)
                    return alert.id

            alert_id = await submit_write(_do_write)

            if self.websocket:
                await self.websocket.broadcast("alert", {
                    "alert_id": alert_id,
                    "severity": severity,
                    "classification": classification,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_domain": dst_domain,
                    "action": firewall_action,
                    "protocol": parsed.get("protocol") if isinstance(parsed, dict) else None,
                    "dst_port": parsed.get("dst_port") if isinstance(parsed, dict) else None,
                    "summary": summary,
                    "enrichment": enrichment,
                    "escalated": False,
                    "source": "custom_rule",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

            return alert_id
        except Exception as e:
            logger.error("Failed to create custom rule alert", extra={"extra_data": {"error": str(e)}})
        return None

    async def _on_syslog_event(self, event_data: dict):
        """Process a received syslog event through the full pipeline.

        Only events with IOC matches or strong behavioral signals go to the LLM.
        During baseline learning (first 500 events), "new destination" flags are
        suppressed — the baseline needs to warm up before flagging novelty.
        """
        if not self._running:
            return

        try:
            self._event_count += 1
            baseline_warm = self._event_count > self._baseline_learning_threshold

            # 1. Save event to database
            event_id = await self._save_syslog_event(event_data)

            # 2. Extract connection endpoints from parsed filterlog, not the
            # syslog sender IP (which is always the firewall management address)
            parsed = event_data.get("parsed_fields") or {}
            if isinstance(parsed, dict) and parsed.get("src_ip"):
                src_ip = parsed["src_ip"]
                dst_ip = parsed.get("dst_ip", "")
            else:
                src_ip = event_data.get("source_ip", "")
                dst_ip = parsed.get("dst_ip", "") if isinstance(parsed, dict) else ""


            # 3. Cross-reference against threat intelligence (IOC match)
            threat_matches = self.threat_matcher.match_event(event_data)

            # 4. Run behavioral analytics BEFORE recording baseline —
            # otherwise every source is "known" before unknown_source can fire
            behavioral_flags = self.behavioral_detector.analyze_event(event_data, self.feed_manager)
            self.behavioral_detector.prune_stale_state()

            # 5. Extract firewall action and port early (used by detectors below)
            firewall_action = parsed.get("action") if isinstance(parsed, dict) else None
            dst_port = parsed.get("dst_port") if isinstance(parsed, dict) else None

            # 6. Now record baseline for future comparisons.
            # Internal sources only — inbound internet scanners would register
            # thousands of phantom "hosts" (1,195 in 2 hours when unguarded).
            if src_ip and dst_ip and _is_private(src_ip):
                self.baseline.record_connection(src_ip, dst_ip)
                await self.baseline.maybe_snapshot()

            # 6b. Run brute force detection for filterlog events
            if event_data.get("event_type") != "pihole" and src_ip and dst_ip:
                brute_flags = self.bruteforce_detector.analyze_event(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=parsed.get("protocol") if isinstance(parsed, dict) else None,
                    action=firewall_action,
                    timestamp=event_data.get("timestamp"),
                )
                behavioral_flags.extend(brute_flags)

                # Run sigma firewall detection
                sigma_fw_flags = self.sigma_firewall.analyze_event(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=parsed.get("protocol") if isinstance(parsed, dict) else None,
                    action=firewall_action,
                    direction=parsed.get("direction") if isinstance(parsed, dict) else None,
                    timestamp=event_data.get("timestamp"),
                )
                behavioral_flags.extend(sigma_fw_flags)

            # 6c. Run first-seen detection for filterlog events
            if event_data.get("event_type") != "pihole" and src_ip and dst_ip:
                first_seen_flags = await self.first_seen.check_filterlog_event(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=parsed.get("protocol") if isinstance(parsed, dict) else None,
                    timestamp=event_data.get("timestamp"),
                )
                behavioral_flags.extend(first_seen_flags)

                # 6e. Biflow correlation — track bidirectional flows
                biflow_record = self.biflow_correlator.process_event(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=parsed.get("src_port") if isinstance(parsed, dict) else None,
                    dst_port=dst_port,
                    protocol=parsed.get("protocol") if isinstance(parsed, dict) else None,
                    action=firewall_action,
                    bytes_count=parsed.get("length", 0) if isinstance(parsed, dict) else 0,
                    timestamp=event_data.get("timestamp"),
                )
                if biflow_record:
                    event_data["_biflow_record"] = biflow_record.to_dict()

                # Phase 5: DNS-Flow Cross-Correlator — check
                # connection against recent DNS queries
                if hasattr(self, '_dns_cross_correlator') and self._dns_cross_correlator:
                    try:
                        dst_port_int = int(dst_port) if dst_port is not None else 0
                    except (ValueError, TypeError):
                        dst_port_int = 0
                    xcorr_flags = self._dns_cross_correlator.check_connection(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port_int,
                    )
                    behavioral_flags.extend(xcorr_flags)

            # 6d. Add Pi-hole-specific flags from _on_pihole_event
            pihole_flags = event_data.get("_pihole_flags", [])
            if pihole_flags:
                behavioral_flags.extend(pihole_flags)

            # Feature 17: Create building blocks from select behavioral flags
            # Internal sources only — inbound scanners/CDNs already suppressed
            # downstream must not accumulate blocks. Exclude WAN IP (NAT
            # gateway) and IOC scraper — they dominate blocks with normal
            # traffic patterns.
            _bb_excluded_ips = self._own_wan_ips | excluded_building_block_ips()
            building_block_types = {
                "beaconing": "single_beaconing",
                "dns_beaconing": "single_dns_beacon",
                "dns_query_burst": "single_dns_burst",
                "dns_unknown_burst": "single_dns_unknown_burst",
                "dest_fanout": "single_dest_fanout",
                "outbound_blocked_ratio": "single_outbound_blocked",
                "connection_without_dns": "single_conn_no_dns",
            }
            for bf in behavioral_flags:
                flag_type = bf.get("flag_type", "")
                single_type = building_block_types.get(flag_type)
                if (single_type and src_ip
                        and is_internal(src_ip)
                        and src_ip not in _bb_excluded_ips):
                    asyncio.create_task(
                        self._save_building_block(
                            src_ip,
                            single_type,
                            {"original_flag_type": flag_type, **bf.get("details", {})} if isinstance(bf, dict) else bf.details,
                        )
                    )

            is_inbound_blocked = (firewall_action == "block"
                                  and src_ip and not _is_private(src_ip))
            is_internal_outbound = (is_internal(src_ip)
                                    and not _is_private(dst_ip) if dst_ip else False)

            is_wan_originated = (src_ip in self._own_wan_ips)

            # --- Smart suppression: cut noise, keep real threats ---

            # 0) Traffic originating from own WAN IP is the firewall/gateway itself.
            #    DNS lookups, NTP sync, BGP, firmware checks — all normal.
            if is_wan_originated and not threat_matches:
                return

            # 1) Blocked inbound from unknown sources = internet background noise.
            #    The firewall already handled it. Suppress unless high/critical IOC
            #    or DDoS volumetric flood. Low/medium IOC matches on blocked inbound
            #    are expected — these IPs are on blocklists precisely because they scan.
            if is_inbound_blocked:
                # Blocked inbound reached nothing — the firewall dropped it. Any
                # IOC match is correct but zero-risk (these IPs are on blocklists
                # precisely because they scan the whole internet), regardless of
                # severity. Suppress; keep only a volumetric DDoS flag as an
                # availability signal. (CTI tuning 2026-07-16 rec #2)
                ddos_flag = self.ddos_detector.analyze_event(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    action=firewall_action,
                    direction=parsed.get("direction") if isinstance(parsed, dict) else None,
                    timestamp=event_data.get("timestamp"),
                )
                if ddos_flag:
                    behavioral_flags.append(ddos_flag)
                else:
                    return

            # 2) dest_fanout and unknown_source from internal/Docker hosts = normal browsing.
            #    Docker containers on .24 use 172.x bridge IPs — treat same as LAN hosts.
            _is_docker_src = (src_ip.startswith("172.") and _is_private(src_ip))
            if is_internal_outbound or _is_docker_src:
                behavioral_flags = [f for f in behavioral_flags
                                    if f["flag_type"] not in ("dest_fanout", "unknown_source")]

            # 2b) Strip connection_without_dns when dst is WAN IP (NAT gateway traffic)
            if dst_ip in self._own_wan_ips:
                behavioral_flags = [f for f in behavioral_flags
                                    if f["flag_type"] not in ("connection_without_dns", "dns_flow_mismatch")]

            # 2c) CTI tuning 2026-07-16 — strip benign flag types toward known-benign
            #     dsts. threat_matches (real IOC hits) are untouched; this only
            #     removes noisy behavioral flags, never a threat-feed match.
            # #5 Apple Private Relay / iCloud / encrypted DNS → connection_without_dns & dga are FPs
            if _dst_prefix(dst_ip, PRIVATE_RELAY_PREFIXES):
                behavioral_flags = [f for f in behavioral_flags
                                    if f["flag_type"] not in ("connection_without_dns", "dns_flow_mismatch", "dga", "dga_classifier")]
            # #6 telemetry endpoints pihole-sinkholes → outbound_blocked_ratio is a pihole artifact
            if _dst_prefix(dst_ip, TELEMETRY_PREFIXES):
                behavioral_flags = [f for f in behavioral_flags
                                    if f["flag_type"] != "outbound_blocked_ratio"]
            # #4 shared cloud/CDN app backends → periodic telemetry, not C2 beaconing
            if _dst_prefix(dst_ip, CLOUD_CDN_PREFIXES):
                behavioral_flags = [f for f in behavioral_flags
                                    if f["flag_type"] not in ("beaconing", "dns_beaconing")]
            # #1 apply the catalogued anomaly suppressions (ip, detector) from the DB
            if self._anomaly_suppressions:
                behavioral_flags = [f for f in behavioral_flags
                                    if (src_ip, f["flag_type"]) not in self._anomaly_suppressions
                                    and (dst_ip, f["flag_type"]) not in self._anomaly_suppressions]

            # 3) During learning, suppress novelty flags (everything looks new)
            if not baseline_warm:
                behavioral_flags = [f for f in behavioral_flags
                                    if f["flag_type"] not in ("geo", "unknown_source")]

            # 4) Determine if this event is truly security-relevant
            # High-value signals only — skip noise generators
            triage_flag_types = ("dga", "port_scan", "beaconing",
                                 "volume", "dns_query_burst", "dns_unknown_burst",
                                 "sigma_dns", "brute_force", "dns_tunnel",
                                 "haddrscan", "first_seen", "sigma_firewall",
                                 "role_deviation", "correlated_threat",
                                 "ddos_flood", "dns_amplification", "dga_classifier",
                                 "dns_beaconing", "connection_without_dns",
                                 "outbound_blocked_ratio", "lateral_movement")
            strong_behavioral = [f for f in behavioral_flags
                                 if f["flag_type"] in triage_flag_types]
            # Novelty flags (first_seen, connection_without_dns) are too noisy
            # on their own — normal browsing generates dozens per hour. Require
            # a corroborating high-value signal (IOC match or a non-novelty flag).
            _novelty_types = {"first_seen", "connection_without_dns"}
            if (strong_behavioral
                    and all(f["flag_type"] in _novelty_types for f in strong_behavioral)
                    and not threat_matches):
                strong_behavioral = []
            is_security_event = bool(threat_matches) or bool(strong_behavioral)

            # Only stream security events to WebSocket — not a network log
            if is_security_event and self.websocket:
                def _serialize_flags(flags):
                    out = []
                    for f in flags:
                        entry = dict(f)
                        if isinstance(entry.get("timestamp"), datetime):
                            entry["timestamp"] = entry["timestamp"].isoformat()
                        if isinstance(entry.get("first_seen"), datetime):
                            entry["first_seen"] = entry["first_seen"].isoformat()
                        out.append(entry)
                    return out

                await self.websocket.broadcast("security_event", {
                    "event_id": event_id,
                    "event_type": event_data.get("event_type"),
                    "source_ip": src_ip,
                    "dst_ip": dst_ip,
                    "parsed_fields": parsed,
                    "threat_matches": _serialize_flags(threat_matches),
                    "behavioral_flags": _serialize_flags(behavioral_flags),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

            # 6. Process security events
            if is_security_event and event_id:
                await self._save_threat_matches(event_id, threat_matches)
                await self._save_behavioral_flags(event_id, behavioral_flags)

                # Enrich flagged IPs with geo/WHOIS/rDNS BEFORE deciding to alert
                enrichment = {}

                # Quick rDNS-only check for Tranco suppression (no API call)
                if not threat_matches:
                    if dst_ip in self._own_wan_ips:
                        remote_ip = src_ip
                    else:
                        remote_ip = dst_ip
                    if remote_ip and not _is_private(remote_ip):
                        import socket as _sock
                        try:
                            rdns = await asyncio.get_event_loop().run_in_executor(
                                None, lambda: _sock.gethostbyaddr(remote_ip)[0])
                        except Exception:
                            rdns = None
                        if rdns and self.feed_manager and self.feed_manager.is_domain_reputable(rdns):
                            return

                    # For WAN IP outbound: suppress dest_fanout (everything fans out
                    # through NAT) but keep unknown_source, beaconing to unknown dests
                    if src_ip in self._own_wan_ips:
                        behavioral_only_fanout = all(
                            f["flag_type"] == "dest_fanout" for f in strong_behavioral
                        )
                        if behavioral_only_fanout:
                            return

                # Enrich IPs that will become alerts (save API calls)
                # Our own network: label with the configured network name
                # and resolve the hostname locally
                async def _enrich_own(ip):
                    import socket as _sock
                    hostname = None
                    try:
                        hostname = await asyncio.get_event_loop().run_in_executor(
                            None, lambda: _sock.gethostbyaddr(ip)[0])
                    except Exception:
                        pass
                    return {
                        "ip": ip, "reverse_dns": hostname,
                        "country": None, "country_code": None,
                        "city": None, "region": None,
                        "lat": None, "lon": None,
                        "isp": network_name(), "org": network_name(), "asn": None,
                    }

                enrich_targets = set()
                for ip in (src_ip, dst_ip):
                    if not ip:
                        continue
                    if is_internal(ip):
                        enrichment[ip] = await _enrich_own(ip)
                    elif not _is_private(ip):
                        enrich_targets.add(ip)
                for ip in enrich_targets:
                    try:
                        enrichment[ip] = await enrich_ip(ip)
                    except Exception:
                        pass

                domain = parsed.get("queried_domain") if isinstance(parsed, dict) else None
                if domain:
                    try:
                        enrichment[domain] = await enrich_domain(domain)
                    except Exception:
                        pass

                # Check against learned false positive patterns
                for bf in strong_behavioral:
                    if self._is_false_positive(src_ip, dst_ip, bf["flag_type"]):
                        logger.debug("Suppressed learned FP", extra={
                            "extra_data": {"src": src_ip, "dst": dst_ip, "flag": bf["flag_type"]}
                        })
                        strong_behavioral = [f for f in strong_behavioral
                                             if not self._is_false_positive(src_ip, dst_ip, f["flag_type"])]
                        break

                # Recheck — if all flags were FPs and no IOC matches, skip
                if not threat_matches and not strong_behavioral:
                    return

                # Infrastructure hosts (network.infra_hosts) run crawlers,
                # scrapers and container workloads — high DNS volume, many
                # destinations, and beaconing to feed sources are all expected.
                # Containers behind them use 172.16/12 bridge addresses.
                # Suppress behavioural-only alerts from these (keep IOC matches).
                _is_infra = (src_ip in infra_hosts()
                             or (src_ip.startswith("172.") and _is_private(src_ip)))
                if _is_infra and not threat_matches:
                    return

                # Suppress low-signal flags to known reputable orgs (CDN, cloud, SaaS)
                _low_signal_types = {"beaconing", "connection_without_dns", "first_seen"}
                if not threat_matches and strong_behavioral:
                    _reputable_orgs = reputable_orgs()
                    if all(f["flag_type"] in _low_signal_types for f in strong_behavioral):
                        remote_ip = dst_ip if not _is_private(dst_ip) else src_ip
                        remote_enrich = enrichment.get(remote_ip, {})
                        org = (remote_enrich.get("org") or "").lower()
                        if any(rep in org for rep in _reputable_orgs):
                            return

                # Alert dedup: don't create duplicate alerts for same (src, dst)
                now = datetime.now(timezone.utc)
                if is_inbound_blocked and threat_matches:
                    # Blocked-inbound IOC sources re-probe on 30-90 min cycles —
                    # wider than the pair cooldown, so each probe re-alerted
                    # (one scanner produced 27 of 37 alerts in a day). Roll up
                    # to one alert per source per day; a NEW malicious source
                    # still alerts immediately.
                    dedup_key = (src_ip, "inbound-ioc")
                    dedup_seconds = 86400
                else:
                    dedup_key = (src_ip, dst_ip)
                    dedup_seconds = self._alert_dedup_seconds
                expires = self._alert_dedup.get(dedup_key)
                if expires and now < expires:
                    return
                self._alert_dedup[dedup_key] = now + timedelta(seconds=dedup_seconds)
                # Prune expired entries periodically
                if len(self._alert_dedup) > 1000:
                    self._alert_dedup = {k: v for k, v in self._alert_dedup.items() if v > now}

                # Evaluate custom rules
                rule_matches = self.evaluate_rules(event_data, enrichment)
                for rm in rule_matches:
                    try:
                        await self._create_custom_rule_alert(
                            event_data, event_id, rm, enrichment
                        )
                    except Exception as e:
                        logger.error("Failed to create custom rule alert", extra={
                            "extra_data": {"rule_id": rm.get("rule_id"), "error": str(e)}
                        })

                alert_id = await self._create_local_alert(
                    event_data, event_id, threat_matches,
                    strong_behavioral, enrichment
                )

                # Post-hoc LLM enrichment (off unless llm.enabled).  Only
                # allowed traffic is submitted: blocked traffic was already
                # handled by the firewall, so triage adds nothing.  The alert
                # exists either way — triage can only upgrade it.
                if (self.config.llm.enabled and self.llm_triage
                        and self.llm_triage.primary_client and alert_id
                        and firewall_action != "block"):
                    await self.llm_triage.submit_event(
                        event_data, threat_matches, behavioral_flags,
                        enrichment=enrichment, alert_id=alert_id
                    )

        except Exception as e:
            logger.error("Event processing failed", extra={"extra_data": {"error": str(e)}})

    async def _on_pihole_event(self, event_data: dict):
        """Process a Pi-hole API poll event — only keeps fields the detectors need."""
        domain = event_data.get("queried_domain", "")
        blocked = event_data.get("blocked", False)
        query_type = event_data.get("query_type", "A")
        client_ip = event_data.get("client_ip", "0.0.0.0")

        # Cache DNS resolution for firewall log correlation
        if domain and not blocked and query_type in ("A", "AAAA"):
            asyncio.create_task(self._cache_dns_resolution(domain))

        # Feed DNS-flow correlator for behavioral policy
        if domain and not blocked and query_type in ("A", "AAAA"):
            asyncio.create_task(self._feed_dns_correlator(client_ip, domain))

        # Phase 5: Feed DNS-Flow Cross-Correlator
        if domain and not blocked and query_type in ("A", "AAAA") and hasattr(self, '_dns_cross_correlator') and self._dns_cross_correlator:
            self._dns_cross_correlator.record_dns_query(client_ip, domain)

        # Run Sigma DNS detection patterns
        sigma_flags = []
        if self.sigma_dns and domain:
            sigma_flags = self.sigma_dns.analyze_query(
                client_ip=client_ip,
                domain=domain,
                query_type=query_type,
                blocked=blocked,
                timestamp=event_data.get("timestamp"),
            )

        # Run DNS tunnel detection
        dns_tunnel_flags = []
        if self.dns_tunnel_detector and domain:
            dns_tunnel_flags = self.dns_tunnel_detector.analyze_query(
                client_ip=client_ip,
                domain=domain,
                query_type=query_type,
                blocked=blocked,
                timestamp=event_data.get("timestamp"),
            )

        # Run supervised DGA classification
        dga_classifier_flags = []
        if self.dga_classifier and domain:
            dga_classifier_flags = self.dga_classifier.analyze_query(
                client_ip=client_ip,
                domain=domain,
                query_type=query_type,
                blocked=blocked,
                timestamp=event_data.get("timestamp"),
            )

        # Run DNS beaconing detection (timing-regular queries to same domain)
        dns_beacon_flags = []
        if getattr(self, "dns_beacon_detector", None) and domain:
            dns_beacon_flags = self.dns_beacon_detector.analyze_query(
                client_ip=client_ip,
                domain=domain,
                query_type=query_type,
                blocked=blocked,
                timestamp=event_data.get("timestamp"),
            )

        # Run DNS amplification detection
        dns_amplification_flag = self.dns_amplification_detector.analyze_query(
            client_ip=client_ip,
            domain=domain,
            timestamp=event_data.get("timestamp"),
        )
        dns_amplification_flags = [dns_amplification_flag] if dns_amplification_flag else []

        # Run first-seen detection for DNS domains
        first_seen_flags = []
        if self.first_seen and domain:
            first_seen_flags = await self.first_seen.check_pihole_event(
                client_ip=client_ip,
                domain=domain,
                query_type=query_type,
                blocked=blocked,
                timestamp=event_data.get("timestamp"),
            )

        # Combine all Pi-hole-specific flags
        all_pihole_flags = (sigma_flags + dns_tunnel_flags + dga_classifier_flags +
                            dns_beacon_flags + dns_amplification_flags + first_seen_flags)

        syslog_event = {
            "timestamp": event_data.get("timestamp", datetime.now(timezone.utc)),
            "source_ip": event_data.get("client_ip", "0.0.0.0"),
            "source_device": "pihole-api",
            "raw_message": "",
            "parsed_fields": {
                "client_ip": client_ip,
                "queried_domain": domain,
                "query_type": query_type,
                "blocked": blocked,
            },
            "event_type": "pihole",
        }

        # Pass Pi-hole-specific flags along for alert creation
        if all_pihole_flags:
            syslog_event["_pihole_flags"] = all_pihole_flags

        await self._on_syslog_event(syslog_event)

    async def _on_triage_result(self, result: dict):
        """Update an existing alert with LLM triage analysis."""
        try:
            alert_id = result.get("alert_id")
            if not alert_id:
                logger.debug("Triage result has no alert_id, skipping")
                return

            if result.get("error") or not result.get("analysis"):
                logger.debug("Triage error, alert already exists from local rules", extra={
                    "extra_data": {"alert_id": alert_id, "error": result.get("error", "no analysis")}
                })
                return

            normalized = result.get("normalized", {})
            analysis = result.get("analysis", {})
            escalate = normalized.get("escalate", False)

            async def _do_write():
                async with async_session_factory() as session:
                    alert = await session.get(Alert, alert_id)
                    if not alert:
                        logger.warning("Alert not found for triage update", extra={
                            "extra_data": {"alert_id": alert_id}
                        })
                        return None, None, None

                    alert.llm_analysis = analysis
                    alert.classification = normalized.get("threat_classification", alert.classification)
                    ds_severity = normalized.get("severity", "info")
                    sev_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                    # Cap blocked traffic at medium — firewall already handled it
                    if alert.firewall_action == "block" and sev_map.get(ds_severity, 1) > 3:
                        ds_severity = "medium"
                    original_severity = alert.severity
                    if sev_map.get(ds_severity, 1) > sev_map.get(original_severity, 1):
                        alert.severity = ds_severity
                    if escalate and alert.status != "false_positive":
                        alert.escalate = True
                    if normalized.get("confidence", 0) > (alert.confidence or 0):
                        alert.confidence = normalized["confidence"]

                    await session.commit()
                    return alert.severity, ds_severity, alert.escalate

            final_severity, ds_severity, did_escalate = await submit_write(_do_write)
            if final_severity is None:
                return  # Alert not found

            if self.websocket:
                await self.websocket.broadcast("alert_updated", {
                    "alert_id": alert_id,
                    "escalate": escalate,
                    "severity": final_severity,
                    "classification": normalized.get("threat_classification", "unknown"),
                    "incident_summary": normalized.get("incident_summary", ""),
                    "confidence": normalized.get("confidence", 0),
                    "source": "ai",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

            if escalate:
                event_data = result.get("event", {})
                escalation_data = {
                    "severity": normalized.get("severity", "info"),
                    "threat_classification": normalized.get("threat_classification", "unknown"),
                    "incident_summary": normalized.get("incident_summary", ""),
                    "offending_host": normalized.get("offending_host", ""),
                    "recommended_containment": normalized.get("recommended_containment", ""),
                    "confidence": normalized.get("confidence", 0),
                    "threat_matches": result.get("threat_matches", []),
                    "behavioral_flags": result.get("behavioral_flags", []),
                    "src_ip": event_data.get("source_ip", ""),
                }
                sent = await send_escalation(escalation_data)
                if sent:
                    logger.info("Alert escalated after triage", extra={
                        "extra_data": {
                            "alert_id": alert_id,
                            "severity": normalized.get("severity"),
                            "host": normalized.get("offending_host"),
                        }
                    })

        except Exception as e:
            logger.error("Triage result processing failed", extra={"extra_data": {"error": str(e)}})

    async def propagate_policy_feedback(
        self, src_ip: str, feedback: str
    ) -> None:
        """Propagate false_positive/true_positive feedback to contributing policies.

        Called when an analyst marks an alert as false positive or true positive.
        Updates baselines for all installed policies for the host.

        Args:
            src_ip: The source IP of the alert.
            feedback: 'false_positive' or 'true_positive'.
        """
        if not self._policies or not src_ip:
            return

        for policy in self._policies:
            try:
                await policy.update_baseline(src_ip, {}, feedback=feedback)
            except Exception:
                logger.warning(
                    "Policy feedback propagation failed",
                    extra={
                        "extra_data": {
                            "policy": policy.name,
                            "host": src_ip,
                            "feedback": feedback,
                        }
                    },
                    exc_info=True,
                )

        logger.info(
            "Policy feedback propagated",
            extra={
                "extra_data": {
                    "host": src_ip,
                    "feedback": feedback,
                    "policy_count": len(self._policies),
                }
            },
        )

    async def _wan_ip_discovery(self):
        """Discover own WAN IP every 2 hours to suppress self-traffic in detections."""
        import httpx
        endpoints = ["https://ifconfig.me", "https://api.ipify.org", "https://checkip.amazonaws.com"]
        while self._running:
            for url in endpoints:
                try:
                    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                        resp = await client.get(url, headers={"User-Agent": "curl/8.0"})
                        if resp.status_code == 200:
                            wan_ip = resp.text.strip()
                            if wan_ip and wan_ip not in self._own_wan_ips:
                                self._own_wan_ips.add(wan_ip)
                                logger.info("WAN IP discovered", extra={
                                    "extra_data": {"wan_ip": wan_ip, "source": url}
                                })
                            break
                except Exception:
                    continue
            try:
                await asyncio.sleep(7200)
            except asyncio.CancelledError:
                break

    async def _storage_pruner(self):
        """Periodically check DB size and prune oldest events if over 30GB."""
        import sqlite3
        max_bytes = 30 * 1024 * 1024 * 1024  # 30GB
        db_path = DB_PATH

        while self._running:
            try:
                await asyncio.sleep(300)
                if not os.path.exists(db_path):
                    continue
                size = os.path.getsize(db_path)
                self._db_size_bytes = size
                if size < max_bytes:
                    continue

                size_gb = round(size / (1024**3), 2)
                logger.warning("DB over 30GB cap, pruning oldest events", extra={
                    "extra_data": {"size_gb": size_gb}
                })

                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM syslog_events")
                total = cur.fetchone()[0]
                if total < 1000:
                    conn.close()
                    continue

                delete_count = max(total // 10, 1000)
                cur.execute(
                    "SELECT id FROM syslog_events ORDER BY id ASC LIMIT 1 OFFSET ?",
                    (delete_count,)
                )
                row = cur.fetchone()
                if not row:
                    conn.close()
                    continue
                cutoff_id = row[0]

                cur.execute("DELETE FROM threat_matches WHERE event_id < ?", (cutoff_id,))
                cur.execute("DELETE FROM behavioral_flags WHERE event_id < ?", (cutoff_id,))
                cur.execute("DELETE FROM opnsense_logs WHERE syslog_event_id < ?", (cutoff_id,))
                cur.execute("DELETE FROM pihole_queries WHERE syslog_event_id < ?", (cutoff_id,))
                cur.execute("DELETE FROM syslog_events WHERE id < ?", (cutoff_id,))
                conn.commit()

                cur.execute("VACUUM")
                conn.close()

                new_size = os.path.getsize(db_path)
                logger.info("Storage pruned", extra={
                    "extra_data": {
                        "deleted": delete_count,
                        "before_gb": size_gb,
                        "after_gb": round(new_size / (1024**3), 2),
                    }
                })

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Storage pruner error", extra={"extra_data": {"error": str(e)}})

    async def _policy_learning_loop(self):
        """Learn per-host policy baselines once per day (plus once shortly after
        startup) so the behavioral policies build real baselines instead of
        scoring every host in cold-start mode forever.

        Each policy's update_baseline() self-extracts current features when
        given an empty feature dict, EMA-updates its baseline, and persists to
        the policy_baselines table.
        """
        try:
            await asyncio.sleep(900)  # 15 min warmup — let ingestion settle
        except asyncio.CancelledError:
            return

        while self._running:
            try:
                since = datetime.now(timezone.utc) - timedelta(hours=24)
                async with async_session_factory() as session:
                    result = await session.execute(
                        select(OPNsenseLog.src_ip)
                        .where(
                            OPNsenseLog.timestamp >= since,
                            lan_filter(OPNsenseLog.src_ip),
                        )
                        .group_by(OPNsenseLog.src_ip)
                    )
                    hosts = [r[0] for r in result.all()]

                policies = self.policy_ensemble.policies if self.policy_ensemble else []
                for host_ip in hosts:
                    for policy in policies:
                        try:
                            await policy.update_baseline(host_ip, {})
                        except Exception:
                            logger.debug("Policy baseline update failed", extra={
                                "extra_data": {"policy": policy.name, "host": host_ip}
                            })
                if hosts and policies:
                    logger.info("Policy baselines learned", extra={
                        "extra_data": {"hosts": len(hosts), "policies": len(policies)}
                    })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Policy learning loop error", extra={
                    "extra_data": {"error": str(e)}
                })
            try:
                await asyncio.sleep(86400)  # daily — days_learned counts real days
            except asyncio.CancelledError:
                break

    async def _anomaly_detection_loop(self):
        """Run anomaly detection every 30 minutes with model caching."""
        cache_dir = self._model_cache_dir

        # Initial delay: let data accumulate before first run
        try:
            await asyncio.sleep(300)  # 5 min warmup
        except asyncio.CancelledError:
            return

        # ML detectors whose runs are recorded to model_runs for history/sparklines
        _tracked_detectors = {"isolation_forest", "autoencoder", "pagerank_graph",
                              "dns_profile", "lstm"}

        while self._running:
            try:
                for detector in self._detectors:
                    try:
                        data_hash = detector.data_hash()
                        model_loaded = False
                        _run_started = datetime.now(timezone.utc)

                        # Check for cached model
                        if data_hash:
                            cache_path = os.path.join(
                                cache_dir, f"{detector.name}_{data_hash}.joblib"
                            )
                            if os.path.exists(cache_path):
                                if detector.load_model(cache_path):
                                    model_loaded = True
                                    logger.debug("Loaded cached model for detector", extra={
                                        "extra_data": {
                                            "detector": detector.name,
                                            "hash": data_hash,
                                        }
                                    })

                        # Run detection (uses cached model if loaded, otherwise trains)
                        anomalies = await detector.detect()

                        # Save model after training (if applicable)
                        if data_hash and not model_loaded:
                            cache_path = os.path.join(
                                cache_dir, f"{detector.name}_{data_hash}.joblib"
                            )
                            detector.save_model(cache_path)

                            # Clean up old caches for this detector
                            pattern = os.path.join(
                                cache_dir, f"{detector.name}_*.joblib"
                            )
                            for old_file in glob.glob(pattern):
                                if old_file != cache_path:
                                    try:
                                        os.unlink(old_file)
                                        logger.debug("Removed old model cache", extra={
                                            "extra_data": {"file": old_file}
                                        })
                                    except OSError as e:
                                        logger.warning("Failed to remove old cache", extra={
                                            "extra_data": {"file": old_file, "error": str(e)}
                                        })

                        if anomalies:
                            # Check shadow mode: save to shadow_results table instead of creating alerts
                            if self._shadow_mode.get(detector.name, False):
                                await self._save_shadow_results(detector.name, anomalies)
                            else:
                                await self._save_anomaly_flags(anomalies)

                        if detector.name in _tracked_detectors:
                            await self._record_model_run(
                                detector, data_hash, _run_started, anomalies or []
                            )
                    except Exception as e:
                        logger.error("Detector error", extra={
                            "extra_data": {"detector": detector.name, "error": str(e)}
                        })

                # Run ensemble after individual detectors
                if self.ensemble:
                    try:
                        composite = await self.ensemble.run_all()
                        self._ensemble_host_scores = {
                            h["ip"]: h["composite_score"] for h in composite
                        }
                    except Exception as e:
                        logger.error("Ensemble run error", extra={
                            "extra_data": {"error": str(e)}
                        })

                # Feature 18: Device role baseline deviation check
                if self._device_roles:
                    try:
                        role_deviations = await self._check_role_deviations()
                        if role_deviations:
                            await self._save_role_deviation_flags(role_deviations)
                    except Exception as e:
                        logger.error("Role deviation check error", extra={
                            "extra_data": {"error": str(e)}
                        })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Anomaly detection loop error", extra={
                    "extra_data": {"error": str(e)}
                })
            try:
                await asyncio.sleep(1800)  # 30 minutes
            except asyncio.CancelledError:
                break

    async def _record_model_run(self, detector, data_hash: str,
                                started: datetime, anomalies: list):
        """Persist a ModelRun row so /analytics/model-history reflects real runs."""
        try:
            now = datetime.now(timezone.utc)
            scores = []
            for a in anomalies:
                s = a.score if isinstance(a, AnomalyResult) else a.get("score")
                if isinstance(s, (int, float)):
                    scores.append(float(s))
            stats = None
            if scores:
                stats = json.dumps({
                    "min": round(min(scores), 4),
                    "max": round(max(scores), 4),
                    "mean": round(sum(scores) / len(scores), 4),
                })

            async def _do_write():
                async with async_session_factory() as session:
                    session.add(ModelRun(
                        detector_name=detector.name,
                        data_hash=data_hash or None,
                        trained_at=now,
                        training_time_ms=int((now - started).total_seconds() * 1000),
                        anomaly_count=len(anomalies),
                        score_stats_json=stats,
                    ))
                    # Keep 30 days of history
                    from sqlalchemy import delete as _sa_delete
                    await session.execute(
                        _sa_delete(ModelRun).where(
                            ModelRun.trained_at < now - timedelta(days=30)
                        )
                    )
                    await session.commit()
            await submit_write(_do_write)
        except Exception as e:
            logger.debug("Failed to record model run", extra={
                "extra_data": {"detector": detector.name, "error": str(e)}
            })

    async def _save_anomaly_flags(self, anomalies: list):
        """Save anomaly detection results as behavioral flags."""
        try:
            # Filter out suppressed (ip, detector_name) pairs
            suppressions = getattr(self, '_anomaly_suppressions', set())
            filtered = []
            for anomaly in anomalies:
                ip = anomaly.ip if isinstance(anomaly, AnomalyResult) else anomaly.get("ip", "")
                detector_name = anomaly.detector_name if isinstance(anomaly, AnomalyResult) else anomaly.get("detector_name", "")
                if (ip, detector_name) in suppressions:
                    logger.debug("Suppressed anomaly", extra={
                        "extra_data": {"ip": ip, "detector": detector_name}
                    })
                    continue
                filtered.append(anomaly)

            if not filtered:
                return

            async def _do_write():
                async with async_session_factory() as session:
                    for anomaly in filtered:
                        if isinstance(anomaly, AnomalyResult):
                            details = {
                                "ip": anomaly.ip,
                                "anomaly_score": anomaly.score,
                                "detector_name": anomaly.detector_name,
                                **anomaly.details,
                            }
                        else:
                            # Backward compat: old-style dict
                            details = {
                                "ip": anomaly["ip"],
                                "anomaly_score": anomaly["anomaly_score"],
                                "unique_destinations": anomaly.get("unique_destinations"),
                                "unique_ports": anomaly.get("unique_ports"),
                                "total_connections": anomaly.get("total_connections"),
                                "blocked_ratio": anomaly.get("blocked_ratio"),
                                "unique_protocols": anomaly.get("unique_protocols"),
                            }
                        bf = BehavioralFlag(
                            event_id=None,
                            flag_type="anomaly",
                            details=details,
                            timestamp=datetime.now(timezone.utc),
                        )
                        session.add(bf)
                    await session.commit()
                    logger.info("Saved anomaly behavioral flags", extra={
                        "extra_data": {"count": len(filtered)}
                    })
            await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to save anomaly flags", extra={
                "extra_data": {"error": str(e)}
            })

    async def _save_shadow_results(self, detector_name: str, anomalies: list):
        """Save anomaly result to shadow_results table (shadow mode — no alerts created)."""
        try:
            async def _do_write():
                async with async_session_factory() as session:
                    for anomaly in anomalies:
                        if isinstance(anomaly, AnomalyResult):
                            score = anomaly.score
                            ip = anomaly.ip
                            details = {
                                "ip": anomaly.ip,
                                "anomaly_score": anomaly.score,
                                "detector_name": anomaly.detector_name,
                                **anomaly.details,
                            }
                        else:
                            score = anomaly.get("anomaly_score", 0)
                            ip = anomaly.get("ip", "")
                            details = dict(anomaly)
                        shadow = ShadowResult(
                            detector_name=detector_name,
                            ip=ip,
                            score=score,
                            details=json.dumps(details),
                            created_at=datetime.now(timezone.utc),
                        )
                        session.add(shadow)
                    await session.commit()
                    logger.info("Saved shadow results", extra={
                        "extra_data": {"detector": detector_name, "count": len(anomalies)}
                    })
            await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to save shadow results", extra={
                "extra_data": {"detector": detector_name, "error": str(e)}
            })

    def set_shadow_mode(self, detector_name: str, enabled: bool):
        """Enable or disable shadow mode for a specific detector."""
        self._shadow_mode[detector_name] = enabled
        logger.info("Shadow mode updated", extra={
            "extra_data": {"detector": detector_name, "shadow_mode": enabled}
        })

    async def get_shadow_results(self, limit: int = 100) -> List[dict]:
        """Retrieve recent shadow results from the database."""
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(ShadowResult)
                    .order_by(ShadowResult.created_at.desc())
                    .limit(limit)
                )
                rows = result.scalars().all()
                return [
                    {
                        "id": r.id,
                        "detector_name": r.detector_name,
                        "ip": r.ip,
                        "score": r.score,
                        "details": json.loads(r.details) if r.details else {},
                        "created_at": r.created_at.isoformat() if r.created_at else None,
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.error("Failed to get shadow results", extra={"extra_data": {"error": str(e)}})
            return []

    # ------------------------------------------------------------------
    # Feature 17: Building Block / Alert Correlation Engine
    # ------------------------------------------------------------------

    async def _save_building_block(self, src_ip: str, flag_type: str, details: dict):
        """Store a single-behavior building block for later correlation."""
        now = datetime.now(timezone.utc)
        block = {
            "src_ip": src_ip,
            "flag_type": flag_type,
            "details": details,
            "created_at": now.isoformat(),
        }

        # In-memory store
        if src_ip not in self._building_blocks:
            self._building_blocks[src_ip] = []
        self._building_blocks[src_ip].append(block)

        # Persist to database
        try:
            async def _do_write():
                async with async_session_factory() as session:
                    bb = BuildingBlock(
                        src_ip=src_ip,
                        flag_type=flag_type,
                        details=json.dumps(details),
                        created_at=now,
                    )
                    session.add(bb)
                    await session.commit()
            await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to persist building block", extra={
                "extra_data": {"src_ip": src_ip, "flag_type": flag_type, "error": str(e)}
            })


    async def _is_dst_reputable(self, ip: str) -> bool:
        """Reputable-destination check with a small cache (MMDB org + rDNS/Tranco)."""
        if not ip or _is_private(ip):
            return False
        cached = self._bb_reputable_cache.get(ip)
        if cached is not None:
            return cached
        result = False
        try:
            info = await enrich_ip(ip)
            org = (info.get("org") or "").lower()
            if any(rep in org for rep in reputable_orgs()):
                result = True
            elif is_destination_reputable(info, self.feed_manager):
                result = True
        except Exception:
            pass
        if len(self._bb_reputable_cache) > 500:
            self._bb_reputable_cache.clear()
        self._bb_reputable_cache[ip] = result
        return result

    async def _check_building_block_correlation(self, src_ip: str) -> Optional[dict]:
        """Check if a source IP has 2+ DISTINCT building block types within the last hour.

        Correlation requires diversity — 10 beaconing events to different Google
        IPs is repetition, not correlation.  We need at least 2 distinct flag types
        (e.g., single_beaconing + single_dns_burst) to indicate converging signals.

        Returns a correlated alert dict if correlation found, else None.
        """
        blocks = self._building_blocks.get(src_ip, [])
        if len(blocks) < 2:
            return None

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=1)

        recent_blocks = []
        for b in blocks:
            try:
                created = datetime.fromisoformat(b["created_at"])
                if created > cutoff:
                    recent_blocks.append(b)
            except (ValueError, KeyError):
                continue

        if len(recent_blocks) < 2:
            return None

        # Drop blocks whose destination is a known reputable org (Apple NTP,
        # Akamai CDN, etc.) — beaconing to those is normal client behavior
        # and shouldn't count toward correlation.
        kept = []
        for b in recent_blocks:
            details = b.get("details") if isinstance(b.get("details"), dict) else {}
            d = details.get("dst_ip")
            if d and await self._is_dst_reputable(d):
                continue
            kept.append(b)
        recent_blocks = kept

        if len(recent_blocks) < 2:
            return None

        distinct_types = set(b.get("flag_type", "") for b in recent_blocks)
        if len(distinct_types) < 2:
            return None

        # Aggregate details from all blocks, keeping per-block detail dicts
        all_details = {}
        all_flag_types = []
        block_flags = []
        dst_ips = []
        for b in recent_blocks:
            ftype = b.get("flag_type", "")
            all_flag_types.append(ftype)
            details = b.get("details") if isinstance(b.get("details"), dict) else {}
            block_flags.append({"flag_type": ftype, "details": details})
            all_details.update(details)
            d = details.get("dst_ip") or details.get("destination")
            if d:
                dst_ips.append(d)

        # Most frequent destination across blocks, if any
        dst_ip = max(set(dst_ips), key=dst_ips.count) if dst_ips else ""

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "block_count": len(recent_blocks),
            "flag_types": all_flag_types,
            "block_flags": block_flags,
            "aggregated_details": all_details,
        }

    async def _create_correlated_alert(self, correlation: dict):
        """Create an alert from correlated building blocks."""
        try:
            # CTI tuning 2026-07-16 rec #4: correlated "beaconing" toward shared
            # cloud/CDN/app backends is periodic app telemetry, not C2. Don't alert.
            if _dst_prefix(correlation.get("dst_ip", ""), CLOUD_CDN_PREFIXES):
                return None
            async def _do_write():
                async with async_session_factory() as session:
                    # Determine investigation playbook from first flag type
                    _guide = ""
                    _flag_types = correlation.get("flag_types", [])
                    if _flag_types:
                        _guide = get_playbook(_flag_types[0])

                    alert = Alert(
                        src_ip=correlation["src_ip"],
                        dst_ip=correlation.get("dst_ip", ""),
                        event_ids=None,
                        threat_matches=None,
                        behavioral_flags=correlation.get("block_flags") or [
                            {"flag_type": ft, "details": ""}
                            for ft in _flag_types
                        ],
                        llm_analysis={
                            "source": "building_block_correlation",
                            "block_count": correlation["block_count"],
                            "flag_types": _flag_types,
                            "aggregated_details": correlation.get("aggregated_details", {}),
                        },
                        escalate=False,
                        severity="medium",
                        classification="correlated_threat",
                        confidence=self._sigmoid_confidence(
                            correlation["block_count"], midpoint=2.0, steepness=1.0
                        ),
                        firewall_action=None,
                        investigation_guide=_guide,
                        created_at=datetime.now(timezone.utc),
                    )
                    session.add(alert)
                    await session.commit()
                    await session.refresh(alert)
                    return alert.id

            alert_id = await submit_write(_do_write)

            if alert_id and self.websocket:
                await self.websocket.broadcast("alert", {
                    "alert_id": alert_id,
                    "severity": "medium",
                    "classification": "correlated_threat",
                    "src_ip": correlation["src_ip"],
                    "dst_ip": correlation.get("dst_ip", ""),
                    "summary": f"Correlated threat: {', '.join(correlation.get('flag_types', []))} ({correlation.get('block_count')} blocks)",
                    "enrichment": {},
                    "escalated": False,
                    "source": "building_block_correlation",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

            return alert_id
        except Exception as e:
            logger.error("Failed to create correlated alert", extra={
                "extra_data": {"src_ip": correlation.get("src_ip"), "error": str(e)}
            })
            return None

    async def _building_block_correlator(self):
        """Periodic task: prune old building blocks and correlate remaining ones every 5 minutes."""
        _corr_dedup: Dict[str, datetime] = {}
        while self._running:
            try:
                await asyncio.sleep(300)  # 5 minutes

                # Prune blocks older than 1 hour
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(hours=1)
                for src_ip in list(self._building_blocks.keys()):
                    self._building_blocks[src_ip] = [
                        b for b in self._building_blocks[src_ip]
                        if _parse_created_at(b.get("created_at"), now) > cutoff
                    ]
                    if not self._building_blocks[src_ip]:
                        del self._building_blocks[src_ip]

                # Prune expired dedup entries
                _corr_dedup = {k: v for k, v in _corr_dedup.items() if v > now}

                # Check all src_ips with 2+ blocks
                for src_ip in list(self._building_blocks.keys()):
                    # Dedup: skip if we already alerted on this IP in the last 30 min
                    if src_ip in _corr_dedup and _corr_dedup[src_ip] > now:
                        continue
                    correlation = await self._check_building_block_correlation(src_ip)
                    if correlation:
                        await self._create_correlated_alert(correlation)
                        _corr_dedup[src_ip] = now + timedelta(minutes=30)
                        # Clear blocks for this IP after creating correlated alert
                        self._building_blocks[src_ip] = []

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Building block correlator error", extra={
                    "extra_data": {"error": str(e)}
                })

    # ------------------------------------------------------------------
    # Feature 18: Device Role Baseline Deviation
    # ------------------------------------------------------------------

    async def _compute_role_baselines(self) -> Dict[str, Dict[str, float]]:
        """Compute per-role baseline stats: avg_connections, avg_destinations, avg_blocked_ratio.

        Returns dict: role -> {avg_X, std_X, ...}
        """
        if not self._device_roles:
            return {}

        # Use in-memory baseline for connection stats per host
        role_groups: Dict[str, List[dict]] = {}
        for ip, role in self._device_roles.items():
            stats = {
                "connections": 0,
                "destinations": 0,
                "blocked_ratio": 0.0,
            }

            # Count connections from in-memory baseline
            if self.baseline and ip in self.baseline.host_connections:
                conns = self.baseline.host_connections[ip]
                if conns:
                    stats["connections"] = sum(conns.values())
                    stats["destinations"] = len(conns)

            # Estimate blocked ratio from opnsense_logs
            try:
                async with async_session_factory() as session:
                    from sqlalchemy import func
                    result = await session.execute(
                        select(func.count())
                        .select_from(OPNsenseLog)
                        .where(
                            OPNsenseLog.src_ip == ip,
                            OPNsenseLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24),
                        )
                    )
                    total = result.scalar() or 0
                    if total > 0:
                        result = await session.execute(
                            select(func.count())
                            .select_from(OPNsenseLog)
                            .where(
                                OPNsenseLog.src_ip == ip,
                                OPNsenseLog.action == "block",
                                OPNsenseLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24),
                            )
                        )
                        blocked = result.scalar() or 0
                        stats["blocked_ratio"] = blocked / total
            except Exception:
                pass

            if role not in role_groups:
                role_groups[role] = []
            role_groups[role].append(stats)

        # Compute per-role mean and std
        import statistics
        role_baselines = {}
        for role, stats_list in role_groups.items():
            if len(stats_list) < 2:
                continue
            role_baseline = {}
            for metric in ("connections", "destinations", "blocked_ratio"):
                values = [s[metric] for s in stats_list]
                mean = statistics.mean(values)
                try:
                    std = statistics.stdev(values)
                except statistics.StatisticsError:
                    std = 0.0
                role_baseline[f"avg_{metric}"] = mean
                role_baseline[f"std_{metric}"] = std
            role_baseline["host_count"] = len(stats_list)
            role_baselines[role] = role_baseline

        return role_baselines

    async def _check_role_deviations(self) -> List[dict]:
        """Check all hosts for role deviations (>2 std from role mean)."""
        if not self._device_roles:
            return []

        role_baselines = await self._compute_role_baselines()
        if not role_baselines:
            return []

        deviations = []
        import statistics

        for ip, role in self._device_roles.items():
            baseline = role_baselines.get(role)
            if not baseline:
                continue

            # Compute host stats (same as _compute_role_baselines but for single IP)
            stats = {"connections": 0, "destinations": 0, "blocked_ratio": 0.0}
            if self.baseline and ip in self.baseline.host_connections:
                conns = self.baseline.host_connections[ip]
                if conns:
                    stats["connections"] = sum(conns.values())
                    stats["destinations"] = len(conns)

            try:
                async with async_session_factory() as session:
                    from sqlalchemy import func
                    result = await session.execute(
                        select(func.count())
                        .select_from(OPNsenseLog)
                        .where(
                            OPNsenseLog.src_ip == ip,
                            OPNsenseLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24),
                        )
                    )
                    total = result.scalar() or 0
                    if total > 0:
                        result = await session.execute(
                            select(func.count())
                            .select_from(OPNsenseLog)
                            .where(
                                OPNsenseLog.src_ip == ip,
                                OPNsenseLog.action == "block",
                                OPNsenseLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24),
                            )
                        )
                        blocked = result.scalar() or 0
                        stats["blocked_ratio"] = blocked / total
            except Exception:
                pass

            deviated_metrics = []
            for metric in ("connections", "destinations", "blocked_ratio"):
                avg_key = f"avg_{metric}"
                std_key = f"std_{metric}"
                mean = baseline.get(avg_key, 0)
                std = baseline.get(std_key, 0)
                if std <= 0:
                    continue
                z_score = (stats[metric] - mean) / std
                if abs(z_score) > 2:
                    deviated_metrics.append({
                        "metric": metric,
                        "value": stats[metric],
                        "role_mean": mean,
                        "role_std": std,
                        "z_score": z_score,
                    })

            if deviated_metrics:
                deviations.append({
                    "ip": ip,
                    "role": role,
                    "deviated_metrics": deviated_metrics,
                })

        return deviations

    async def _save_role_deviation_flags(self, deviations: list):
        """Save role deviation results as behavioral flags."""
        try:
            async def _do_write():
                async with async_session_factory() as session:
                    now = datetime.now(timezone.utc)
                    for dev in deviations:
                        bf = BehavioralFlag(
                            event_id=None,
                            flag_type="role_deviation",
                            details={
                                "ip": dev["ip"],
                                "role": dev["role"],
                                "deviated_metrics": dev["deviated_metrics"],
                            },
                            timestamp=now,
                        )
                        session.add(bf)
                    await session.commit()
                    logger.info("Saved role deviation flags", extra={
                        "extra_data": {"count": len(deviations)}
                    })
            await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to save role deviation flags", extra={
                "extra_data": {"error": str(e)}
            })

    # ------------------------------------------------------------------
    # Feature 25: Blacklist Hot-Reload via File Watching
    # ------------------------------------------------------------------

    async def _feed_file_watcher(self):
        """Poll feed cache directory for file changes and hot-reload feeds."""
        cache_dir = getattr(self.feed_manager, 'cache_dir', '/tmp/feeds')
        last_mtimes = {}
        while self._running:
            try:
                await asyncio.sleep(30)
                if not os.path.isdir(cache_dir):
                    continue
                reloaded = False
                for root, dirs, files in os.walk(cache_dir):
                    if reloaded:
                        break
                    for f in files:
                        fpath = os.path.join(root, f)
                        try:
                            mtime = os.path.getmtime(fpath)
                        except OSError:
                            continue
                        if fpath not in last_mtimes:
                            last_mtimes[fpath] = mtime
                        elif mtime > last_mtimes[fpath]:
                            last_mtimes[fpath] = mtime
                            logger.info("Feed file changed, reloading", extra={
                                "extra_data": {"file": fpath}
                            })
                            await self.feed_manager.load_all_feeds()
                            reloaded = True
                            break
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Feed watcher error", extra={
                    "extra_data": {"error": str(e)}
                })

    async def _syslog_watchdog(self):
        """Restart syslog listener if OPNsense logs go stale for 5+ minutes."""
        import sqlite3
        db_path = DB_PATH
        stale_seconds = 300

        while self._running:
            try:
                await asyncio.sleep(60)
                if not self.syslog_listener or not self.syslog_listener.is_running:
                    continue
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute(
                    "SELECT MAX(timestamp) FROM opnsense_logs"
                )
                row = cur.fetchone()
                conn.close()
                if not row or not row[0]:
                    continue
                last_ts = datetime.fromisoformat(row[0])
                if last_ts.tzinfo is None:
                    last_ts = last_ts.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - last_ts).total_seconds()
                if age > stale_seconds:
                    queue = self.syslog_listener.queue_depth
                    logger.warning("Syslog watchdog: OPNsense stale, restarting listener", extra={
                        "extra_data": {"last_log_age_s": int(age), "queue_depth": queue}
                    })
                    await self.syslog_listener.restart()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Syslog watchdog error", extra={
                    "extra_data": {"error": str(e)}
                })

    async def health_check(self) -> dict:
        """Return comprehensive health status."""
        feed_status = self.feed_manager.get_feed_status() if self.feed_manager else []
        feeds_loaded = sum(1 for f in feed_status if f["status"] == "active")
        feeds_failed = sum(1 for f in feed_status if f["status"] == "failed")

        return {
            "status": "healthy" if self._running else "stopped",
            "syslog_listener": {
                "running": self.syslog_listener.is_running if self.syslog_listener else False,
                "port": self.config.listeners.syslog_port,
                "queue_depth": self.syslog_listener.queue_depth if self.syslog_listener else 0,
            },
            "threat_intel": {
                "feeds_loaded": feeds_loaded,
                "feeds_failed": feeds_failed,
                "total_iocs": self.feed_manager.total_ioc_count if self.feed_manager else 0,
                "feeds": feed_status[:20],
            },
            "llm": await self.llm_triage.health_check() if self.llm_triage else {"initialized": False},
            "websocket": {
                "connections": self.websocket.connection_count if self.websocket else 0,
                "queue_depth": self.websocket.queue_depth if self.websocket else 0,
            },
            "pihole_pollers": {
                "active": len(getattr(self, '_pihole_pollers', [])),
            },
        }

    @property
    def is_running(self) -> bool:
        return self._running


# Singleton
_engine: Optional[UEBAEngine] = None


def get_engine() -> UEBAEngine:
    global _engine
    if _engine is None:
        _engine = UEBAEngine()
    return _engine


async def init_engine() -> UEBAEngine:
    global _engine
    _engine = UEBAEngine()
    await _engine.startup()
    return _engine
