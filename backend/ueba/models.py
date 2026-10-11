"""SQLAlchemy ORM models for UEBA platform."""
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text,
    ForeignKey, Index, JSON,
)
from sqlalchemy.orm import relationship

from ueba.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SyslogEvent(Base):
    __tablename__ = "syslog_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow)
    source_ip = Column(String(45), nullable=False)
    source_device = Column(String(255), nullable=True)
    raw_message = Column(Text, nullable=False)
    parsed_fields = Column(JSON, nullable=True)
    event_type = Column(String(50), nullable=False)  # opnsense, pihole, generic
    received_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_syslog_events_timestamp", "timestamp"),
        Index("ix_syslog_events_source_ip", "source_ip"),
        Index("ix_syslog_events_event_type", "event_type"),
    )


class OPNsenseLog(Base):
    __tablename__ = "opnsense_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    syslog_event_id = Column(Integer, ForeignKey("syslog_events.id", ondelete="CASCADE"), nullable=True)
    timestamp = Column(DateTime, nullable=False)
    interface = Column(String(50), nullable=True)
    src_ip = Column(String(45), nullable=False)  # supports IPv4 and IPv6
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    action = Column(String(10), nullable=True)  # pass, block
    direction = Column(String(10), nullable=True)  # in, out
    rule_id = Column(Integer, nullable=True)

    syslog_event = relationship("SyslogEvent", backref="opnsense_logs")

    __table_args__ = (
        Index("ix_opnsense_logs_timestamp", "timestamp"),
        Index("ix_opnsense_logs_src_ip", "src_ip"),
        Index("ix_opnsense_logs_dst_ip", "dst_ip"),
    )


class PiHoleQuery(Base):
    __tablename__ = "pihole_queries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    syslog_event_id = Column(Integer, ForeignKey("syslog_events.id", ondelete="CASCADE"), nullable=True)
    timestamp = Column(DateTime, nullable=False)
    client_ip = Column(String(45), nullable=False)
    queried_domain = Column(String(512), nullable=False)
    query_type = Column(String(10), nullable=True)  # A, AAAA, PTR, etc.
    blocked = Column(Boolean, default=False)
    reply_type = Column(String(50), nullable=True)

    syslog_event = relationship("SyslogEvent", backref="pihole_queries")

    __table_args__ = (
        Index("ix_pihole_queries_timestamp", "timestamp"),
        Index("ix_pihole_queries_client_ip", "client_ip"),
        Index("ix_pihole_queries_domain", "queried_domain"),
        Index("ix_pihole_queries_blocked", "blocked"),
    )


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    category = Column(String(100), nullable=False)  # malware, ransomware, botnet, phishing, apt, dns, reputation
    url = Column(String(1024), nullable=False)
    refresh_interval = Column(Integer, default=21600)
    last_refresh = Column(DateTime, nullable=True)
    status = Column(String(20), default="pending")  # active, failed, stale, pending
    ioc_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_threat_feeds_status", "status"),
    )


class ThreatMatch(Base):
    __tablename__ = "threat_matches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("syslog_events.id", ondelete="CASCADE"), nullable=False)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="SET NULL"), nullable=True)
    ioc_value = Column(String(512), nullable=False)
    threat_category = Column(String(100), nullable=False)
    severity_hint = Column(String(20), nullable=False)  # critical, high, medium, low, info
    first_seen = Column(DateTime, nullable=False, default=utcnow)

    event = relationship("SyslogEvent", backref="threat_matches")
    feed = relationship("ThreatFeed", backref="matches")

    __table_args__ = (
        Index("ix_threat_matches_event_id", "event_id"),
        Index("ix_threat_matches_ioc", "ioc_value"),
    )


class BehavioralFlag(Base):
    __tablename__ = "behavioral_flags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("syslog_events.id", ondelete="CASCADE"), nullable=True)
    flag_type = Column(String(50), nullable=False)  # volume, geo, dga, blocked_repeat, port_scan, beaconing
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow)

    event = relationship("SyslogEvent", backref="behavioral_flags")

    __table_args__ = (
        Index("ix_behavioral_flags_type", "flag_type"),
        Index("ix_behavioral_flags_timestamp", "timestamp"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=True)
    event_ids = Column(JSON, nullable=True)  # list of event IDs
    threat_matches = Column(JSON, nullable=True)  # serialized threat match data
    behavioral_flags = Column(JSON, nullable=True)  # serialized behavioral flag data
    llm_analysis = Column(JSON, nullable=True)  # LLM triage response JSON
    escalate = Column(Boolean, default=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    classification = Column(String(255), nullable=True)
    confidence = Column(Float, nullable=True)
    status = Column(String(20), default="open")
    firewall_action = Column(String(10), nullable=True)  # pass, block
    dst_domain = Column(String(512), nullable=True)  # DNS-correlated domain name
    created_at = Column(DateTime, nullable=False, default=utcnow)
    attack_technique = Column(String(20), nullable=True)  # e.g., T1071
    attack_tactic = Column(String(50), nullable=True)       # e.g., Command and Control
    investigation_guide = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_alerts_src_ip", "src_ip"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_created_at", "created_at"),
        Index("ix_alerts_escalate", "escalate"),
        Index("ix_alerts_firewall_action", "firewall_action"),
    )


class LLMCache(Base):
    __tablename__ = "llm_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_llm_cache_lookup", "src_ip", "dst_ip"),
        Index("ix_llm_cache_expires", "expires_at"),
    )


class NetworkBaseline(Base):
    __tablename__ = "network_baseline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asn = Column(String(50), nullable=True)
    country = Column(String(10), nullable=True)
    ip_address = Column(String(45), nullable=True)
    first_seen = Column(DateTime, nullable=False, default=utcnow)
    last_seen = Column(DateTime, nullable=False, default=utcnow)
    connection_count = Column(Integer, default=1)

    __table_args__ = (
        Index("ix_network_baseline_asn", "asn"),
        Index("ix_network_baseline_country", "country"),
        Index("ix_network_baseline_ip", "ip_address"),
    )


class CustomRule(Base):
    __tablename__ = "custom_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    rule_json = Column(Text, nullable=False)  # stores JSON string
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    enabled = Column(Boolean, default=True)
    maturity_status = Column(String(20), default="active")  # experimental, active, stable, deprecated
    deprecation_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_custom_rules_enabled", "enabled"),
    )


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")  # admin, analyst, viewer
    created_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_users_username", "username"),
    )


class AnomalySuppression(Base):
    __tablename__ = "anomaly_suppressions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    detector_name = Column(String(100), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    created_by = Column(String(100), nullable=True)

    __table_args__ = (
        Index("ix_anomaly_suppressions_ip_detector", "ip", "detector_name", unique=True),
    )


class FalsePositivePattern(Base):
    __tablename__ = "false_positive_patterns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detector_name = Column(String(100), nullable=False)
    src_pattern = Column(String(255), nullable=True)
    dst_pattern = Column(String(255), nullable=True)
    domain_pattern = Column(String(512), nullable=True)
    classification = Column(String(255), nullable=False)
    reason = Column(Text, nullable=True)
    times_matched = Column(Integer, default=0)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    created_by = Column(String(100), nullable=True)

    __table_args__ = (
        Index("ix_false_positive_patterns_detector", "detector_name"),
    )


class ShadowResult(Base):
    __tablename__ = "shadow_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detector_name = Column(String(100), nullable=False)
    ip = Column(String(45), nullable=False)
    score = Column(Float, nullable=True)
    details = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_shadow_results_detector", "detector_name"),
    )


class BuildingBlock(Base):
    __tablename__ = "building_blocks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False)
    flag_type = Column(String(50), nullable=False)  # single_beaconing, single_dest_fanout, single_dns_burst
    details = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_building_blocks_src_ip", "src_ip"),
        Index("ix_building_blocks_created_at", "created_at"),
    )


class DeviceRole(Base):
    __tablename__ = "device_roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    role = Column(String(50), nullable=False)  # server, workstation, iot, infrastructure
    label = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_device_roles_ip", "ip", unique=True),
        Index("ix_device_roles_role", "role"),
    )


class DGATrainingLabel(Base):
    __tablename__ = "dga_training_labels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(512), nullable=False, unique=True)
    label = Column(Integer, nullable=False)  # 0 = legitimate, 1 = DGA
    source = Column(String(50), nullable=False)  # analyst, tranco, ioc
    created_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_dga_training_labels_domain", "domain", unique=True),
    )


class ModelRun(Base):
    __tablename__ = "model_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detector_name = Column(String(100), nullable=False)
    data_hash = Column(String(64), nullable=True)
    trained_at = Column(DateTime, nullable=False, default=utcnow)
    training_time_ms = Column(Integer, nullable=True)
    sample_count = Column(Integer, nullable=True)
    anomaly_count = Column(Integer, nullable=True)
    score_stats_json = Column(Text, nullable=True)  # JSON: {min, max, mean, std}

    __table_args__ = (
        Index("ix_model_runs_detector", "detector_name"),
        Index("ix_model_runs_trained_at", "trained_at"),
    )


class DeviceProfile(Base):
    __tablename__ = "device_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    date = Column(String(10), nullable=False)
    feature_vector = Column(JSON, nullable=False)
    event_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_device_profiles_ip_date", "ip", "date", unique=True),
    )


class PolicyBaseline(Base):
    __tablename__ = "policy_baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_name = Column(String(100), nullable=False)
    host_ip = Column(String(45), nullable=False)
    baseline_data = Column(JSON, nullable=False)
    sensitivity = Column(Float, default=1.0, nullable=False)
    days_learned = Column(Integer, default=0, nullable=False)
    updated_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_policy_baselines_policy_host", "policy_name", "host_ip", unique=True),
    )


class DNSHostProfile(Base):
    __tablename__ = "dns_host_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    date = Column(String(10), nullable=False)
    profile_data = Column(JSON, nullable=False)
    total_queries = Column(Integer, default=0)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_dns_host_profiles_ip_date", "ip", "date", unique=True),
    )


class BaselineSnapshot(Base):
    __tablename__ = "baseline_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), nullable=False, index=True)
    destinations = Column(JSON, nullable=False)
    asns = Column(JSON, nullable=True)
    countries = Column(JSON, nullable=True)
    event_count = Column(Integer, default=0)
    updated_at = Column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_baseline_host", "host_ip", unique=True),
    )
