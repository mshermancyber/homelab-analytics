"""Configuration management via env vars and config.yaml.

Precedence, highest first:

1. Environment variables (including anything loaded from ``.env``)
2. ``config.yaml`` (plus an optional ``env_<UEBA_ENV>`` override block)
3. The dataclass defaults below

Secrets never live in ``config.yaml`` — they come from the environment or
``.env``; see :mod:`ueba.secrets`.
"""
import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

from ueba.dotenv import hydrate_environment

# Make .env visible to every os.environ lookup below.  Real environment
# variables (systemd, Docker, your shell) keep precedence.
hydrate_environment()

# Repository layout: <backend>/ueba/config.py
BACKEND_ROOT = Path(__file__).resolve().parent.parent
CONFIG_YAML_PATH = BACKEND_ROOT / "config.yaml"
DATA_DIR = Path(os.environ.get("UEBA_DATA_DIR", str(BACKEND_ROOT / "data")))


def _env_list(name: str, default: List[str]) -> List[str]:
    """Read a comma-separated env var into a list, falling back to ``default``."""
    raw = os.environ.get(name)
    if raw is None:
        return list(default)
    return [part.strip() for part in raw.split(",") if part.strip()]


@dataclass
class FeedConfig:
    refresh_interval_seconds: int = 21600
    urls: dict = field(default_factory=dict)
    # Optional local SQLite mirror of CVE/EPSS/Tranco data (see docs/FEEDS.md).
    # Empty means "skip the local-database feeds".
    local_db_path: str = ""


@dataclass
class NetworkConfig:
    """Site-specific topology.  Override every value for your own network."""

    name: str = "LAN"
    # Networks treated as "internal".  Add every monitored subnet.
    lan_cidrs: List[str] = field(default_factory=lambda: ["192.168.1.0/24"])
    # Router / firewall addresses — all traffic transits these.
    gateway_ips: List[str] = field(default_factory=list)
    # Local DNS resolvers (e.g. Pi-hole instances).
    dns_servers: List[str] = field(default_factory=list)
    # Known own public addresses.  Usually left empty: the engine discovers the
    # current WAN address at runtime and adds it here.
    static_wan_ips: List[str] = field(default_factory=list)
    # Hosts that are noisy by design (feed scrapers, CI runners, crawlers).
    # Behavioural-only alerts from these are suppressed; IOC matches still fire.
    infra_hosts: List[str] = field(default_factory=list)
    # Hosts exempt from DNS burst detectors.
    dns_burst_whitelist: List[str] = field(default_factory=list)
    # Own dynamic-DNS / external hostnames, excluded from DynDNS detectors.
    own_hostnames: List[str] = field(default_factory=list)
    # SearXNG instances for the LLM web-search tool.
    searxng_urls: List[str] = field(default_factory=list)
    # Org-name fragments treated as reputable when suppressing weak signals.
    reputable_orgs: List[str] = field(default_factory=lambda: [
        "cloudflare", "akamai", "fastly", "amazon", "google", "microsoft",
        "apple", "meta", "facebook", "netflix", "github", "digitalocean",
        "oracle",
    ])
    # Optional {ip: "what this host is"} notes handed to the LLM triage prompt.
    host_notes: dict = field(default_factory=dict)


@dataclass
class AnalyticsThresholds:
    outbound_volume_bytes_per_minute: int = 104857600
    high_entropy_shannon_threshold: float = 4.0
    blocked_query_repeat_threshold: int = 5
    port_scan_distinct_ports: int = 20
    beaconing_interval_tolerance_seconds: int = 3
    beaconing_min_repetitions: int = 20


@dataclass
class AnalyticsConfig:
    thresholds: AnalyticsThresholds = field(default_factory=AnalyticsThresholds)
    baseline_window_days: int = 30
    cooldown: dict = field(default_factory=lambda: {
        "alert_dedup_seconds": 600,
        "llm_rate_limit": 3,
        "llm_batch_window_seconds": 30,
    })
    feature_weights: dict = field(default_factory=lambda: {
        "blocked_ratio": 2.0,
        "unique_destinations": 1.5,
        "protocol_entropy": 1.5,
        "unique_protocols": 1.2,
        "hour_entropy": 1.0,
        "unique_ports": 0.8,
        "total_connections": 0.5,
    })
    sigmoid_midpoint: float = 5.0
    sigmoid_steepness: float = 2.0
    shadow_mode_enabled: dict = field(default_factory=dict)  # detector_name -> bool
    volumetric_threshold: int = 200  # blocked/min for DDoS
    dns_amplification_threshold: int = 50  # queries/min


@dataclass
class LLMConfig:
    """LLM provider settings.

    ``provider`` selects the client implementation:

    * ``anthropic`` — the official Anthropic SDK (Messages API).  Default.
    * ``openai`` / ``ollama`` / anything else — an OpenAI-compatible
      ``/chat/completions`` endpoint at ``base_url``.

    ``temperature`` applies only to the OpenAI-compatible path; current Claude
    models reject sampling parameters.  Depth is controlled by ``effort``.
    """

    provider: str = "anthropic"
    model: str = "claude-opus-5-5"
    base_url: str = ""  # empty = provider default
    temperature: float = 0.1
    max_tokens: int = 16000
    effort: str = "medium"  # low | medium | high | xhigh | max
    # Re-run a policy-declined request on a safe fallback model, server-side.
    server_side_fallback: bool = True
    api_key: str = ""  # from the environment / .env, never config.yaml
    fallback_provider: str = ""  # secondary provider, tried if the primary errors
    fallback_base_url: str = ""
    fallback_model: str = ""
    fallback_api_key: str = ""
    enabled: bool = False  # LLM triage is opt-in; local rules always alert


@dataclass
class ListenerConfig:
    syslog_port: int = 1514
    api_host: str = "0.0.0.0"
    api_port: int = 28819


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"


@dataclass
class AppConfig:
    feeds: FeedConfig = field(default_factory=FeedConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    analytics: AnalyticsConfig = field(default_factory=AnalyticsConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    listeners: ListenerConfig = field(default_factory=ListenerConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(config_path: Optional[Path] = None) -> AppConfig:
    """Load configuration from YAML file and environment variables."""
    path = config_path or CONFIG_YAML_PATH
    yaml_data: dict = {}
    if path.exists():
        with open(path) as f:
            yaml_data = yaml.safe_load(f) or {}

    # Load and merge environment-specific overrides
    env = os.environ.get("UEBA_ENV", "prod")
    env_overrides = yaml_data.pop(f"env_{env}", {})
    if env_overrides:
        _deep_merge(yaml_data, env_overrides)

    # Build config from yaml with env var overrides
    config = AppConfig()

    fd = yaml_data.get("feeds") or {}
    config.feeds = FeedConfig(
        refresh_interval_seconds=int(os.environ.get("FEED_REFRESH_INTERVAL", fd.get("refresh_interval_seconds", 21600))),
        urls=fd.get("urls", {}),
        local_db_path=os.environ.get("FEEDS_LOCAL_DB_PATH", fd.get("local_db_path", "")),
    )

    nd = yaml_data.get("network") or {}
    defaults = NetworkConfig()
    config.network = NetworkConfig(
        name=os.environ.get("UEBA_NETWORK_NAME", nd.get("name", defaults.name)),
        lan_cidrs=_env_list("UEBA_LAN_CIDRS", nd.get("lan_cidrs", defaults.lan_cidrs)),
        gateway_ips=_env_list("UEBA_GATEWAY_IPS", nd.get("gateway_ips", defaults.gateway_ips)),
        dns_servers=_env_list("UEBA_DNS_SERVERS", nd.get("dns_servers", defaults.dns_servers)),
        static_wan_ips=_env_list("UEBA_WAN_IPS", nd.get("static_wan_ips", defaults.static_wan_ips)),
        infra_hosts=_env_list("UEBA_INFRA_HOSTS", nd.get("infra_hosts", defaults.infra_hosts)),
        dns_burst_whitelist=_env_list("UEBA_DNS_BURST_WHITELIST", nd.get("dns_burst_whitelist", defaults.dns_burst_whitelist)),
        own_hostnames=_env_list("UEBA_OWN_HOSTNAMES", nd.get("own_hostnames", defaults.own_hostnames)),
        searxng_urls=_env_list("UEBA_SEARXNG_URLS", nd.get("searxng_urls", defaults.searxng_urls)),
        reputable_orgs=_env_list("UEBA_REPUTABLE_ORGS", nd.get("reputable_orgs", defaults.reputable_orgs)),
        host_notes=nd.get("host_notes", {}) or {},
    )

    if "analytics" in yaml_data:
        ad = yaml_data["analytics"]
        thresholds_raw = ad.get("thresholds", {})
        config.analytics = AnalyticsConfig(
            thresholds=AnalyticsThresholds(
                outbound_volume_bytes_per_minute=int(os.environ.get("ANALYTICS_VOLUME_THRESHOLD", thresholds_raw.get("outbound_volume_bytes_per_minute", 104857600))),
                high_entropy_shannon_threshold=float(os.environ.get("ANALYTICS_ENTROPY_THRESHOLD", thresholds_raw.get("high_entropy_shannon_threshold", 4.0))),
                blocked_query_repeat_threshold=int(os.environ.get("ANALYTICS_BLOCKED_REPEAT", thresholds_raw.get("blocked_query_repeat_threshold", 5))),
                port_scan_distinct_ports=int(os.environ.get("ANALYTICS_PORT_SCAN", thresholds_raw.get("port_scan_distinct_ports", 20))),
                beaconing_interval_tolerance_seconds=int(os.environ.get("ANALYTICS_BEACON_TOLERANCE", thresholds_raw.get("beaconing_interval_tolerance_seconds", 3))),
                beaconing_min_repetitions=int(os.environ.get("ANALYTICS_BEACON_MIN", thresholds_raw.get("beaconing_min_repetitions", 10))),
            ),
            baseline_window_days=int(os.environ.get("ANALYTICS_BASELINE_DAYS", ad.get("baseline_window_days", 30))),
            cooldown=ad.get("cooldown", AnalyticsConfig().cooldown),
            feature_weights=ad.get("feature_weights", AnalyticsConfig().feature_weights),
            sigmoid_midpoint=float(os.environ.get("ANALYTICS_SIGMOID_MIDPOINT", ad.get("sigmoid_midpoint", 5.0))),
            sigmoid_steepness=float(os.environ.get("ANALYTICS_SIGMOID_STEEPNESS", ad.get("sigmoid_steepness", 2.0))),
            shadow_mode_enabled=ad.get("shadow_mode_enabled", {}),
            volumetric_threshold=int(os.environ.get("ANALYTICS_VOLUMETRIC_THRESHOLD", ad.get("volumetric_threshold", 200))),
            dns_amplification_threshold=int(os.environ.get("ANALYTICS_DNS_AMPLIFICATION_THRESHOLD", ad.get("dns_amplification_threshold", 50))),
        )

    llm_raw = yaml_data.get("llm") or {}
    llm_defaults = LLMConfig()
    config.llm = LLMConfig(
        provider=os.environ.get("LLM_PROVIDER", llm_raw.get("provider", llm_defaults.provider)),
        model=os.environ.get("LLM_MODEL", llm_raw.get("model", llm_defaults.model)),
        base_url=os.environ.get("LLM_BASE_URL", llm_raw.get("base_url", llm_defaults.base_url)),
        temperature=float(os.environ.get("LLM_TEMPERATURE", llm_raw.get("temperature", llm_defaults.temperature))),
        max_tokens=int(os.environ.get("LLM_MAX_TOKENS", llm_raw.get("max_tokens", llm_defaults.max_tokens))),
        effort=os.environ.get("LLM_EFFORT", llm_raw.get("effort", llm_defaults.effort)),
        server_side_fallback=_as_bool(os.environ.get("LLM_SERVER_SIDE_FALLBACK"), llm_raw.get("server_side_fallback", llm_defaults.server_side_fallback)),
        api_key=os.environ.get("LLM_API_KEY", ""),
        fallback_provider=os.environ.get("LLM_FALLBACK_PROVIDER", llm_raw.get("fallback_provider", "")),
        fallback_base_url=os.environ.get("LLM_FALLBACK_BASE_URL", llm_raw.get("fallback_base_url", "")),
        fallback_model=os.environ.get("LLM_FALLBACK_MODEL", llm_raw.get("fallback_model", "")),
        fallback_api_key=os.environ.get("LLM_FALLBACK_API_KEY", ""),
        enabled=_as_bool(os.environ.get("LLM_ENABLED"), llm_raw.get("enabled", llm_defaults.enabled)),
    )

    if "listeners" in yaml_data:
        ld = yaml_data["listeners"]
        config.listeners = ListenerConfig(
            syslog_port=int(os.environ.get("SYSLOG_PORT", ld.get("syslog_port", 1514))),
            api_host=os.environ.get("API_HOST", ld.get("api_host", "0.0.0.0")),
            api_port=int(os.environ.get("API_PORT", ld.get("api_port", 28819))),
        )

    if "logging" in yaml_data:
        lgd = yaml_data["logging"]
        config.logging = LoggingConfig(
            level=os.environ.get("LOG_LEVEL", lgd.get("level", "INFO")),
            format=lgd.get("format", "json"),
        )

    return config


def _as_bool(env_value: Optional[str], default: bool) -> bool:
    """Interpret an env var as a boolean, falling back to ``default``."""
    if env_value is None or env_value == "":
        return bool(default)
    return env_value.strip().lower() in ("1", "true", "yes", "on")


# Singleton
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> AppConfig:
    global _config
    _config = load_config()
    return _config
