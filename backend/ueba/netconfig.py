"""Site-specific network topology — the single place that knows your addresses.

Detection code never hardcodes an IP, CIDR or hostname.  Everything comes from
the ``network:`` block of ``config.yaml`` (or the matching ``UEBA_*`` env vars),
so the same source tree runs on any LAN.

Defaults are deliberately generic (``192.168.1.0/24``).  Set your own values
before first run — see ``.env.example`` and the README.
"""
import ipaddress
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from sqlalchemy import or_

from ueba.config import NetworkConfig, get_config
from ueba.logging_config import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------
def net() -> NetworkConfig:
    """Return the active network config block."""
    return get_config().network


def network_name() -> str:
    """Friendly name for the monitored LAN (used in labels and LLM prompts)."""
    return net().name or "LAN"


# ---------------------------------------------------------------------------
# LAN membership
# ---------------------------------------------------------------------------
_CACHE_KEY: Optional[Tuple[str, ...]] = None
_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_LIKE_PATTERNS: List[str] = []


def _rebuild_cache(cidrs: Sequence[str]) -> None:
    global _CACHE_KEY, _NETWORKS, _LIKE_PATTERNS
    networks = []
    patterns = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("Ignoring invalid LAN CIDR", extra={"extra_data": {"cidr": cidr}})
            continue
        networks.append(network)
        pattern = _like_pattern(network)
        if pattern:
            patterns.append(pattern)
    _NETWORKS = networks
    _LIKE_PATTERNS = patterns
    _CACHE_KEY = tuple(cidrs)


def _like_pattern(network) -> Optional[str]:
    """Build a SQL ``LIKE`` prefix pattern for a network.

    Only octet-boundary prefixes map cleanly onto a string prefix.  A network
    with a different prefix length is widened to the next octet boundary — the
    pattern then matches a few extra addresses, which is fine because every
    pattern is a coarse pre-filter; :func:`is_internal` is the authority.
    """
    if network.version != 4:
        return None  # IPv6 text forms are not prefix-comparable; use is_internal()
    octets = str(network.network_address).split(".")
    if network.prefixlen >= 24:
        return ".".join(octets[:3]) + ".%"
    if network.prefixlen >= 16:
        return ".".join(octets[:2]) + ".%"
    if network.prefixlen >= 8:
        return octets[0] + ".%"
    return None


def lan_networks() -> List:
    """Parsed LAN networks from config."""
    cidrs = net().lan_cidrs
    if _CACHE_KEY != tuple(cidrs):
        _rebuild_cache(cidrs)
    return _NETWORKS


def lan_like_patterns() -> List[str]:
    """SQL ``LIKE`` patterns covering the configured LAN(s)."""
    lan_networks()  # ensure cache is warm
    return _LIKE_PATTERNS


def lan_prefix() -> str:
    """First LAN's string prefix, e.g. ``"192.168.1."``.

    Useful for display shortening.  Returns an empty string when the LAN is not
    on an octet boundary.
    """
    patterns = lan_like_patterns()
    return patterns[0][:-1] if patterns else ""


def is_internal(ip: Optional[str]) -> bool:
    """True when ``ip`` belongs to a configured LAN network."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in lan_networks())


def lan_filter(column):
    """SQLAlchemy clause matching rows whose ``column`` is a LAN address.

    Falls back to "any non-null value" when no usable pattern exists, so a
    query never silently returns an empty set.
    """
    patterns = lan_like_patterns()
    if not patterns:
        return column.isnot(None)
    if len(patterns) == 1:
        return column.like(patterns[0])
    return or_(*[column.like(p) for p in patterns])


# ---------------------------------------------------------------------------
# Named hosts
# ---------------------------------------------------------------------------
def gateway_ips() -> Set[str]:
    """Router/firewall addresses — all traffic transits these."""
    return set(net().gateway_ips)


def dns_server_ips() -> Set[str]:
    """Local DNS resolvers (e.g. Pi-hole instances)."""
    return set(net().dns_servers)


def infra_hosts() -> Set[str]:
    """Hosts whose behaviour is noisy by design (scrapers, CI, crawlers).

    Behavioural-only alerts from these are suppressed; IOC matches still fire.
    """
    return set(net().infra_hosts)


def dns_burst_whitelist() -> Set[str]:
    """Hosts exempt from DNS burst detectors (high query volume is expected)."""
    return set(net().dns_burst_whitelist)


def static_wan_ips() -> Set[str]:
    """Known own public addresses, seeding runtime WAN discovery."""
    return set(net().static_wan_ips)


def own_hostnames() -> Tuple[str, ...]:
    """Own dynamic-DNS / external hostnames, excluded from DynDNS detectors."""
    return tuple(h.lower().lstrip(".") for h in net().own_hostnames if h)


def is_own_hostname(domain: Optional[str]) -> bool:
    """True when ``domain`` is, or is a subdomain of, one of our own hostnames."""
    if not domain:
        return False
    d = domain.lower().rstrip(".")
    return any(d == h or d.endswith("." + h) for h in own_hostnames())


def searxng_urls() -> List[str]:
    """SearXNG instances used for LLM web-search tool calls."""
    return list(net().searxng_urls)


def reputable_orgs() -> Tuple[str, ...]:
    """Lowercase org-name fragments treated as reputable during suppression."""
    return tuple(o.lower() for o in net().reputable_orgs if o)


def host_notes() -> dict:
    """``{ip: description}`` context passed to the LLM triage prompt."""
    return dict(net().host_notes or {})


def host_notes_prompt() -> str:
    """Render :func:`host_notes` as prompt lines, or an empty string if unset."""
    notes = host_notes()
    if not notes:
        return ""
    lines = [f"- {ip} — {desc}" for ip, desc in sorted(notes.items())]
    return "\n".join(lines)


def excluded_building_block_ips() -> Set[str]:
    """IPs that must never accumulate building blocks (gateways, scrapers)."""
    return static_wan_ips() | infra_hosts()


def any_internal(ips: Iterable[Optional[str]]) -> bool:
    """True when any address in ``ips`` is on the LAN."""
    return any(is_internal(ip) for ip in ips)
