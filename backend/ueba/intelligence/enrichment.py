"""IP and domain enrichment — local DB-IP MMDB + reverse DNS."""
import asyncio
import socket
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict

from ueba.logging_config import get_logger

logger = get_logger(__name__)

_GEOIP_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "geoip"
_city_reader = None
_asn_reader = None

_cache: Dict[str, dict] = {}
_cache_ttl = timedelta(hours=6)
_cache_timestamps: Dict[str, datetime] = {}


def _init_mmdb():
    global _city_reader, _asn_reader
    if _city_reader is not None:
        return
    try:
        import maxminddb
        city_path = _GEOIP_DIR / "dbip-city-lite.mmdb"
        asn_path = _GEOIP_DIR / "dbip-asn-lite.mmdb"
        if city_path.exists():
            _city_reader = maxminddb.open_database(str(city_path))
            logger.info("DB-IP city database loaded", extra={"extra_data": {"path": str(city_path)}})
        if asn_path.exists():
            _asn_reader = maxminddb.open_database(str(asn_path))
            logger.info("DB-IP ASN database loaded", extra={"extra_data": {"path": str(asn_path)}})
    except ImportError:
        logger.warning("maxminddb not installed — geo enrichment disabled")
    except Exception as e:
        logger.error("Failed to load MMDB", extra={"extra_data": {"error": str(e)}})


def _cache_get(key: str) -> Optional[dict]:
    ts = _cache_timestamps.get(key)
    if ts and datetime.now(timezone.utc) - ts < _cache_ttl:
        return _cache.get(key)
    return None


def _cache_set(key: str, value: dict):
    _cache[key] = value
    _cache_timestamps[key] = datetime.now(timezone.utc)
    if len(_cache) > 5000:
        oldest = sorted(_cache_timestamps, key=_cache_timestamps.get)[:1000]
        for k in oldest:
            _cache.pop(k, None)
            _cache_timestamps.pop(k, None)


async def enrich_ip(ip: str) -> dict:
    """Enrich an IP with geolocation, reverse DNS, and ASN info.

    Uses local DB-IP Lite MMDB files — no external API calls.
    """
    cached = _cache_get(f"ip:{ip}")
    if cached:
        return cached

    _init_mmdb()

    result = {
        "ip": ip,
        "reverse_dns": None,
        "country": None,
        "country_code": None,
        "city": None,
        "region": None,
        "lat": None,
        "lon": None,
        "isp": None,
        "org": None,
        "asn": None,
    }

    # Reverse DNS (local, fast)
    try:
        hostname = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.gethostbyaddr(ip)[0]
        )
        result["reverse_dns"] = hostname
    except (socket.herror, socket.gaierror, OSError):
        pass

    # City/geo from local MMDB
    if _city_reader:
        try:
            geo = _city_reader.get(ip)
            if geo:
                country = geo.get("country", {})
                result["country"] = country.get("names", {}).get("en")
                result["country_code"] = country.get("iso_code")
                city = geo.get("city", {})
                result["city"] = city.get("names", {}).get("en")
                subdivisions = geo.get("subdivisions", [])
                if subdivisions:
                    result["region"] = subdivisions[0].get("names", {}).get("en")
                loc = geo.get("location", {})
                result["lat"] = loc.get("latitude")
                result["lon"] = loc.get("longitude")
        except Exception as e:
            logger.debug("MMDB city lookup failed", extra={"extra_data": {"ip": ip, "error": str(e)}})

    # ASN/org from local MMDB
    if _asn_reader:
        try:
            asn_data = _asn_reader.get(ip)
            if asn_data:
                asn_num = asn_data.get("autonomous_system_number")
                asn_org = asn_data.get("autonomous_system_organization")
                result["asn"] = f"AS{asn_num}" if asn_num else None
                result["org"] = asn_org
                result["isp"] = asn_org
        except Exception as e:
            logger.debug("MMDB ASN lookup failed", extra={"extra_data": {"ip": ip, "error": str(e)}})

    _cache_set(f"ip:{ip}", result)
    return result


async def enrich_domain(domain: str) -> dict:
    """Enrich a domain with DNS resolution and geo/ASN of resolved IPs."""
    cached = _cache_get(f"domain:{domain}")
    if cached:
        return cached

    _init_mmdb()

    result = {
        "domain": domain,
        "resolved_ips": [],
        "registrar": None,
        "org": None,
        "country": None,
        "country_code": None,
        "asn": None,
        "hosting_org": None,
    }

    try:
        ips = await asyncio.get_event_loop().run_in_executor(
            None, lambda: [info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET)]
        )
        result["resolved_ips"] = list(set(ips))[:5]
    except (socket.gaierror, OSError):
        pass

    if result["resolved_ips"]:
        first_ip = result["resolved_ips"][0]
        if _asn_reader:
            try:
                asn_data = _asn_reader.get(first_ip)
                if asn_data:
                    asn_num = asn_data.get("autonomous_system_number")
                    asn_org = asn_data.get("autonomous_system_organization")
                    result["asn"] = f"AS{asn_num}" if asn_num else None
                    result["hosting_org"] = asn_org
                    result["org"] = asn_org
            except Exception:
                pass
        if _city_reader:
            try:
                geo = _city_reader.get(first_ip)
                if geo:
                    country = geo.get("country", {})
                    result["country"] = country.get("names", {}).get("en")
                    result["country_code"] = country.get("iso_code")
            except Exception:
                pass

    _cache_set(f"domain:{domain}", result)
    return result
