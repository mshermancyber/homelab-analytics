"""Per-host DNS query profiling from Pi-hole data.

Builds a rolling profile for each client IP: query volume, domain diversity,
TLD distribution, blocked ratio, and time-of-day pattern.  Flags anomalies
when a host's recent behavior deviates significantly from its own baseline.

Runs in the 30-minute anomaly detection loop (batch mode via ``detect()``).
Also accepts per-event updates via ``record_query()`` for real-time counters.
"""

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import select, func, text

from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult
from ueba.database import async_session_factory
from ueba.models import PiHoleQuery, DNSHostProfile
from ueba.logging_config import get_logger

logger = get_logger(__name__)

PROFILE_DAYS = 7
RECENT_HOURS = 1
MIN_BASELINE_QUERIES = 200


def _extract_tld(domain: str) -> str:
    parts = domain.rstrip(".").rsplit(".", 2)
    if len(parts) >= 2:
        return parts[-1]
    return domain


def _extract_sld(domain: str) -> str:
    parts = domain.rstrip(".").rsplit(".", 2)
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _jensen_shannon(p: Dict[str, float], q: Dict[str, float]) -> float:
    """Jensen-Shannon divergence between two probability distributions."""
    all_keys = set(p) | set(q)
    if not all_keys:
        return 0.0
    jsd = 0.0
    for k in all_keys:
        pk = p.get(k, 0.0)
        qk = q.get(k, 0.0)
        m = (pk + qk) / 2.0
        if m > 0:
            if pk > 0:
                jsd += 0.5 * pk * math.log2(pk / m)
            if qk > 0:
                jsd += 0.5 * qk * math.log2(qk / m)
    return jsd


class DNSProfileDetector(BaseAnomalyDetector):
    """Batch DNS profile anomaly detector.

    On each ``detect()`` call:
    1. Query pihole_queries for the last PROFILE_DAYS as baseline
    2. Query the last RECENT_HOURS as "current window"
    3. For each client IP, compare current vs baseline on:
       - Query volume rate (queries/hour)
       - Domain diversity (unique domains / total queries)
       - TLD distribution shift (Jensen-Shannon divergence)
       - Blocked query ratio change
       - New TLDs not seen in baseline
    4. Flag hosts whose deviation score exceeds threshold
    """

    def __init__(self, lookback_hours: int = 24):
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None
        self._lookback_hours = lookback_hours

    @property
    def name(self) -> str:
        return "dns_profile"

    @property
    def description(self) -> str:
        return "Per-host DNS query profile anomaly detection"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    async def detect(self) -> List[AnomalyResult]:
        now = datetime.now(timezone.utc)
        baseline_start = now - timedelta(days=PROFILE_DAYS)
        recent_start = now - timedelta(hours=RECENT_HOURS)

        try:
            async with async_session_factory() as session:
                baseline_profiles = await self._build_profiles(
                    session, baseline_start, recent_start
                )
                recent_profiles = await self._build_profiles(
                    session, recent_start, now
                )
        except Exception as e:
            logger.error("DNS profile detection failed",
                         extra={"extra_data": {"error": str(e)}})
            return []

        results = []
        for ip, recent in recent_profiles.items():
            baseline = baseline_profiles.get(ip)
            if not baseline or baseline["total_queries"] < MIN_BASELINE_QUERIES:
                continue

            score, details = self._compare_profiles(baseline, recent, ip)
            if score > 0.6:
                results.append(AnomalyResult(
                    ip=ip,
                    score=score,
                    details=details,
                    detector_name=self.name,
                ))

        await self._persist_profiles(baseline_profiles)

        self._last_results = results
        self._last_run = now
        if results:
            logger.info("DNS profile anomalies detected", extra={
                "extra_data": {
                    "count": len(results),
                    "hosts": [r.ip for r in results],
                }
            })
        return results

    async def _build_profiles(
        self, session, start: datetime, end: datetime
    ) -> Dict[str, dict]:
        result = await session.execute(
            select(
                PiHoleQuery.client_ip,
                PiHoleQuery.queried_domain,
                PiHoleQuery.query_type,
                PiHoleQuery.blocked,
            ).where(
                PiHoleQuery.timestamp >= start,
                PiHoleQuery.timestamp < end,
            )
        )
        rows = result.all()

        per_host: Dict[str, dict] = {}
        host_domains: Dict[str, list] = defaultdict(list)
        host_blocked: Dict[str, int] = defaultdict(int)
        host_total: Dict[str, int] = defaultdict(int)
        host_tlds: Dict[str, Counter] = defaultdict(Counter)
        host_slds: Dict[str, set] = defaultdict(set)

        host_txt: Dict[str, int] = defaultdict(int)

        for client_ip, domain, query_type, blocked in rows:
            host_total[client_ip] += 1
            host_domains[client_ip].append(domain)
            host_tlds[client_ip][_extract_tld(domain)] += 1
            host_slds[client_ip].add(_extract_sld(domain))
            if blocked:
                host_blocked[client_ip] += 1
            if query_type in ("TXT", "NULL"):
                host_txt[client_ip] += 1

        hours = max((end - start).total_seconds() / 3600.0, 0.01)

        for ip in host_total:
            total = host_total[ip]
            unique_domains = len(set(host_domains[ip]))
            tld_counts = host_tlds[ip]
            tld_total = sum(tld_counts.values())
            tld_dist = {
                tld: cnt / tld_total for tld, cnt in tld_counts.items()
            } if tld_total > 0 else {}

            per_host[ip] = {
                "total_queries": total,
                "queries_per_hour": total / hours,
                "unique_domains": unique_domains,
                "diversity": unique_domains / total if total > 0 else 0,
                "blocked_count": host_blocked[ip],
                "blocked_ratio": host_blocked[ip] / total if total > 0 else 0,
                "tld_distribution": tld_dist,
                "tld_set": set(tld_counts.keys()),
                "unique_slds": len(host_slds[ip]),
                "txt_ratio": host_txt[ip] / total if total > 0 else 0,
            }

        return per_host

    def _compare_profiles(
        self, baseline: dict, recent: dict, ip: str
    ) -> tuple:
        scores = []
        details: Dict[str, any] = {"ip": ip}

        bl_qph = baseline["queries_per_hour"]
        rc_qph = recent["queries_per_hour"]
        if bl_qph > 0:
            volume_ratio = rc_qph / bl_qph
            if volume_ratio > 5.0:
                scores.append(min(1.0, (volume_ratio - 5.0) / 10.0 + 0.6))
                details["volume_spike"] = round(volume_ratio, 1)

        bl_div = baseline["diversity"]
        rc_div = recent["diversity"]
        div_delta = abs(rc_div - bl_div)
        if div_delta > 0.3:
            scores.append(min(1.0, div_delta))
            details["diversity_shift"] = round(div_delta, 3)

        jsd = _jensen_shannon(baseline["tld_distribution"], recent["tld_distribution"])
        if jsd > 0.3:
            scores.append(min(1.0, jsd))
            details["tld_divergence"] = round(jsd, 3)

        new_tlds = recent.get("tld_set", set()) - baseline.get("tld_set", set())
        if new_tlds:
            details["new_tlds"] = list(new_tlds)[:10]
            if len(new_tlds) >= 3:
                scores.append(0.7)

        bl_blocked = baseline["blocked_ratio"]
        rc_blocked = recent["blocked_ratio"]
        if rc_blocked > bl_blocked + 0.2 and recent["blocked_count"] > 5:
            scores.append(min(1.0, rc_blocked - bl_blocked))
            details["blocked_ratio_spike"] = round(rc_blocked, 3)

        # TXT/NULL query ratio spike — DNS tunneling/exfil carries data in
        # TXT records; normal clients rarely exceed a few percent.
        bl_txt = baseline.get("txt_ratio", 0)
        rc_txt = recent.get("txt_ratio", 0)
        if rc_txt > max(bl_txt * 3, 0.10) and recent["total_queries"] >= 20:
            scores.append(min(1.0, 0.5 + rc_txt))
            details["txt_ratio_spike"] = round(rc_txt, 3)

        if not scores:
            return 0.0, details

        composite = max(scores)
        details["component_scores"] = [round(s, 3) for s in sorted(scores, reverse=True)]
        return composite, details

    async def _persist_profiles(self, profiles: Dict[str, dict]):
        """Save latest profile snapshots to DB for dashboard/history."""
        try:
            now = datetime.now(timezone.utc)
            date_str = now.strftime("%Y-%m-%d")

            async def _do_write():
                async with async_session_factory() as session:
                    for ip, profile in profiles.items():
                        existing = await session.execute(
                            select(DNSHostProfile).where(
                                DNSHostProfile.ip == ip,
                                DNSHostProfile.date == date_str,
                            )
                        )
                        row = existing.scalar_one_or_none()
                        feature_data = {
                            "queries_per_hour": round(profile["queries_per_hour"], 2),
                            "unique_domains": profile["unique_domains"],
                            "diversity": round(profile["diversity"], 4),
                            "blocked_ratio": round(profile["blocked_ratio"], 4),
                            "txt_ratio": round(profile.get("txt_ratio", 0), 4),
                            "unique_slds": profile["unique_slds"],
                            "top_tlds": dict(
                                sorted(
                                    profile["tld_distribution"].items(),
                                    key=lambda x: -x[1],
                                )[:10]
                            ),
                        }
                        if row:
                            row.profile_data = feature_data
                            row.total_queries = profile["total_queries"]
                        else:
                            session.add(DNSHostProfile(
                                ip=ip,
                                date=date_str,
                                profile_data=feature_data,
                                total_queries=profile["total_queries"],
                                created_at=now,
                            ))
                    await session.commit()

            from ueba.database import submit_write
            await submit_write(_do_write)
        except Exception as e:
            logger.warning("Failed to persist DNS profiles",
                           extra={"extra_data": {"error": str(e)}})
