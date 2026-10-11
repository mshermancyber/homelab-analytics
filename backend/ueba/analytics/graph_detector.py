"""NetworkX PageRank graph analysis detector.

Builds a directed graph from OPNsense connection logs, runs PageRank,
and flags anomalous internal hosts and potential C2 infrastructure.
"""

import asyncio
import socket as _sock
import networkx as nx
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from sqlalchemy import select, func

from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult
from ueba.database import async_session_factory
from ueba.models import OPNsenseLog
from ueba.intelligence.enrichment import enrich_ip
from ueba.logging_config import get_logger
from ueba.netconfig import is_internal, lan_filter, reputable_orgs

logger = get_logger(__name__)

# Reputable org fragments come from network.reputable_orgs (config.yaml).


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False


class GraphAnomalyDetector(BaseAnomalyDetector):
    """NetworkX PageRank graph analysis detecting anomalous hosts and potential C2 infrastructure."""

    def __init__(self, lookback_hours: int = 24, feed_manager=None):
        self.lookback_hours = lookback_hours
        self.feed_manager = feed_manager
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None

    @property
    def name(self) -> str:
        return "pagerank_graph"

    @property
    def description(self) -> str:
        return "NetworkX PageRank graph analysis detecting anomalous hosts and potential C2 infrastructure"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    def data_hash(self) -> str:
        return f"gr_{self.lookback_hours}"

    async def _is_reputable_ip(self, ip: str) -> bool:
        """Check if an IP belongs to a known reputable org via MMDB + rDNS/Tranco."""
        try:
            info = await enrich_ip(ip)
            org = (info.get("org") or info.get("isp") or "").lower()
            if any(rep in org for rep in reputable_orgs()):
                return True
        except Exception:
            pass

        if self.feed_manager:
            try:
                loop = asyncio.get_event_loop()
                rdns = await loop.run_in_executor(
                    None, lambda: _sock.gethostbyaddr(ip)[0])
                if rdns and self.feed_manager.is_domain_reputable(rdns):
                    return True
            except Exception:
                pass

        return False

    async def detect(self) -> List[AnomalyResult]:
        """Run PageRank graph analysis on OPNsense connection logs."""
        results: List[AnomalyResult] = []

        try:
            since = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)

            async with async_session_factory() as session:
                query_result = await session.execute(
                    select(
                        OPNsenseLog.src_ip,
                        OPNsenseLog.dst_ip,
                        func.count(OPNsenseLog.id).label("cnt"),
                    )
                    .where(OPNsenseLog.timestamp >= since)
                    .group_by(OPNsenseLog.src_ip, OPNsenseLog.dst_ip)
                )
                rows = query_result.all()

            if not rows:
                self._last_results = results
                self._last_run = datetime.now(timezone.utc)
                return results

            G = nx.DiGraph()
            for row in rows:
                G.add_edge(row.src_ip, row.dst_ip, weight=row.cnt)

            if G.number_of_nodes() < 3:
                self._last_results = results
                self._last_run = datetime.now(timezone.utc)
                return results

            pr = nx.pagerank(G, weight="weight")

            # Flag internal hosts with PageRank > mean + 2*std
            internal_hosts = [ip for ip in pr if is_internal(ip)]
            if internal_hosts:
                internal_pr_values = np.array([pr[ip] for ip in internal_hosts], dtype=np.float64)
                mean_pr = float(np.mean(internal_pr_values))
                std_pr = float(np.std(internal_pr_values))
                threshold = mean_pr + 2 * std_pr

                for ip in internal_hosts:
                    if pr[ip] > threshold:
                        results.append(AnomalyResult(
                            ip=ip,
                            score=round(float(pr[ip]), 6),
                            details={
                                "pagerank": round(float(pr[ip]), 6),
                                "mean": round(mean_pr, 6),
                                "std": round(std_pr, 6),
                                "reason": "internal_host_pagerank_anomaly",
                            },
                            detector_name=self.name,
                        ))

            # C2 candidate detection: external IPs contacted by 3+ internal hosts
            external_sources: dict = {}
            for row in rows:
                if is_internal(row.src_ip) and not _is_private(row.dst_ip):
                    if row.dst_ip not in external_sources:
                        external_sources[row.dst_ip] = set()
                    external_sources[row.dst_ip].add(row.src_ip)

            c2_candidates = {ip: srcs for ip, srcs in external_sources.items()
                             if len(srcs) >= 3}

            if c2_candidates:
                filtered_count = 0
                for dst_ip, sources in c2_candidates.items():
                    if await self._is_reputable_ip(dst_ip):
                        filtered_count += 1
                        continue

                    in_degree = G.in_degree(dst_ip, weight="weight") if dst_ip in G else len(sources)
                    score = min(1.0, len(sources) / 10.0)
                    results.append(AnomalyResult(
                        ip=dst_ip,
                        score=round(score, 4),
                        details={
                            "pagerank": round(float(pr.get(dst_ip, 0)), 6),
                            "distinct_internal_sources": len(sources),
                            "internal_sources": sorted(list(sources)),
                            "in_degree": int(in_degree) if isinstance(in_degree, (int, float)) else len(sources),
                            "reason": "potential_c2_fanout",
                        },
                        detector_name=self.name,
                    ))

                if filtered_count:
                    logger.info("PageRank filtered reputable C2 candidates", extra={
                        "extra_data": {"filtered": filtered_count,
                                       "remaining": len(c2_candidates) - filtered_count}
                    })

        except Exception as e:
            logger.error("PageRank graph analysis failed", extra={
                "extra_data": {"error": str(e)}
            })

        self._last_results = results
        self._last_run = datetime.now(timezone.utc)

        if results:
            anomalous_ips = [r.ip for r in results]
            logger.info("PageRank graph analysis completed", extra={
                "extra_data": {
                    "total_anomalies": len(results),
                    "anomalous_ips": anomalous_ips,
                }
            })

        return results
