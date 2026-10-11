"""First-seen detection engine.

A general-purpose novelty detector that alerts when field value combinations
appear for the FIRST TIME within a configurable history window.

Detection types:
- First time src_ip connects to dst_port (new service usage)
- First time src_ip connects to a dst_ip (new communication path)
- First time any internal host contacts a specific external IP (new external service)
- First time a domain is queried by any client (new domain, from Pi-hole)

Maintains history in SQLite table ``first_seen_history`` to persist across
restarts.  Operates in both the event pipeline (per-event) and the ensemble
loop (batch detect).
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Column, Integer, String, DateTime, Index

from ueba.logging_config import get_logger
from ueba.database import async_session_factory, submit_write
from ueba.models import Base, OPNsenseLog, PiHoleQuery
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)

# Default history window
DEFAULT_HISTORY_DAYS = 5
# Default batch lookback for detect()
DEFAULT_LOOKBACK_HOURS = 1


class FirstSeenHistory(Base):
    """Persistent first-seen history table.

    Each row records the first time a particular field-tuple combination was
    observed and when it was most recently seen.
    """

    __tablename__ = "first_seen_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    field_key = Column(String(100), nullable=False)
    field_value = Column(String(512), nullable=False)  # serialized tuple values
    first_seen_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_fsh_field_key_value", "field_key", "field_value", unique=True),
        Index("ix_fsh_first_seen_at", "first_seen_at"),
        Index("ix_fsh_last_seen_at", "last_seen_at"),
    )


class FirstSeenDetector(BaseAnomalyDetector):
    """First-seen novelty detector.

    Checks if observed (field_key, field_value) combinations have been seen
    before in the history window. Emits BehavioralFlag with flag_type='first_seen'
    for previously unseen combinations.

    Parameters:
        history_days: How many days of history to retain (default 5).
        learning_event_threshold: Suppress alerts until this many events have
            been processed (default 500, same as baseline learning period).
        lookback_hours: How many hours of recent data to query in detect()
            batch mode (default 1).
    """

    def __init__(
        self,
        history_days: int = DEFAULT_HISTORY_DAYS,
        learning_event_threshold: int = 500,
        lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
    ):
        self.history_days = history_days
        self.learning_event_threshold = learning_event_threshold
        self.lookback_hours = lookback_hours

        # In-memory cache: (field_key, field_value) -> present
        self._cache: Set[Tuple[str, str]] = set()
        self._cache_loaded = False
        self._event_count = 0

        # Track last cache refresh
        self._last_cache_refresh: float = 0.0
        self._cache_refresh_interval = 300  # 5 minutes

        # Cooldown for repeated first-seen alerts on same tuple
        self._alert_cooldown: Dict[Tuple[str, str], float] = {}
        self._cooldown_seconds = 3600  # 1 hour

        # BaseAnomalyDetector state
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None

    # ------------------------------------------------------------------
    # BaseAnomalyDetector interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "first_seen"

    @property
    def description(self) -> str:
        return (
            "First-seen novelty detector — flags previously unseen field value "
            "combinations (src→port, src→dst, any→external IP, new domains) "
            "within a configurable history window."
        )

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    async def detect(self) -> List[AnomalyResult]:
        """Run batch first-seen detection on recent OPNsenseLog and PiHoleQuery records.

        Queries both tables within the configured lookback window (default 1 hour),
        runs the per-event check methods on each record, and returns AnomalyResult
        objects for newly observed field-value combinations.

        Returns:
            List of AnomalyResult for first-seen patterns detected during
            this batch run.
        """
        lookback = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
        results: List[AnomalyResult] = []

        # Temporarily bypass learning period during batch detection so the
        # per-event check methods produce results regardless of event count.
        saved_count = self._event_count
        if self._event_count < self.learning_event_threshold:
            self._event_count = self.learning_event_threshold

        try:
            # Ensure cache is loaded before processing
            await self.ensure_cache_loaded()
            self._maybe_refresh()

            # --- OPNsense / filterlog records ---
            try:
                async with async_session_factory() as session:
                    stmt = (
                        select(OPNsenseLog)
                        .where(OPNsenseLog.timestamp >= lookback)
                        .order_by(OPNsenseLog.timestamp.asc())
                    )
                    result = await session.execute(stmt)
                    opnsense_rows = result.scalars().all()

                for row in opnsense_rows:
                    flags = await self.check_filterlog_event(
                        src_ip=row.src_ip,
                        dst_ip=row.dst_ip,
                        dst_port=row.dst_port,
                        protocol=row.protocol,
                        timestamp=row.timestamp,
                    )
                    for flag in flags:
                        results.append(self._flag_to_anomaly_result(flag))

                if opnsense_rows:
                    logger.debug(
                        "First-seen batch: processed OPNsense logs",
                        extra={"extra_data": {"count": len(opnsense_rows)}}
                    )
            except Exception as e:
                logger.error("First-seen batch: failed to query OPNsense logs", extra={
                    "extra_data": {"error": str(e)}
                })

            # --- Pi-hole / DNS query records ---
            try:
                async with async_session_factory() as session:
                    stmt = (
                        select(PiHoleQuery)
                        .where(PiHoleQuery.timestamp >= lookback)
                        .order_by(PiHoleQuery.timestamp.asc())
                    )
                    result = await session.execute(stmt)
                    pihole_rows = result.scalars().all()

                for row in pihole_rows:
                    flags = await self.check_pihole_event(
                        client_ip=row.client_ip,
                        domain=row.queried_domain,
                        query_type=row.query_type or "A",
                        blocked=row.blocked or False,
                        timestamp=row.timestamp,
                    )
                    for flag in flags:
                        results.append(self._flag_to_anomaly_result(flag))

                if pihole_rows:
                    logger.debug(
                        "First-seen batch: processed Pi-hole queries",
                        extra={"extra_data": {"count": len(pihole_rows)}}
                    )
            except Exception as e:
                logger.error("First-seen batch: failed to query Pi-hole queries", extra={
                    "extra_data": {"error": str(e)}
                })

        finally:
            # Restore original event count so per-event pipeline usage
            # is not affected by the batch run.
            self._event_count = saved_count

        self._last_results = results
        self._last_run = datetime.now(timezone.utc)

        if results:
            logger.info("First-seen batch detection completed", extra={
                "extra_data": {
                    "novelties_found": len(results),
                    "sample": [
                        r.details.get("field_key", "") + ":" + r.details.get("field_value", "")
                        for r in results[:5]
                    ],
                }
            })
        else:
            logger.debug("First-seen batch detection completed, no novelties")

        return results

    def _flag_to_anomaly_result(self, flag: Dict[str, Any]) -> AnomalyResult:
        """Convert a BehavioralFlag dict from check_* methods into an AnomalyResult.

        Chooses the most relevant IP as the anomalous entity based on the
        field_key type.
        """
        details = flag.get("details", {})
        field_key = details.get("field_key", "")

        # Determine the most relevant IP for this anomaly
        if field_key in ("src_to_port", "src_to_dst"):
            ip = details.get("src_ip", "0.0.0.0")
        elif field_key == "any_to_external":
            ip = details.get("dst_ip", "0.0.0.0")
        elif field_key == "domain_queried":
            ip = details.get("client_ip", "0.0.0.0")
        else:
            # Fallback: use whichever IP is available
            ip = details.get("src_ip") or details.get("dst_ip") or details.get("client_ip", "0.0.0.0")

        return AnomalyResult(
            ip=ip,
            score=0.8,  # Binary novel/known — high confidence for any first-seen
            details={
                "flag_type": flag.get("flag_type", "first_seen"),
                "field_key": field_key,
                "field_value": details.get("field_value", ""),
                "description": details.get("description", ""),
                "src_ip": details.get("src_ip", ""),
                "dst_ip": details.get("dst_ip", ""),
                "dst_port": details.get("dst_port"),
                "protocol": details.get("protocol"),
                "domain": details.get("domain", ""),
                "client_ip": details.get("client_ip", ""),
                "query_type": details.get("query_type", ""),
                "blocked": details.get("blocked", False),
            },
            detector_name=self.name,
        )

    # ------------------------------------------------------------------
    # Per-event methods (kept unchanged from original)
    # ------------------------------------------------------------------

    @property
    def is_learning(self) -> bool:
        """True during the learning period (suppress alerts)."""
        return self._event_count < self.learning_event_threshold

    async def ensure_cache_loaded(self) -> None:
        """Preload the in-memory cache from the database."""
        if self._cache_loaded:
            return
        await self._refresh_cache()
        self._cache_loaded = True

    async def _refresh_cache(self) -> None:
        """Reload cache from database."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.history_days)
        try:
            async with async_session_factory() as session:
                stmt = select(
                    FirstSeenHistory.field_key,
                    FirstSeenHistory.field_value,
                ).where(FirstSeenHistory.last_seen_at >= cutoff)
                result = await session.execute(stmt)
                rows = result.all()
                self._cache = {(r.field_key, r.field_value) for r in rows}
                logger.debug("First-seen cache refreshed", extra={
                    "extra_data": {"entries": len(self._cache)}
                })
        except Exception as e:
            logger.error("Failed to refresh first-seen cache", extra={
                "extra_data": {"error": str(e)}
            })

    def _maybe_refresh(self) -> None:
        """Periodically refresh the in-memory cache."""
        now = time.monotonic()
        if now - self._last_cache_refresh > self._cache_refresh_interval:
            # Schedule async refresh (called from sync context, use asyncio task)
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._refresh_cache())
            except RuntimeError:
                pass
            self._last_cache_refresh = now

    async def check_filterlog_event(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Check a filterlog event for first-seen patterns.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            dst_port: Destination port.
            protocol: Protocol name/number.
            timestamp: Event timestamp.

        Returns:
            List of BehavioralFlag dicts for first-seen patterns.
        """
        self._event_count += 1
        if self.is_learning:
            return []

        await self.ensure_cache_loaded()
        self._maybe_refresh()

        ts = timestamp or datetime.now(timezone.utc)
        flags: List[Dict[str, Any]] = []
        now = time.monotonic()

        checks: List[Tuple[str, str, str]] = []

        # Check 1: First time src_ip connects to dst_port (new service usage)
        if src_ip and dst_port is not None:
            checks.append((
                "src_to_port",
                f"{src_ip}:{dst_port}",
                f"First time {src_ip} connects to port {dst_port} (new service usage)",
            ))

        # Check 2: First time src_ip connects to a dst_ip (new communication path)
        if src_ip and dst_ip:
            checks.append((
                "src_to_dst",
                f"{src_ip}->{dst_ip}",
                f"First time {src_ip} communicates with {dst_ip} (new communication path)",
            ))

        # Check 3: First time any internal host contacts a specific external IP
        if dst_ip and not (
            dst_ip.startswith("192.168.")
            or dst_ip.startswith("10.")
            or dst_ip.startswith(("172.16.", "172.17.", "172.18.", "172.19.",
                                  "172.20.", "172.21.", "172.22.", "172.23.",
                                  "172.24.", "172.25.", "172.26.", "172.27.",
                                  "172.28.", "172.29.", "172.30.", "172.31."))
            or dst_ip.startswith("127.")
            or dst_ip.startswith("169.254.")
        ):
            checks.append((
                "any_to_external",
                f"any->{dst_ip}",
                f"First time any host contacts external IP {dst_ip} (new external service)",
            ))

        for field_key, field_value, description in checks:
            cache_key = (field_key, field_value)
            if cache_key in self._cache:
                continue

            # Check cooldown
            if cache_key in self._alert_cooldown:
                continue

            self._alert_cooldown[cache_key] = now
            self._cache.add(cache_key)

            # Persist to database
            await self._persist_first_seen(field_key, field_value, ts)

            flags.append({
                "flag_type": "first_seen",
                "details": {
                    "field_key": field_key,
                    "field_value": field_value,
                    "description": description,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                },
                "timestamp": ts,
            })

        # Prune cooldowns
        cooldown_cutoff = now - self._cooldown_seconds
        expired = [k for k, c in self._alert_cooldown.items() if c < cooldown_cutoff]
        for k in expired:
            del self._alert_cooldown[k]

        return flags

    async def check_pihole_event(
        self,
        client_ip: str,
        domain: str,
        query_type: str = "A",
        blocked: bool = False,
        timestamp: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Check a Pi-hole event for first-seen patterns.

        Args:
            client_ip: Client IP making the query.
            domain: Queried domain name.
            query_type: DNS query type.
            blocked: Whether Pi-hole blocked the query.
            timestamp: Event timestamp.

        Returns:
            List of BehavioralFlag dicts for first-seen patterns.
        """
        self._event_count += 1
        if self.is_learning:
            return []
        if not domain:
            return []

        await self.ensure_cache_loaded()
        self._maybe_refresh()

        ts = timestamp or datetime.now(timezone.utc)
        flags: List[Dict[str, Any]] = []
        now = time.monotonic()

        # Check: First time a domain is queried by any client
        field_key = "domain_queried"
        field_value = f"any->{domain.lower()}"
        cache_key = (field_key, field_value)

        if cache_key not in self._cache and cache_key not in self._alert_cooldown:
            self._alert_cooldown[cache_key] = now
            self._cache.add(cache_key)

            await self._persist_first_seen(field_key, field_value, ts)

            flags.append({
                "flag_type": "first_seen",
                "details": {
                    "field_key": field_key,
                    "field_value": field_value,
                    "description": f"First time domain '{domain}' is queried by any client (new domain)",
                    "client_ip": client_ip,
                    "domain": domain,
                    "query_type": query_type,
                    "blocked": blocked,
                },
                "timestamp": ts,
            })

        return flags

    async def _persist_first_seen(
        self,
        field_key: str,
        field_value: str,
        timestamp: datetime,
    ) -> None:
        """Persist a first-seen observation to the database."""
        try:
            async def _do_write():
                async with async_session_factory() as session:
                    # Upsert: update last_seen_at if exists, else insert
                    stmt = select(FirstSeenHistory).where(
                        and_(
                            FirstSeenHistory.field_key == field_key,
                            FirstSeenHistory.field_value == field_value,
                        )
                    )
                    result = await session.execute(stmt)
                    existing = result.scalar_one_or_none()

                    if existing:
                        existing.last_seen_at = timestamp
                    else:
                        entry = FirstSeenHistory(
                            field_key=field_key,
                            field_value=field_value,
                            first_seen_at=timestamp,
                            last_seen_at=timestamp,
                        )
                        session.add(entry)
                    await session.commit()

            await submit_write(_do_write)
        except Exception as e:
            logger.error("Failed to persist first-seen entry", extra={
                "extra_data": {
                    "field_key": field_key,
                    "field_value": field_value,
                    "error": str(e),
                }
            })

    async def prune_old_entries(self) -> int:
        """Delete entries older than the history window. Returns count deleted."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.history_days)
        try:
            async def _do_write():
                async with async_session_factory() as session:
                    stmt = select(FirstSeenHistory).where(
                        FirstSeenHistory.last_seen_at < cutoff
                    )
                    result = await session.execute(stmt)
                    old_rows = result.scalars().all()
                    count = len(old_rows)
                    for row in old_rows:
                        await session.delete(row)
                    await session.commit()
                    return count

            deleted = await submit_write(_do_write)
            if deleted:
                logger.info("Pruned first-seen history", extra={
                    "extra_data": {"deleted": deleted, "cutoff": cutoff.isoformat()}
                })
                # Refresh cache after pruning
                await self._refresh_cache()
            return deleted
        except Exception as e:
            logger.error("Failed to prune first-seen history", extra={
                "extra_data": {"error": str(e)}
            })
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """Return current detection statistics."""
        return {
            "cache_entries": len(self._cache),
            "cache_loaded": self._cache_loaded,
            "event_count": self._event_count,
            "is_learning": self.is_learning,
            "cooldown_entries": len(self._alert_cooldown),
            "history_days": self.history_days,
        }
