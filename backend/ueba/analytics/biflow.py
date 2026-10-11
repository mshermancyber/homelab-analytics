"""Biflow Correlation.

Correlates unidirectional filterlog events into bidirectional flow records.
Matches forward and reverse flows within a 5-second window, merging packet
counts, byte counts, duration, and final action.

Used by volume and beaconing detectors to improve accuracy by considering
full conversation context rather than individual packets.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple

from ueba.logging_config import get_logger

logger = get_logger(__name__)

# Flow key: (src_ip, src_port, dst_ip, dst_port, protocol)
FlowKey = Tuple[str, int, str, int, str]

BIFLOW_MERGE_WINDOW_SEC = 5


class BiflowRecord:
    """A merged bidirectional flow record."""

    __slots__ = (
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "request_count", "response_count", "total_bytes",
        "total_duration_ms", "final_action", "start_time", "end_time",
        "is_biflow",
    )

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.request_count = 0
        self.response_count = 0
        self.total_bytes = 0
        self.total_duration_ms = 0.0
        self.final_action: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.is_biflow = False

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "request_count": self.request_count,
            "response_count": self.response_count,
            "total_bytes": self.total_bytes,
            "total_duration_ms": self.total_duration_ms,
            "final_action": self.final_action,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "is_biflow": self.is_biflow,
        }


class BiflowCorrelator:
    """Correlates unidirectional filterlog events into biflow records.

    Maintains an in-memory table of pending flows keyed by
    (src_ip, src_port, dst_ip, dst_port, protocol). When a matching
    reverse flow arrives within 5 seconds, the two are merged into
    a single biflow record.
    """

    def __init__(self):
        # _flows: FlowKey -> dict with pending flow data
        self._flows: Dict[FlowKey, dict] = {}
        # Emitted biflow records (for detectors to consume)
        self._emitted: List[BiflowRecord] = []
        self._max_emitted = 5000  # cap emitted records in memory

    def process_event(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        action: Optional[str] = None,
        bytes_count: int = 0,
        timestamp: Optional[datetime] = None,
    ) -> Optional[BiflowRecord]:
        """Process a filterlog event and return a biflow record if one is completed.

        Returns None if no biflow record was completed by this event.
        """
        if not src_ip or not dst_ip:
            return None
        if src_port is None or dst_port is None:
            return None
        if not protocol:
            return None

        ts = timestamp or datetime.now(timezone.utc)
        key = (src_ip, int(src_port), dst_ip, int(dst_port), protocol)
        reverse_key = (dst_ip, int(dst_port), src_ip, int(src_port), protocol)

        # Check if a reverse flow exists
        if reverse_key in self._flows:
            # Merge into biflow record
            reverse_data = self._flows.pop(reverse_key)
            record = BiflowRecord(
                src_ip=reverse_data["src_ip"],
                dst_ip=reverse_data["dst_ip"],
                src_port=reverse_data["src_port"],
                dst_port=reverse_data["dst_port"],
                protocol=protocol,
            )
            record.request_count = reverse_data.get("request_count", 1)
            record.response_count = 1
            record.total_bytes = reverse_data.get("total_bytes", 0) + bytes_count
            start = reverse_data.get("start_time", ts)
            record.start_time = min(start, ts) if start else ts
            record.end_time = max(reverse_data.get("end_time", ts), ts)
            record.total_duration_ms = (
                (record.end_time - record.start_time).total_seconds() * 1000
            )
            # Final action: prefer 'block' if either side was blocked
            rev_action = reverse_data.get("final_action", "")
            if action == "block" or rev_action == "block":
                record.final_action = "block"
            else:
                record.final_action = action or rev_action or "pass"
            record.is_biflow = True

            self._emitted.append(record)
            if len(self._emitted) > self._max_emitted:
                self._emitted = self._emitted[-self._max_emitted:]

            logger.debug("Biflow record merged", extra={
                "extra_data": {
                    "src": f"{src_ip}:{src_port}",
                    "dst": f"{dst_ip}:{dst_port}",
                    "proto": protocol,
                    "duration_ms": round(record.total_duration_ms, 1),
                }
            })
            return record

        # No reverse flow yet — store this flow for potential merge
        self._flows[key] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": protocol,
            "request_count": 1,
            "response_count": 0,
            "total_bytes": bytes_count,
            "start_time": ts,
            "end_time": ts,
            "final_action": action,
        }

        # Prune stale entries (> merge window)
        self._prune_stale(ts)

        return None

    def create_unidirectional_record(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        bytes_count: int = 0,
        action: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> BiflowRecord:
        """Create a unidirectional flow record when no reverse flow is found.

        Useful for volume/beaconing detectors that can work with partial data.
        """
        ts = timestamp or datetime.now(timezone.utc)
        record = BiflowRecord(src_ip, dst_ip, src_port, dst_port, protocol)
        record.request_count = 1
        record.total_bytes = bytes_count
        record.start_time = ts
        record.end_time = ts
        record.final_action = action
        record.is_biflow = False
        return record

    def get_recent_records(self, seconds: int = 10) -> List[BiflowRecord]:
        """Return biflow records emitted in the last N seconds."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        return [r for r in self._emitted if r.start_time and r.start_time >= cutoff]

    def get_all_records(self) -> List[BiflowRecord]:
        """Return all emitted biflow records."""
        return list(self._emitted)

    def _prune_stale(self, now: datetime):
        """Remove flow entries older than the merge window."""
        cutoff = now - timedelta(seconds=BIFLOW_MERGE_WINDOW_SEC)
        stale_keys = [
            k for k, v in self._flows.items()
            if v.get("start_time") and v["start_time"] < cutoff
        ]
        for k in stale_keys:
            del self._flows[k]

    def get_stats(self) -> Dict[str, Any]:
        """Return correlator statistics."""
        return {
            "pending_flows": len(self._flows),
            "emitted_biflows": len(self._emitted),
            "merge_window_seconds": BIFLOW_MERGE_WINDOW_SEC,
        }
