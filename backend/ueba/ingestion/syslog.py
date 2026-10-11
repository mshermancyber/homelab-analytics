"""UDP syslog listener on port 1514 (Docker-mapped from 514).

Parses OPNsense filterlog CSV, Pi-hole syslog, and generic syslog messages.
"""
import asyncio
import re
from datetime import datetime, timezone
from typing import Optional, Callable, Awaitable, List

from ueba.logging_config import get_logger
from ueba.config import get_config
from ueba.models import SyslogEvent

logger = get_logger(__name__)

# OPNsense filterlog CSV field positions per filterlog specification
# Fields: rule_id,sub_rule,anchor,tracker,interface,reason,action,dir,version,...
# For filterlog format: "rule,sub_rule,anchor,tracker,interface,reason,action,dir,proto,..."
OPNSENSE_FILTERLOG_PATTERN = re.compile(
    r"(\d+),"  # rule_id
    r"(\d*),"  # sub_rule
    r"([^,]*),"  # anchor
    r"([^,]*),"  # tracker
    r"([^,]*),"  # interface
    r"([^,]*),"  # reason
    r"([^,]*),"  # action
    r"([^,]*),"  # direction
    r"(\d+),"  # version
    r"([^,]*),"  # ...
)

# Pi-hole syslog patterns
PIHOLE_BLOCKED_PATTERN = re.compile(
    r"(?:gravity blocked|blocked) ([^ ]+) is (?:\d+\.\d+\.\d+\.\d+)"
    # More generic patterns
)
PIHOLE_QUERY_PATTERN = re.compile(
    r"query\[([A-Z]+)\] ([^ ]+) from ([\d\.]+|[:0-9a-fA-F]+)"
)
PIHOLE_REPLY_PATTERN = re.compile(
    r"(?:reply|config) ([^ ]+) is (?:([^ ]+)|NODATA|NXDOMAIN)"
)


def parse_priority_facility(raw: str) -> tuple:
    """Parse syslog PRI field <facility*8+severity>."""
    # In RFC 3164 format: <PRI>timestamp hostname message
    # We handle this loosely since OPNsense sends structured data
    return None, None


def parse_opnsense_filterlog(message: str) -> Optional[dict]:
    """Parse OPNsense filterlog CSV message.

    OPNsense filterlog format (CSV), field positions:
      0: rule_id, 1: sub_rule, 2: anchor, 3: tracker, 4: interface,
      5: reason, 6: action, 7: direction, 8: ip_version

    IPv4 (version=4):
      9: tos, 10: ecn, 11: ttl, 12: id, 13: offset, 14: flags,
      15: proto_id, 16: proto_name, 17: length,
      18: src_ip, 19: dst_ip
      For TCP/UDP: 20: src_port, 21: dst_port, 22: data_length

    IPv6 (version=6):
      9: class, 10: flow_label, 11: hop_limit, 12: proto_name, 13: proto_id,
      14: length,
      15: src_ip, 16: dst_ip
      For TCP/UDP: 17: src_port, 18: dst_port, 19: data_length
    """
    if message.count(",") < 10:
        return None

    # Strip syslog header if present (e.g. "<134>Jun 27 12:00:00 fw filterlog[123]: ...")
    msg = message
    filterlog_idx = msg.find("filterlog")
    if filterlog_idx >= 0:
        colon_idx = msg.find(":", filterlog_idx)
        if colon_idx >= 0:
            msg = msg[colon_idx + 1:].strip()

    parts = msg.split(",")
    if len(parts) < 15:
        return None

    try:
        result = {
            "rule_id": int(parts[0]) if parts[0].strip().isdigit() else None,
            "sub_rule": parts[1].strip(),
            "anchor": parts[2].strip(),
            "tracker": parts[3].strip(),
            "interface": parts[4].strip(),
            "reason": parts[5].strip(),
            "action": parts[6].strip(),
            "direction": parts[7].strip(),
            "version": int(parts[8]) if parts[8].strip().isdigit() else None,
        }

        version = result["version"]
        if version == 4 and len(parts) >= 20:
            result["protocol"] = parts[16].strip()
            result["src_ip"] = parts[18].strip()
            result["dst_ip"] = parts[19].strip()
            if len(parts) > 21 and parts[20].strip().isdigit():
                result["src_port"] = int(parts[20])
                result["dst_port"] = int(parts[21]) if parts[21].strip().isdigit() else None
            result["length"] = int(parts[17]) if parts[17].strip().isdigit() else None
        elif version == 6 and len(parts) >= 17:
            result["protocol"] = parts[12].strip()
            result["src_ip"] = parts[15].strip()
            result["dst_ip"] = parts[16].strip()
            if len(parts) > 18 and parts[17].strip().isdigit():
                result["src_port"] = int(parts[17])
                result["dst_port"] = int(parts[18]) if parts[18].strip().isdigit() else None
            result["length"] = int(parts[14]) if parts[14].strip().isdigit() else None

        return result
    except (ValueError, IndexError) as e:
        logger.debug("Failed to parse OPNsense filterlog", extra={
            "extra_data": {"error": str(e), "message": msg[:200]}
        })
        return None


def parse_pihole_syslog(message: str) -> Optional[dict]:
    """Parse Pi-hole syslog message to extract DNS query info."""
    result = {}
    
    # Try Pi-hole FTL query log format
    # Format: "query[A] example.com from 192.168.1.100"
    query_match = PIHOLE_QUERY_PATTERN.search(message)
    if query_match:
        result["query_type"] = query_match.group(1)
        result["queried_domain"] = query_match.group(2)
        result["client_ip"] = query_match.group(3)
        result["blocked"] = "blocked" in message.lower() or "gravity" in message.lower()
        return result
    
    # Try Pi-hole reply format
    # "reply example.com is 1.2.3.4" or "config example.com is NODATA"
    reply_match = PIHOLE_REPLY_PATTERN.search(message)
    if reply_match:
        result["queried_domain"] = reply_match.group(1)
        reply = reply_match.group(2) if reply_match.group(2) else "NODATA"
        result["reply_type"] = reply
        result["blocked"] = reply in ("0.0.0.0", "::", "NODATA", "NXDOMAIN") or "blocked" in message.lower()
        return result
    
    # Generic Pi-hole log detection
    if "pihole" in message.lower() or "dnsmasq" in message.lower():
        # Extract domain-like patterns
        domain_pattern = re.compile(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b')
        domains = domain_pattern.findall(message)
        # Extract IP patterns
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        ips = ip_pattern.findall(message)
        
        if domains:
            result["queried_domain"] = domains[0] if isinstance(domains[0], str) else ".".join(domains[0])
        if ips:
            result["client_ip"] = ips[0]
        result["blocked"] = "blocked" in message.lower() or "gravity" in message.lower()
        return result if result else None
    
    return None


def detect_event_type(message: str) -> str:
    """Detect the event type from a syslog message."""
    msg_lower = message.lower()

    # OPNsense filterlog — look for the process name or CSV pattern
    if "filterlog" in msg_lower:
        return "opnsense"
    if message.count(",") >= 10:
        if re.search(r'\d+,\d*,', message[:80]):
            return "opnsense"

    # Pi-hole / dnsmasq
    if "pihole" in msg_lower or "dnsmasq" in msg_lower:
        return "pihole"
    if re.search(r'query\[[A-Z]+\]', message):
        return "pihole"
    if "gravity" in msg_lower and "blocked" in msg_lower:
        return "pihole"

    return "generic"


class SyslogListener:
    """UDP syslog listener that accepts and parses syslog messages."""

    _NUM_WORKERS = 8

    def __init__(self, event_callback: Optional[Callable[[dict], Awaitable[None]]] = None):
        self.config = get_config()
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.event_callback = event_callback
        self._running = False
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._worker_tasks: List[asyncio.Task] = []

    async def _process_queue(self):
        """Process queued syslog messages."""
        while self._running:
            try:
                data, addr = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._handle_message(data, addr)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Error processing syslog message", extra={"extra_data": {"error": str(e)}})

    async def _handle_message(self, data: bytes, addr: tuple):
        """Handle a single syslog message."""
        try:
            message = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        if not message:
            return

        source_ip = addr[0]
        event_type = detect_event_type(message)
        parsed = None

        if event_type == "opnsense":
            parsed = parse_opnsense_filterlog(message)
        elif event_type == "pihole":
            parsed = parse_pihole_syslog(message)

        event_data = {
            "timestamp": datetime.now(timezone.utc),
            "source_ip": source_ip,
            "source_device": source_ip,  # Can be enriched later
            "raw_message": message,
            "parsed_fields": parsed,
            "event_type": event_type,
        }

        logger.debug("Received syslog event", extra={
            "extra_data": {"source_ip": source_ip, "event_type": event_type}
        })

        if self.event_callback:
            try:
                await self.event_callback(event_data)
            except Exception as e:
                logger.error("Event callback failed", extra={"extra_data": {"error": str(e)}})

    def _datagram_received(self, data: bytes, addr: tuple):
        """Callback for asyncio datagram protocol."""
        try:
            self._queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            logger.warning("Syslog queue full, dropping message")

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        logger.info("Syslog listener started", extra={
            "extra_data": {"port": self.config.listeners.syslog_port}
        })

    def error_received(self, exc: Exception):
        logger.error("Syslog listener error", extra={"extra_data": {"error": str(exc)}})

    def connection_lost(self, exc: Optional[Exception]):
        logger.info("Syslog listener connection lost")

    async def start(self) -> "SyslogListener":
        """Start the UDP syslog listener."""
        self._running = True
        loop = asyncio.get_running_loop()
        
        class Protocol(asyncio.DatagramProtocol):
            def __init__(self_):
                pass
            def datagram_received(self_, data, addr):
                self._datagram_received(data, addr)
            def connection_made(self_, transport):
                self.connection_made(transport)
            def error_received(self_, exc):
                self.error_received(exc)
            def connection_lost(self_, exc):
                self.connection_lost(exc)

        listen_addr = ("0.0.0.0", self.config.listeners.syslog_port)
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                Protocol,
                local_addr=listen_addr,
            )
            for i in range(self._NUM_WORKERS):
                self._worker_tasks.append(asyncio.create_task(self._process_queue()))
            logger.info("Syslog UDP listener bound", extra={
                "extra_data": {"address": f"{listen_addr[0]}:{listen_addr[1]}",
                               "workers": self._NUM_WORKERS}
            })
        except OSError as e:
            logger.error("Failed to bind syslog listener", extra={"extra_data": {"error": str(e)}})
            raise

        return self

    async def stop(self):
        """Stop the syslog listener."""
        self._running = False
        if self.transport:
            self.transport.close()
        for task in self._worker_tasks:
            task.cancel()
        for task in self._worker_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._worker_tasks.clear()
        logger.info("Syslog listener stopped")

    async def restart(self):
        """Stop, drain the queue, and restart the listener and workers."""
        dropped = self._queue.qsize()
        await self.stop()
        self._queue = asyncio.Queue(maxsize=10000)
        await self.start()
        logger.warning("Syslog listener restarted", extra={
            "extra_data": {"dropped_queued": dropped}
        })

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()
