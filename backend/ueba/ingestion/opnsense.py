"""OPNsense firewall log parsing utilities."""
from datetime import datetime, timezone
from typing import Optional

from ueba.ingestion.syslog import parse_opnsense_filterlog
from ueba.logging_config import get_logger

logger = get_logger(__name__)


def normalize_opnsense_event(parsed_fields: dict, source_ip: str) -> Optional[dict]:
    """Convert parsed OPNsense filterlog fields to normalized OPNsenseLog format."""
    try:
        return {
            "timestamp": datetime.now(timezone.utc),
            "interface": parsed_fields.get("interface"),
            "src_ip": parsed_fields.get("src_ip", source_ip),
            "dst_ip": parsed_fields.get("dst_ip", "0.0.0.0"),
            "src_port": parsed_fields.get("src_port"),
            "dst_port": parsed_fields.get("dst_port"),
            "protocol": parsed_fields.get("protocol"),
            "action": parsed_fields.get("action"),
            "direction": parsed_fields.get("direction"),
            "rule_id": parsed_fields.get("rule_id"),
        }
    except Exception as e:
        logger.error("Failed to normalize OPNsense event", extra={"extra_data": {"error": str(e)}})
        return None
