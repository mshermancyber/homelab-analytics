"""MITRE ATT&CK TTP mapping for behavioral flag types."""

MITRE_MAPPING = {
    "beaconing": ("T1071", "Command and Control"),
    "port_scan": ("T1046", "Discovery"),
    "dga": ("T1568.002", "Command and Control"),
    "volume": ("T1048", "Exfiltration"),
    "dns_query_burst": ("T1071.004", "Command and Control"),
    "unknown_source": ("T1190", "Initial Access"),
    "dest_fanout": ("T1046", "Discovery"),
    "dns_unknown_burst": ("T1071.004", "Command and Control"),
    # New mappings from Phase 4 features
    "haddrscan": ("T1595.001", "Reconnaissance"),
    "sigma_dns": ("T1071.004", "Command and Control"),
    "sigma_firewall": ("T1071", "Command and Control"),
    "brute_force": ("T1110", "Credential Access"),
    "dns_tunnel": ("T1572", "Command and Control"),
    "first_seen": ("T1071", "Command and Control"),
    "ddos_flood": ("T1498", "Impact"),
    "dns_amplification": ("T1498.002", "Impact"),
    "dga_classifier": ("T1568.002", "Command and Control"),
    "connection_without_dns": ("T1571", "Command and Control"),
    "dns_beaconing": ("T1071.004", "Command and Control"),
    "outbound_blocked_ratio": ("T1071", "Command and Control"),
    "lateral_movement": ("T1021", "Lateral Movement"),
}


def get_mitre_mapping(flag_type: str) -> tuple:
    """Return (technique, tactic) tuple for a behavioral flag type."""
    return MITRE_MAPPING.get(flag_type, (None, None))


def get_all_mappings(flag_types: list) -> list:
    """Return list of {"technique": ..., "tactic": ...} for each flag_type."""
    results = []
    for ft in flag_types:
        technique, tactic = MITRE_MAPPING.get(ft, (None, None))
        if technique:
            results.append({"technique": technique, "tactic": tactic})
    return results
