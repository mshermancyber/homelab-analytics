"""Investigation playbooks for behavioral detection types."""

from typing import Optional


def get_playbook(flag_type: str) -> str:
    """Return the investigation playbook markdown for a given detection flag type.

    Args:
        flag_type: The behavioral flag type (e.g. 'beaconing', 'port_scan', 'dga').

    Returns:
        Markdown string with investigation steps, or empty string if unknown.
    """
    if not flag_type:
        return ""
    # Normalize common aliases
    normalized = flag_type.lower().replace(" ", "_")
    return PLAYBOOKS.get(normalized, PLAYBOOKS.get(flag_type, ""))


PLAYBOOKS = {
    "beaconing": """## Beaconing Investigation Playbook
1. **Verify the destination**: Check if dst_ip is a known CDN (Cloudflare, Akamai, Fastly), cloud provider (AWS, GCP, Azure), or SaaS platform (Microsoft 365, Google Workspace). These often produce regular heartbeat traffic.
2. **Check dst_port and protocol**: HTTPS/443 beaconing to a known-good service is usually benign. Non-standard ports (e.g., 4444, 8080, 53) are more suspicious.
3. **Review beaconing interval**: Consistent intervals (e.g., exactly 60s or 300s) may indicate C2 polling. Variable intervals are more typical of legitimate software updates/telemetry.
4. **Inspect traffic volume**: Low-byte, regular outbound connections are classic C2 behavior. Check if the volume per beacon is consistent (e.g., always ~64 bytes).
5. **Look up the destination IP**: Use OSINT (Shodan, VirusTotal, abuse.ch) to check if the IP is associated with malware infrastructure.
6. **Correlate with DNS**: If a domain was resolved for this IP, check its registration date (new domains <30 days are higher risk) and TLD (.tk, .ml, .ga are riskier).
7. **Check process context** (if EDR available): Identify which process is generating the beaconing. Legitimate processes like update services should be whitelisted.
8. **Escalate if**: Beaconing to newly registered domains, known malicious IPs, non-standard ports, or encrypted traffic with no legitimate business purpose.""",

    "port_scan": """## Port Scan Investigation Playbook
1. **Identify the source**: Is the scanning host internal (LAN) or external (WAN)? Internal scans may indicate compromised host lateral movement. External scans may be reconnaissance.
2. **Review scan pattern**: Horizontal scan (many hosts, few ports) suggests service discovery. Vertical scan (few hosts, many ports) suggests vulnerability enumeration.
3. **Check ports targeted**: Common service ports (22, 80, 443, 3389, 3306, 5432) indicate targeted service discovery. Sequential or random port scans are more likely automated.
4. **Correlate with time**: Was this during business hours? After-hours scanning is more suspicious. Check if it coincides with other alerts.
5. **Review host activity**: Has the source host generated other alerts (beaconing, data exfiltration)? Multiple indicators compound risk.
6. **Check firewall logs**: Were the scan attempts blocked or allowed? Successful connections to unusual ports warrant immediate investigation.
7. **Escalate if**: Scan targets critical infrastructure ports (RDP 3389, SSH 22, database ports), originates from an unexpected host, or correlates with other behavioral alerts.""",

    "haddrscan": """## Hardware Address Scan Investigation Playbook
1. **Identify the scanning host**: MAC address scans typically originate from network mapping tools (nmap, arp-scan) or ARP spoofing tools.
2. **Check for legitimate tools**: Network management systems (Nagios, Zabbix, PRTG) and vulnerability scanners (Nessus, Qualys) perform ARP scanning legitimately. Verify with IT operations.
3. **Review scan scope**: Is it scanning the entire subnet or specific IP ranges? Broad scans across multiple subnets are more suspicious.
4. **Correlate with other events**: ARP scanning often precedes man-in-the-middle attacks. Check for ARP spoofing alerts or unusual gateway MAC changes.
5. **Check host ownership**: Is the scanning host a managed asset? Unmanaged or rogue devices performing ARP scans are high-risk.
6. **Review timing**: Persistent ARP scanning over hours/days suggests automated tooling. Brief bursts may be one-off network discovery.
7. **Escalate if**: Scan originates from unexpected host, correlates with ARP cache anomalies, or targets gateway/subnet broadcast addresses.""",

    "dga": """## Domain Generation Algorithm (DGA) Investigation Playbook
1. **Verify DGA detection**: Check the Shannon entropy score and domain characteristics (length, character distribution, TLD). Entropy > 3.5 with random-looking domains strongly suggests DGA.
2. **Inspect the queried domains**: Look for patterns — non-resolving domains, unusual TLDs (.xyz, .top, .tk), high ratio of NXDOMAIN responses.
3. **Check DNS query volume**: DGA malware often generates hundreds to thousands of DNS queries in short bursts. Correlate query volume with the entropy alert.
4. **Identify the affected host**: Is it a single host or multiple? Single host with DGA-like queries is classic malware C2 fallback behavior.
5. **Check domain registration**: Use whois to check when suspicious domains were registered. DGA domains are typically registered just before use.
6. **Review for other C2 indicators**: Check if the host also exhibits beaconing, unusual outbound connections, or data exfiltration patterns.
7. **Escalate if**: Multiple DGA-like domains detected from same host, domains resolve to known-bad IPs, or host shows multiple behavioral indicators.""",

    "volume": """## Traffic Volume Anomaly Investigation Playbook
1. **Establish baseline**: Compare current traffic volume against historical baseline for this host and time-of-day. Is this a 2x, 10x, or 100x spike?
2. **Identify the destination**: Is the traffic going to a known service (CDN, backup, cloud storage) or an unknown IP? Known services suggest legitimate bulk transfers.
3. **Check protocol and port**: High-volume HTTPS/443 may be large file uploads/downloads. High-volume DNS/53 could indicate DNS tunneling or DGA.
4. **Review the source process**: If possible, identify which process generated the traffic. Backup agents, sync clients, and streaming services can generate legitimate volume spikes.
5. **Assess direction**: Outbound volume spikes are more concerning (potential data exfiltration) than inbound (downloads, updates).
6. **Check time pattern**: Sustained high volume vs. burst. Sustained exfiltration is classic data theft. Bursts may be automated backups.
7. **Correlate with other alerts**: Volume + beaconing = potential C2 with data exfil. Volume + unusual hours = higher risk.
8. **Escalate if**: Traffic to unknown/untrusted destinations, outbound volume exceeding normal by 5x+, or correlation with other behavioral alerts.""",

    "dns_query_burst": """## DNS Query Burst Investigation Playbook
1. **Identify the source host**: DNS query bursts from DNS servers (Pi-hole, AD DC) are expected. Bursts from client workstations or IoT devices are suspicious.
2. **Analyze queried domains**: Are they diverse (many unique domains) or repetitive (same domain)? Diverse bursts suggest DGA or web scraping. Repetitive suggests misconfiguration.
3. **Check NXDOMAIN ratio**: High percentage of non-resolving domains is a strong DGA/C2 indicator. Legitimate bursts should mostly resolve.
4. **Review the TLDs**: Unusual or cheap TLDs (.tk, .ml, .ga, .cf, .xyz) in burst queries suggest malicious activity.
5. **Correlate with entropy**: DNS burst + high entropy domains = almost certainly DGA malware.
6. **Check time of day**: 3 AM DNS bursts from a workstation are far more suspicious than 10 AM bursts.
7. **Escalate if**: >70% NXDOMAIN, domains have high entropy, source is a non-DNS-server host, or burst correlates with other alerts.""",

    "dns_unknown_burst": """## Unknown DNS Domain Burst Investigation Playbook
1. **Verify domain novelty**: These are domains not previously seen in your network baseline. New domains can be legitimate (new services) or malicious (DGA, phishing).
2. **Check domain registration age**: Use whois to check when domains were registered. Domains <30 days old are higher risk. Domains registered today/tomorrow are extremely suspicious.
3. **Analyze domain structure**: Do they look like human-readable names or random strings? Random strings suggest DGA. Typosquatted versions of known brands suggest phishing.
4. **Review DNS response IPs**: What IPs do these domains resolve to? Check reputation of resolved IPs (VirusTotal, abuse.ch, Shodan).
5. **Check for CDN/CSP patterns**: New CDN edge IPs and cloud provider hostnames appear frequently and are benign. Cross-reference with ASN/organization data.
6. **Correlate with threat intel**: Do any of the unknown domains or their resolved IPs appear in threat feeds?
7. **Escalate if**: Domains are algorithmically generated, resolve to known-bad IPs, hosted on bulletproof hosting, or domains mimic legitimate services (typosquatting).""",

    "brute_force": """## Brute Force Attack Investigation Playbook
1. **Identify the target service**: Which service is being attacked (SSH/22, RDP/3389, WordPress/wp-login, email/IMAP/POP3)? Different services require different responses.
2. **Determine attack source**: Is it a single IP (targeted attack) or distributed across many IPs (botnet)? Single IP may be easier to block. Distributed requires rate limiting.
3. **Check for successful logins**: Review authentication logs for successful logins from the attacking IP(s) or around the same timeframe. A successful brute force changes the incident severity.
4. **Review account targets**: Are they targeting default accounts (root, admin, administrator) or specific usernames? Targeted username attacks suggest prior reconnaissance.
5. **Check geographic source**: Is the attack from an unexpected country? Cross-reference with normal user login geography.
6. **Implement immediate block**: If attack is ongoing, block the source IP(s) at the firewall or add to fail2ban.
7. **Escalate if**: Successful login detected, attack targets privileged accounts, attack is distributed (difficult to block), or target is critical infrastructure service.""",

    "dns_tunnel": """## DNS Tunnel Investigation Playbook
1. **Verify tunnel indicators**: DNS tunnels exhibit unusually large query/response sizes (>512 bytes), high TXT record usage, or base64-encoded subdomains.
2. **Analyze query patterns**: Tunnels show consistent, periodic DNS queries that may encode data in subdomains (e.g., `base64data.attacker.com`). Look for long subdomain labels.
3. **Check destination domain**: Is the authoritative DNS server for the queried domain legitimate or attacker-controlled? Check domain registration and reputation.
4. **Measure bandwidth**: DNS tunneling can exfiltrate significant data over time. Calculate the byte volume of DNS traffic from the affected host.
5. **Review process context**: DNS tunneling tools (dnscat2, iodine, DNScrypt wrappers) often run as separate processes. Check for unexpected DNS-related processes.
6. **Correlate with other C2 indicators**: DNS tunneling is often used when traditional C2 channels are blocked. Check for prior blocked outbound connection attempts.
7. **Escalate if**: Consistent high-volume DNS to single domain, encoded-looking subdomains, queries to attacker-controlled DNS servers, or correlation with data exfiltration alerts.""",

    "first_seen": """## First Seen Communication Investigation Playbook
1. **Characterize the new endpoint**: Is the dst_ip a well-known service (CDN, cloud API, software update) or an obscure IP? Check enrichment data (ASN, organization, country).
2. **Check the destination port**: Common service ports (443, 80, 53) are less suspicious than unusual high ports. Check what service is running on the destination.
3. **Review DNS history**: Was a domain resolved to this IP? If so, check the domain's reputation and registration age.
4. **Analyze traffic pattern**: Is this a single connection or persistent communication? First-seen + beaconing or volume is much more concerning.
5. **Check destination reputation**: Use threat intel and OSINT (VirusTotal, Shodan, AlienVault OTX) to check the IP/domain reputation.
6. **Correlate with software changes**: Recent software installations, updates, or configuration changes may explain new communication patterns. Check with the host owner.
7. **Escalate if**: Destination has poor/no reputation, communication is persistent, destination is in a high-risk country, or host has other behavioral alerts.""",

    "dns_beaconing": """## DNS Beaconing Investigation Playbook
1. **Verify the cadence**: Review mean interval and jitter in the alert details. Sub-15% jitter over 12+ queries is machine-driven, not human browsing.
2. **Rule out TTL re-resolution**: Legit clients re-query on TTL expiry. Check whether the interval matches the domain's DNS TTL (dig +noall +answer <domain>). Tranco-listed domains are pre-filtered, so a flagged domain is already unpopular.
3. **Check if the domain is blocked**: A host periodically querying a Pi-hole-BLOCKED domain is likely malware retrying its C2 — high confidence signal.
4. **Investigate the domain**: Registration age (young = suspicious), registrar, authoritative NS. Check VirusTotal/URLhaus/ThreatFox for the registered domain.
5. **Correlate with firewall flows**: Did the host also open connections to the resolved IPs? DNS beaconing without follow-up connections may be a dormant implant polling for tasking.
6. **Identify the device**: IoT devices poll vendor clouds periodically — check the device role. An IoT device polling its vendor is normal; a workstation polling an unknown domain is not.
7. **Escalate if**: Domain is newly registered, blocked-but-retried, resolves to hosting/VPS IPs, or the host has other behavioral alerts.""",

    "sigma_dns": """## Sigma DNS Rule Match Investigation Playbook
1. **Review the matched Sigma rule**: Identify which specific Sigma rule fired (DNS-based threat detection). Understand what the rule is designed to detect.
2. **Analyze the DNS query**: Examine the queried domain, query type, and response. Is this a known-bad domain, a DGA domain, or a suspicious query type (TXT, NULL, ANY)?
3. **Check the rule's false positive rate**: Sigma rules can produce false positives. Check if this rule has previously generated false positives in your environment.
4. **Verify against threat intel**: Cross-reference the domain and any resolved IPs against multiple threat intelligence sources.
5. **Check for tooling signatures**: Some Sigma rules detect specific tools (nmap DNS probes, dnscat2, SQL injection via DNS). If a tool is identified, investigate accordingly.
6. **Correlate with host activity**: Has the source host generated other alerts? A Sigma match + behavioral anomaly is higher confidence.
7. **Escalate if**: Rule matches known malware C2 patterns, domain is confirmed malicious, or host shows multiple detection indicators.""",

    "sigma_firewall": """## Sigma Firewall Rule Match Investigation Playbook
1. **Review the matched Sigma rule**: Identify which firewall-specific Sigma rule fired. Understand the detection logic (e.g., suspicious port usage, protocol anomalies, traffic patterns).
2. **Analyze the firewall event**: Examine src_ip, dst_ip, src_port, dst_port, protocol, and action (pass/block). Understand the full connection context.
3. **Check if traffic was allowed or blocked**: Blocked traffic matching Sigma rules is informational — the firewall already handled it. Allowed traffic matching Sigma rules requires immediate investigation.
4. **Verify rule logic against environment**: Some Sigma rules detect legitimate enterprise software behavior. Check if the rule is known to produce false positives in your environment.
5. **Assess the destination**: Is the traffic destined for a known service, internal system, or unknown external IP? Unknown external IPs are highest risk.
6. **Correlate with other alerts**: Firewall Sigma matches combined with IDS/endpoint alerts increase confidence significantly.
7. **Escalate if**: Traffic was allowed through, destination is unknown/suspicious, pattern matches known attack techniques (C2, exfiltration, lateral movement), or rule fires repeatedly from same source.""",
}
