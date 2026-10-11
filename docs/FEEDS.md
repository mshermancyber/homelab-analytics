# Threat feeds

18 public feeds are refreshed every six hours (`feeds.refresh_interval_seconds`)
and matched against every event. Feed URLs live in `backend/config.yaml` under
`feeds.urls`; remove any you do not want and the loader skips it.

| Category | Feeds |
|---|---|
| Malware / C2 | URLhaus, ThreatFox, Feodo Tracker, SSL Blacklist, MalwareBazaar |
| Ransomware | ransomware.live recent victims |
| Botnet / DDoS | Spamhaus DROP, DShield top blocks |
| Phishing | OpenPhish, PhishTank |
| APT / vulnerability | Emerging Threats compromised IPs, CISA KEV |
| Reputation | blocklist.de, CINS Army |
| Anonymizers | Tor exit nodes |
| Curated domains | stamparm/blackbook |
| Framework | MITRE ATT&CK STIX bundle (technique mapping, not IOCs) |

Tor exits are deliberately kept alertable: an internal host talking to a Tor
exit is high-signal on a home network, even though it is unremarkable elsewhere.

## Blacklist hot-reload

Any IOC files you drop in the feed cache directory are polled every 60 seconds
and reloaded on change — handy for pushing an indicator from an incident
straight into matching without waiting for a refresh cycle.

## Manual refresh

```bash
curl -X POST http://localhost:28819/api/threat-intel/refresh \
  -H "Authorization: Bearer $TOKEN"
```

Feed status, IOC counts and last-refresh times are on the dashboard's Threat
Intel page, or at `GET /api/threat-intel/status`.

## Optional local feeds database

Four loaders can read from a local SQLite mirror instead of a public API, which
is worth having if you already sync CVE data for something else. It is **off by
default**:

```yaml
feeds:
  local_db_path: "/path/to/feeds.db"
```

or `FEEDS_LOCAL_DB_PATH=/path/to/feeds.db`.

Expected schema — each loader reads one table and ignores the rest, so you only
need the ones you care about:

```sql
CREATE TABLE kev    (cve TEXT PRIMARY KEY);                      -- CISA KEV identifiers
CREATE TABLE nvd    (cve TEXT PRIMARY KEY, score REAL, severity TEXT);
CREATE TABLE epss   (cve TEXT PRIMARY KEY, epss REAL);           -- exploit prediction scores
CREATE TABLE tranco (domain TEXT PRIMARY KEY);                   -- Tranco top 1M
```

Behaviour when unset or unreadable:

| Loader | Fallback |
|---|---|
| CISA KEV | fetches the public CISA JSON feed |
| NVD (CVSS ≥ 7.0) | skipped |
| EPSS | fetches the FIRST.org API |
| Tranco top 1M | skipped — domain-reputation suppression stays off |

Of the four, **Tranco is the one worth wiring up**: it is what stops popular
domains re-resolving on TTL expiry from looking like DNS beaconing. Build it
from the published list:

```bash
# https://tranco-list.eu/ — download the current top-1M CSV, then:
python3 - <<'PY'
import csv, sqlite3
conn = sqlite3.connect("feeds.db")
conn.execute("CREATE TABLE IF NOT EXISTS tranco (domain TEXT PRIMARY KEY)")
with open("top-1m.csv") as fh:
    rows = [(domain,) for _rank, domain in csv.reader(fh)]
conn.executemany("INSERT OR IGNORE INTO tranco VALUES (?)", rows)
conn.commit()
print(f"{len(rows)} domains")
PY
```
