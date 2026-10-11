# Architecture

## Data flow

```
Firewall (syslog :1514/udp) ─┐
                             ├─→ Engine → Detectors → Suppression → Local alert → LLM triage
DNS filter (API polling)   ──┘                                           │              │
                                                                    Enrichment    updates the alert's
                                                                   (GeoIP/ASN,    severity, class,
                                                                    reverse DNS)  escalation flag
Frontend (Angular 18) ←→ nginx ←→ Backend API (:28819) ←→ SQLite (ueba.db)
```

Design rule: **deterministic alerts first, LLM second.** Local rules own alert
creation. The LLM can raise severity, add a classification, and set the
escalation flag; it can never create, downgrade, or delete an alert. Everything
keeps working with the LLM switched off.

## Event pipeline (`engine.py:_on_syslog_event`)

1. **Persist** the event. Parsed events store structured rows in
   `opnsense_logs` / `pihole_queries`; `syslog_events.raw_message` and
   `parsed_fields` are intentionally left empty for those to save space.
2. **Extract** the real `src_ip` / `dst_ip` from the parsed filterlog fields.
   `source_ip` is always the syslog *sender* (your firewall), never the
   connection source — a distinction worth remembering when writing detectors.
3. **Match** against loaded threat-intel IOCs.
4. **Run behavioural detectors** — before recording the baseline, so
   `unknown_source` and the first-seen engine can still fire.
5. **Suppress**, cheapest check first:
   - WAN-originated traffic without an IOC match → drop
   - Blocked inbound from external sources without an IOC match → drop (the
     firewall already handled it)
   - Blocked inbound *with* an IOC match but severity ≤ medium → drop
   - `dest_fanout` / `unknown_source` from internal or container hosts →
     suppress (normal browsing)
   - `connection_without_dns` / `dns_flow_mismatch` toward the WAN address →
     suppress (NAT gateway traffic)
   - `first_seen` as the only flag → suppress (novelty alone is too noisy)
   - Configured infrastructure hosts and container ranges, behavioural-only →
     suppress, keeping IOC matches
   - Novelty flags during baseline learning (first 500 events) → suppress
6. **If still security-relevant** (IOC match or strong behavioural flag):
   - reverse DNS → check against the Tranco top 1M → suppress if reputable
   - enrich both IPs (GeoIP city/ASN/org + reverse DNS)
   - check learned false-positive patterns → suppress on match
   - suppress beaconing toward configured reputable orgs
   - alert-level dedup: 30-minute cooldown per (src_ip, dst_ip)
   - **create the alert** with enrichment, rule-derived severity, and a
     confidence of 80% (IOC) or 60% (behavioural)
   - ensemble boost: a source with composite score > 0.7 raises confidence and
     may upgrade severity
   - submit to LLM triage asynchronously, if enabled

## Backend modules (`backend/ueba/`)

| File | Purpose |
|---|---|
| `app.py` | FastAPI app, REST endpoints, WebSocket |
| `engine.py` | Core pipeline: intake → detection → enrichment → triage → alert |
| `netconfig.py` | The only module that knows your addresses; everything else asks it |
| `config.py` | Dataclass config from `config.yaml` + env vars |
| `dotenv.py` | Dependency-free `.env` loader, run before config is read |
| `credentials.py` | Secret resolution (environment, then `.env`) |
| `llm_client.py` | Anthropic (Messages API) and OpenAI-compatible clients, tool use, JSON extraction |
| `triage.py` | Batched LLM triage with web-search tool use and a fallback chain |
| `chat.py` | Analyst chat over SSE with alert context attachment |
| `models.py` | SQLAlchemy models |
| `database.py` | Async SQLite via aiosqlite, serialized single-writer queue |
| `auth.py` | JWT auth, role-based access (admin / analyst / viewer) |
| `websocket_manager.py` | Real-time event broadcasting |
| `escalation.py` | Webhook alert escalation |
| `ingestion/syslog.py` | UDP syslog listener (8 workers, queue of 10 000) |
| `ingestion/opnsense.py` | `filterlog` parser |
| `ingestion/pihole.py` | Pi-hole v6 API poller (`/api/auth` then `/api/queries`) |
| `intelligence/feeds.py` | 18 threat feeds + blacklist hot-reload file watcher |
| `intelligence/matcher.py` | IOC matching against the loaded feeds |
| `intelligence/enrichment.py` | GeoIP/ASN enrichment from local MMDB files — no outbound API calls |
| `analytics/detectors.py` | Core behavioural detectors |
| `analytics/baseline.py` | Network baseline for novelty detection |
| `analytics/ensemble.py` | Multi-model ensemble, weighted feature deviation, sigmoid calibration |
| `analytics/attack_mapping.py` | MITRE ATT&CK technique mapping per detector |
| `analytics/playbooks.py` | Investigation playbooks attached to alerts by type |
| `analytics/policies/` | Seven per-host behavioural policies with learned baselines |

Detector modules: `haddrscan_detector`, `sigma_dns`, `sigma_firewall`,
`bruteforce_detector`, `dns_tunnel_detector`, `dns_beacon_detector`,
`dns_amplification`, `dns_profile`, `dns_flow_correlator`, `ddos_detector`,
`first_seen`, `dga_classifier`, `graph_detector`, `autoencoder_detector`,
`anomaly` (IsolationForest), `biflow`, `lstm_detector`.

> `lstm_detector` needs TensorFlow, which is not in `requirements.txt`. Without
> it the detector reports itself inactive and the rest of the stack is
> unaffected.

## Resilience

- **Syslog watchdog** — `_syslog_watchdog` checks the last firewall event every
  60s. After five minutes of silence it drains the queue and restarts the
  listener and workers, which clears stale-worker jams without a full restart.
- **Single DB writer** — all writes go through one `asyncio.Queue` worker, so
  concurrent syslog workers cannot trigger SQLite lock errors.
- **Baseline persistence** — per-host connection maps and ASN/country sets are
  snapshotted every 10 minutes and reloaded on startup, which prevents a flood
  of `first_seen` alerts after a restart.
- **External healthcheck** — `backend/scripts/ueba-healthcheck.sh` restarts the
  service only when *both* ingestion sources have gone stale.

## Noise reduction

### Reputable-org suppression
Beaconing-only alerts (no IOC) are dropped when the remote address's GeoIP org
matches `network.reputable_orgs`.

### Alert dedup
In-memory `(src_ip, dst_ip) → expiry` cache, 30-minute cooldown, pruned at
1 000 entries. Beaconing fires on every matching event; this is what stops the
flood.

### False-positive learning
`PATCH /api/alerts/{id}/status` with `{"status": "false_positive"}` records a
`(src_prefix, dst_prefix, classification)` pattern in
`false_positive_patterns`, reloads the in-memory set immediately, and suppresses
matching events from then on. DGA alerts marked FP also add the domain to the
classifier's known-good labels; confirmed ones add it as known-DGA.

### Rule whitelists
Sigma firewall rules skip STUN (3478), NAT-PMP (5351), SSDP (1900), mDNS
(5353), OpenVPN (1194) and container bridge ranges. Sigma DNS rules skip your
own hostnames (`network.own_hostnames`), `*.plex.direct`, and `*.ntp.org`. The
DGA classifier skips `*.in-addr.arpa` and `*.ip6.arpa`.

### Building blocks
Created only for internal sources, excluding the WAN address and configured
infrastructure hosts — those alone accounted for ~88% of blocks as pure noise.
Seven block types; correlation requires **2+ distinct types within an hour**, and
blocks whose destination enriches to a reputable org are dropped before
counting.

## API

All endpoints are under `/api/`, authenticated with a JWT bearer token that the
frontend attaches automatically.

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/health` | none | Feed, listener and LLM status |
| POST | `/auth/register` · `/auth/login` | none | Account creation, login |
| GET | `/auth/me` · `/auth/users` | any · admin | Current user, user list |
| GET | `/events` · `/events/{id}` | analyst | Paginated events, event detail |
| GET | `/alerts` | analyst | Alerts with filters (severity, classification, source_ip, escalate, since, until) |
| GET | `/alerts/{id}` · `/alerts/{id}/related` | analyst | Alert detail, ±1h correlation timeline |
| PATCH | `/alerts/{id}/status` | analyst | open / false_positive / resolved / acknowledged |
| GET | `/alerts/top-offenders` | analyst | Top source and destination addresses |
| GET/POST/DELETE | `/fp-patterns` | analyst | False-positive pattern CRUD |
| GET | `/threat-intel/status` | analyst | Feed status and IOC counts |
| POST | `/threat-intel/refresh` | analyst | Force a feed refresh |
| GET | `/network/overview` | analyst | Active hosts, flagged hosts, event breakdown |
| GET/POST/PUT/DELETE | `/devices/roles` | analyst | Device role management |
| GET | `/dashboard/summary` · `/geo-breakdown` · `/device-activity` · `/host-risk` | analyst | Dashboard aggregates |
| GET | `/analytics/anomalies` · `/ensemble` · `/shadow-results` · `/coverage` · `/model-history` | analyst | Anomalies, ensemble scores, shadow runs, ATT&CK coverage, model history |
| POST/DELETE | `/analytics/anomalies/suppress` | analyst | Suppress an anomaly |
| GET/POST/PUT/DELETE | `/rules` | analyst | Custom detection rules |
| POST | `/rules/test` | analyst | Test a rule against recent events |
| PATCH | `/rules/{id}/promote` · `/deprecate` | analyst | Rule maturity lifecycle |
| GET/PUT | `/config` | analyst · admin | Runtime configuration |
| POST | `/chat` | analyst | Analyst chat (SSE stream) |
| WS | `/ws/events` | none | Live security events |

## Frontend

Angular 18 standalone components, dark theme, card layout on mobile and tables
on desktop.

| Route | Page |
|---|---|
| `/live-feed` | Real-time WebSocket event feed |
| `/alerts` | Alert history with filters, severity summary, FP patterns |
| `/alerts/:id` | Alert detail, related-alert timeline, investigation playbook |
| `/top-offenders` | Top talkers |
| `/threat-intel` | Feed status and manual refresh |
| `/network` | Active and flagged hosts, device roles |
| `/anomalies` | Anomaly detection, shadow results, model-history sparklines |
| `/rules` | Custom rules with test mode and maturity badges |
| `/chat` | Analyst chat |
| `/coverage` | MITRE ATT&CK coverage heatmap |
| `/config` | Runtime configuration editor |

Services: `ApiService` (HTTP), `AuthService` (JWT), `WebsocketService` (live
events). `interceptors/auth.interceptor.ts` attaches the bearer token.

## Database

SQLite at `backend/data/ueba.db` (override with `UEBA_DB_PATH`), async through
aiosqlite with SQLAlchemy async sessions. Events older than the retention period
are pruned on startup.

Tables: `syslog_events`, `opnsense_logs`, `pihole_queries`, `alerts`,
`threat_feeds`, `threat_matches`, `behavioral_flags`, `llm_cache`,
`network_baseline`, `users`, `custom_rules`, `anomaly_suppressions`,
`false_positive_patterns`, `shadow_results`, `building_blocks`, `device_roles`,
`model_runs`, `dga_training_labels`, `device_profiles`, `baseline_snapshots`,
`dns_host_profiles`, `policy_baselines`.

The database grows roughly in proportion to firewall log volume — on a busy
link it reaches multiple gigabytes. Keep an eye on `backend/data/` and tune the
retention window if space is tight.
