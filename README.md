# UEBA Platform

Self-hosted **User and Entity Behavior Analytics** for a home or lab network.
It ingests firewall syslog and DNS query logs, runs ~25 behavioural detectors
over them, cross-references 18 threat-intelligence feeds, suppresses the noise,
and — optionally — asks an LLM for a second opinion on whatever survives.

Built for the case where a full SIEM is overkill but `tail -f` is not enough. The
design goal is **single-digit alerts per day**: a detection is only worth having
if the alert it produces is worth reading.

![version](https://img.shields.io/badge/version-0.1.0-informational)
![license](https://img.shields.io/badge/license-GPL--3.0-blue)
![status](https://img.shields.io/badge/status-stable-brightgreen)
![python](https://img.shields.io/badge/python-3.12%2B-blue)
![angular](https://img.shields.io/badge/angular-18-red)

---

## How it works

```
Firewall (syslog :1514/udp) ─┐
                             ├─→ Engine → Detectors → Suppression → Alert → LLM triage (optional)
DNS filter (API polling)   ──┘                                        │           │
                                                                  Enrichment   updates the alert's
                                                                 (GeoIP/ASN)   severity + analysis
Frontend (Angular 18) ←→ nginx ←→ Backend API (:28819) ←→ SQLite
```

**Alerts are created by local rules first.** An IOC match or a strong behavioural
flag raises an alert on its own; LLM triage is post-hoc enrichment that can only
*upgrade* an existing alert — raise its severity, add a classification, flag it
for escalation. If the LLM is down, misconfigured, or switched off, alerting is
unaffected.

### What it detects

| Category | Detectors |
|---|---|
| Core behavioural | Beaconing, port scan, DGA (Shannon entropy), DNS burst, DNS unknown burst, outbound volume, destination fanout, unknown source |
| Scanning | Horizontal address scan, network brute force (simple / distributed / user enumeration) |
| DNS | DNS tunnelling (subdomain encoding), DNS beaconing, DNS amplification, per-host DNS profiling, Sigma DNS rules (Cobalt Strike, DynDNS, mining pools, DoH bypass, punycode homoglyphs) |
| Firewall | Sigma firewall rules (cleartext protocols, outbound SMB/RDP), outbound blocked ratio, lateral movement, DDoS volumetrics |
| Novelty | First-seen IP/port/protocol combinations (Elastic `new_terms` pattern), network baseline deviation |
| ML | Multi-model ensemble with weighted feature deviation, per-device autoencoder baselines, IsolationForest, PageRank graph analysis, supervised DGA classifier that retrains from analyst feedback |
| Correlation | Building-block correlation (2+ distinct flag types within an hour), DNS↔flow cross-correlation, biflow matching, MITRE ATT&CK mapping, investigation playbooks |

### How noise is kept down

Suppression runs before alert creation, cheapest check first:

1. WAN-originated traffic without an IOC match
2. Blocked inbound from external sources (the firewall already handled it)
3. Reputable-destination checks — reverse DNS against the Tranco top 1M, then
   GeoIP org name against a configurable reputable-org list
4. Learned false-positive patterns — mark an alert as an FP in the UI and
   matching events are suppressed from then on
5. Per-pair dedup with a 30-minute cooldown
6. Novelty-only flags during baseline learning

---

## Quick start

> Full step-by-step instructions, including firewall and Pi-hole setup:
> **[docs/INSTALL.md](docs/INSTALL.md)**.

### Requirements

- Python 3.12+
- Node.js 20+ (to build the dashboard)
- A firewall that can forward syslog (OPNsense/pfSense `filterlog` format)
- Optional: one or more Pi-hole v6 instances for DNS data
- Optional: an Anthropic API key for LLM triage

### 1. Configure

```bash
git clone https://github.com/mshermancyber/homelab-analytics.git
cd homelab-analytics
cp .env.example .env
```

Edit **`.env`** for secrets (`JWT_SECRET`, API keys, Pi-hole password) and
**`backend/config.yaml`** for your network. The `network:` block is the only
section you must change:

```yaml
network:
  name: "LAN"
  lan_cidrs: ["192.168.1.0/24"]   # your subnet(s)
  gateway_ips: ["192.168.1.1"]    # router / firewall
  dns_servers: ["192.168.1.10"]   # Pi-hole, if you run one
  own_hostnames: []               # your dynamic-DNS name, so it never alerts
```

Nothing else in the tree hardcodes an address. Everything reads from here (or
the matching `UEBA_*` environment variables), so detectors, prompts, and SQL
filters all follow your topology. Mirror the display settings for the dashboard
in `frontend/src/app/config/network.config.ts`.

Generate a signing secret while you're there:

```bash
echo "JWT_SECRET=$(openssl rand -hex 32)" >> .env
```

### 2. Run with Docker (simplest)

The nginx container serves the built dashboard, so build it once first:

```bash
cd frontend && npm install && npx ng build --configuration production && cd ..
docker compose up -d --build
```

Backend on `:28819`, dashboard on `:28818` (change with `WEB_PORT` in `.env`).

### 3. Or run it directly

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt
./backend/scripts/ueba-start.sh
```

Dashboard, in a second shell:

```bash
cd frontend && npm install
npx ng serve --port 28818 --proxy-config proxy.conf.json
```

To run it as a background service, install the bundled systemd user unit:

```bash
mkdir -p ~/.config/systemd/user
sed "s|%REPO%|$(pwd)|" backend/scripts/ueba.service > ~/.config/systemd/user/ueba.service
systemctl --user daemon-reload && systemctl --user enable --now ueba
sudo loginctl enable-linger "$USER"   # survive logout
```

### 4. Point your data sources at it

**Firewall** — send `filterlog` via syslog to UDP port `1514` on the host
running the backend. On OPNsense: *System → Settings → Logging / Targets*, add a
remote target with the **Filter** facility selected.

**Pi-hole** (optional) — set `PIHOLE_URL` (comma-separated for several) and
`PIHOLE_PASSWORD` in `.env`. Polling starts from the newest query, so history is
not replayed.

**GeoIP/ASN enrichment** (recommended) — download the free DB-IP Lite databases
into `backend/data/geoip/`. See [docs/GEOIP.md](docs/GEOIP.md). Without them the
platform still runs; enrichment-based suppression just has less to work with.

### 5. Create your account

```bash
curl -X POST http://localhost:28819/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<choose-one>","role":"admin"}'
```

Then open the dashboard and log in. Roles are `admin`, `analyst`, `viewer`.

---

## LLM triage (optional)

Off by default. Everything alerts without it; turning it on adds classification,
a written incident summary, a containment recommendation, and an escalation
decision on top of alerts that already exist.

```bash
# .env
LLM_ENABLED=true
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL=claude-opus-5-5
LLM_EFFORT=medium          # low | medium | high | xhigh | max
```

Events are batched for 30 seconds before a call, deduplicated per
(source, destination) pair, and capped by a concurrency semaphore, so cost
tracks the number of *distinct* alerts rather than the event rate. The model
can call a `search_web` tool (via a SearXNG instance you point it at with
`network.searxng_urls`) to look up unfamiliar IPs and ASNs before classifying
them.

**Other providers.** Set `LLM_PROVIDER` to `ollama`, `openai`, or anything else
speaking the OpenAI `/chat/completions` shape, plus `LLM_BASE_URL` and a key.
A `LLM_FALLBACK_PROVIDER` chain is supported for both triage and chat.

---

## Configuration reference

| File | What lives there |
|---|---|
| `.env` | Secrets and host-specific overrides (git-ignored) |
| `backend/config.yaml` | Network topology, detector thresholds, feed URLs, LLM settings |
| `frontend/src/app/config/network.config.ts` | How the dashboard labels your addresses |

Every YAML value can be overridden by an environment variable. See
[docs/INSTALL.md](docs/INSTALL.md) to set it up end to end,
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the full variable table, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the pipeline, detector list,
database schema, and API surface.

Detector thresholds worth tuning first:

| Detector | Default | Variable |
|---|---|---|
| Outbound volume | 100 MB/min | `ANALYTICS_VOLUME_THRESHOLD` |
| DGA Shannon entropy | 4.0 | `ANALYTICS_ENTROPY_THRESHOLD` |
| Port scan distinct ports | 20 | `ANALYTICS_PORT_SCAN` |
| Beaconing min repetitions | 10 | `ANALYTICS_BEACON_MIN` |
| Alert dedup window | 30 min | `analytics.cooldown.alert_dedup_seconds` |

---

## Security notes

- **No secrets in the repository.** Keys are read from the environment or
  `.env`, which is git-ignored. `JWT_SECRET` has no default: unset, the server
  generates an ephemeral one and logs a warning, so sessions reset on restart.
- **Bind it to your LAN.** There is no TLS termination in the stack; put it
  behind your own reverse proxy if you expose it beyond the local network.
- **Pi-hole polling skips TLS verification** by design, since v6 instances use
  self-signed certificates on a trusted segment. Review this if that assumption
  does not hold for you.
- **The database holds network metadata** — who talked to whom, when. Treat it
  as sensitive and keep `backend/data/` out of backups you share.

---

## Project layout

```
backend/
  ueba/
    app.py              FastAPI app, REST + WebSocket
    engine.py           pipeline: intake → detect → suppress → alert
    netconfig.py        the only module that knows your addresses
    config.py           YAML + env configuration
    credentials.py      secret resolution (env / .env)
    llm_client.py       Anthropic + OpenAI-compatible clients
    triage.py           batched LLM triage
    chat.py             analyst chat (SSE)
    analytics/          detectors, ML models, policies, playbooks
    ingestion/          syslog listener, firewall parser, Pi-hole poller
    intelligence/       threat feeds, IOC matcher, GeoIP enrichment
  config.yaml           network topology + thresholds
  scripts/              start / stop / healthcheck / systemd unit
frontend/               Angular 18 dashboard
nginx/                  reverse-proxy config for the compose stack
docs/                   install, architecture, configuration, GeoIP, feeds
```

## Author

Mark Sherman — [@mshermancyber](https://github.com/mshermancyber)

Issues and pull requests: <https://github.com/mshermancyber/homelab-analytics>

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

```
UEBA Platform — behavioural analytics for home and lab networks
Copyright (C) 2026  Mark Sherman

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program.  If not, see <https://www.gnu.org/licenses/>.
```
