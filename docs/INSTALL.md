# Installation guide

This walks through a complete install, from an empty directory to alerts in the
dashboard. Budget about 30 minutes, most of it waiting for `npm install` and
the first threat-feed download.

Two install paths are covered — pick one:

- **[Docker Compose](#path-a--docker-compose)** — least to go wrong, one command
  to update.
- **[Native + systemd](#path-b--native--systemd)** — easier to tail, easier to
  patch, no container networking in the way of UDP syslog.

Both end up at the same place: backend on `:28819`, dashboard on `:28818`.

---

## Contents

1. [Before you start](#1-before-you-start)
2. [Get the code](#2-get-the-code)
3. [Describe your network](#3-describe-your-network)
4. [Set your secrets](#4-set-your-secrets)
5. [Install the GeoIP databases](#5-install-the-geoip-databases)
6. [Install and run](#6-install-and-run)
7. [Create your account](#7-create-your-account)
8. [Connect your firewall](#8-connect-your-firewall)
9. [Connect Pi-hole](#9-connect-pi-hole-optional)
10. [Verify the install](#10-verify-the-install)
11. [Optional extras](#11-optional-extras)
12. [The first 24 hours](#12-the-first-24-hours)
13. [Upgrading](#13-upgrading)
14. [Uninstalling](#14-uninstalling)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Before you start

### Hardware

| | Minimum | Comfortable |
|---|---|---|
| CPU | 2 cores | 4 cores |
| RAM | 2 GB | 4 GB+ |
| Disk | 10 GB | 40 GB+ |

The ML detectors (IsolationForest, autoencoder, PageRank graph) retrain on a
schedule and are the only real CPU consumers; between runs the process idles.

**On disk:** the database is the thing that grows. A busy home link produces
hundreds of thousands of firewall rows a day, and the database reaches several
gigabytes within weeks. A background pruner deletes the oldest events once the
file passes **30 GB** — hardcoded in `backend/ueba/engine.py` (`_storage_pruner`,
`max_bytes`), so edit it there if your disk is smaller. Plan for 30 GB plus the
write-ahead log, which can add a few more.

### Software

| Need | Version | Why |
|---|---|---|
| Python | 3.12+ | Backend |
| Node.js | 20+ | Builds the dashboard (not needed at runtime) |
| Docker + Compose | recent | Path A only |
| `curl`, `git` | any | Setup steps |

### Data sources

At least one of:

- **A firewall that forwards syslog** in OPNsense/pfSense `filterlog` CSV
  format. This is the primary source — connection flows are what most
  detectors read.
- **Pi-hole v6** (one or more) for DNS queries, which feed the DNS detectors:
  DGA, tunnelling, beaconing, per-host profiling, Sigma DNS rules.

With only Pi-hole you get the DNS half; with only the firewall you get flows but
no DNS correlation. Both is the design target.

### Where to run it

On the LAN it is monitoring, reachable by the firewall over UDP. **Do not expose
it to the internet.** There is no TLS in the stack and `/api/auth/register` is
deliberately open so you can create the first account — see
[step 7](#7-create-your-account).

---

## 2. Get the code

```bash
git clone https://github.com/mshermancyber/homelab-analytics.git
cd homelab-analytics
```

Everything below runs from that directory.

---

## 3. Describe your network

**This is the step that matters.** Nothing in the tree hardcodes an address;
detectors, SQL filters and LLM prompts all read the `network:` block. Get it
wrong and either everything looks external, or nothing does.

Edit `backend/config.yaml`:

```yaml
network:
  name: "LAN"                      # appears in labels and LLM prompts

  lan_cidrs:                       # every subnet you monitor
    - "192.168.1.0/24"

  gateway_ips:                     # router / firewall — never flagged as a source
    - "192.168.1.1"

  dns_servers:                     # Pi-hole or other local resolvers
    - "192.168.1.10"

  own_hostnames:                   # your dynamic-DNS name, so it never alerts
    - "myhost.example-ddns.net"

  infra_hosts: []                  # see below
  static_wan_ips: []               # leave empty — discovered at runtime
```

**`lan_cidrs`** takes any prefix length and accepts several entries — list every
VLAN you monitor, including guest and IoT networks if their traffic reaches the
firewall log.

**`infra_hosts`** is the one to come back to. Put hosts here whose *job* is to
look suspicious: a machine that scrapes package registries or threat feeds, a CI
runner, a crawler. They legitimately fan out to hundreds of destinations and
beacon to the same endpoints on a timer. Listing them suppresses
behavioural-only alerts from them while keeping every threat-feed IOC match. You
will know which hosts belong here after a day of running — leave it empty for
now.

**`host_notes`** is optional and only matters with LLM triage on, where it is the
cheapest accuracy win available:

```yaml
  host_notes:
    "192.168.1.1": "Router/firewall. All traffic transits here. Never suspicious."
    "192.168.1.20": "Build server; pulls from package registries all day."
    "192.168.1.31": "Phone. App beaconing to CDN ranges is expected."
```

Then mirror the display settings for the dashboard in
`frontend/src/app/config/network.config.ts`:

```ts
export const NETWORK_CONFIG: NetworkConfig = {
  name: 'LAN',
  lanPrefixes: ['192.168.1.'],   // shortens 192.168.1.42 to ".42" in charts
  wanIps: [],                    // optional: label your public address "WAN"
};
```

This file only affects labelling — no detection logic reads it.

> Prefer environment variables (containers, config management)? Every key has a
> `UEBA_*` equivalent that overrides the YAML — see
> [CONFIGURATION.md](CONFIGURATION.md).

---

## 4. Set your secrets

```bash
cp .env.example .env
echo "JWT_SECRET=$(openssl rand -hex 32)" >> .env
```

`.env` is git-ignored and is the only place secrets live. `JWT_SECRET` has no
default: leave it unset and the backend generates a random one per process,
logging a warning — safe, but every dashboard session drops on restart.

Fill in the rest as they become relevant: `PIHOLE_PASSWORD` in
[step 9](#9-connect-pi-hole-optional), `ANTHROPIC_API_KEY` in
[step 11](#11-optional-extras). Nothing else is required to start.

---

## 5. Install the GeoIP databases

Strongly recommended. Enrichment answers "who owns the other end of this
connection", and a large part of the noise suppression depends on the answer.

Download the free [DB-IP Lite](https://db-ip.com/db/lite.php) **City** and
**ASN** databases in MMDB format, then:

```bash
mkdir -p backend/data/geoip
mv ~/Downloads/dbip-city-lite-*.mmdb backend/data/geoip/dbip-city-lite.mmdb
mv ~/Downloads/dbip-asn-lite-*.mmdb  backend/data/geoip/dbip-asn-lite.mmdb
```

The filenames must match exactly. MaxMind GeoLite2 City/ASN work too — rename
them to the same names. They are not shipped in the repository: ~135 MB together,
with their own licence terms. Refresh monthly.

Without them everything still runs; you lose country/ASN fields, the geo
breakdown, reputable-org suppression, and the org context that makes LLM triage
accurate. Details in [GEOIP.md](GEOIP.md).

---

## 6. Install and run

### Path A — Docker Compose

The nginx container serves a pre-built dashboard, so build it once:

```bash
cd frontend
npm install
npx ng build --configuration production
cd ..
```

Then bring the stack up:

```bash
docker compose up -d --build
docker compose logs -f ueba-backend     # watch it come up
```

Compose reads `.env` automatically. Verify:

```bash
curl -s http://localhost:28819/api/health | head -c 200
```

Useful commands:

```bash
docker compose ps
docker compose restart ueba-backend
docker compose down                     # stop (data in backend/data/ survives)
```

> **UDP syslog and Docker.** Port `1514/udp` is published to the host, which is
> enough for a firewall on the same LAN. If packets arrive but nothing is
> ingested, the container is seeing the Docker gateway as the sender rather than
> your firewall — harmless for parsing (real addresses come from the log body,
> not the packet source), but if you want the true sender recorded, add
> `network_mode: host` to the backend service and drop its `ports:` block.

### Path B — Native + systemd

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
```

Run it in the foreground first, to see any configuration complaint immediately:

```bash
./backend/scripts/ueba-start.sh
```

Startup order is: database init → threat feeds (the slow part, a minute or two
on first run) → syslog listener → detectors. When you see the syslog listener
start, it is live. `Ctrl-C` to stop.

Once it starts cleanly, install the bundled user service:

```bash
mkdir -p ~/.config/systemd/user
sed "s|%REPO%|$(pwd)|" backend/scripts/ueba.service > ~/.config/systemd/user/ueba.service
systemctl --user daemon-reload
systemctl --user enable --now ueba
sudo loginctl enable-linger "$USER"     # keep it running after logout
```

```bash
systemctl --user status ueba
journalctl --user -u ueba -f            # logs are JSON, one object per line
```

The unit reads `.env` through `EnvironmentFile=`, sets `Restart=always`, and
calls the same start script.

Then build and serve the dashboard. For development, with live reload and an
API proxy:

```bash
cd frontend
npm install
npx ng serve --port 28818 --host 0.0.0.0 --proxy-config proxy.conf.json
```

For a permanent install, build it and serve the output with your own nginx:

```bash
npx ng build --configuration production
# output: frontend/dist/frontend/browser
```

Point `root` at that directory and proxy `/api/` and `/ws/` to
`127.0.0.1:28819` — `nginx/nginx.conf` is a working example to adapt (it is
written for the container, so change the upstream to `127.0.0.1:28819`).

---

## 7. Create your account

`/api/auth/register` is **unauthenticated** — it has to be, for the first
account. Register yours now, before anything else can reach the port:

```bash
curl -X POST http://localhost:28819/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<a-real-password>","role":"admin"}'
```

The response includes a JWT you can use straight away. Roles are `admin`
(everything, including config), `analyst` (alerts, events, rules, FP marking),
and `viewer` (read-only).

There is no password-strength check and no limit on how many accounts can be
registered, so **treat the API port as trusted-LAN-only** and bind it
accordingly (`API_HOST=127.0.0.1` in `.env` if the dashboard runs on the same
host, with nginx in front).

Open `http://<host>:28818` and log in.

---

## 8. Connect your firewall

Send **filter logs only** to UDP port **1514**. Port 1514 is used instead of 514
so the listener needs no root; if your firewall insists on 514, redirect it:

```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 1514
```

### OPNsense

1. **System → Settings → Logging / Targets → `+`**
2. Transport: `UDP(4)`
3. Applications: select **`filter`** — this is the important field. Leave it
   empty and you get every subsystem's logs, which the parser discards as
   `generic` events while still storing them.
4. Levels: `Informational` and above; Facilities: leave empty
5. Hostname: the IP running the backend; Port: `1514`
6. Tick **Enabled**, then **Save** and **Apply**

Confirm the firewall is actually logging the rules you care about under
**Firewall → Settings → Advanced** (log default blocks / passes as you prefer).
Rules with logging switched off produce nothing to analyse.

Exact labels shift slightly between OPNsense versions; the shape is always
transport, applications, host, port.

### pfSense

**Status → System Logs → Settings → Remote Logging**: enable it, set the server
to `<host>:1514`, and tick **Firewall events** only.

### Confirm packets are arriving

```bash
sudo tcpdump -ni any udp port 1514 -c 5
```

Nothing? The firewall is not sending, or something between you is dropping UDP.
Packets arriving but no events in the dashboard? See
[troubleshooting](#15-troubleshooting).

---

## 9. Connect Pi-hole (optional)

Pi-hole **v6** only — the poller uses the v6 REST API (`/api/auth`, then
`/api/queries` every 10 seconds).

Add to `.env`:

```bash
PIHOLE_URL=http://192.168.1.10
PIHOLE_PASSWORD=your-pihole-web-password
```

Several instances, comma-separated, sharing one password:

```bash
PIHOLE_URL=http://192.168.1.10,http://192.168.1.11
```

Include the scheme, and a port if it is not the default
(`http://192.168.1.10:8080`). Certificate verification is skipped by design,
since v6 instances typically carry self-signed certificates on a trusted
segment.

Restart the backend. In the logs you should see `Pi-hole starting from current
position` — the first poll jumps to the newest query ID, so your existing
history is not replayed as live events. Pi-hole rate-limits authentication; a
`429` triggers a 120-second backoff and a warning, which is normal if you
restart repeatedly.

Also add the resolvers to `network.dns_servers` in `config.yaml` if you have not
already.

---

## 10. Verify the install

### Health

```bash
curl -s http://localhost:28819/api/health | python3 -m json.tool
```

What to look for:

| Field | Expected |
|---|---|
| `status` | `healthy`. `starting` means it is still booting; `stopped` means the engine fell over while the HTTP server stayed up — restart it |
| `syslog_listener.running` | `true`, with the port you configured |
| `syslog_listener.queue_depth` | near `0`. Steadily climbing means workers are stuck |
| `threat_intel.feeds_loaded` | 15–18. A couple of failures are normal — public feeds rate-limit |
| `threat_intel.total_iocs` | hundreds of thousands |
| `pihole_pollers.active` | the number of Pi-hole URLs you configured |
| `llm.initialized` | `false` until you enable triage — expected |

### End-to-end, without waiting for real traffic

Send a synthetic filterlog line — an internal host sweeping ports on another,
which should trip the lateral-movement detector. Replace `192.168.1.x` with
addresses inside your own `lan_cidrs`:

```bash
python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i, port in enumerate(range(3300, 3330)):
    msg = ("<134>Jan  1 00:00:00 fw filterlog[1234]: "
           "5,,,0,igb0,match,pass,out,4,0x0,,64,12345,0,DF,6,tcp,60,"
           f"192.168.1.50,192.168.1.10,{40000+i},{port},0,S,123456,,8192,,mss")
    s.sendto(msg.encode(), ("127.0.0.1", 1514))
s.close()
print("sent 30 events")
EOF
```

Within a few seconds:

```bash
TOKEN=$(curl -s -X POST http://localhost:28819/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your-password>"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s "http://localhost:28819/api/events?limit=3" -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:28819/api/alerts?limit=5" -H "Authorization: Bearer $TOKEN"
```

Events but no alert is still a pass for ingestion — alerting depends on your
thresholds and on `lan_cidrs` containing both addresses. An alert classified
`lateral_movement` means the whole pipeline works: parse → detect → suppress →
alert.

### Dashboard

Log in and check **Live Feed** (events as they arrive, over WebSocket) and
**Threat Intel** (feed status and IOC counts). Those two confirm the browser can
reach both the API and the WebSocket through your proxy.

---

## 11. Optional extras

### LLM triage

Off by default. Everything alerts without it; enabling it adds a classification,
a written incident summary, a containment recommendation and an escalation
decision on top of alerts that already exist. It can only *raise* an alert's
severity — never create, lower or delete one.

```bash
# .env
LLM_ENABLED=true
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL=claude-opus-5-5
LLM_EFFORT=medium          # low | medium | high | xhigh | max
```

Restart, then confirm `llm.initialized` is `true` in `/api/health`. Cost tracks
distinct alerts rather than event volume: events are batched for 30 seconds,
deduplicated per source/destination pair, and capped by a concurrency limit of
three.

Other providers — Ollama, OpenAI, any OpenAI-compatible gateway:

```bash
LLM_PROVIDER=ollama
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=llama3.1
```

### SearXNG web search

Lets the model look up an unfamiliar IP or ASN before classifying it. Point it
at an instance you run:

```yaml
network:
  searxng_urls:
    - "http://192.168.1.10:8080"
```

The instance needs its JSON output format enabled. Empty list disables search,
and triage still works.

### Escalation webhook

```bash
ESCALATION_WEBHOOK_URL=https://hooks.example.com/...
```

Alerts flagged for escalation are POSTed there — Slack, Discord, ntfy, whatever
accepts a JSON webhook.

### Tranco domain list

The single most effective noise filter after GeoIP: it stops popular domains
re-resolving on TTL expiry from looking like DNS beaconing. It comes from the
optional local feeds database — build instructions in [FEEDS.md](FEEDS.md), then:

```yaml
feeds:
  local_db_path: "/path/to/feeds.db"
```

### Stall watchdog

The backend already restarts its own syslog listener after five minutes of
silence. For a belt-and-braces external check that restarts the service only
when *both* sources have gone quiet:

```bash
crontab -e
# */5 * * * * /full/path/to/backend/scripts/ueba-healthcheck.sh >> /tmp/ueba-healthcheck.log 2>&1
```

Test it first with `./backend/scripts/ueba-healthcheck.sh --dry`.

---

## 12. The first 24 hours

**Expect noise early, and do not tune in the first hour.** The platform is
learning what your network normally does.

- **First 500 events** — baseline learning. Novelty flags (`first_seen`,
  `unknown_source`) are suppressed on purpose, because during this window
  everything is new.
- **First few hours** — the network baseline, per-host DNS profiles and
  first-seen history fill in. Alert volume should fall noticeably as the
  reputable-destination and dedup layers get something to work with.
- **After ~15 minutes** — the policy learner runs for the first time, then
  daily. The ML detectors retrain on their own schedules.
- **After a day** — baselines are meaningful. Now tune.

### Tuning, in the order that pays

1. Open **Alert History** and sort by classification. Whatever dominates is your
   problem, and it is usually one host or one detector.
2. If it is a host doing its job (scraper, CI, crawler): add it to
   `network.infra_hosts`.
3. If it is a detector firing too eagerly: raise its threshold — table in
   [CONFIGURATION.md](CONFIGURATION.md).
4. For everything else, hit **FP** on the alert. That records a
   `(source prefix, destination prefix, classification)` pattern and suppresses
   matching events from then on, immediately — no restart.
5. If a destination is reputable but not recognised, add its org name fragment
   to `network.reputable_orgs` (your ISP's consumer ranges are a common one).

The target is single digits per day. If you are still in the hundreds after a
week of this, something in `lan_cidrs` is probably wrong — check that internal
hosts are actually being classified as internal on the **Network** page.

---

## 13. Upgrading

```bash
git pull
```

**Docker:**

```bash
cd frontend && npx ng build --configuration production && cd ..
docker compose up -d --build
```

**Native:**

```bash
. .venv/bin/activate
pip install -r backend/requirements.txt
systemctl --user restart ueba
cd frontend && npm install && npx ng build --configuration production
```

Back up `backend/data/ueba.db` first if you care about the history. There are no
schema migrations in this release: a column added upstream will not appear in an
existing database, so if a release note mentions a schema change, move the old
database aside and let a new one be created.

Your `.env`, `backend/config.yaml` and
`frontend/src/app/config/network.config.ts` are the files you have edited — check
`git status` after pulling and reconcile any conflicts there.

---

## 14. Uninstalling

**Docker:**

```bash
docker compose down -v
```

**Native:**

```bash
systemctl --user disable --now ueba
rm ~/.config/systemd/user/ueba.service
systemctl --user daemon-reload
```

Then remove the directory. Note `backend/data/` holds a record of which hosts on
your network talked to which external addresses, and when — shred it rather than
leaving it on a disk you are passing on.

Remember to turn off the remote syslog target on the firewall.

---

## 15. Troubleshooting

### Nothing is being ingested

| Check | Command |
|---|---|
| Packets arriving at all? | `sudo tcpdump -ni any udp port 1514 -c 5` |
| Listener up? | `curl -s localhost:28819/api/health` → `syslog_listener.running` |
| Events reaching the database? | `GET /api/events?limit=5` |
| Anything in the log? | `journalctl --user -u ueba -n 50` |

Packets arriving but no events: the messages are probably not in filterlog
format. The parser needs the CSV `filterlog` shape and requires at least ten
commas; anything else is stored as a `generic` event and no detector reads it.
Check that you selected the **`filter`** application on the firewall rather than
exporting every subsystem.

### `queue_depth` keeps climbing

Workers are wedged — usually CPU starvation on a shared host. The built-in
watchdog drains the queue and restarts the listener after five minutes of
silence; the cron healthcheck in [step 11](#11-optional-extras) is the next line
of defence. If it recurs constantly, the host is undersized for the log volume.

### Service shows `active` but nothing works

`systemctl is-active` only reports the process, not the engine inside it. If
`/api/health` returns `status: stopped`, the engine shut down while uvicorn
stayed up — `systemctl --user restart ueba`. **Always check `/api/health`, not
just systemd.**

### Far too many alerts

Almost always `lan_cidrs`. If your internal subnet is not listed, internal hosts
are treated as external and nearly every suppression rule stops matching. Verify
on the **Network** page that your hosts appear as internal, then work through
[the tuning order](#12-the-first-24-hours).

### No geo or ASN data on alerts

The MMDB files are missing or misnamed. Check for `DB-IP city database loaded`
in the startup log, and that the filenames are exactly
`backend/data/geoip/dbip-city-lite.mmdb` and `dbip-asn-lite.mmdb`.

### Sessions drop on every restart

`JWT_SECRET` is unset, so a random one is generated per process. Set it in
`.env` ([step 4](#4-set-your-secrets)).

### Pi-hole data never appears

- v6 required — the v5 API is a different shape and will not authenticate
- Check the password by hand:
  `curl -k -X POST http://192.168.1.10/api/auth -H 'Content-Type: application/json' -d '{"password":"..."}'`
- Repeated `429` warnings mean Pi-hole is rate-limiting; wait out the
  120-second backoff rather than restarting in a loop
- Only the newest queries are ingested by design; history is never replayed

### LLM triage does nothing

- `LLM_ENABLED=true` set, and the backend restarted?
- `/api/health` → `llm.initialized` and `llm.has_api_key`
- `LLM client unavailable` in the log means the SDK or the key is missing:
  `pip install -r backend/requirements.txt`, and check `ANTHROPIC_API_KEY`
- Remember triage only runs on events that **already produced an alert**, and
  never on blocked traffic — the firewall handled that already

### Dashboard loads but has no data

The browser is reaching the static files but not the API. With `ng serve`, make
sure `--proxy-config proxy.conf.json` is passed. Behind your own nginx, confirm
`/api/` **and** `/ws/` are both proxied — the Live Feed needs the WebSocket, and
a missing `/ws/` route shows up as an empty feed with a healthy-looking
everything else.

---

Still stuck? [ARCHITECTURE.md](ARCHITECTURE.md) explains what the pipeline does
with an event at each stage, which is usually enough to tell which stage is
dropping yours.
