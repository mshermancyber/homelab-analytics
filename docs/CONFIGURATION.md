# Configuration

Three places hold settings, and they do not overlap:

| File | Contents | In git? |
|---|---|---|
| `.env` | Secrets and host-specific overrides | **no** (ignored) |
| `backend/config.yaml` | Network topology, thresholds, feeds, LLM settings | yes |
| `frontend/src/app/config/network.config.ts` | How the dashboard labels addresses | yes |

Precedence, highest first:

1. Real environment variables (systemd `EnvironmentFile`, Docker, your shell)
2. `.env` — loaded into the environment at startup by `ueba/dotenv.py`
3. `backend/config.yaml`
4. Dataclass defaults in `ueba/config.py`

`.env` is searched at `$UEBA_ENV_FILE`, then `backend/.env`, then the repository
root `.env`.

## Environment-specific blocks

`config.yaml` may carry `env_<name>` blocks that are deep-merged over the base
when `UEBA_ENV=<name>` is set:

```yaml
analytics:
  thresholds:
    port_scan_distinct_ports: 20

env_dev:
  analytics:
    thresholds:
      port_scan_distinct_ports: 5   # noisier, for testing
```

## Network topology

The `network:` block in `config.yaml`. Every detector, SQL filter and LLM prompt
reads from here, so this is the one section you must set.

| Key | Env var | Meaning |
|---|---|---|
| `name` | `UEBA_NETWORK_NAME` | Friendly name used in labels and prompts |
| `lan_cidrs` | `UEBA_LAN_CIDRS` | Subnets treated as internal. Add every monitored network |
| `gateway_ips` | `UEBA_GATEWAY_IPS` | Router / firewall addresses; never flagged as sources |
| `dns_servers` | `UEBA_DNS_SERVERS` | Local resolvers (Pi-hole etc.) |
| `static_wan_ips` | `UEBA_WAN_IPS` | Known own public addresses. Leave empty — discovered at runtime |
| `infra_hosts` | `UEBA_INFRA_HOSTS` | Hosts that are noisy by design; behavioural-only alerts suppressed, IOC matches kept |
| `dns_burst_whitelist` | `UEBA_DNS_BURST_WHITELIST` | Hosts exempt from DNS burst detectors |
| `own_hostnames` | `UEBA_OWN_HOSTNAMES` | Your dynamic-DNS names, excluded from DynDNS and low-reputation-TLD rules |
| `searxng_urls` | `UEBA_SEARXNG_URLS` | SearXNG instances for the LLM's web-search tool. Empty disables search |
| `reputable_orgs` | `UEBA_REPUTABLE_ORGS` | GeoIP org fragments treated as reputable during suppression |
| `host_notes` | — | `{address: description}` notes handed to the LLM as "known hosts" |

List-valued environment variables are comma-separated:

```bash
UEBA_LAN_CIDRS=192.168.1.0/24,10.10.0.0/16
UEBA_GATEWAY_IPS=192.168.1.1
```

### A note on CIDR prefixes

`is_internal()` does proper network containment, so any prefix length works. A
few SQL queries pre-filter with a `LIKE` pattern, which can only express octet
boundaries — a `/25` is widened to its `/24` for that pre-filter and the exact
check still decides. Nothing is mislabelled; the query just reads a few extra
rows.

### `host_notes` and LLM quality

`host_notes` is the cheapest accuracy win available when triage is enabled. Tell
the model what a host legitimately does and it stops classifying that behaviour
as a threat:

```yaml
network:
  host_notes:
    "192.168.1.1": "Router/firewall. All traffic transits here. Never suspicious."
    "192.168.1.20": "Build server; scrapes package registries. High destination fanout is normal."
    "192.168.1.31": "Phone. Social-media app beaconing to CDN ranges is expected."
```

## Detector thresholds

| Setting | Default | Env var |
|---|---|---|
| `outbound_volume_bytes_per_minute` | 100 MB | `ANALYTICS_VOLUME_THRESHOLD` |
| `high_entropy_shannon_threshold` | 4.0 | `ANALYTICS_ENTROPY_THRESHOLD` |
| `blocked_query_repeat_threshold` | 5 | `ANALYTICS_BLOCKED_REPEAT` |
| `port_scan_distinct_ports` | 20 | `ANALYTICS_PORT_SCAN` |
| `beaconing_interval_tolerance_seconds` | 3 | `ANALYTICS_BEACON_TOLERANCE` |
| `beaconing_min_repetitions` | 10 | `ANALYTICS_BEACON_MIN` |
| `volumetric_threshold` (DDoS, blocked/min) | 200 | `ANALYTICS_VOLUMETRIC_THRESHOLD` |
| `dns_amplification_threshold` (queries/min) | 50 | `ANALYTICS_DNS_AMPLIFICATION_THRESHOLD` |
| `baseline_window_days` | 30 | `ANALYTICS_BASELINE_DAYS` |
| `sigmoid_midpoint` / `sigmoid_steepness` | 5.0 / 2.0 | `ANALYTICS_SIGMOID_MIDPOINT` / `_STEEPNESS` |

Cooldowns live under `analytics.cooldown`: `alert_dedup_seconds` (1800),
`llm_rate_limit` (3 concurrent calls), `llm_batch_window_seconds` (30).

**Tuning order that works:** run for a day, sort the alert history by
classification, and raise the threshold on whatever dominates. Mark the rest as
false positives in the UI so the learned patterns handle them.

## LLM

| Setting | Env var | Default |
|---|---|---|
| `enabled` | `LLM_ENABLED` | `false` |
| `provider` | `LLM_PROVIDER` | `anthropic` |
| `model` | `LLM_MODEL` | `claude-opus-5-5` |
| `effort` | `LLM_EFFORT` | `medium` |
| `max_tokens` | `LLM_MAX_TOKENS` | `16000` |
| `base_url` | `LLM_BASE_URL` | provider default |
| `temperature` | `LLM_TEMPERATURE` | `0.1` (OpenAI-compatible only) |
| `server_side_fallback` | `LLM_SERVER_SIDE_FALLBACK` | `true` |
| `fallback_provider` | `LLM_FALLBACK_PROVIDER` | unset |
| `fallback_model` | `LLM_FALLBACK_MODEL` | unset |
| `fallback_base_url` | `LLM_FALLBACK_BASE_URL` | unset |

API keys come only from the environment or `.env`, never from `config.yaml`:
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or the provider-agnostic `LLM_API_KEY`
(plus `LLM_FALLBACK_API_KEY`).

**`effort`** sets reasoning depth: `low`, `medium`, `high`, `xhigh`, `max`.
`medium` is a good default for triage; raise it if the model's verdicts on
correlated multi-signal alerts read as shallow. Current Claude models always
think, so `effort` — not `temperature` — is the quality/cost dial, and sampling
parameters are not sent to them at all.

**`server_side_fallback`** re-runs a request on a safe fallback model, inside the
same call, if the primary declines on policy grounds. Network-attack analysis
occasionally trips a safety classifier; this keeps triage flowing instead of
returning nothing. A decline that survives the fallback is logged and the alert
simply keeps its locally-derived severity.

**Switching providers**

```bash
# Local Ollama
LLM_PROVIDER=ollama
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=llama3.1

# Any OpenAI-compatible gateway
LLM_PROVIDER=openai
LLM_BASE_URL=https://your-gateway.example.com/v1
LLM_API_KEY=...
```

## Secrets

| Variable | Required | Purpose |
|---|---|---|
| `JWT_SECRET` | **yes, in production** | Signs dashboard sessions. `openssl rand -hex 32`. Unset ⇒ a random per-process secret and a startup warning; sessions reset on restart |
| `ANTHROPIC_API_KEY` | only with LLM triage | Anthropic API key |
| `LLM_API_KEY` / `OPENAI_API_KEY` | only with those providers | Provider key |
| `PIHOLE_URL` | optional | Comma-separated Pi-hole base URLs |
| `PIHOLE_PASSWORD` | with Pi-hole | Pi-hole web password |
| `ESCALATION_WEBHOOK_URL` | optional | Receives escalated alerts |

## Paths and listeners

| Variable | Default |
|---|---|
| `UEBA_DB_PATH` | `backend/data/ueba.db` |
| `UEBA_DATA_DIR` | `backend/data` |
| `UEBA_ENV_FILE` | `backend/.env`, then `./.env` |
| `SYSLOG_PORT` | `1514` |
| `API_HOST` / `API_PORT` | `0.0.0.0` / `28819` |
| `LOG_LEVEL` | `INFO` |
| `JWT_EXPIRATION_HOURS` | `24` |
| `FEED_REFRESH_INTERVAL` | `21600` (6 h) |
| `FEEDS_LOCAL_DB_PATH` | unset — see [FEEDS.md](FEEDS.md) |

Port 1514 is used instead of 514 so the listener needs no elevated privileges.
To receive on 514, redirect it at the firewall:

```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 1514
```

## Frontend

`frontend/src/app/config/network.config.ts` controls labelling only — nothing
there is secret. Mirror your backend topology and rebuild:

```ts
export const NETWORK_CONFIG: NetworkConfig = {
  name: 'LAN',
  lanPrefixes: ['192.168.1.'],   // used to shorten 192.168.1.42 to ".42"
  wanIps: [],                    // optional: label your public address "WAN"
};
```
