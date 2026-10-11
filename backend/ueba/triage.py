"""LLM triage integration.

Sends events that already matched threat intelligence or tripped a behavioural
detector to an LLM for a second opinion: classification, severity, and an
escalation recommendation.  Alerts are created by local rules first — triage is
post-hoc enrichment and can only upgrade an existing alert, never gate one.

Features:
- Provider-neutral: Anthropic by default, or any OpenAI-compatible endpoint
- Primary → fallback chain: tries primary, then fallback, then gives up cleanly
- Batch window: collects events for a configurable window, then sends one call
- Rate limiting via an asyncio.Semaphore
- Deduplication: (src_ip, dst_ip) pairs share a cooldown
- Tolerant JSON parsing of the model's verdict
- Web-search tool use so the model can look up unfamiliar IPs and domains
"""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Awaitable, Callable, Dict, List, Optional

import httpx

from ueba.logging_config import get_logger
from ueba.config import get_config, LLMConfig
from ueba.credentials import resolve_fallback_llm_key, resolve_llm_key
from ueba.llm_client import (
    MAX_TOOL_ROUNDS,
    SEARCH_TOOL_SPEC,
    BaseLLMClient,
    LLMRefusal,
    LLMUnavailable,
    build_client,
    extract_json,
)
from ueba.netconfig import host_notes_prompt, net, network_name, searxng_urls

logger = get_logger(__name__)

# Re-exported for ueba.chat
SEARCH_TOOL = SEARCH_TOOL_SPEC
__all__ = [
    "LLMTriage",
    "SEARCH_TOOL",
    "MAX_TOOL_ROUNDS",
    "build_triage_system_prompt",
    "searxng_search",
]


TRIAGE_PROMPT_TEMPLATE = """You are a Tier-2 SOC Incident Responder and Cyber Threat Intelligence analyst operating as an automated triage engine for a UEBA platform. You receive pre-filtered events that have already matched threat intelligence IOCs or triggered behavioral anomaly detectors — normal traffic never reaches you.

## Your role
Analyze each event, determine if it represents a real threat to the network, classify it, and decide whether to escalate to the human operator. You are the last gate before a human gets paged — be accurate, not alarmist.

## Context: {network_name}, monitored subnets {lan_cidrs}
- LAN hosts sit behind a firewall with local DNS filtering
- Private IP ranges (10.x, 172.16-31.x, 192.168.x) are internal LAN devices
- The operator runs self-hosted services — some unusual traffic patterns are expected
- The DNS filter blocks ads and trackers by default — a blocked query is not always malicious
{known_hosts}
### How to assess unknown external IPs — USE THE ENRICHMENT DATA:
Each event includes IP enrichment with org, ASN, and reverse DNS. Use that to reason:
- If enrichment shows the org is a CDN (Fastly, Cloudflare, Akamai, AWS, Google, Microsoft, Apple), beaconing is app polling, NOT C2. C2 servers don't run on major CDN infrastructure.
- If enrichment shows a DNS provider, or reverse DNS contains "dns", "ns", "resolver", "root-servers" — it's DNS infrastructure, not a threat.
- If the destination is a well-known tech company by org/ASN, mobile beaconing is normal app behavior.
- Only flag beaconing as C2 when the destination has NO enrichment (unknown org), is hosted on a suspicious ASN (bulletproof hosting, small VPS providers), or matches a threat feed IOC.

### What is NOT suspicious:
- Mobile devices beaconing to CDN/app infrastructure — apps poll their backends constantly
- A host whose job is crawling or scraping connecting to many unique IPs
- Blocked inbound on the WAN interface from random IPs — internet background noise, only flag on an IOC match

## What you receive
Each event includes:
- **ip_enrichment**: GeoIP/ASN data for each IP in the event. This tells you WHO OWNS the IP — org name, ASN, reverse DNS, country. USE THIS to decide if a destination is legitimate infrastructure or suspicious. Real C2 servers use bulletproof hosting, unknown VPS providers, or residential IPs — not major CDNs and cloud platforms.
- **threat_matches**: IOC hits from real threat feeds (abuse.ch, Spamhaus, CISA KEV, PhishTank, etc.). If present, the IP/domain is in a known-bad list.
- **behavioral_flags**: anomaly detections. Types:
  - `unknown_source` — external IP never seen before connecting inbound
  - `dga` — DNS query for a high-entropy domain (potential domain generation algorithm)
  - `port_scan` — one source probing many ports on a target
  - `beaconing` — regular-interval callbacks to the same external IP (C2 pattern)
  - `volume` — unusually high outbound data transfer from one host
  - `dest_fanout` — one host connecting to many unique external IPs rapidly (worm, exfil, or scanning)
  - `blocked_repeat` — same client repeatedly trying to reach a blocked domain
  - `dns_query_burst` — one client querying many unique domains in a short window (DGA cycling, DNS exfil)
  - `dns_unknown_burst` — one client querying many domains not in the Tranco top-1M (unusual for normal browsing)

## Triage logic
Apply these rules in order:

**CRITICAL — escalate immediately:**
- IOC match on a CISA KEV entry (actively exploited vulnerability indicator)
- Beaconing to a known C2 IP/domain
- IOC match + behavioral flag on the same host (correlation = high confidence)
- Active data exfiltration pattern (high volume out + dest_fanout or dns_query_burst)

**HIGH — escalate:**
- IOC match against malware/ransomware feeds (Feodo, ThreatFox, MalwareBazaar)
- Port scan from an external unknown source targeting internal hosts
- DGA detection + repeated blocked queries from the same client (malware trying to phone home)

**MEDIUM — escalate only if correlated with other signals:**
- Single IOC match against a reputation feed (blocklist.de, Spamhaus DROP) — could be stale
- Unknown source connecting inbound on a non-standard port
- DNS unknown burst without other signals (could be a new app or service)

**LOW / INFO — do NOT escalate:**
- Single blocked DNS query to a phishing URL (the DNS filter already blocked it)
- IOC match only against phishtank/openphish with no behavioral signal (user clicked a link, it was blocked)
- Unknown source on common ports (80, 443) with no follow-up activity (internet noise)
- Volume anomaly alone without other signals (could be a backup job or an update)

## Response format
Return ONLY valid JSON — no prose, no code fences. The response must be a JSON object with key "events" containing an array of assessments, one per input event, in the same order.

Each assessment must have exactly these fields:
- escalate (bool): true ONLY if this needs immediate human attention per the rules above
- threat_classification (string): specific classification, e.g. "C2 callback", "ransomware IOC", "port reconnaissance", "DNS tunneling suspect", "inbound probe", "data exfiltration"
- severity (string): one of "critical", "high", "medium", "low", "info"
- offending_host (string): the IP most likely compromised or attacking — for inbound threats the source, for outbound the internal host
- incident_summary (string): 1-2 sentence summary a SOC analyst can act on. Include the specific IOC or pattern that triggered the alert.
- recommended_containment (string): concrete action — "block IP X at the firewall", "isolate host Y", "add domain Z to the DNS blocklist", "investigate host A for malware", or "monitor — no action needed"
- confidence (int 0-100): your confidence this is a true positive. Be honest — 40-60 for single weak signals, 70-85 for correlated signals, 90+ only for clear IOC matches with behavioral confirmation

Do NOT over-escalate. A false positive that pages the operator at 3am is worse than a medium-severity event logged for morning review.

## Tools available
You have a `search_web` tool. Use it to look up any IP, domain, or ASN you're uncertain about — for example "whois 203.0.113.10" or "AS13335 owner" — before classifying it. A 10-second lookup beats a false positive. If ip_enrichment is missing or sparse for a key IP, always search before calling it malicious."""


def build_triage_system_prompt() -> str:
    """Render the triage prompt for the configured network."""
    notes = host_notes_prompt()
    known_hosts = (
        f"\n### Known hosts (do NOT flag as suspicious):\n{notes}\n" if notes else "\n"
    )
    return TRIAGE_PROMPT_TEMPLATE.format(
        network_name=network_name(),
        lan_cidrs=", ".join(net().lan_cidrs) or "unspecified",
        known_hosts=known_hosts,
    )


async def searxng_search(query: str) -> str:
    """Execute a search via the configured SearXNG instances."""
    instances = searxng_urls()
    if not instances:
        return "Search unavailable (no SearXNG instance configured)"
    for base_url in instances:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{base_url.rstrip('/')}/search",
                    params={"q": query, "format": "json", "categories": "general"},
                )
                if resp.status_code != 200:
                    continue
                results = resp.json().get("results", [])[:5]
                if not results:
                    continue
                return "\n".join(
                    f"- {r.get('title', '')}: {r.get('content', '')[:200]}"
                    for r in results
                )
        except Exception:
            continue
    return "Search unavailable"


async def _tool_handler(name: str, args: Dict[str, Any]) -> str:
    """Dispatch a model tool call."""
    if name == SEARCH_TOOL_SPEC["name"]:
        query = str(args.get("query", "")).strip()
        if not query:
            return "No query supplied"
        logger.info("LLM searching", extra={"extra_data": {"query": query}})
        return await searxng_search(query)
    return f"Unknown tool: {name}"


# Backwards-compatible private alias used by ueba.chat
_searxng_search = searxng_search


class LLMTriage:
    """Manages LLM triage with batching, rate limiting, deduplication,
    and a primary→fallback provider chain."""

    def __init__(self):
        self.config = get_config()
        self.primary_client: Optional[BaseLLMClient] = None
        self.fallback_client: Optional[BaseLLMClient] = None
        self.semaphore = asyncio.Semaphore(
            self.config.analytics.cooldown.get("llm_rate_limit", 3)
        )
        self._api_key: Optional[str] = None
        self.provider = self.config.llm.provider

        # Batch collection
        self._batch: List[dict] = []
        self._batch_lock = asyncio.Lock()
        self._batch_task: Optional[asyncio.Task] = None
        self._batch_event = asyncio.Event()

        # Deduplication cache: {src_ip: {dst_ip: expires_at}}
        self._dedup_cache: Dict[str, Dict[str, datetime]] = {}
        self._dedup_lock = asyncio.Lock()

        # Callback for results
        self.result_callback: Optional[Callable[[dict], Awaitable[None]]] = None

        self._running = False
        self._initialized = False

    async def initialize(self):
        """Build the primary and optional fallback clients.

        A missing SDK or credential is logged and leaves the client unset — the
        pipeline keeps running on local rules alone.
        """
        if self._initialized:
            return

        self._api_key = await resolve_llm_key()

        try:
            self.primary_client = build_client(self.config.llm, self._api_key, timeout=120.0)
            logger.info("LLM primary client initialized", extra={
                "extra_data": {"provider": self.config.llm.provider,
                               "model": self.config.llm.model}
            })
        except LLMUnavailable as exc:
            logger.warning("LLM primary client unavailable", extra={
                "extra_data": {"reason": str(exc)}
            })
            self.primary_client = None
        except Exception as exc:
            logger.error("Failed to initialize primary LLM client", extra={
                "extra_data": {"error": str(exc)}
            })
            self.primary_client = None

        self.fallback_client = None
        if self.config.llm.fallback_provider:
            fallback_config = self._fallback_config()
            try:
                self.fallback_client = build_client(
                    fallback_config, await resolve_fallback_llm_key(), timeout=120.0
                )
                logger.info("LLM fallback client initialized", extra={
                    "extra_data": {"provider": fallback_config.provider,
                                   "model": fallback_config.model}
                })
            except LLMUnavailable as exc:
                logger.warning("LLM fallback client unavailable", extra={
                    "extra_data": {"reason": str(exc)}
                })
            except Exception as exc:
                logger.error("Failed to initialize fallback LLM client", extra={
                    "extra_data": {"error": str(exc)}
                })

        self._initialized = True

    def _fallback_config(self) -> LLMConfig:
        """Derive an LLMConfig for the fallback provider from the primary one."""
        llm = self.config.llm
        return LLMConfig(
            provider=llm.fallback_provider,
            model=llm.fallback_model or llm.model,
            base_url=llm.fallback_base_url,
            temperature=llm.temperature,
            max_tokens=llm.max_tokens,
            effort=llm.effort,
            server_side_fallback=llm.server_side_fallback,
            api_key=llm.fallback_api_key,
        )

    async def _clean_dedup_cache(self):
        """Remove expired dedup entries."""
        now = datetime.now(timezone.utc)
        async with self._dedup_lock:
            expired_src = []
            for src_ip, dst_map in self._dedup_cache.items():
                expired_dst = [dst for dst, expires in dst_map.items() if now >= expires]
                for dst in expired_dst:
                    del dst_map[dst]
                if not dst_map:
                    expired_src.append(src_ip)
            for src in expired_src:
                del self._dedup_cache[src]

    async def is_duplicate(self, src_ip: str, dst_ip: str) -> bool:
        """Check if (src_ip, dst_ip) pair is within the cooldown window."""
        await self._clean_dedup_cache()
        async with self._dedup_lock:
            if src_ip in self._dedup_cache and dst_ip in self._dedup_cache[src_ip]:
                expires = self._dedup_cache[src_ip][dst_ip]
                if datetime.now(timezone.utc) < expires:
                    return True
        return False

    async def record_dedup(self, src_ip: str, dst_ip: str):
        """Record a dedup entry."""
        cooldown = self.config.analytics.cooldown.get("alert_dedup_seconds", 600)
        expires = datetime.now(timezone.utc) + timedelta(seconds=cooldown)
        async with self._dedup_lock:
            self._dedup_cache.setdefault(src_ip, {})[dst_ip] = expires

    async def submit_event(self, event_data: dict, threat_matches: List[dict],
                           behavioral_flags: List[dict],
                           enrichment: Optional[Dict] = None,
                           alert_id: Optional[int] = None) -> bool:
        """Submit an event for LLM triage.

        Returns True if submitted, False if deduplicated.
        """
        await self.initialize()

        parsed = event_data.get("parsed_fields")
        if isinstance(parsed, dict) and parsed.get("src_ip"):
            src_ip = parsed["src_ip"]
            dst_ip = parsed.get("dst_ip", "")
        else:
            src_ip = event_data.get("source_ip", "unknown")
            dst_ip = parsed.get("dst_ip", "") if isinstance(parsed, dict) else ""

        if await self.is_duplicate(src_ip, dst_ip):
            logger.debug("Event deduplicated for LLM triage", extra={
                "extra_data": {"src_ip": src_ip, "dst_ip": dst_ip}
            })
            return False

        await self.record_dedup(src_ip, dst_ip)

        triage_event = {
            "event": event_data,
            "threat_matches": threat_matches,
            "behavioral_flags": behavioral_flags,
            "enrichment": enrichment or {},
            "alert_id": alert_id,
        }

        async with self._batch_lock:
            self._batch.append(triage_event)
            self._batch_event.set()

        return True

    async def _batch_processor(self):
        """Background task that collects events and sends batch prompts."""
        batch_window = self.config.analytics.cooldown.get("llm_batch_window_seconds", 30)

        while self._running:
            try:
                try:
                    await asyncio.wait_for(self._batch_event.wait(), timeout=batch_window)
                except asyncio.TimeoutError:
                    pass  # Batch window expired

                self._batch_event.clear()

                async with self._batch_lock:
                    if not self._batch:
                        continue
                    batch = self._batch[:]
                    self._batch.clear()

                await self._process_batch(batch)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Batch processor error", extra={"extra_data": {"error": str(e)}})
                await asyncio.sleep(5)

    async def _process_batch(self, batch: List[dict]):
        """Process a batch of events through the primary→fallback chain."""
        if not self.primary_client and not self.fallback_client:
            logger.warning("No LLM clients available, skipping batch")
            await self._emit_errors(batch, "No LLM client available")
            return

        clients_to_try = []
        if self.primary_client:
            clients_to_try.append((self.primary_client, "primary"))
        if self.fallback_client:
            clients_to_try.append((self.fallback_client, "fallback"))

        async with self.semaphore:
            for client, label in clients_to_try:
                try:
                    await self._call_llm(client, batch, label)
                    return  # Success — don't try fallback
                except LLMRefusal as exc:
                    logger.warning("LLM declined the batch", extra={
                        "extra_data": {"provider": label, "category": exc.category}
                    })
                except Exception as e:
                    logger.warning("LLM call failed, trying next provider", extra={
                        "extra_data": {"provider": label, "error": str(e)}
                    })

            logger.error("All LLM providers failed for batch", extra={
                "extra_data": {"batch_size": len(batch)}
            })
            await self._emit_errors(batch, "All LLM providers unavailable")

    async def _emit_errors(self, batch: List[dict], message: str):
        for item in batch:
            await self._emit_result({
                "event": item["event"],
                "alert_id": item.get("alert_id"),
                "analysis": None,
                "error": message,
            })

    @staticmethod
    def _build_prompt(batch: List[dict]) -> str:
        """Serialize a batch into the user turn."""
        events_json = []
        for i, item in enumerate(batch):
            enrichment_summary = {}
            for ip, data in (item.get("enrichment") or {}).items():
                if isinstance(data, dict):
                    enrichment_summary[ip] = {
                        k: v for k, v in {
                            "org": data.get("org"),
                            "isp": data.get("isp"),
                            "asn": data.get("asn"),
                            "country": data.get("country"),
                            "reverse_dns": data.get("reverse_dns"),
                        }.items() if v
                    }
            events_json.append({
                "event_index": i,
                "event_type": item["event"].get("event_type", "unknown"),
                "source_ip": item["event"].get("source_ip", "unknown"),
                "raw_message": item["event"].get("raw_message", "")[:500],
                "parsed_fields": item["event"].get("parsed_fields"),
                "ip_enrichment": enrichment_summary,
                "threat_matches": [
                    {"feed": m.get("feed"), "category": m.get("threat_category"),
                     "severity": m.get("severity_hint"), "ioc": m.get("ioc_value")}
                    for m in item.get("threat_matches", [])
                ],
                "behavioral_flags": [
                    {"type": f.get("flag_type"), "details": f.get("details")}
                    for f in item.get("behavioral_flags", [])
                ],
            })
        return json.dumps({"events": events_json}, indent=2)

    async def _call_llm(self, client: BaseLLMClient, batch: List[dict], label: str):
        """Execute a single LLM call for a batch and emit the assessments."""
        content = await client.complete(
            system=build_triage_system_prompt(),
            user_content=self._build_prompt(batch),
            tools=[SEARCH_TOOL_SPEC],
            tool_handler=_tool_handler,
        )

        logger.debug("LLM response", extra={
            "extra_data": {"content": (content or "")[:500], "provider": label}
        })

        result = extract_json(content)
        if result is None:
            logger.error("LLM returned unparseable JSON", extra={
                "extra_data": {"content": (content or "")[:500], "provider": label}
            })
            await self._emit_errors(batch, "Invalid JSON response from LLM")
            return

        assessments = result.get("events", [result])
        if isinstance(assessments, dict):
            assessments = [assessments]

        for i, item in enumerate(batch):
            assessment = assessments[i] if i < len(assessments) else None
            await self._emit_result({
                "event": item["event"],
                "threat_matches": item.get("threat_matches", []),
                "behavioral_flags": item.get("behavioral_flags", []),
                "analysis": assessment,
                "alert_id": item.get("alert_id"),
                "error": None if assessment else "No assessment returned",
            })

    async def _emit_result(self, result: dict):
        """Emit a triage result via the result callback."""
        try:
            analysis = result.get("analysis")
            if analysis and isinstance(analysis, dict):
                result["normalized"] = {
                    "escalate": analysis.get("escalate", False),
                    "threat_classification": analysis.get("threat_classification", "unknown"),
                    "severity": analysis.get("severity", "info"),
                    "offending_host": analysis.get("offending_host", ""),
                    "incident_summary": analysis.get("incident_summary", ""),
                    "recommended_containment": analysis.get("recommended_containment", ""),
                    "confidence": analysis.get("confidence", 50),
                }
            elif result.get("error"):
                result["normalized"] = {
                    "escalate": False,
                    "threat_classification": "triage_error",
                    "severity": "info",
                    "offending_host": "",
                    "incident_summary": result["error"],
                    "recommended_containment": "",
                    "confidence": 0,
                }

            if self.result_callback:
                await self.result_callback(result)
        except Exception as e:
            logger.error("Result callback failed", extra={"extra_data": {"error": str(e)}})

    async def start(self):
        """Start the batch processor."""
        await self.initialize()
        self._running = True
        self._batch_task = asyncio.create_task(self._batch_processor())
        logger.info("LLM triage started", extra={
            "extra_data": {"provider": self.provider, "model": self.config.llm.model}
        })

    async def stop(self):
        """Stop the batch processor and flush remaining events."""
        self._running = False
        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass

        async with self._batch_lock:
            if self._batch:
                logger.info("Flushing remaining batch events", extra={
                    "extra_data": {"count": len(self._batch)}
                })
                batch = self._batch[:]
                self._batch.clear()
                await self._process_batch(batch)

        for client in (self.primary_client, self.fallback_client):
            if client:
                await client.close()
        logger.info("LLM triage stopped")

    async def health_check(self) -> dict:
        """Return health status of the LLM integration."""
        return {
            "initialized": self._initialized,
            "has_api_key": bool(self._api_key),
            "has_primary_client": self.primary_client is not None,
            "has_fallback_client": self.fallback_client is not None,
            "provider": self.provider,
            "model": self.config.llm.model,
            "fallback_provider": self.config.llm.fallback_provider or None,
            "batch_queue_depth": len(self._batch),
            "running": self._running,
        }
