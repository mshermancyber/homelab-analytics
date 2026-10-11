"""Interactive AI chat for alert investigation with streaming responses.

Provides an SSE streaming endpoint analysts can use to ask questions about
alerts, threats, and security patterns.  Includes web-search tool use, alert
context attachment, per-user rate limiting, and a primary→fallback provider
chain (matching triage.py).
"""
import json
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict, Optional

from sqlalchemy import select

from ueba.logging_config import get_logger
from ueba.config import get_config, LLMConfig
from ueba.credentials import resolve_fallback_llm_key, resolve_llm_key
from ueba.database import async_session_factory
from ueba.llm_client import (
    SEARCH_TOOL_SPEC,
    BaseLLMClient,
    LLMRefusal,
    LLMUnavailable,
    build_client,
)
from ueba.models import Alert
from ueba.netconfig import network_name
from ueba.triage import _tool_handler

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Rate limiter — per-user, 10 queries per minute
# ---------------------------------------------------------------------------
_rate_limits: Dict[str, list] = {}


def _check_rate_limit(user_id: str) -> bool:
    """Return True if the user is within limits, False if rate-limited."""
    now = datetime.now(timezone.utc)
    timestamps = _rate_limits.setdefault(user_id, [])
    # Prune timestamps older than 60 seconds
    timestamps[:] = [t for t in timestamps if (now - t).total_seconds() < 60]
    if len(timestamps) >= 10:
        return False
    timestamps.append(now)
    return True


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
def build_chat_system_prompt() -> str:
    """Chat prompt, named for the monitored network."""
    return (
        f"You are a cybersecurity analyst assistant for the {network_name()} UEBA platform.\n"
        "You help investigate alerts, explain threats, and suggest remediation.\n"
        "You have a web search tool for looking up IPs, domains, and threat intelligence.\n"
        "Be concise and actionable."
    )


# ---------------------------------------------------------------------------
# Alert context loading
# ---------------------------------------------------------------------------
async def _load_alert_context(alert_id: int) -> Optional[str]:
    """Load alert details from the database and format as a context string."""
    try:
        async with async_session_factory() as session:
            result = await session.execute(
                select(Alert).where(Alert.id == alert_id)
            )
            alert = result.scalar_one_or_none()
            if not alert:
                return None

            parts = [
                f"## Alert #{alert.id} Context",
                f"**Severity**: {alert.severity or 'unknown'}",
                f"**Classification**: {alert.classification or 'unknown'}",
                f"**Source IP**: {alert.src_ip or 'unknown'}",
                f"**Destination IP**: {alert.dst_ip or 'unknown'}",
                f"**Destination Domain**: {alert.dst_domain or 'N/A'}",
                f"**Status**: {alert.status or 'open'}",
                f"**Confidence**: {alert.confidence or 'N/A'}",
                f"**Firewall Action**: {alert.firewall_action or 'N/A'}",
                f"**Escalate**: {'yes' if alert.escalate else 'no'}",
            ]

            # Include a previous LLM assessment if one exists
            if alert.llm_analysis and isinstance(alert.llm_analysis, dict):
                analysis = alert.llm_analysis
                inc = (analysis.get("incident_summary")
                       or analysis.get("normalized", {}).get("incident_summary"))
                if inc:
                    parts.append(f"**Previous Analysis**: {inc}")

            # Include threat matches
            if isinstance(alert.threat_matches, list):
                matches = [
                    f"- {m.get('feed')} / {m.get('ioc_value')} ({m.get('threat_category', 'unknown')})"
                    for m in alert.threat_matches[:5] if isinstance(m, dict)
                ]
                if matches:
                    parts.append("**Threat Intel Matches**:\n" + "\n".join(matches))

            # Include behavioral flags
            if isinstance(alert.behavioral_flags, list):
                flags = [
                    f"- {f.get('flag_type')}: {f.get('details', '')}"
                    for f in alert.behavioral_flags[:5] if isinstance(f, dict)
                ]
                if flags:
                    parts.append("**Behavioral Flags**:\n" + "\n".join(flags))

            return "\n\n".join(parts)
    except Exception as e:
        logger.error("Failed to load alert context", extra={
            "extra_data": {"alert_id": alert_id, "error": str(e)}
        })
        return None


# ---------------------------------------------------------------------------
# Streaming chat
# ---------------------------------------------------------------------------
def _fallback_config(primary: LLMConfig) -> LLMConfig:
    """Derive an LLMConfig for the fallback provider."""
    return LLMConfig(
        provider=primary.fallback_provider,
        model=primary.fallback_model or primary.model,
        base_url=primary.fallback_base_url,
        temperature=primary.temperature,
        max_tokens=primary.max_tokens,
        effort=primary.effort,
        server_side_fallback=primary.server_side_fallback,
        api_key=primary.fallback_api_key,
    )


async def _stream_from_client(
    client: BaseLLMClient,
    system: str,
    user_content: str,
    provider_label: str,
) -> AsyncGenerator[str, None]:
    """Yield SSE chunks from one provider.  Raises on provider failure so the
    caller can try the next one."""
    try:
        async for event in client.stream(
            system=system,
            user_content=user_content,
            tools=[SEARCH_TOOL_SPEC],
            tool_handler=_tool_handler,
        ):
            if event["type"] == "text":
                yield f"data: {json.dumps({'content': event['text']})}\n\n"
            elif event["type"] == "tool_call":
                query = str(event.get("input", {}).get("query", ""))
                logger.info("Chat LLM searching", extra={
                    "extra_data": {"query": query, "provider": provider_label}
                })
                notice = f"\n🔍 Searching: {query}...\n"
                yield f"data: {json.dumps({'content': notice})}\n\n"
    except LLMRefusal as exc:
        logger.warning("Chat LLM declined the request", extra={
            "extra_data": {"provider": provider_label, "category": exc.category}
        })
        raise
    except Exception as e:
        logger.warning("Chat LLM provider failed", extra={
            "extra_data": {"provider": provider_label, "error": str(e)}
        })
        raise


async def stream_chat(
    message: str,
    alert_id: Optional[int] = None,
    user_id: str = "anonymous",
) -> AsyncGenerator[str, None]:
    """Async generator that yields SSE-formatted strings from the LLM.

    Tries the configured primary provider, then the fallback provider.

    Yields lines like::

        data: {"content": "chunk text"}\\n\\n
        data: [DONE]\\n\\n
    """
    # 1. Build the user turn, with optional alert context
    user_content = message
    if alert_id is not None:
        ctx = await _load_alert_context(alert_id)
        if ctx:
            user_content = f"{ctx}\n\n---\n\n**User question**: {message}"
        else:
            user_content = f"[Alert #{alert_id} not found]\n\n**User question**: {message}"

    # 2. Build clients (primary + optional fallback)
    config = get_config()
    clients: list = []

    try:
        clients.append((
            build_client(config.llm, await resolve_llm_key(), timeout=180.0),
            "primary",
        ))
    except LLMUnavailable as exc:
        logger.warning("Chat primary client unavailable", extra={
            "extra_data": {"reason": str(exc)}
        })
    except Exception as exc:
        logger.error("Failed to initialize chat primary client", extra={
            "extra_data": {"error": str(exc)}
        })

    if config.llm.fallback_provider:
        try:
            clients.append((
                build_client(
                    _fallback_config(config.llm),
                    await resolve_fallback_llm_key(),
                    timeout=180.0,
                ),
                "fallback",
            ))
        except LLMUnavailable as exc:
            logger.warning("Chat fallback client unavailable", extra={
                "extra_data": {"reason": str(exc)}
            })
        except Exception as exc:
            logger.error("Failed to initialize chat fallback client", extra={
                "extra_data": {"error": str(exc)}
            })

    if not clients:
        yield f"data: {json.dumps({'error': 'No LLM provider is configured — set ANTHROPIC_API_KEY in .env'})}\n\n"
        yield "data: [DONE]\n\n"
        return

    # 3. Try each provider in order
    system = build_chat_system_prompt()
    last_error = None
    succeeded = False
    for client, label in clients:
        try:
            async for chunk in _stream_from_client(client, system, user_content, label):
                yield chunk
            succeeded = True
            break
        except Exception as e:
            last_error = str(e)

    if not succeeded:
        logger.error("All chat LLM providers failed", extra={
            "extra_data": {"last_error": last_error}
        })
        yield f"data: {json.dumps({'error': f'All LLM providers unavailable: {last_error}'})}\n\n"

    # 4. Cleanup
    for client, _label in clients:
        try:
            await client.close()
        except Exception:
            pass

    yield "data: [DONE]\n\n"
