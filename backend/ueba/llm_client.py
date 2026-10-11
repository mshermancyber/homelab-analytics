"""LLM client abstraction: Anthropic (default) or any OpenAI-compatible endpoint.

Both the triage engine (`ueba.triage`) and the analyst chat (`ueba.chat`) talk to
this module instead of a vendor SDK, so swapping providers is a config change.

* ``provider: anthropic`` — official Anthropic SDK, Messages API.  Thinking is
  always on for current Claude models; depth is set with ``effort``, and
  sampling parameters (``temperature``) are not sent because those models
  reject them.  Policy declines are rescued by the server-side fallback.
* anything else (``openai``, ``ollama``, a local gateway, ...) — OpenAI-style
  ``/chat/completions`` at ``base_url``.

Tools are declared once in the neutral :data:`SEARCH_TOOL_SPEC` shape and
converted per provider.
"""
import json
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, List, Optional

from ueba.config import LLMConfig
from ueba.logging_config import get_logger

logger = get_logger(__name__)

# Max consecutive tool-call rounds before we ask for a final answer.
MAX_TOOL_ROUNDS = 3

# Beta flag + value for the scalar server-side fallback form.
_FALLBACK_BETA = "server-side-fallback-2026-07-01"
_FALLBACK_VALUE = "default"

ToolHandler = Callable[[str, Dict[str, Any]], Awaitable[str]]


# ---------------------------------------------------------------------------
# Neutral tool spec
# ---------------------------------------------------------------------------
SEARCH_TOOL_SPEC: Dict[str, Any] = {
    "name": "search_web",
    "description": (
        "Search the web to investigate an IP address, domain, or ASN. Use for "
        "WHOIS lookups, threat intel, or identifying who operates infrastructure."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query, e.g. 'whois 203.0.113.10' or 'ASN 13335 owner'",
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}


def to_anthropic_tool(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a neutral tool spec to the Anthropic Messages API shape."""
    return {
        "name": spec["name"],
        "description": spec["description"],
        "input_schema": spec["parameters"],
    }


def to_openai_tool(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a neutral tool spec to the OpenAI function-calling shape."""
    return {
        "type": "function",
        "function": {
            "name": spec["name"],
            "description": spec["description"],
            "parameters": spec["parameters"],
        },
    }


class LLMRefusal(Exception):
    """The model declined the request on policy grounds."""

    def __init__(self, category: Optional[str], explanation: Optional[str] = None):
        self.category = category
        self.explanation = explanation
        super().__init__(f"model refused the request (category={category or 'unknown'})")


class LLMUnavailable(Exception):
    """The provider SDK is not installed, or no credential is configured."""


def extract_json(text: Optional[str]) -> Optional[dict]:
    """Best-effort JSON extraction from a model response.

    Handles a bare object, a ```json fenced block, and prose around an object.
    Returns ``None`` when nothing parseable is found.
    """
    if not text:
        return None
    candidate = text.strip()
    if candidate.startswith("```"):
        # strip a fenced block, with or without a language tag
        fence_end = candidate.find("\n")
        candidate = candidate[fence_end + 1:] if fence_end != -1 else candidate
        closing = candidate.rfind("```")
        if closing != -1:
            candidate = candidate[:closing]
        candidate = candidate.strip()
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else {"events": parsed}
    except json.JSONDecodeError:
        pass
    # Fall back to the first balanced {...} span.
    start = candidate.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for idx in range(start, len(candidate)):
            char = candidate[idx]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(candidate[start:idx + 1])
                    except json.JSONDecodeError:
                        break
                    return parsed if isinstance(parsed, dict) else None
        start = candidate.find("{", start + 1)
    return None


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class BaseLLMClient:
    """Common surface used by triage and chat."""

    def __init__(self, llm_config: LLMConfig, api_key: Optional[str], timeout: float = 120.0):
        self.config = llm_config
        self.api_key = api_key
        self.timeout = timeout

    @property
    def provider(self) -> str:
        return self.config.provider

    @property
    def model(self) -> str:
        return self.config.model

    async def complete(
        self,
        system: str,
        user_content: str,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_handler: Optional[ToolHandler] = None,
    ) -> str:
        raise NotImplementedError

    def stream(
        self,
        system: str,
        user_content: str,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_handler: Optional[ToolHandler] = None,
    ) -> AsyncGenerator[dict, None]:
        raise NotImplementedError

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------
class AnthropicLLMClient(BaseLLMClient):
    """Anthropic Messages API client.

    Notes on current Claude models (Opus 5.5 and siblings):

    * thinking is always on — the ``thinking`` parameter is omitted, and depth
      comes from ``output_config.effort`` (default ``medium`` on Opus 5.5, so it
      is always sent explicitly)
    * ``temperature`` / ``top_p`` are rejected and therefore never sent
    * forced ``tool_choice`` is rejected; the prompt asks for the tool instead
    """

    def __init__(self, llm_config: LLMConfig, api_key: Optional[str], timeout: float = 120.0):
        super().__init__(llm_config, api_key, timeout)
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:  # pragma: no cover - depends on install
            raise LLMUnavailable(
                "the 'anthropic' package is required for provider=anthropic "
                "(pip install -r backend/requirements.txt)"
            ) from exc
        if not api_key:
            raise LLMUnavailable("ANTHROPIC_API_KEY is not set (see .env.example)")
        kwargs: Dict[str, Any] = {"api_key": api_key, "timeout": timeout}
        if llm_config.base_url:
            kwargs["base_url"] = llm_config.base_url
        self._client = AsyncAnthropic(**kwargs)

    # -- request construction ------------------------------------------------
    def _request_kwargs(self, system: str, messages: List[dict],
                        tools: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "system": system,
            "messages": messages,
            "output_config": {"effort": self.config.effort},
        }
        if tools:
            kwargs["tools"] = [to_anthropic_tool(t) for t in tools]
        if self.config.server_side_fallback:
            kwargs["betas"] = [_FALLBACK_BETA]
            kwargs["fallbacks"] = _FALLBACK_VALUE
        return kwargs

    @property
    def _messages_api(self):
        """Beta namespace when server-side fallback is on, stable otherwise."""
        return self._client.beta.messages if self.config.server_side_fallback else self._client.messages

    @staticmethod
    def _text_of(message) -> str:
        return "".join(block.text for block in message.content if block.type == "text")

    @staticmethod
    def _check_refusal(message) -> None:
        if getattr(message, "stop_reason", None) == "refusal":
            details = getattr(message, "stop_details", None)
            raise LLMRefusal(
                getattr(details, "category", None),
                getattr(details, "explanation", None),
            )

    async def _run_tools(self, message, tool_handler: Optional[ToolHandler]) -> Optional[List[dict]]:
        """Execute every ``tool_use`` block; return the matching results, or None."""
        tool_uses = [b for b in message.content if b.type == "tool_use"]
        if not tool_uses:
            return None
        results = []
        for block in tool_uses:
            if tool_handler is None:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": "Tool execution is unavailable",
                    "is_error": True,
                })
                continue
            try:
                output = await tool_handler(block.name, dict(block.input or {}))
            except Exception as exc:
                logger.warning("Tool execution failed", extra={
                    "extra_data": {"tool": block.name, "error": str(exc)}
                })
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": f"Tool error: {exc}",
                    "is_error": True,
                })
                continue
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": output,
            })
        return results

    # -- non-streaming -------------------------------------------------------
    async def complete(self, system: str, user_content: str,
                       tools: Optional[List[Dict[str, Any]]] = None,
                       tool_handler: Optional[ToolHandler] = None) -> str:
        messages: List[dict] = [{"role": "user", "content": user_content}]
        text = ""
        for _round in range(MAX_TOOL_ROUNDS):
            message = await self._messages_api.create(**self._request_kwargs(system, messages, tools))
            self._check_refusal(message)
            text = self._text_of(message)

            if getattr(message, "stop_reason", None) == "pause_turn":
                messages.append({"role": "assistant", "content": message.content})
                continue

            results = await self._run_tools(message, tool_handler)
            if results is None:
                return text
            messages.append({"role": "assistant", "content": message.content})
            messages.append({"role": "user", "content": results})

        # Tool budget spent — ask once more with no tools so we get an answer.
        message = await self._messages_api.create(**self._request_kwargs(system, messages, None))
        self._check_refusal(message)
        return self._text_of(message) or text

    # -- streaming -----------------------------------------------------------
    async def stream(self, system: str, user_content: str,
                     tools: Optional[List[Dict[str, Any]]] = None,
                     tool_handler: Optional[ToolHandler] = None) -> AsyncGenerator[dict, None]:
        messages: List[dict] = [{"role": "user", "content": user_content}]

        for round_index in range(MAX_TOOL_ROUNDS + 1):
            last_round = round_index == MAX_TOOL_ROUNDS
            kwargs = self._request_kwargs(system, messages, None if last_round else tools)

            async with self._messages_api.stream(**kwargs) as stream:
                async for event in stream:
                    if event.type == "content_block_delta" and event.delta.type == "text_delta":
                        yield {"type": "text", "text": event.delta.text}
                message = await stream.get_final_message()

            self._check_refusal(message)

            if last_round:
                return

            tool_uses = [b for b in message.content if b.type == "tool_use"]
            if not tool_uses:
                return

            for block in tool_uses:
                if block.name == SEARCH_TOOL_SPEC["name"]:
                    yield {"type": "tool_call", "name": block.name,
                           "input": dict(block.input or {})}

            results = await self._run_tools(message, tool_handler)
            messages.append({"role": "assistant", "content": message.content})
            messages.append({"role": "user", "content": results or []})

    async def close(self) -> None:
        try:
            await self._client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# OpenAI-compatible
# ---------------------------------------------------------------------------
class OpenAICompatibleLLMClient(BaseLLMClient):
    """Any endpoint speaking OpenAI's ``/chat/completions`` (OpenAI, Ollama, ...)."""

    def __init__(self, llm_config: LLMConfig, api_key: Optional[str], timeout: float = 120.0):
        super().__init__(llm_config, api_key, timeout)
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:  # pragma: no cover - depends on install
            raise LLMUnavailable(
                "the 'openai' package is required for OpenAI-compatible providers"
            ) from exc
        if not llm_config.base_url and llm_config.provider == "ollama":
            base_url = "http://127.0.0.1:11434/v1"
        else:
            base_url = llm_config.base_url or None
        self._client = AsyncOpenAI(
            api_key=api_key or "not-needed",
            base_url=base_url,
            timeout=timeout,
        )

    def _request_kwargs(self, messages: List[dict],
                        tools: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = [to_openai_tool(t) for t in tools]
            kwargs["tool_choice"] = "auto"
        return kwargs

    async def complete(self, system: str, user_content: str,
                       tools: Optional[List[Dict[str, Any]]] = None,
                       tool_handler: Optional[ToolHandler] = None) -> str:
        messages: List[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content},
        ]
        content = ""
        for round_index in range(MAX_TOOL_ROUNDS + 1):
            last_round = round_index == MAX_TOOL_ROUNDS
            response = await self._client.chat.completions.create(
                **self._request_kwargs(messages, None if last_round else tools)
            )
            message = response.choices[0].message
            content = message.content or content

            if last_round or not message.tool_calls:
                return content or ""

            messages.append(message)
            for call in message.tool_calls:
                output = "Tool execution is unavailable"
                if tool_handler is not None:
                    try:
                        args = json.loads(call.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {"query": str(call.function.arguments or "")}
                    try:
                        output = await tool_handler(call.function.name, args)
                    except Exception as exc:
                        output = f"Tool error: {exc}"
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": output,
                })
        return content or ""

    async def stream(self, system: str, user_content: str,
                     tools: Optional[List[Dict[str, Any]]] = None,
                     tool_handler: Optional[ToolHandler] = None) -> AsyncGenerator[dict, None]:
        messages: List[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content},
        ]

        for round_index in range(MAX_TOOL_ROUNDS + 1):
            last_round = round_index == MAX_TOOL_ROUNDS
            kwargs = self._request_kwargs(messages, None if last_round else tools)
            kwargs["stream"] = True
            stream = await self._client.chat.completions.create(**kwargs)

            finish_reason = None
            collected_content = ""
            collected_calls: List[dict] = []

            async for chunk in stream:
                if not chunk.choices:
                    continue
                choice = chunk.choices[0]
                finish_reason = choice.finish_reason or finish_reason
                delta = choice.delta
                if delta.content:
                    collected_content += delta.content
                    yield {"type": "text", "text": delta.content}
                for call in (delta.tool_calls or []):
                    while len(collected_calls) <= call.index:
                        collected_calls.append(
                            {"id": "", "function": {"name": "", "arguments": ""}}
                        )
                    slot = collected_calls[call.index]
                    if call.id:
                        slot["id"] = call.id
                    if call.function:
                        if call.function.name:
                            slot["function"]["name"] = call.function.name
                        if call.function.arguments:
                            slot["function"]["arguments"] += call.function.arguments

            if last_round or finish_reason != "tool_calls" or not collected_calls:
                return

            messages.append({
                "role": "assistant",
                "content": collected_content or None,
                "tool_calls": [
                    {"id": c["id"], "type": "function", "function": c["function"]}
                    for c in collected_calls
                ],
            })

            for call in collected_calls:
                name = call["function"]["name"]
                try:
                    args = json.loads(call["function"]["arguments"] or "{}")
                except json.JSONDecodeError:
                    args = {"query": str(call["function"]["arguments"] or "")}
                if name == SEARCH_TOOL_SPEC["name"]:
                    yield {"type": "tool_call", "name": name, "input": args}
                output = "Tool execution is unavailable"
                if tool_handler is not None:
                    try:
                        output = await tool_handler(name, args)
                    except Exception as exc:
                        output = f"Tool error: {exc}"
                messages.append({
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "content": output,
                })

    async def close(self) -> None:
        try:
            await self._client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def build_client(llm_config: LLMConfig, api_key: Optional[str],
                 timeout: float = 120.0) -> BaseLLMClient:
    """Instantiate the client for ``llm_config.provider``.

    Raises :class:`LLMUnavailable` when the SDK or credential is missing — the
    caller treats that as "no LLM", never as a fatal error.
    """
    provider = (llm_config.provider or "anthropic").lower()
    if provider == "anthropic":
        return AnthropicLLMClient(llm_config, api_key, timeout)
    return OpenAICompatibleLLMClient(llm_config, api_key, timeout)
