"""Secret resolution from the environment and a local ``.env`` file.

Nothing secret is stored in the repository.  Values are read from the process
environment, which :mod:`ueba.dotenv` has already seeded from ``.env`` (real
environment variables win).

``.env`` is git-ignored.  Copy ``.env.example`` to ``.env`` and fill it in.
"""
import os
from typing import Optional

from ueba.config import get_config
from ueba.dotenv import load_dotenv, source_path
from ueba.logging_config import get_logger

logger = get_logger(__name__)


def env_file_path() -> Optional[str]:
    """Path of the ``.env`` in use, for diagnostics.  None when there is none."""
    path = source_path()
    return str(path) if path else None


def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    """Return a secret from the environment, then ``.env``, then ``default``."""
    value = os.environ.get(name)
    if value:
        return value
    value = load_dotenv().get(name)
    if value:
        return value
    return default


def list_secret_names() -> list:
    """Names present in ``.env`` (never the values) — used by diagnostics."""
    return sorted(load_dotenv().keys())


# ---------------------------------------------------------------------------
# LLM API keys
# ---------------------------------------------------------------------------
_PROVIDER_KEY_VARS = {
    "anthropic": ("ANTHROPIC_API_KEY", "LLM_API_KEY"),
    "openai": ("OPENAI_API_KEY", "LLM_API_KEY"),
    "ollama": (),  # local, no credential needed
}


def _key_for_provider(provider: str) -> Optional[str]:
    for var in _PROVIDER_KEY_VARS.get(provider, ("LLM_API_KEY",)):
        value = get_secret(var)
        if value:
            return value
    return None


async def resolve_llm_key() -> Optional[str]:
    """Resolve the primary provider's API key.

    Async for call-site compatibility; resolution itself is local and cheap.
    """
    config = get_config()
    provider = (config.llm.provider or "anthropic").lower()
    if config.llm.api_key:
        return config.llm.api_key
    key = _key_for_provider(provider)
    if key:
        return key
    if provider == "ollama":
        return None  # expected: Ollama needs no credential
    logger.warning("No LLM API key found", extra={
        "extra_data": {"provider": provider,
                       "looked_for": list(_PROVIDER_KEY_VARS.get(provider, ("LLM_API_KEY",)))}
    })
    return None


async def resolve_fallback_llm_key() -> Optional[str]:
    """Resolve the fallback provider's API key, if one is configured."""
    config = get_config()
    provider = (config.llm.fallback_provider or "").lower()
    if not provider:
        return None
    if config.llm.fallback_api_key:
        return config.llm.fallback_api_key
    return _key_for_provider(provider)
