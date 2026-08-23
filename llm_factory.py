"""
HandshakeOS — LLM Factory
==========================
Smart LLM factory that checks for API keys in environment variables
and instantiates the appropriate ChatModel provider.

Priority order:
  1. GOOGLE_API_KEY   → ChatGoogleGenerativeAI (Gemini)
  2. OPENAI_API_KEY   → ChatOpenAI
  3. ANTHROPIC_API_KEY → ChatAnthropic
  4. (fallback)       → GenericFakeChatModel (deterministic mock)

Usage:
    from llm_factory import get_llm_info, build_llm
    info = get_llm_info()          # { mode, provider, model, detail }
    llm  = build_llm(system_prompt="...")  # BaseChatModel instance
"""

import os
import logging
from dataclasses import dataclass, asdict
from typing import Optional, Iterator

from dotenv import load_dotenv

# Load .env file so API keys are available via os.getenv()
load_dotenv()

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────
# LLM Info
# ──────────────────────────────────────────────────────────

@dataclass
class LLMInfo:
    mode: str          # "live" | "mock"
    provider: str      # "google" | "openai" | "anthropic" | "mock"
    model: str         # e.g. "gemini-2.0-flash", "gpt-4o-mini"
    detail: str        # Human-readable description

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────────────────
# Provider detection
# ──────────────────────────────────────────────────────────

def _try_google() -> Optional[tuple[BaseChatModel, LLMInfo]]:
    """Try to create a Google Gemini LLM."""
    api_key = os.getenv("GOOGLE_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        model_name = os.getenv("GOOGLE_MODEL", "gemini-2.0-flash")
        llm = ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=api_key,
            temperature=0.3,
            convert_system_message_to_human=True,
        )
        info = LLMInfo(
            mode="live",
            provider="google",
            model=model_name,
            detail=f"Google Gemini ({model_name}) — live LLM active",
        )
        logger.info(f"LLM Factory: Using Google Gemini ({model_name})")
        return llm, info
    except ImportError:
        logger.warning(
            "GOOGLE_API_KEY is set but langchain-google-genai is not installed. "
            "Run: pip install langchain-google-genai"
        )
        return None
    except Exception as e:
        logger.warning(f"Failed to initialize Google Gemini: {e}")
        return None


def _try_openai() -> Optional[tuple[BaseChatModel, LLMInfo]]:
    """Try to create an OpenAI LLM."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        from langchain_openai import ChatOpenAI
        model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        llm = ChatOpenAI(
            model=model_name,
            api_key=api_key,
            temperature=0.3,
        )
        info = LLMInfo(
            mode="live",
            provider="openai",
            model=model_name,
            detail=f"OpenAI ({model_name}) — live LLM active",
        )
        logger.info(f"LLM Factory: Using OpenAI ({model_name})")
        return llm, info
    except ImportError:
        logger.warning(
            "OPENAI_API_KEY is set but langchain-openai is not installed. "
            "Run: pip install langchain-openai"
        )
        return None
    except Exception as e:
        logger.warning(f"Failed to initialize OpenAI: {e}")
        return None


def _try_anthropic() -> Optional[tuple[BaseChatModel, LLMInfo]]:
    """Try to create an Anthropic LLM."""
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        from langchain_anthropic import ChatAnthropic
        model_name = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
        llm = ChatAnthropic(
            model=model_name,
            api_key=api_key,
            temperature=0.3,
        )
        info = LLMInfo(
            mode="live",
            provider="anthropic",
            model=model_name,
            detail=f"Anthropic ({model_name}) — live LLM active",
        )
        logger.info(f"LLM Factory: Using Anthropic ({model_name})")
        return llm, info
    except ImportError:
        logger.warning(
            "ANTHROPIC_API_KEY is set but langchain-anthropic is not installed. "
            "Run: pip install langchain-anthropic"
        )
        return None
    except Exception as e:
        logger.warning(f"Failed to initialize Anthropic: {e}")
        return None


def _build_mock(default_response: str = "Task completed successfully.") -> tuple[GenericFakeChatModel, LLMInfo]:
    """Build the deterministic mock LLM (no API key needed)."""
    def _responses() -> Iterator[BaseMessage]:
        while True:
            yield AIMessage(content=default_response)

    llm = GenericFakeChatModel(messages=_responses())
    info = LLMInfo(
        mode="mock",
        provider="mock",
        model="GenericFakeChatModel",
        detail="No API key found. Set GOOGLE_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable live LLM.",
    )
    return llm, info


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

# Module-level cache so all agents share the same LLM instance
_cached_llm: Optional[BaseChatModel] = None
_cached_info: Optional[LLMInfo] = None


def _resolve() -> tuple[BaseChatModel, LLMInfo]:
    """Resolve the best available LLM provider."""
    global _cached_llm, _cached_info
    if _cached_llm is not None and _cached_info is not None:
        return _cached_llm, _cached_info

    # Try providers in priority order
    for provider_fn in [_try_google, _try_openai, _try_anthropic]:
        result = provider_fn()
        if result is not None:
            _cached_llm, _cached_info = result
            return _cached_llm, _cached_info

    # Fallback to mock
    _cached_llm, _cached_info = _build_mock()
    logger.info("LLM Factory: Using deterministic mock LLM (no API key configured)")
    return _cached_llm, _cached_info


def build_llm() -> BaseChatModel:
    """Get the LLM instance (cached, shared across agents)."""
    llm, _ = _resolve()
    return llm


def get_llm_info() -> LLMInfo:
    """Get metadata about the active LLM provider."""
    _, info = _resolve()
    return info


def is_live() -> bool:
    """Check if a real LLM provider is active."""
    return get_llm_info().mode == "live"


def refresh():
    """Force re-detection of LLM provider (e.g., after env change)."""
    global _cached_llm, _cached_info
    _cached_llm = None
    _cached_info = None
    _resolve()
