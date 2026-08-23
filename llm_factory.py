"""
HandshakeOS — LLM Factory
==========================
Smart LLM factory that checks for API keys in environment variables
and instantiates the appropriate configuration for ADK and google.genai.

Priority order:
  1. GOOGLE_API_KEY   → Google Gemini Model String
  2. (fallback)       → GenericMockModel (deterministic mock)

Usage:
    from llm_factory import get_llm_info, build_llm_model_name, get_genai_client
    info = get_llm_info()          # { mode, provider, model, detail }
    model = build_llm_model_name() # string like "gemini-2.5-flash"
    client = get_genai_client()    # google.genai.Client instance
"""

import os
import logging
from dataclasses import dataclass, asdict
from typing import Optional

from dotenv import load_dotenv
from google.genai import Client

# Load .env file so API keys are available via os.getenv()
load_dotenv()

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────
# LLM Info
# ──────────────────────────────────────────────────────────

@dataclass
class LLMInfo:
    mode: str          # "live" | "mock"
    provider: str      # "google" | "mock"
    model: str         # e.g. "gemini-2.5-flash"
    detail: str        # Human-readable description

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────────────────
# Provider detection
# ──────────────────────────────────────────────────────────

def _try_google() -> Optional[tuple[str, LLMInfo]]:
    """Try to configure Google Gemini LLM."""
    api_key = os.getenv("GOOGLE_API_KEY", "").strip()
    if not api_key:
        return None
    model_name = os.getenv("GOOGLE_MODEL", "gemini-2.5-flash")
    info = LLMInfo(
        mode="live",
        provider="google",
        model=model_name,
        detail=f"Google Gemini ({model_name}) — live LLM active",
    )
    logger.info(f"LLM Factory: Using Google Gemini ({model_name})")
    return model_name, info

def _build_mock() -> tuple[str, LLMInfo]:
    """Build the deterministic mock configuration (no API key needed)."""
    model_name = "mock-model"
    info = LLMInfo(
        mode="mock",
        provider="mock",
        model=model_name,
        detail="No API key found. Set GOOGLE_API_KEY to enable live LLM.",
    )
    return model_name, info


# ──────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────

# Module-level cache
_cached_model_name: Optional[str] = None
_cached_info: Optional[LLMInfo] = None
_cached_client: Optional[Client] = None

def _resolve() -> tuple[str, LLMInfo]:
    """Resolve the best available LLM provider."""
    global _cached_model_name, _cached_info
    if _cached_model_name is not None and _cached_info is not None:
        return _cached_model_name, _cached_info

    # Try providers in priority order
    result = _try_google()
    if result is not None:
        _cached_model_name, _cached_info = result
        return _cached_model_name, _cached_info

    # Fallback to mock
    _cached_model_name, _cached_info = _build_mock()
    logger.info("LLM Factory: Using deterministic mock LLM (no API key configured)")
    return _cached_model_name, _cached_info


def build_llm_model_name() -> str:
    """Get the LLM model name string for ADK."""
    model_name, _ = _resolve()
    return model_name

def get_genai_client() -> Client:
    """Get the raw google.genai Client."""
    global _cached_client
    if _cached_client:
        return _cached_client
    api_key = os.getenv("GOOGLE_API_KEY", "").strip()
    if api_key:
        _cached_client = Client(api_key=api_key)
    else:
        # Fallback to a mock/empty client if no key (will fail if used)
        _cached_client = Client()
    return _cached_client

def get_llm_info() -> LLMInfo:
    """Get metadata about the active LLM provider."""
    _, info = _resolve()
    return info


def is_live() -> bool:
    """Check if a real LLM provider is active."""
    return get_llm_info().mode == "live"


def refresh():
    """Force re-detection of LLM provider (e.g., after env change)."""
    global _cached_model_name, _cached_info, _cached_client
    _cached_model_name = None
    _cached_info = None
    _cached_client = None
    _resolve()
