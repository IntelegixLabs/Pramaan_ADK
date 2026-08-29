"""
HandshakeOS — LLM Factory
==========================
Smart LLM factory that dynamically resolves user-specific Gemini API keys and models
stored in the database, with fallback to environment variables and deterministic mock.

Priority order:
  1. User's saved Gemini API Key in Database (per-user isolation)
  2. GOOGLE_API_KEY / GEMINI_API_KEY in environment
  3. Deterministic Mock Model

Usage:
    from llm_factory import get_llm_info, build_llm_model_name, get_genai_client
    info = get_llm_info(user=current_user)          # { mode, provider, model, detail }
    model = build_llm_model_name(user=current_user) # string like "gemini-2.5-flash"
    client = get_genai_client(user=current_user)    # google.genai.Client instance
"""

import os
import logging
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

from dotenv import load_dotenv
from google.genai import Client

# Load .env file
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
    has_key: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────────────────
# Dynamic Resolution Helpers
# ──────────────────────────────────────────────────────────

def resolve_user_api_key(user: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Resolve API key for a user or fallback."""
    if user and isinstance(user, dict):
        key = user.get("gemini_api_key")
        if key and isinstance(key, str) and key.strip():
            return key.strip()
    
    # Fallback to env var if explicitly set
    env_key = os.getenv("GOOGLE_API_KEY", os.getenv("GEMINI_API_KEY", "")).strip()
    return env_key if env_key else None


def resolve_user_model(user: Optional[Dict[str, Any]] = None) -> str:
    """Resolve Gemini model for a user or fallback."""
    if user and isinstance(user, dict):
        model = user.get("gemini_model")
        if model and isinstance(model, str) and model.strip():
            return model.strip()
            
    return os.getenv("GOOGLE_MODEL", "gemini-2.5-flash").strip()


def get_llm_info(user: Optional[Dict[str, Any]] = None) -> LLMInfo:
    """Get metadata about the active LLM provider for the given user or globally."""
    api_key = resolve_user_api_key(user)
    model = resolve_user_model(user)

    if api_key:
        return LLMInfo(
            mode="live",
            provider="google",
            model=model,
            detail=f"Google Gemini ({model}) — live LLM active",
            has_key=True
        )
    else:
        return LLMInfo(
            mode="mock",
            provider="mock",
            model=model,
            detail="No Gemini API key configured. Click 'Live LLM' in the top bar to paste your key.",
            has_key=False
        )


def build_llm_model_name(user: Optional[Dict[str, Any]] = None) -> str:
    """Get the LLM model name string for ADK / DeepTeam."""
    return resolve_user_model(user)


def get_genai_client(user: Optional[Dict[str, Any]] = None, api_key: Optional[str] = None) -> Client:
    """Get a google.genai Client instance configured with user's key."""
    resolved_key = api_key or resolve_user_api_key(user)
    if resolved_key:
        return Client(api_key=resolved_key)
    return Client()


def is_live(user: Optional[Dict[str, Any]] = None) -> bool:
    """Check if a real LLM provider is active for the user."""
    return get_llm_info(user).mode == "live"


def refresh():
    """No-op kept for backwards compatibility."""
    pass
