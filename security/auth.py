"""
Pramaan - Authentication & User Management Module
=================================================
Provides Google OAuth token verification, user session management,
and user-data isolation helpers.
"""

import os
import sqlite3
import hmac
import hashlib
import base64
import json
import time
import uuid
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from pydantic import BaseModel
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

logger = logging.getLogger(__name__)

# Secret key for signing session tokens
SECRET_KEY = os.getenv("SESSION_SECRET", os.getenv("JWT_SECRET", "pramaan-secure-auth-secret-key-2026"))
GOOGLE_CLIENT_ID = (os.getenv("GOOGLE_CLIENT_ID") or os.getenv("VITE_GOOGLE_CLIENT_ID", "")).strip()

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/handshakeos.db"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "handshakeos.db")


# ──────────────────────────────────────────────────────────
# User Database Manager
# ──────────────────────────────────────────────────────────

from security.db import db

class UserManager:
    def __init__(self, db_path: str = None):
        db.initialize()

    def get_or_create_user(self, email: str, name: str, picture: Optional[str] = None, provider: str = "google", user_id: Optional[str] = None) -> Dict[str, Any]:
        row = db.fetchone("SELECT * FROM users WHERE email = ?", (email.lower(),))
        now = datetime.now(timezone.utc).isoformat()

        if row:
            db.execute(
                "UPDATE users SET name = ?, picture = COALESCE(?, picture), last_login = ? WHERE email = ?",
                (name, picture, now, email.lower())
            )
            return db.fetchone("SELECT * FROM users WHERE email = ?", (email.lower(),)) or {}
        else:
            uid = user_id or f"usr_{uuid.uuid4().hex[:12]}"
            db.execute(
                "INSERT INTO users (user_id, email, name, picture, provider, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (uid, email.lower(), name, picture or "", provider, now, now)
            )
            return db.fetchone("SELECT * FROM users WHERE user_id = ?", (uid,)) or {}

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        return db.fetchone("SELECT * FROM users WHERE user_id = ?", (user_id,))

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return db.fetchone("SELECT * FROM users WHERE email = ?", (email.lower(),))

    def update_user_llm_config(self, user_id: str, email: Optional[str] = None, name: Optional[str] = None, api_key: Optional[str] = None, model: Optional[str] = None) -> Dict[str, Any]:
        row = db.fetchone("SELECT * FROM users WHERE user_id = ?", (user_id,))
        now = datetime.now(timezone.utc).isoformat()

        if not row:
            user_email = (email or f"{user_id}@user.local").lower()
            user_name = name or "User"
            db.execute(
                "INSERT INTO users (user_id, email, name, gemini_api_key, gemini_model, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user_id, user_email, user_name, api_key.strip() if api_key else None, (model or "gemini-2.5-flash").strip(), now, now)
            )
        else:
            if api_key is not None and model is not None:
                db.execute(
                    "UPDATE users SET gemini_api_key = ?, gemini_model = ?, last_login = ? WHERE user_id = ?",
                    (api_key.strip() if api_key else None, model.strip(), now, user_id)
                )
            elif api_key is not None:
                db.execute(
                    "UPDATE users SET gemini_api_key = ?, last_login = ? WHERE user_id = ?",
                    (api_key.strip() if api_key else None, now, user_id)
                )
            elif model is not None:
                db.execute(
                    "UPDATE users SET gemini_model = ?, last_login = ? WHERE user_id = ?",
                    (model.strip(), now, user_id)
                )
        return self.get_user_by_id(user_id) or {}


user_manager = UserManager()


# ──────────────────────────────────────────────────────────
# Token Utilities (HMAC-SHA256 Token)
# ──────────────────────────────────────────────────────────

def create_session_token(user_data: Dict[str, Any], expires_in_days: int = 30) -> str:
    """Create a tamper-proof signed session token."""
    payload = {
        "user_id": user_data["user_id"],
        "email": user_data["email"],
        "name": user_data["name"],
        "picture": user_data.get("picture", ""),
        "exp": int(time.time()) + (expires_in_days * 86400),
        "iat": int(time.time()),
    }
    header = {"alg": "HS256", "typ": "JWT"}
    b64_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    b64_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    
    signing_input = f"{b64_header}.{b64_payload}".encode()
    signature = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    b64_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    
    return f"{b64_header}.{b64_payload}.{b64_signature}"


def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode session token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        b64_header, b64_payload, b64_signature = parts
        
        signing_input = f"{b64_header}.{b64_payload}".encode()
        expected_sig = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(b64_signature + "=" * (-len(b64_signature) % 4))
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
            
        payload_bytes = base64.urlsafe_b64decode(b64_payload + "=" * (-len(b64_payload) % 4))
        payload = json.loads(payload_bytes.decode())
        
        if payload.get("exp", 0) < time.time():
            return None
            
        return payload
    except Exception as e:
        logger.warning("Token verification failed: %s", e)
        return None


# ──────────────────────────────────────────────────────────
# FastAPI Dependencies
# ──────────────────────────────────────────────────────────

async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Dependency that requires a valid Bearer token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
    
    token = parts[1]
    payload = verify_session_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    
    user = user_manager.get_user_by_id(payload["user_id"])
    if not user:
        user = user_manager.get_or_create_user(
            email=payload["email"],
            name=payload.get("name", "User"),
            picture=payload.get("picture", ""),
            user_id=payload["user_id"]
        )
    return user


async def get_optional_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    """Dependency that extracts user if present, or returns None."""
    if not authorization:
        return None
    try:
        parts = authorization.split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            payload = verify_session_token(parts[1])
            if payload:
                return user_manager.get_user_by_id(payload["user_id"]) or payload
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────
# Auth Router
# ──────────────────────────────────────────────────────────

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


class GoogleAuthRequest(BaseModel):
    credential: str  # Google ID token JWT


class DevAuthRequest(BaseModel):
    email: str
    name: Optional[str] = None


@auth_router.get("/config")
async def get_auth_config():
    """Return public auth configuration."""
    return {
        "google_client_id": GOOGLE_CLIENT_ID,
        "has_google_client_id": bool(GOOGLE_CLIENT_ID),
    }


@auth_router.post("/google")
async def auth_google(body: GoogleAuthRequest):
    """Authenticate with a Google OAuth ID token."""
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    credential = body.credential

    try:
        # Verify token with Google's public keys
        request_transport = google_requests.Request()
        # If client_id is set, verify audience matches
        id_info = id_token.verify_oauth2_token(
            credential,
            request_transport,
            audience=client_id if client_id else None
        )

        email = id_info.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid Google token: email missing")

        name = id_info.get("name") or email.split("@")[0]
        picture = id_info.get("picture", "")
        google_sub = id_info.get("sub", "")
        user_id = f"google_{google_sub}" if google_sub else None

        user = user_manager.get_or_create_user(
            email=email,
            name=name,
            picture=picture,
            provider="google",
            user_id=user_id,
        )

        token = create_session_token(user)

        return {
            "token": token,
            "user": user,
            "message": "Authentication successful"
        }

    except ValueError as e:
        logger.error("Google ID token verification failed: %s", e)
        raise HTTPException(status_code=400, detail=f"Invalid Google ID token: {str(e)}")
    except Exception as e:
        logger.error("Unexpected error in auth_google: %s", e)
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")


@auth_router.post("/dev-login")
async def auth_dev(body: DevAuthRequest):
    """Development / Demo login endpoint."""
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email address is required")

    name = body.name or email.split("@")[0].capitalize()
    avatar_url = f"https://api.dicebear.com/7.x/avataaars/svg?seed={email}"

    user = user_manager.get_or_create_user(
        email=email,
        name=name,
        picture=avatar_url,
        provider="dev",
    )

    token = create_session_token(user)

    return {
        "token": token,
        "user": user,
        "message": "Dev login successful"
    }


@auth_router.get("/me")
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user details."""
    return {
        "user": current_user
    }


class SaveLLMConfigRequest(BaseModel):
    api_key: Optional[str] = None
    model: Optional[str] = "gemini-2.5-flash"


AVAILABLE_GEMINI_MODELS = [
    # Gemini 3 Series
    {"id": "gemini-3.7-flash", "name": "Gemini 3.7 Flash", "series": "Gemini 3", "tag": "Latest Frontier", "desc": "Most capable Flash model, built for complex coding and agentic workflows"},
    {"id": "gemini-3.6-flash", "name": "Gemini 3.6 Flash", "series": "Gemini 3", "tag": "High Agentic", "desc": "Balanced speed and multimodal capabilities across agentic workflows"},
    {"id": "gemini-3.5-flash", "name": "Gemini 3.5 Flash", "series": "Gemini 3", "tag": "High Throughput", "desc": "Foundational performance for routine high-throughput workloads"},
    {"id": "gemini-3.5-flash-lite", "name": "Gemini 3.5 Flash-Lite", "series": "Gemini 3", "tag": "Ultra Fast", "desc": "Fastest, most cost-effective 3.5 model for high-throughput execution"},
    {"id": "gemini-3.1-pro", "name": "Gemini 3.1 Pro", "series": "Gemini 3", "tag": "Deep Intelligence", "desc": "Advanced intelligence and complex zero-trust threat modeling"},
    {"id": "gemini-3.1-flash-lite", "name": "Gemini 3.1 Flash-Lite", "series": "Gemini 3", "tag": "Cost Effective", "desc": "Frontier-class performance rivaling larger models"},
    {"id": "gemini-3-flash", "name": "Gemini 3 Flash", "series": "Gemini 3", "tag": "Frontier Flash", "desc": "Frontier-class speed at a fraction of latency"},

    # Gemini 2.5 & 2.0 Series
    {"id": "gemini-2.5-flash", "name": "Gemini 2.5 Flash", "series": "Gemini 2.5", "tag": "Recommended", "desc": "Fast response & high throughput for live multi-agent scanning"},
    {"id": "gemini-2.5-pro", "name": "Gemini 2.5 Pro", "series": "Gemini 2.5", "tag": "Deep Reasoning", "desc": "Advanced reasoning and complex zero-trust policy generation"},
    {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash", "series": "Gemini 2.0", "tag": "Low Latency", "desc": "Next-gen low latency and high multimodal performance"},
    {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro", "series": "Gemini 1.5", "tag": "Long Context", "desc": "Extended context window for deep repository & audit inspection"},
    {"id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash", "series": "Gemini 1.5", "tag": "Lightweight", "desc": "Lightweight baseline for fast verification tasks"},
]


@auth_router.get("/llm-config")
async def get_user_llm_config(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Fetch user's saved Gemini LLM configuration."""
    user = user_manager.get_user_by_id(current_user["user_id"]) or current_user
    api_key = user.get("gemini_api_key") or ""
    model = user.get("gemini_model") or "gemini-2.5-flash"
    has_key = bool(api_key.strip())
    masked_key = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) >= 10 else ("****" if has_key else "")

    return {
        "mode": "live" if has_key else "mock",
        "provider": "google",
        "model": model,
        "has_key": has_key,
        "masked_key": masked_key,
        "detail": f"Google Gemini ({model}) — live LLM active" if has_key else "No user Gemini API key saved. Please add your key to activate live LLM.",
        "available_models": AVAILABLE_GEMINI_MODELS,
    }


@auth_router.post("/llm-config")
async def save_user_llm_config(body: SaveLLMConfigRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Save user's Gemini API key and model selection."""
    api_key = (body.api_key or "").strip()
    model = (body.model or "gemini-2.5-flash").strip()

    # If user provided a new key, perform format validation
    if api_key:
        if len(api_key) < 8:
            raise HTTPException(status_code=400, detail="API key is too short. Please provide a valid Gemini API key.")
        
        # Non-blocking key check with Google GenAI SDK (fail-open on network/verification issues)
        try:
            from google.genai import Client
            test_client = Client(api_key=api_key)
            try:
                _ = test_client.models.get(model="gemini-2.5-flash")
            except Exception as inner_e:
                err_str = str(inner_e).upper()
                if "API_KEY_INVALID" in err_str:
                    logger.warning("Gemini key check returned API_KEY_INVALID: %s", inner_e)
                else:
                    logger.info("Non-blocking model check notice: %s", inner_e)
        except Exception as e:
            logger.info("Gemini Client init notice: %s", e)

    updated_user = user_manager.update_user_llm_config(
        user_id=current_user["user_id"],
        email=current_user.get("email"),
        name=current_user.get("name"),
        api_key=api_key if api_key else None,
        model=model
    )

    saved_key = updated_user.get("gemini_api_key") or ""
    has_key = bool(saved_key.strip())
    masked_key = f"{saved_key[:6]}...{saved_key[-4:]}" if len(saved_key) >= 10 else ("****" if has_key else "")

    return {
        "success": True,
        "message": "Gemini LLM configuration saved successfully",
        "config": {
            "mode": "live" if has_key else "mock",
            "provider": "google",
            "model": updated_user.get("gemini_model") or model,
            "has_key": has_key,
            "masked_key": masked_key,
            "detail": f"Google Gemini ({model}) — live LLM active" if has_key else "Mock mode",
        }
    }


@auth_router.delete("/llm-config")
async def delete_user_llm_config(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Remove user's saved Gemini API key."""
    updated_user = user_manager.update_user_llm_config(
        user_id=current_user["user_id"],
        api_key="",
        model=current_user.get("gemini_model") or "gemini-2.5-flash"
    )
    return {
        "success": True,
        "message": "Gemini API key removed",
        "config": {
            "mode": "mock",
            "provider": "google",
            "model": updated_user.get("gemini_model") or "gemini-2.5-flash",
            "has_key": False,
            "masked_key": "",
            "detail": "No API key configured.",
        }
    }

