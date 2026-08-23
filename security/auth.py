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
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/handshakeos.db"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "handshakeos.db")


# ──────────────────────────────────────────────────────────
# User Database Manager
# ──────────────────────────────────────────────────────────

class UserManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    picture TEXT,
                    provider TEXT DEFAULT 'google',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()

    def get_or_create_user(self, email: str, name: str, picture: Optional[str] = None, provider: str = "google", user_id: Optional[str] = None) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
            row = cursor.fetchone()
            now = datetime.now(timezone.utc).isoformat()

            if row:
                cursor.execute(
                    "UPDATE users SET name = ?, picture = COALESCE(?, picture), last_login = ? WHERE email = ?",
                    (name, picture, now, email.lower())
                )
                conn.commit()
                cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
                return dict(cursor.fetchone())
            else:
                uid = user_id or f"usr_{uuid.uuid4().hex[:12]}"
                cursor.execute(
                    "INSERT INTO users (user_id, email, name, picture, provider, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (uid, email.lower(), name, picture or "", provider, now, now)
                )
                conn.commit()
                cursor.execute("SELECT * FROM users WHERE user_id = ?", (uid,))
                return dict(cursor.fetchone())

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
            row = cursor.fetchone()
            return dict(row) if row else None


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
        # Fallback to token payload if user record is cached
        user = {
            "user_id": payload["user_id"],
            "email": payload["email"],
            "name": payload.get("name", "User"),
            "picture": payload.get("picture", ""),
        }
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
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
        "has_google_client_id": bool(os.getenv("GOOGLE_CLIENT_ID", "").strip()),
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
