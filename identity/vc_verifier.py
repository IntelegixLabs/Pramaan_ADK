"""
HandshakeOS - Verifiable Credential Verifier
Decodes and validates Agent Passport VCs and Human Approval Credentials.
"""

import jwt
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class VerificationResult:
    ok: bool
    claims: dict = field(default_factory=dict)
    error: str = ""


class VCVerifier:
    """Verifies Verifiable Credentials (signed JWTs)."""

    def __init__(self, signing_key: str = "handshakeos-demo-signing-key-2026"):
        self.signing_key = signing_key

    def verify_vc(self, vc_jwt: str) -> VerificationResult:
        """Decode and validate an Agent Passport VC JWT."""
        try:
            claims = jwt.decode(vc_jwt, self.signing_key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return VerificationResult(ok=False, error="Agent credential has expired")
        except jwt.InvalidTokenError as e:
            return VerificationResult(ok=False, error=f"Invalid agent credential: {e}")

        # Check W3C VC type
        vc_types = claims.get("type", [])
        if "VerifiableCredential" not in vc_types or "AgentPassport" not in vc_types:
            return VerificationResult(ok=False, error="Not a valid AgentPassport VC")

        # Check validUntil
        valid_until_str = claims.get("validUntil", "")
        if valid_until_str:
            try:
                valid_until = datetime.fromisoformat(valid_until_str)
                if valid_until.tzinfo is None:
                    valid_until = valid_until.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > valid_until:
                    return VerificationResult(ok=False, error="Agent credential validUntil has passed")
            except (ValueError, TypeError):
                return VerificationResult(ok=False, error="Invalid validUntil date format")

        return VerificationResult(ok=True, claims=claims)

    def verify_human_approval(self, approval_jwt: str) -> VerificationResult:
        """Decode and validate a Human Approval Credential JWT."""
        try:
            claims = jwt.decode(approval_jwt, self.signing_key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return VerificationResult(ok=False, error="Human approval has expired")
        except jwt.InvalidTokenError as e:
            return VerificationResult(ok=False, error=f"Invalid human approval: {e}")

        if claims.get("type") != "HumanApprovalCredential":
            return VerificationResult(ok=False, error="Not a HumanApprovalCredential")

        if not claims.get("validForOneExecution", False):
            return VerificationResult(ok=False, error="Approval is not valid for execution")

        # Check expiry
        expires_at_str = claims.get("expiresAt", "")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > expires_at:
                    return VerificationResult(ok=False, error="Human approval has expired")
            except (ValueError, TypeError):
                return VerificationResult(ok=False, error="Invalid expiresAt date format")

        return VerificationResult(ok=True, claims=claims)

