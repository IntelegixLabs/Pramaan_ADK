"""
HandshakeOS - Verifiable Credential Issuer
Issues Agent Passport VCs as signed JWTs (W3C VC Data Model v2.0 compatible).
"""

import jwt
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional


class VCIssuer:
    """Issues Verifiable Credentials for agent identity and human approvals."""

    def __init__(self, issuer_did: str = "did:gcc:authority:agent-issuer",
                 signing_key: str = "handshakeos-demo-signing-key-2026"):
        self.issuer_did = issuer_did
        self.signing_key = signing_key

    def issue_agent_passport(
        self,
        agent_did: str,
        agent_name: str,
        business_domain: str,
        owner_human: str,
        allowed_actions: list[str],
        forbidden_actions: list[str],
        max_autonomous_amount: dict,
        delegation_depth: int = 0,
        allowed_counterparties: Optional[list[str]] = None,
        model_hash: str = "",
        policy_bundle: str = "",
        valid_hours: int = 24,
    ) -> str:
        """Issue an Agent Passport VC as a signed JWT."""
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(hours=valid_hours)

        if not model_hash:
            model_hash = hashlib.sha256(f"{agent_did}-model".encode()).hexdigest()

        vc_payload = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "AgentPassport"],
            "issuer": self.issuer_did,
            "validFrom": now.isoformat(),
            "validUntil": valid_until.isoformat(),
            "credentialSubject": {
                "id": agent_did,
                "agentName": agent_name,
                "businessDomain": business_domain,
                "ownerHuman": owner_human,
                "allowedActions": allowed_actions,
                "forbiddenActions": forbidden_actions,
                "maxAutonomousAmount": max_autonomous_amount,
                "delegationDepth": delegation_depth,
                "allowedCounterparties": allowed_counterparties or [],
                "modelHash": model_hash,
                "policyBundle": policy_bundle,
            },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod": f"{self.issuer_did}#key-1",
            },
            # JWT standard claims for expiry validation
            "iat": int(now.timestamp()),
            "exp": int(valid_until.timestamp()),
            "iss": self.issuer_did,
            "sub": agent_did,
            "jti": f"vc-{uuid.uuid4().hex[:12]}",
        }

        return jwt.encode(vc_payload, self.signing_key, algorithm="HS256")

    def issue_human_approval_credential(
        self,
        approved_by: str,
        task_id: str,
        approved_action: str,
        approved_amount_hash: str,
        expires_minutes: int = 30,
    ) -> str:
        """Issue a one-time Human Approval Credential as a signed JWT."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=expires_minutes)

        payload = {
            "type": "HumanApprovalCredential",
            "approvedBy": approved_by,
            "taskId": task_id,
            "approvedAction": approved_action,
            "approvedAmountHash": approved_amount_hash,
            "validForOneExecution": True,
            "expiresAt": expires_at.isoformat(),
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self.issuer_did,
            "jti": f"hac-{uuid.uuid4().hex[:12]}",
        }

        return jwt.encode(payload, self.signing_key, algorithm="HS256")



