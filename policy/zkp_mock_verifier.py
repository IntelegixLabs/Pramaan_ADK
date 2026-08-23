"""
HandshakeOS - Mock ZKP Verifier
Demo-level zero-knowledge proof for range proofs (amount <= policy limit).
For production, use circom/snarkjs or a formally verified ZKP library.
"""

import json
import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

# Demo signing key for mock ZKP tokens
ZKP_DEMO_KEY = "handshakeos-zkp-demo-key-2026"


@dataclass
class ZKPVerificationResult:
    valid: bool
    claim: str = ""
    error: str = ""


class ZKPMockVerifier:
    """
    Mock ZKP verifier for demo.
    Proves: amount <= policy_limit without revealing the exact amount.

    MVP: Uses signed proof tokens (HMAC).
    Strong demo: Would use circom/snarkjs for real range proofs.
    Production: Formally reviewed circuit, secure commitments, key rotation.
    """

    def __init__(self, signing_key: str = ZKP_DEMO_KEY):
        self._signing_key = signing_key

    def generate_proof(
        self,
        private_amount: float,
        policy_limit: float,
        policy_id: str,
        currency: str = "USD",
    ) -> dict:
        """
        Generate a mock ZKP range proof.
        Private input: amount
        Public input: policy_limit
        Constraint: amount <= policy_limit
        """
        is_under_limit = private_amount <= policy_limit

        # Compute limit commitment (public)
        limit_commitment = hashlib.sha256(
            f"{policy_limit}:{policy_id}".encode()
        ).hexdigest()

        # Build proof payload
        proof_payload = {
            "type": "zk-range-proof",
            "claim": "amount_is_under_limit",
            "constraint_satisfied": is_under_limit,
            "limit_commitment": limit_commitment,
            "policy_id": policy_id,
            "currency": currency,
        }

        # Sign the proof payload (HMAC for demo)
        payload_bytes = json.dumps(proof_payload, sort_keys=True).encode()
        signature = hmac.new(
            self._signing_key.encode(), payload_bytes, hashlib.sha256
        ).hexdigest()

        proof_token = base64.b64encode(
            json.dumps({"payload": proof_payload, "sig": signature}).encode()
        ).decode()

        return {
            "policyId": policy_id,
            "proofType": "zk-range-proof",
            "claim": "amount_is_under_limit",
            "publicInputs": {
                "limitCommitment": limit_commitment,
                "currency": currency,
                "policyVersion": policy_id.split("-")[-1] if "-" in policy_id else "v1",
            },
            "proof": proof_token,
            "valid": is_under_limit,
        }

    def verify_proof(self, proof_dict: dict, policy_limit: float) -> ZKPVerificationResult:
        """Verify a mock ZKP range proof."""
        proof_token = proof_dict.get("proof", "")
        if not proof_token:
            return ZKPVerificationResult(valid=False, error="Missing proof token")

        try:
            decoded = json.loads(base64.b64decode(proof_token))
        except Exception as e:
            return ZKPVerificationResult(valid=False, error=f"Invalid proof format: {e}")

        payload = decoded.get("payload", {})
        provided_sig = decoded.get("sig", "")

        # Verify HMAC signature
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        expected_sig = hmac.new(
            self._signing_key.encode(), payload_bytes, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(provided_sig, expected_sig):
            return ZKPVerificationResult(valid=False, error="Proof signature invalid")

        # Verify limit commitment matches
        policy_id = payload.get("policy_id", "")
        expected_commitment = hashlib.sha256(
            f"{policy_limit}:{policy_id}".encode()
        ).hexdigest()

        if payload.get("limit_commitment") != expected_commitment:
            return ZKPVerificationResult(
                valid=False, error="Limit commitment mismatch"
            )

        if not payload.get("constraint_satisfied", False):
            return ZKPVerificationResult(
                valid=False, claim="amount_is_under_limit",
                error="Amount exceeds policy limit",
            )

        return ZKPVerificationResult(
            valid=True, claim=payload.get("claim", "amount_is_under_limit"),
        )

    def generate_sealed_payload(
        self, amount: float, recipient_agent_did: str
    ) -> str:
        """
        Create a sealed payload encrypted to the recipient agent.
        Only the target agent can open this to see the actual amount.
        Demo: base64-encoded JSON. Production: use public-key encryption.
        """
        payload = {
            "type": "sealed-payment-payload",
            "recipientAgent": recipient_agent_did,
            "amount": amount,
            "currency": "USD",
        }
        sealed = base64.b64encode(json.dumps(payload).encode()).decode()
        return sealed

    def unseal_payload(self, sealed: str) -> Optional[dict]:
        """Unseal a payment payload (demo: just base64 decode)."""
        try:
            return json.loads(base64.b64decode(sealed))
        except Exception:
            return None

