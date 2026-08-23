"""
HandshakeOS - Policy Engine
Evaluates policy rules and delegates ZKP verification to the mock verifier.
"""

from dataclasses import dataclass
from typing import Optional

from policy.zkp_mock_verifier import ZKPMockVerifier


@dataclass
class PolicyResult:
    valid: bool
    policy_id: str = ""
    claim: str = ""
    error: str = ""


class PolicyEngine:
    """Evaluates governance policies and verifies ZKP proofs."""

    def __init__(self):
        self._policies: dict[str, dict] = {}
        self._zkp_verifier = ZKPMockVerifier()

    def register_policy(
        self,
        policy_id: str,
        policy_type: str = "range-limit",
        limit_value: float = 10000.0,
        currency: str = "USD",
        version: str = "v1",
        required_actions: Optional[list[str]] = None,
    ):
        """Register a governance policy."""
        self._policies[policy_id] = {
            "policy_id": policy_id,
            "policy_type": policy_type,
            "limit_value": limit_value,
            "currency": currency,
            "version": version,
            "required_actions": required_actions or [],
        }

    def verify_policy_proof(self, policy_proofs: list[dict]) -> PolicyResult:
        """Verify policy proofs (including ZKP)."""
        if not policy_proofs:
            return PolicyResult(valid=False, error="No policy proofs provided")

        for proof in policy_proofs:
            policy_id = proof.get("policyId", "")
            policy = self._policies.get(policy_id)
            if not policy:
                return PolicyResult(
                    valid=False, policy_id=policy_id,
                    error=f"Unknown policy: {policy_id}",
                )

            proof_type = proof.get("proofType", "")

            if proof_type == "zk-range-proof":
                zkp_result = self._zkp_verifier.verify_proof(
                    proof, policy["limit_value"]
                )
                if not zkp_result.valid:
                    return PolicyResult(
                        valid=False, policy_id=policy_id,
                        claim=zkp_result.claim, error=zkp_result.error,
                    )
                return PolicyResult(
                    valid=True, policy_id=policy_id, claim=zkp_result.claim,
                )

            elif proof_type == "signed-attestation":
                # For demo: accept if proof field is non-empty
                if proof.get("proof"):
                    return PolicyResult(
                        valid=True, policy_id=policy_id,
                        claim=proof.get("claim", "attested"),
                    )
                return PolicyResult(
                    valid=False, policy_id=policy_id,
                    error="Missing attestation signature",
                )

            else:
                return PolicyResult(
                    valid=False, policy_id=policy_id,
                    error=f"Unknown proof type: {proof_type}",
                )

        return PolicyResult(valid=True)

    def check_action_allowed(self, action: str, policy_id: str) -> bool:
        """Check if an action is allowed under a policy."""
        policy = self._policies.get(policy_id)
        if not policy:
            return False
        required = policy.get("required_actions", [])
        if not required:
            return True  # No restrictions
        return action in required

    def get_policy(self, policy_id: str) -> Optional[dict]:
        return self._policies.get(policy_id)

    def requires_human_approval(self, policy_id: str, context: dict) -> bool:
        """Check if context requires human approval based on policy limits."""
        policy = self._policies.get(policy_id)
        if not policy:
            return True  # Fail-safe: require approval for unknown policies
        amount = context.get("amount", 0)
        limit = policy.get("limit_value", 0)
        return amount > limit

    def generate_zkp_proof(self, amount: float, policy_id: str) -> dict:
        """Generate a ZKP proof for a given amount against a policy."""
        policy = self._policies.get(policy_id)
        if not policy:
            return {"valid": False, "error": f"Unknown policy: {policy_id}"}

        return self._zkp_verifier.generate_proof(
            private_amount=amount,
            policy_limit=policy["limit_value"],
            policy_id=policy_id,
            currency=policy.get("currency", "USD"),
        )


