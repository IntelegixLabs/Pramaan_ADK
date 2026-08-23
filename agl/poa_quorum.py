"""
HandshakeOS - Proof-of-Authority Validator Quorum
Collects validator results and issues Trust Receipts based on quorum rules.
"""

import uuid
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from agl.trust_receipt import TrustReceipt


@dataclass
class ValidatorResult:
    validator_id: str
    approved: bool
    signature: str = ""
    reason: str = ""


@dataclass
class QuorumConfig:
    total_validators: int
    required_approvals: int
    validator_ids: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.required_approvals}-of-{self.total_validators}"


# Default quorum configurations
DEFAULT_QUORUM_CONFIGS = {
    "low": QuorumConfig(
        total_validators=3,
        required_approvals=2,
        validator_ids=["identity-validator", "delegation-validator", "policy-validator"],
    ),
    "high": QuorumConfig(
        total_validators=5,
        required_approvals=3,
        validator_ids=[
            "identity-validator", "delegation-validator",
            "policy-validator", "risk-validator", "finance-control-validator",
        ],
    ),
    "suspicious": None,  # No quorum allowed; circuit breaker
}


class PoAQuorum:
    """Proof-of-Authority quorum validator for governance handshakes."""

    def __init__(self, quorum_configs: Optional[dict] = None):
        self.quorum_configs = quorum_configs or DEFAULT_QUORUM_CONFIGS

    def determine_quorum(self, risk_score: float,
                         amount_policy_verified: bool = True) -> Optional[QuorumConfig]:
        """Determine the appropriate quorum based on risk level."""
        if risk_score >= 0.85:
            return None  # Suspicious — circuit breaker

        if risk_score >= 0.5 or not amount_policy_verified:
            return self.quorum_configs.get("high")

        return self.quorum_configs.get("low")

    def collect_validations(
        self,
        identity_result: ValidatorResult,
        delegation_result: ValidatorResult,
        policy_result: ValidatorResult,
        risk_result: Optional[ValidatorResult] = None,
        finance_result: Optional[ValidatorResult] = None,
    ) -> list[ValidatorResult]:
        """Collect all validator results into a list."""
        results = [identity_result, delegation_result, policy_result]
        if risk_result is not None:
            results.append(risk_result)
        if finance_result is not None:
            results.append(finance_result)
        return results

    def issue_trust_receipt(
        self,
        handshake_id: str,
        requester_did: str,
        target_did: str,
        action: str,
        policy_id: str,
        validations: list[ValidatorResult],
        quorum_config: QuorumConfig,
        risk_score: float,
        ledger_root: str,
        expires_at: str,
    ) -> TrustReceipt:
        """Issue a Trust Receipt if quorum is met."""
        approved_count = sum(1 for v in validations if v.approved)
        quorum_met = approved_count >= quorum_config.required_approvals
        decision = "APPROVED" if quorum_met else "REJECTED"

        receipt_id = f"tr-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8]}"

        validator_sigs = [
            {"validator_id": v.validator_id, "signature": v.signature, "approved": v.approved}
            for v in validations
        ]

        # Aggregate signature (demo: hash of all signatures)
        sig_data = ":".join(v.signature for v in validations if v.approved)
        receipt_signature = hashlib.sha256(sig_data.encode()).hexdigest()

        return TrustReceipt(
            receipt_id=receipt_id,
            handshake_id=handshake_id,
            decision=decision,
            requester=requester_did,
            target=target_did,
            action=action,
            policy=policy_id,
            poa_quorum=str(quorum_config),
            validator_signatures=validator_sigs,
            constraints={
                "oneTimeUse": True,
                "expiresAt": expires_at,
                "maxAmountPolicyVerified": True,
            },
            ledger_root=ledger_root,
            receipt_signature=receipt_signature,
            approved=quorum_met,
        )



