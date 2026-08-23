"""
HandshakeOS - Trust Receipt
Model and serialization for PoA Trust Receipts.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TrustReceipt:
    receipt_id: str
    handshake_id: str
    decision: str  # APPROVED, REJECTED
    requester: str
    target: str
    action: str
    policy: str
    poa_quorum: str
    validator_signatures: list[dict] = field(default_factory=list)
    constraints: dict = field(default_factory=dict)
    ledger_root: str = ""
    receipt_signature: str = ""
    approved: bool = False

    def to_json(self) -> dict:
        return {
            "receiptId": self.receipt_id,
            "handshakeId": self.handshake_id,
            "decision": self.decision,
            "requester": self.requester,
            "target": self.target,
            "action": self.action,
            "policy": self.policy,
            "poa": {
                "quorum": self.poa_quorum,
                "validators": [v.get("validator_id", "") for v in self.validator_signatures],
                "signatures": [v.get("signature", "") for v in self.validator_signatures],
            },
            "constraints": self.constraints,
            "ledgerRoot": self.ledger_root,
            "receiptSignature": self.receipt_signature,
        }

    def to_a2a_metadata(self) -> dict:
        return {"trustReceipt": self.to_json()}

    @classmethod
    def from_dict(cls, data: dict) -> "TrustReceipt":
        poa = data.get("poa", {})
        validators = poa.get("validators", [])
        signatures = poa.get("signatures", [])
        validator_sigs = [
            {"validator_id": v, "signature": s}
            for v, s in zip(validators, signatures)
        ]
        return cls(
            receipt_id=data.get("receiptId", ""),
            handshake_id=data.get("handshakeId", ""),
            decision=data.get("decision", ""),
            requester=data.get("requester", ""),
            target=data.get("target", ""),
            action=data.get("action", ""),
            policy=data.get("policy", ""),
            poa_quorum=poa.get("quorum", ""),
            validator_signatures=validator_sigs,
            constraints=data.get("constraints", {}),
            ledger_root=data.get("ledgerRoot", ""),
            receipt_signature=data.get("receiptSignature", ""),
            approved=data.get("decision") == "APPROVED",
        )

