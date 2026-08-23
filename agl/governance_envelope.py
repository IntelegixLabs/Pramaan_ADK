"""
HandshakeOS - Governance Envelope Builder
Constructs AGL governance envelopes for A2A message metadata.
"""

import uuid
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass
class RequesterInfo:
    agent_did: str
    agent_vc: str  # JWT


@dataclass
class TargetInfo:
    agent_did: str
    skill_id: str


@dataclass
class IntentInfo:
    action: str
    business_case_ref: str
    intent_hash: str
    originating_human: str


@dataclass
class DelegationProof:
    ledger_root: str
    delegation_event_id: str
    delegated_by: str
    delegation_scope: str
    valid_until: str


@dataclass
class PolicyProof:
    policy_id: str
    proof_type: str
    claim: str
    public_inputs: dict = field(default_factory=dict)
    proof: str = ""


@dataclass
class RiskSignals:
    agent_model_hash: str = ""
    prompt_template_hash: str = ""
    risk_score: float = 0.0


@dataclass
class GovernanceEnvelope:
    version: str
    handshake_id: str
    requester: RequesterInfo
    target: TargetInfo
    intent: IntentInfo
    delegation_proof: DelegationProof
    policy_proofs: list[PolicyProof]
    risk_signals: RiskSignals
    nonce: str
    expires_at: str
    signature: str = ""

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "handshakeId": self.handshake_id,
            "requester": {
                "agentDid": self.requester.agent_did,
                "agentVc": self.requester.agent_vc,
            },
            "target": {
                "agentDid": self.target.agent_did,
                "skillId": self.target.skill_id,
            },
            "intent": {
                "action": self.intent.action,
                "businessCaseRef": self.intent.business_case_ref,
                "intentHash": self.intent.intent_hash,
                "originatingHuman": self.intent.originating_human,
            },
            "delegationProof": {
                "ledgerRoot": self.delegation_proof.ledger_root,
                "delegationEventId": self.delegation_proof.delegation_event_id,
                "delegatedBy": self.delegation_proof.delegated_by,
                "delegationScope": self.delegation_proof.delegation_scope,
                "validUntil": self.delegation_proof.valid_until,
            },
            "policyProofs": [
                {
                    "policyId": p.policy_id,
                    "proofType": p.proof_type,
                    "claim": p.claim,
                    "publicInputs": p.public_inputs,
                    "proof": p.proof,
                }
                for p in self.policy_proofs
            ],
            "riskSignals": {
                "agentModelHash": self.risk_signals.agent_model_hash,
                "promptTemplateHash": self.risk_signals.prompt_template_hash,
                "riskScore": self.risk_signals.risk_score,
            },
            "nonce": self.nonce,
            "expiresAt": self.expires_at,
            "signature": self.signature,
        }


def build_governance_envelope(
    requester_did: str,
    requester_vc: str,
    target_did: str,
    skill_id: str,
    action: str,
    business_case_ref: str,
    originating_human: str,
    delegation_proof: DelegationProof,
    policy_proofs: list[PolicyProof],
    risk_signals: Optional[RiskSignals] = None,
    expires_minutes: int = 30,
) -> GovernanceEnvelope:
    """Build a complete AGL governance envelope."""
    now = datetime.now(timezone.utc)
    uid = uuid.uuid4().hex[:6]
    handshake_id = f"hs-{now.year}-{uid}"

    intent_hash = hashlib.sha256(
        f"{action}:{business_case_ref}".encode()
    ).hexdigest()

    nonce = secrets.token_hex(16)
    expires_at = (now + timedelta(minutes=expires_minutes)).isoformat()

    if risk_signals is None:
        risk_signals = RiskSignals()

    # Placeholder signature (in production, sign the envelope)
    signature = hashlib.sha256(
        f"{handshake_id}:{nonce}:{requester_did}".encode()
    ).hexdigest()

    return GovernanceEnvelope(
        version="1.0",
        handshake_id=handshake_id,
        requester=RequesterInfo(agent_did=requester_did, agent_vc=requester_vc),
        target=TargetInfo(agent_did=target_did, skill_id=skill_id),
        intent=IntentInfo(
            action=action,
            business_case_ref=business_case_ref,
            intent_hash=intent_hash,
            originating_human=originating_human,
        ),
        delegation_proof=delegation_proof,
        policy_proofs=policy_proofs,
        risk_signals=risk_signals,
        nonce=nonce,
        expires_at=expires_at,
        signature=signature,
    )


def build_a2a_message(
    text: str,
    envelope: GovernanceEnvelope,
    message_id: Optional[str] = None,
    configuration: Optional[dict] = None,
) -> dict:
    """Build a full A2A SendMessageRequest with governance envelope in metadata."""
    if message_id is None:
        message_id = f"msg-{uuid.uuid4().hex[:8]}"

    if configuration is None:
        configuration = {
            "acceptedOutputModes": ["application/json"],
            "returnImmediately": False,
        }

    return {
        "message": {
            "messageId": message_id,
            "role": "ROLE_USER",
            "parts": [{"text": text}],
            "extensions": ["urn:gcc-ascend:agl-handshake:v1"],
            "metadata": {
                "agl": envelope.to_dict(),
            },
        },
        "configuration": configuration,
    }

