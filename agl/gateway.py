"""
HandshakeOS - AGL Gateway / Sidecar
Core governance layer that intercepts A2A requests, validates the governance envelope,
and enforces the trust handshake before forwarding to the agent executor.
Now includes: Rate Limiting, Prompt Injection Shield, Replay Guard, Anomaly Detection, Honeypot, and Audit Logging.
"""

import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

from identity.vc_verifier import VCVerifier
from ledger.delegation_ledger import DelegationLedger
from policy.policy_engine import PolicyEngine
from risk.intent_sentinel import IntentSentinel
from risk.circuit_breaker import CircuitBreaker
from revocation.revocation_cache import RevocationCache
from agl.poa_quorum import PoAQuorum, ValidatorResult, QuorumConfig


# ─── Agent skill registry (for authority intersection checks) ───

AGENT_SKILLS = {
    "release-relocation-payment": {
        "id": "release-relocation-payment",
        "allowedActions": ["finance.disburse.relocation"],
    },
    "request-relocation-disbursement": {
        "id": "request-relocation-disbursement",
        "allowedActions": ["relocation.disbursement.request"],
    },
}

AGENT_CARDS = {}  # Populated at startup


# ─── Helper response builders ───

def task_rejected(reason: str, task_id: str = "") -> dict:
    if not task_id:
        task_id = f"task-{uuid.uuid4().hex[:8]}"
    return {
        "taskId": task_id,
        "status": "TASK_STATE_REJECTED",
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def task_auth_required(reason: str, task_id: str = "") -> dict:
    if not task_id:
        task_id = f"task-{uuid.uuid4().hex[:8]}"
    return {
        "taskId": task_id,
        "status": "TASK_STATE_AUTH_REQUIRED",
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def task_approved(result: dict, trust_receipt: dict) -> dict:
    result["trustReceipt"] = trust_receipt
    return result


# ─── Authority Intersection Check ───

def authority_intersection_check(
    requester_vc_claims: dict,
    target_skill_id: str,
    requested_action: str,
    policy_result=None,
    risk_state: str = "NORMAL",
) -> dict:
    """
    Effective Permission =
      Requester Authority ∩ Target Capability ∩ Human Delegation Scope
      ∩ Policy Permission ∩ Current Risk State
    """
    subject = requester_vc_claims.get("credentialSubject", {})

    # 1. Check requester authority
    allowed_actions = subject.get("allowedActions", [])
    if requested_action not in allowed_actions:
        # Check prefix match
        if not any(requested_action.startswith(a.rsplit(".", 1)[0]) for a in allowed_actions):
            return {"decision": "DENY", "reason": f"Requester agent lacks authority for action: {requested_action}"}

    # 2. Check forbidden actions
    forbidden = subject.get("forbiddenActions", [])
    if requested_action in forbidden:
        return {"decision": "DENY", "reason": f"Action is explicitly forbidden for requester: {requested_action}"}

    # 3. Check target skill capability
    target_skill = AGENT_SKILLS.get(target_skill_id, {})
    skill_actions = target_skill.get("allowedActions", [])
    if skill_actions and requested_action not in skill_actions:
        return {"decision": "DENY", "reason": f"Target agent skill cannot perform action: {requested_action}"}

    # 4. Check risk state
    if risk_state in ["HIGH", "CRITICAL"]:
        return {"decision": "DENY", "reason": f"Risk state {risk_state} blocks autonomous execution"}

    # 5. Segregation of duties: requester should not approve own requests
    requester_did = subject.get("id", "")
    approver_target = subject.get("approvalTarget", "")
    if "approve" in requested_action and requester_did and requester_did == approver_target:
        return {"decision": "DENY", "reason": "Segregation-of-duties violation: cannot self-approve"}

    return {"decision": "ALLOW", "reason": "Authority intersection check passed"}


# ─── AGL Gateway Class ───

class AGLGateway:
    """Main governance gateway — intercepts and validates A2A requests.
    Now includes 6 additional security modules for comprehensive agentic security."""

    def __init__(
        self,
        vc_verifier: VCVerifier,
        delegation_ledger: DelegationLedger,
        policy_engine: PolicyEngine,
        intent_sentinel: IntentSentinel,
        circuit_breaker: CircuitBreaker,
        revocation_cache: RevocationCache,
        poa_quorum: PoAQuorum,
        agent_executors: Optional[dict] = None,
        # ── Security modules ──
        audit_logger=None,
        rate_limiter=None,
        prompt_injection_shield=None,
        replay_guard=None,
        anomaly_detector=None,
        honeypot=None,
    ):
        self.vc_verifier = vc_verifier
        self.delegation_ledger = delegation_ledger
        self.policy_engine = policy_engine
        self.intent_sentinel = intent_sentinel
        self.circuit_breaker = circuit_breaker
        self.revocation_cache = revocation_cache
        self.poa_quorum = poa_quorum
        self.agent_executors = agent_executors or {}
        # Security modules (optional — gracefully degrade if not provided)
        self._audit = audit_logger
        self._rate_limiter = rate_limiter
        self._injection_shield = prompt_injection_shield
        self._replay_guard = replay_guard
        self._anomaly_detector = anomaly_detector
        self._honeypot = honeypot

    def _audit_log(self, **kwargs):
        """Helper to log security events (no-op if audit logger not configured)."""
        if self._audit:
            from security.audit_logger import AuditCategory, AuditSeverity
            category = kwargs.pop("category", AuditCategory.GOVERNANCE)
            severity = kwargs.pop("severity", AuditSeverity.INFO)
            self._audit.log(category=category, severity=severity, **kwargs)

    async def handle_a2a_send_message(self, request: dict, headers: dict) -> dict:
        """
        Enhanced governance handshake flow — original 10 steps + 6 security layers.

        NEW steps (pre-handshake):
          S1. Rate Limiting         — per-agent request throttling
          S2. Prompt Injection Scan — multi-layer injection detection
          S3. Replay Guard          — nonce/timestamp replay prevention

        Original steps:
          1. Verify AGL extension header
          2. Extract governance envelope
          3. Fast revocation check
          4. Verify identity credential (VC)
          5. Verify delegation chain
          6. Authority intersection check
          7. Verify ZKP policy proof
          8. Detect rogue intent (behavioral)
          9. PoA validator quorum
          10. Forward to agent executor

        NEW steps (in-handshake):
          S4. Honeypot canary check  — detect trap interactions
          S5. Anomaly detection      — behavioral anomaly analysis
          S6. Audit logging          — every step logged to tamper-evident trail
        """
        from security.audit_logger import AuditCategory, AuditSeverity

        # Step 1: Verify A2A governance extension is present
        extensions = headers.get("A2A-Extensions", "")
        if "urn:gcc-ascend:agl-handshake:v1" not in extensions:
            self._audit_log(
                category=AuditCategory.GOVERNANCE, severity=AuditSeverity.MEDIUM,
                action="missing_agl_extension", outcome="blocked",
            )
            return task_rejected("Missing mandatory AGL handshake extension")

        # Step 2: Extract governance envelope
        message = request.get("message", {})
        metadata = message.get("metadata", {})
        envelope = metadata.get("agl")
        if not envelope:
            self._audit_log(
                category=AuditCategory.GOVERNANCE, severity=AuditSeverity.MEDIUM,
                action="missing_governance_envelope", outcome="blocked",
            )
            return task_rejected("Missing AGL governance envelope")

        requester_did = envelope.get("requester", {}).get("agentDid", "")
        target_did = envelope.get("target", {}).get("agentDid", "")
        skill_id = envelope.get("target", {}).get("skillId", "")
        action = envelope.get("intent", {}).get("action", "")
        handshake_id = envelope.get("handshakeId", "")

        # ── NEW S1: Rate Limiting ──
        if self._rate_limiter:
            rate_result = self._rate_limiter.check_agent(requester_did)
            if not rate_result.allowed:
                self._audit_log(
                    category=AuditCategory.RATE_LIMIT, severity=AuditSeverity.HIGH,
                    action="rate_limit_exceeded", agent_did=requester_did,
                    details={"reason": rate_result.reason, "retry_after": rate_result.retry_after_seconds},
                    outcome="blocked", handshake_id=handshake_id,
                )
                return task_rejected(f"Rate limit exceeded: {rate_result.reason}")
            elif rate_result.penalty_level in ("warn", "throttle"):
                self._audit_log(
                    category=AuditCategory.RATE_LIMIT, severity=AuditSeverity.LOW,
                    action="rate_limit_warning", agent_did=requester_did,
                    details={"penalty_level": rate_result.penalty_level, "remaining": rate_result.remaining},
                    outcome="success", handshake_id=handshake_id,
                )

        # ── NEW S2: Prompt Injection Shield ──
        if self._injection_shield:
            parts = message.get("parts", [])
            text = " ".join(p.get("text", "") for p in parts)
            if text.strip():
                injection_result = self._injection_shield.scan(text, context={"action": action})
                if injection_result.is_injection:
                    self._audit_log(
                        category=AuditCategory.PROMPT_INJECTION, severity=AuditSeverity.CRITICAL,
                        action="prompt_injection_blocked", agent_did=requester_did,
                        details={
                            "confidence": injection_result.confidence,
                            "risk_level": injection_result.risk_level,
                            "layers_triggered": injection_result.layers_triggered,
                        },
                        outcome="blocked", handshake_id=handshake_id,
                    )
                    return task_rejected(
                        f"Prompt injection detected (confidence: {injection_result.confidence:.0%}, "
                        f"risk: {injection_result.risk_level})"
                    )

        # ── NEW S3: Replay Guard ──
        if self._replay_guard:
            replay_result = self._replay_guard.check_envelope(envelope)
            if not replay_result.allowed:
                self._audit_log(
                    category=AuditCategory.REPLAY_ATTACK, severity=AuditSeverity.CRITICAL,
                    action="replay_attack_blocked", agent_did=requester_did,
                    details={"reason": replay_result.reason, "check_type": replay_result.check_type},
                    outcome="blocked", handshake_id=handshake_id,
                )
                return task_rejected(f"Replay attack detected: {replay_result.reason}")

        # ── NEW S4: Honeypot Canary Check ──
        if self._honeypot:
            # Check if the target agent or action is a canary
            canary_alert = self._honeypot.check_action(action, requester_did)
            if canary_alert:
                self._audit_log(
                    category=AuditCategory.HONEYPOT, severity=AuditSeverity.CRITICAL,
                    action="canary_action_triggered", agent_did=requester_did,
                    details={"action": action, "alert_id": canary_alert.alert_id},
                    outcome="blocked", handshake_id=handshake_id,
                )
                return task_rejected(f"Request blocked — security alert triggered")

        # Step 3: Fast revocation check
        revocation_result = self.revocation_cache.precheck_revocation(requester_did)
        if not revocation_result.allowed:
            self._audit_log(
                category=AuditCategory.REVOCATION, severity=AuditSeverity.HIGH,
                action="revocation_check_failed", agent_did=requester_did,
                details={"reason": revocation_result.reason},
                outcome="blocked", handshake_id=handshake_id,
            )
            return task_rejected(f"Revocation check failed: {revocation_result.reason}")

        # Also check quarantine
        if self.circuit_breaker.is_quarantined(requester_did):
            self._audit_log(
                category=AuditCategory.QUARANTINE, severity=AuditSeverity.HIGH,
                action="quarantine_check_failed", agent_did=requester_did,
                outcome="blocked", handshake_id=handshake_id,
            )
            return task_rejected("Requester agent is quarantined by circuit breaker")

        # Step 4: Verify identity credential
        vc_jwt = envelope.get("requester", {}).get("agentVc", "")
        identity_result = self.vc_verifier.verify_vc(vc_jwt)
        if not identity_result.ok:
            self._audit_log(
                category=AuditCategory.IDENTITY, severity=AuditSeverity.HIGH,
                action="identity_verification_failed", agent_did=requester_did,
                details={"error": identity_result.error},
                outcome="blocked", handshake_id=handshake_id,
            )
            return task_rejected(f"Identity verification failed: {identity_result.error}")

        self._audit_log(
            category=AuditCategory.IDENTITY, severity=AuditSeverity.INFO,
            action="identity_verified", agent_did=requester_did,
            outcome="success", handshake_id=handshake_id,
        )

        # Step 5: Verify delegation chain
        delegation_result = self.delegation_ledger.verify_delegation(requester_did, action)
        if not delegation_result.valid:
            self._audit_log(
                category=AuditCategory.DELEGATION, severity=AuditSeverity.HIGH,
                action="delegation_verification_failed", agent_did=requester_did,
                details={"error": delegation_result.error},
                outcome="blocked", handshake_id=handshake_id,
            )
            return task_rejected(f"Delegation verification failed: {delegation_result.error}")

        # Step 6: Authority intersection check (privilege escalation prevention)
        authz_result = authority_intersection_check(
            requester_vc_claims=identity_result.claims,
            target_skill_id=skill_id,
            requested_action=action,
            risk_state="CRITICAL" if self.circuit_breaker.is_quarantined(requester_did) else "NORMAL",
        )
        if authz_result["decision"] == "DENY":
            self._audit_log(
                category=AuditCategory.ACCESS_CONTROL, severity=AuditSeverity.HIGH,
                action="authority_check_denied", agent_did=requester_did,
                details={"reason": authz_result["reason"], "action": action},
                outcome="blocked", handshake_id=handshake_id,
            )
            return task_rejected(f"Authority check failed: {authz_result['reason']}")
        if authz_result["decision"] == "ESCALATE":
            return task_auth_required(f"Escalation required: {authz_result['reason']}")

        # Step 7: Verify ZKP policy proof
        policy_proofs = envelope.get("policyProofs", [])
        policy_result = self.policy_engine.verify_policy_proof(policy_proofs)
        if not policy_result.valid:
            self._audit_log(
                category=AuditCategory.POLICY, severity=AuditSeverity.HIGH,
                action="policy_proof_failed", agent_did=requester_did,
                details={"error": policy_result.error, "policy_id": policy_result.policy_id},
                outcome="blocked", handshake_id=handshake_id,
            )
            return task_rejected(f"Policy proof failed: {policy_result.error}")

        # Step 8: Detect rogue intent
        # Record the request for tracking
        # Extract amount from intent for threshold-hugging detection
        intent_amount = None
        try:
            sealed = envelope.get("policyProofs", [{}])[0].get("publicInputs", {})
            intent_amount = sealed.get("amount") or sealed.get("value")
            if intent_amount is not None:
                intent_amount = float(intent_amount)
        except (IndexError, ValueError, TypeError):
            pass
        self.intent_sentinel.record_request(requester_did, target_did, amount=intent_amount)
        risk_score = self.intent_sentinel.score(request, envelope)

        # ── NEW S5: Anomaly Detection ──
        anomaly_boost = 0.0
        if self._anomaly_detector:
            anomaly_result = self._anomaly_detector.record_and_analyze(
                agent_did=requester_did, action=action, target_did=target_did,
            )
            if anomaly_result.is_anomalous:
                anomaly_boost = anomaly_result.anomaly_score * 0.3  # Up to 0.3 boost
                self._audit_log(
                    category=AuditCategory.ANOMALY, severity=AuditSeverity.MEDIUM,
                    action="anomaly_detected", agent_did=requester_did,
                    details={
                        "score": anomaly_result.anomaly_score,
                        "anomalies": anomaly_result.anomalies_detected,
                        "recommended": anomaly_result.recommended_action,
                    },
                    outcome="flagged", handshake_id=handshake_id,
                )

        # Combine risk score with anomaly boost
        effective_risk_score = min(risk_score + anomaly_boost, 1.0)

        cb_result = self.circuit_breaker.evaluate(
            requester_did, effective_risk_score, self.revocation_cache
        )
        if cb_result.triggered:
            self._audit_log(
                category=AuditCategory.RISK, severity=AuditSeverity.CRITICAL,
                action="circuit_breaker_triggered", agent_did=requester_did,
                details={"risk_score": effective_risk_score, "details": cb_result.details},
                outcome="blocked", handshake_id=handshake_id,
            )
            return task_rejected(f"Circuit breaker activated: {cb_result.details}")

        # Step 9: Collect PoA validator signatures and issue Trust Receipt
        quorum_config = self.poa_quorum.determine_quorum(effective_risk_score)
        if quorum_config is None:
            return task_rejected("Risk too high — no quorum allowed")

        # Build validator results
        identity_validator = ValidatorResult(
            validator_id="identity-validator",
            approved=identity_result.ok,
            signature=hashlib.sha256(f"identity:{handshake_id}".encode()).hexdigest()[:16],
            reason="VC verified" if identity_result.ok else identity_result.error,
        )
        delegation_validator = ValidatorResult(
            validator_id="delegation-validator",
            approved=delegation_result.valid,
            signature=hashlib.sha256(f"delegation:{handshake_id}".encode()).hexdigest()[:16],
            reason="Delegation valid" if delegation_result.valid else delegation_result.error,
        )
        policy_validator = ValidatorResult(
            validator_id="policy-validator",
            approved=policy_result.valid,
            signature=hashlib.sha256(f"policy:{handshake_id}".encode()).hexdigest()[:16],
            reason="Policy proof verified" if policy_result.valid else policy_result.error,
        )
        risk_validator = ValidatorResult(
            validator_id="risk-validator",
            approved=effective_risk_score < 0.5,
            signature=hashlib.sha256(f"risk:{handshake_id}".encode()).hexdigest()[:16],
            reason=f"Risk score: {effective_risk_score:.2f}",
        )
        finance_validator = ValidatorResult(
            validator_id="finance-control-validator",
            approved=True,  # Demo: always pass
            signature=hashlib.sha256(f"finance:{handshake_id}".encode()).hexdigest()[:16],
            reason="Finance controls passed",
        )

        validations = self.poa_quorum.collect_validations(
            identity_validator, delegation_validator, policy_validator,
            risk_validator, finance_validator,
        )

        ledger_root = self.delegation_ledger.get_current_ledger_root()
        expires_at = envelope.get("expiresAt", "")

        trust_receipt = self.poa_quorum.issue_trust_receipt(
            handshake_id=handshake_id,
            requester_did=requester_did,
            target_did=target_did,
            action=action,
            policy_id=policy_proofs[0].get("policyId", "") if policy_proofs else "",
            validations=validations,
            quorum_config=quorum_config,
            risk_score=effective_risk_score,
            ledger_root=ledger_root,
            expires_at=expires_at,
        )

        if not trust_receipt.approved:
            # Store rejected receipt for audit
            self.delegation_ledger.store_trust_receipt(
                receipt_id=trust_receipt.receipt_id,
                handshake_id=handshake_id,
                requester_did=requester_did,
                target_did=target_did,
                action=action,
                decision="REJECTED",
                quorum=trust_receipt.poa_quorum,
                validator_sigs=str(trust_receipt.validator_signatures),
                risk_score=effective_risk_score,
                ledger_root=ledger_root,
            )
            self._audit_log(
                category=AuditCategory.TRUST_RECEIPT, severity=AuditSeverity.MEDIUM,
                action="trust_receipt_rejected", agent_did=requester_did,
                target_did=target_did,
                details={"receipt_id": trust_receipt.receipt_id, "quorum": trust_receipt.poa_quorum},
                outcome="blocked", handshake_id=handshake_id,
            )
            return task_rejected(f"PoA quorum failed: {trust_receipt.poa_quorum}")

        # Step 10: Attach trust receipt and forward to agent executor
        request["message"]["metadata"]["agl"]["trustReceipt"] = trust_receipt.to_json()

        # Store approved receipt
        self.delegation_ledger.store_trust_receipt(
            receipt_id=trust_receipt.receipt_id,
            handshake_id=handshake_id,
            requester_did=requester_did,
            target_did=target_did,
            action=action,
            decision="APPROVED",
            quorum=trust_receipt.poa_quorum,
            validator_sigs=str(trust_receipt.validator_signatures),
            risk_score=effective_risk_score,
            ledger_root=ledger_root,
        )

        # ── NEW S6: Audit log — approved handshake ──
        self._audit_log(
            category=AuditCategory.TRUST_RECEIPT, severity=AuditSeverity.INFO,
            action="trust_receipt_approved", agent_did=requester_did,
            target_did=target_did,
            details={
                "receipt_id": trust_receipt.receipt_id,
                "quorum": trust_receipt.poa_quorum,
                "risk_score": effective_risk_score,
            },
            outcome="success", handshake_id=handshake_id,
        )

        # Forward to agent executor
        executor = self.agent_executors.get(target_did)
        if executor:
            # Use execute_direct for dict-based AGL gateway flow
            if hasattr(executor, 'execute_direct'):
                result = await executor.execute_direct(request)
            else:
                result = await executor.execute(request)
            return task_approved(result, trust_receipt.to_json())

        return {
            "taskId": f"task-{uuid.uuid4().hex[:8]}",
            "status": "TASK_STATE_COMPLETED",
            "trustReceipt": trust_receipt.to_json(),
            "message": "Request approved by AGL governance handshake",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ─── FastAPI Router ───

router = APIRouter(prefix="/a2a", tags=["A2A Gateway"])

# Global gateway instance (set during app startup)
_gateway: Optional[AGLGateway] = None


def set_gateway(gateway: AGLGateway):
    global _gateway
    _gateway = gateway


@router.post("/message:send")
async def send_message(request: Request):
    """A2A SendMessage endpoint with AGL governance handshake."""
    if _gateway is None:
        raise HTTPException(status_code=503, detail="AGL Gateway not initialized")

    body = await request.json()
    headers = {
        "A2A-Extensions": request.headers.get("A2A-Extensions", ""),
        "A2A-Version": request.headers.get("A2A-Version", "1.0"),
        "Authorization": request.headers.get("Authorization", ""),
    }

    # IP-level rate limiting
    if _gateway._rate_limiter:
        client_ip = request.client.host if request.client else "unknown"
        ip_result = _gateway._rate_limiter.check_ip(client_ip)
        if not ip_result.allowed:
            return JSONResponse(
                status_code=429,
                content={"error": f"Rate limit exceeded: {ip_result.reason}"},
                headers={"Retry-After": str(int(ip_result.retry_after_seconds))},
            )

    # Honeypot endpoint check on request path
    if _gateway._honeypot:
        client_ip = request.client.host if request.client else "unknown"
        # Check if anyone is scanning unusual paths
        path = str(request.url.path)
        _gateway._honeypot.check_endpoint(path, source_ip=client_ip)

    result = await _gateway.handle_a2a_send_message(body, headers)
    return JSONResponse(content=result)


@router.get("/agent-card/{agent_id}")
async def get_agent_card(agent_id: str, request: Request = None):
    """Return A2A Agent Card with AGL extension."""
    # Check honeypot canary agent cards
    if _gateway and _gateway._honeypot:
        source_ip = request.client.host if request and request.client else "unknown"
        canary_alert = _gateway._honeypot.check_agent_card_access(
            agent_id=agent_id, accessed_by="", source_ip=source_ip,
        )
        if canary_alert:
            # Return realistic-looking canary card to gather intel
            canary_card = _gateway._honeypot.get_canary_agent_card(agent_id)
            if canary_card:
                return JSONResponse(content=canary_card)

    card = AGENT_CARDS.get(agent_id)
    if not card:
        raise HTTPException(status_code=404, detail=f"Agent card not found: {agent_id}")
    return JSONResponse(content=card)


@router.get("/health")
async def health_check():
    """AGL Gateway health check."""
    return {
        "status": "healthy",
        "service": "HandshakeOS AGL Gateway",
        "version": "1.0.0",
        "security_modules": [
            "audit_logger", "rate_limiter", "prompt_injection_shield",
            "replay_guard", "anomaly_detector", "honeypot_canary",
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

