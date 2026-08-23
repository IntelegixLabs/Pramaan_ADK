"""
HandshakeOS - Governance Test Bench
===================================
A configurable governance/security tester. Pick a requester agent and a target
agent, supply a test payload (message / action / amount), toggle which security
parameters to run, and get a real per-parameter result by executing each enabled
check against the live security services.

Groups:
  - Global Security Pipeline (PII, Goal, OPA, Sandbox, Human Review, Output Validator)
  - Core Governance (VC, Delegation, ZKP, Risk, PoA Quorum, Authority, Revocation,
    Circuit Breaker, Segregation of Duties)
  - Advanced Security (Audit, Rate Limit, Prompt Injection, Replay, Anomaly, Honeypot)
"""

import time
import uuid
import asyncio
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

DEFAULT_POLICY_ID = "policy-relocation-autopay-v3"
DEFAULT_ACTION = "finance.disburse.relocation"

# Built-in demo agents that already have governance (VC / delegation) provisioned.
BUILTIN_AGENTS = [
    {
        "id": "hr-relocation-07",
        "name": "HR Relocation Agent",
        "did": "did:gcc:agent:hr-relocation-07",
        "kind": "builtin",
        "owner_human": "did:gcc:employee:global-mobility-director",
        "allowed_actions": ["relocation.case.create", "relocation.disbursement.request", "finance.disburse.relocation"],
        "forbidden_actions": ["finance.payment.approve", "finance.payment.release"],
        "tools": [{"name": "relocation.disbursement.request"}, {"name": "finance.disburse.relocation"}],
    },
    {
        "id": "finance-disbursement-02",
        "name": "Finance Disbursement Agent",
        "did": "did:gcc:agent:finance-disbursement-02",
        "kind": "builtin",
        "owner_human": "did:gcc:employee:finance-controller",
        "allowed_actions": ["finance.disburse.relocation"],
        "forbidden_actions": [],
        "tools": [{"name": "finance.disburse.relocation"}],
    },
]


# ── Catalog of testable governance parameters (grouped) ──────────────────────
GOVERNANCE_PARAMS: List[Dict[str, Any]] = [
    # Global Security Pipeline
    {"id": "pii_redactor", "name": "PII Redactor", "group": "Global Security Pipeline",
     "description": "Masks sensitive entities (email, SSN, cards, API keys) in the request.", "default": True},
    {"id": "goal_checker", "name": "Goal Integrity Checker", "group": "Global Security Pipeline",
     "description": "Validates the requested action aligns with the user's stated intent.", "default": True},
    {"id": "opa_rego", "name": "OPA / Rego Engine", "group": "Global Security Pipeline",
     "description": "Declarative access control over principal + tool risk.", "default": True},
    {"id": "sandbox", "name": "Sandbox Limits", "group": "Global Security Pipeline",
     "description": "Blocklist for unsafe tools and autonomy budget limits.", "default": True},
    {"id": "human_review", "name": "Human Review Queue", "group": "Global Security Pipeline",
     "description": "High-risk / high-value actions pause for human approval.", "default": True},
    {"id": "output_validator", "name": "Output Validator", "group": "Global Security Pipeline",
     "description": "Final scan of agent output against a blocklist.", "default": True},
    # Core Governance
    {"id": "identity_verification", "name": "Verifiable Credential", "group": "Core Governance",
     "description": "Agent Passport VC (W3C VC v2.0) issued + verified.", "default": True},
    {"id": "revocation_check", "name": "Revocation Enforcement", "group": "Core Governance",
     "description": "Sub-second fail-closed revocation denylist check.", "default": True},
    {"id": "delegation_verification", "name": "Delegation Proof", "group": "Core Governance",
     "description": "Human-to-agent delegation chain covers the action.", "default": True},
    {"id": "authority_intersection", "name": "Authority Intersection", "group": "Core Governance",
     "description": "Effective permission = Requester ∩ Target ∩ Delegation ∩ Policy ∩ Risk.", "default": True},
    {"id": "zkp_policy_proof", "name": "ZKP Policy Proof", "group": "Core Governance",
     "description": "Zero-knowledge proof that amount ≤ policy limit.", "default": True},
    {"id": "intent_risk_scoring", "name": "Intent Risk Scoring", "group": "Core Governance",
     "description": "6-signal behavioral rogue-agent risk score.", "default": True},
    {"id": "poa_quorum", "name": "PoA Quorum + Trust Receipt", "group": "Core Governance",
     "description": "Multi-validator consensus (2-of-3 / 3-of-5) + signed receipt.", "default": True},
    {"id": "circuit_breaker", "name": "Circuit Breaker", "group": "Core Governance",
     "description": "Auto-quarantine when risk threshold is breached.", "default": True},
    {"id": "segregation_of_duties", "name": "Segregation of Duties", "group": "Core Governance",
     "description": "An agent cannot approve its own request.", "default": True},
    # Advanced Security
    {"id": "audit_logger", "name": "Security Audit Logger", "group": "Advanced Security",
     "description": "Tamper-evident hash-chained audit trail.", "default": True},
    {"id": "rate_limiter", "name": "API Rate Limiter", "group": "Advanced Security",
     "description": "Per-agent sliding-window rate limiting.", "default": True},
    {"id": "prompt_injection_shield", "name": "Prompt Injection Shield", "group": "Advanced Security",
     "description": "6-layer prompt-injection detection on the payload.", "default": True},
    {"id": "replay_guard", "name": "Replay Attack Guard", "group": "Advanced Security",
     "description": "Nonce / timestamp / hash replay prevention.", "default": True},
    {"id": "anomaly_detector", "name": "Behavioral Anomaly Detector", "group": "Advanced Security",
     "description": "Time-series anomaly detection vs the agent's baseline.", "default": True},
    {"id": "honeypot_canary", "name": "Honeypot / Canary", "group": "Advanced Security",
     "description": "Trap actions/endpoints that no legitimate agent should touch.", "default": True},
]

_GROUP_ORDER = ["Global Security Pipeline", "Core Governance", "Advanced Security"]


def get_governance_params() -> Dict[str, Any]:
    groups: Dict[str, List[dict]] = {}
    for p in GOVERNANCE_PARAMS:
        groups.setdefault(p["group"], []).append(p)
    return {
        "groups": [{"name": g, "items": groups.get(g, [])} for g in _GROUP_ORDER],
        "all_ids": [p["id"] for p in GOVERNANCE_PARAMS],
        "default_ids": [p["id"] for p in GOVERNANCE_PARAMS if p["default"]],
        "total": len(GOVERNANCE_PARAMS),
    }


def get_governance_agents() -> List[Dict[str, Any]]:
    """Selectable agents: built-in governed demo agents + custom builder agents."""
    agents = [dict(a) for a in BUILTIN_AGENTS]
    try:
        from security.agent_manager import agent_manager
        for a in agent_manager.get_all_agents():
            agents.append({
                "id": a["id"],
                "name": a.get("name", a["id"]),
                "did": f"did:gcc:agent:{a['id']}",
                "kind": "custom",
                "owner_human": a.get("owner_human", "did:gcc:employee:builder"),
                "allowed_actions": [t.get("name") for t in a.get("tools", []) if t.get("name")],
                "forbidden_actions": [],
                "tools": a.get("tools", []),
            })
    except Exception as e:
        logger.info(f"governance agents: could not load custom agents: {e}")
    return agents


def _result(pid, name, group, status, detail, severity="info"):
    return {"id": pid, "name": name, "group": group, "status": status, "detail": detail, "severity": severity}


async def run_governance_test(config: dict) -> Dict[str, Any]:
    """Run the enabled governance parameters against the requester→target request."""
    # ── Lazy imports of live services (avoids circular import at module load) ──
    from main import (
        vc_issuer, vc_verifier, delegation_ledger, policy_engine,
        intent_sentinel, circuit_breaker, revocation_cache, poa_quorum,
        audit_logger, rate_limiter, prompt_injection_shield, replay_guard,
        anomaly_detector, honeypot,
    )
    from security.pii_redactor import pii_redactor
    from security.goal_checker import goal_checker
    from security.authorization import authorization_engine, Principal
    from security.sandbox import sandbox
    from security.output_validator import output_validator
    from agl.gateway import authority_intersection_check
    from agl.poa_quorum import ValidatorResult
    import hashlib

    t0 = time.time()

    requester = config.get("requester") or {}
    target = config.get("target") or {}
    requester_did = requester.get("did") or f"did:gcc:agent:{requester.get('id','requester')}"
    target_did = target.get("did") or f"did:gcc:agent:{target.get('id','target')}"
    owner_human = requester.get("owner_human") or "did:gcc:employee:builder"
    allowed_actions = requester.get("allowed_actions") or []
    forbidden_actions = requester.get("forbidden_actions") or []

    message = (config.get("message") or "").strip()
    action = (config.get("action") or DEFAULT_ACTION).strip()
    try:
        amount = float(config.get("amount", 8000) or 0)
    except (TypeError, ValueError):
        amount = 8000.0
    policy_id = config.get("policy_id") or DEFAULT_POLICY_ID
    policy = policy_engine.get_policy(policy_id) or {}
    policy_limit = float(policy.get("limit_value", 10000.0))

    checks = config.get("checks")
    # No checks dict -> run everything. A dict -> run only the ids set truthy.
    if checks is None:
        enabled = {p["id"]: True for p in GOVERNANCE_PARAMS}
    else:
        enabled = {p["id"]: bool(checks.get(p["id"], False)) for p in GOVERNANCE_PARAMS}

    if action not in allowed_actions:
        allowed_actions = allowed_actions + [action]

    results: List[Dict[str, Any]] = []

    # Issue a passport for the requester (used by identity + authority + quorum).
    vc_jwt = None
    vc_claims = {}
    try:
        vc_jwt = vc_issuer.issue_agent_passport(
            agent_did=requester_did, agent_name=requester.get("name", requester_did),
            business_domain="Test", owner_human=owner_human,
            allowed_actions=allowed_actions, forbidden_actions=forbidden_actions,
            max_autonomous_amount={"value": policy_limit, "currency": "USD"},
            allowed_counterparties=[target_did], policy_bundle="relocation-policy-v3",
        )
        vres = vc_verifier.verify_vc(vc_jwt)
        vc_ok = vres.ok
        vc_claims = vres.claims or {}
    except Exception as e:
        vc_ok = False
        vc_claims = {}
        logger.info(f"VC issue/verify failed: {e}")

    def add(pid, fn):
        """Run a check fn if enabled, else mark skipped."""
        meta = next((p for p in GOVERNANCE_PARAMS if p["id"] == pid), {"name": pid, "group": ""})
        if not enabled.get(pid, False):
            results.append(_result(pid, meta["name"], meta["group"], "skipped", "Disabled for this run", "none"))
            return
        try:
            status, detail, severity = fn()
            results.append(_result(pid, meta["name"], meta["group"], status, detail, severity))
        except Exception as e:
            results.append(_result(pid, meta["name"], meta["group"], "error", f"Check error: {str(e)[:160]}", "medium"))

    # ── Global Security Pipeline ──
    redaction = None

    def _pii():
        nonlocal redaction
        redaction = pii_redactor.redact(message or " ")
        findings = getattr(redaction, "findings", []) or []
        if findings:
            return "warning", f"Redacted {len(findings)} PII entity(ies): {', '.join(str(f) for f in findings)[:120]}", "medium"
        return "passed", "No PII detected in the payload.", "info"
    add("pii_redactor", _pii)

    def _goal():
        text = getattr(redaction, "text", message) if redaction else message
        ok, msg = goal_checker.check(text or " ", action)
        return ("passed", msg or "Goal aligns with requested action.", "info") if ok else ("failed", msg or "Goal mismatch.", "high")
    add("goal_checker", _goal)

    # OPA decision is reused by human_review
    opa_decision = {"decision": "allow", "reason": ""}

    def _opa():
        nonlocal opa_decision
        risk = "low" if amount <= policy_limit * 0.5 else "high"
        principal = Principal(user_id=owner_human, tenant_id="t1", role="admin",
                              scopes=[action], department="HR", environment="prod")
        opa_decision = authorization_engine.evaluate(
            principal=principal,
            tool={"name": action, "risk": risk, "required_scope": action},
            context={"goal_match": True, "amount": amount},
        )
        dec = opa_decision.get("decision", "deny")
        reason = opa_decision.get("reason", "")
        if dec == "allow":
            return "passed", reason or "OPA allowed the action.", "info"
        if dec == "review":
            return "review", reason or "OPA routed to human review.", "medium"
        return "failed", reason or "OPA denied the action.", "high"
    add("opa_rego", _opa)

    def _sandbox():
        ok, msg = sandbox.check_tool(action)
        return ("passed", msg or "Tool within sandbox limits.", "info") if ok else ("failed", msg or "Tool blocked by sandbox.", "high")
    add("sandbox", _sandbox)

    def _human_review():
        high_value = amount >= policy_limit * 0.9
        if opa_decision.get("decision") == "review" or high_value:
            return "review", f"High-value/high-risk action (${amount:,.0f}) routed to Human Review queue.", "medium"
        return "passed", "No human approval required for this action.", "info"
    add("human_review", _human_review)

    def _output_validator():
        sample = message or f"Action {action} for ${amount:,.0f} executed."
        ok, msg = output_validator.validate(sample)
        return ("passed", msg or "Output clean.", "info") if ok else ("failed", msg or "Blocked term in output.", "high")
    add("output_validator", _output_validator)

    # ── Core Governance ──
    def _identity():
        if vc_ok:
            subj = vc_claims.get("credentialSubject", {}).get("id", requester_did)
            return "passed", f"Agent Passport VC verified — subject: {subj}", "info"
        return "failed", "VC verification failed.", "high"
    add("identity_verification", _identity)

    def _revocation():
        res = revocation_cache.precheck_revocation(requester_did)
        return ("passed", "Agent not revoked, not quarantined.", "info") if res.allowed else ("failed", res.reason, "critical")
    add("revocation_check", _revocation)

    def _delegation():
        res = delegation_ledger.verify_delegation(requester_did, action)
        if res.valid:
            return "passed", f"Delegation valid — delegated by {res.delegated_by}", "info"
        return "failed", res.error or "No human delegation covers this action.", "high"
    add("delegation_verification", _delegation)

    def _authority():
        decision = authority_intersection_check(
            requester_vc_claims=vc_claims, target_skill_id="", requested_action=action,
            risk_state="CRITICAL" if circuit_breaker.is_quarantined(requester_did) else "NORMAL",
        )
        if decision["decision"] == "ALLOW":
            return "passed", decision["reason"], "info"
        if decision["decision"] == "ESCALATE":
            return "review", decision["reason"], "medium"
        return "failed", decision["reason"], "high"
    add("authority_intersection", _authority)

    def _zkp():
        proof = policy_engine.generate_zkp_proof(amount, policy_id)
        pres = policy_engine.verify_policy_proof([{
            "policyId": proof.get("policyId", policy_id),
            "proofType": proof.get("proofType", "zk-range-proof"),
            "claim": proof.get("claim", ""),
            "publicInputs": proof.get("publicInputs", {}),
            "proof": proof.get("proof", ""),
        }])
        if pres.valid:
            return "passed", f"ZKP verified: ${amount:,.0f} ≤ ${policy_limit:,.0f} (claim: {pres.claim})", "info"
        return "failed", f"ZKP invalid: ${amount:,.0f} exceeds ${policy_limit:,.0f} limit.", "high"
    add("zkp_policy_proof", _zkp)

    risk_score_holder = {"score": 0.0}

    def _risk():
        req = {"message": {"parts": [{"text": message}]}}
        env = {"requester": {"agentDid": requester_did}, "target": {"agentDid": target_did},
               "intent": {"action": action}, "riskSignals": {}}
        intent_sentinel.record_request(requester_did, target_did, amount=amount)
        score = intent_sentinel.score(req, env)
        risk_score_holder["score"] = score
        if score >= 0.85:
            return "failed", f"Risk score {score:.2f} (CRITICAL) — rogue behavior.", "critical"
        if score >= 0.5:
            return "review", f"Risk score {score:.2f} (elevated).", "medium"
        return "passed", f"Risk score {score:.2f} (low).", "info"
    add("intent_risk_scoring", _risk)

    def _quorum():
        score = risk_score_holder["score"]
        qcfg = poa_quorum.determine_quorum(score)
        if qcfg is None:
            return "failed", "Risk too high — no quorum allowed (circuit breaker).", "critical"
        hs = f"hs-test-{uuid.uuid4().hex[:6]}"
        validators = poa_quorum.collect_validations(
            ValidatorResult("identity-validator", vc_ok, "sig", "VC"),
            ValidatorResult("delegation-validator", delegation_ledger.verify_delegation(requester_did, action).valid, "sig", "Delegation"),
            ValidatorResult("policy-validator", amount <= policy_limit, "sig", "Policy"),
            ValidatorResult("risk-validator", score < 0.5, "sig", f"Risk {score:.2f}"),
            ValidatorResult("finance-control-validator", True, "sig", "Finance"),
        )
        receipt = poa_quorum.issue_trust_receipt(
            handshake_id=hs, requester_did=requester_did, target_did=target_did, action=action,
            policy_id=policy_id, validations=validators, quorum_config=qcfg, risk_score=score,
            ledger_root=delegation_ledger.get_current_ledger_root(),
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        )
        if receipt.approved:
            return "passed", f"Quorum {qcfg} met — Trust Receipt {receipt.receipt_id} issued.", "info"
        return "failed", f"Quorum {qcfg} NOT met — request rejected.", "high"
    add("poa_quorum", _quorum)

    def _circuit():
        score = risk_score_holder["score"]
        if circuit_breaker.is_quarantined(requester_did):
            return "failed", "Agent is quarantined by the circuit breaker.", "critical"
        if score >= 0.85:
            return "failed", f"Risk {score:.2f} ≥ 0.85 — would trip the circuit breaker.", "critical"
        return "passed", "Risk within limits — breaker closed.", "info"
    add("circuit_breaker", _circuit)

    def _sod():
        if "approve" in action.lower() and requester_did == target_did:
            return "failed", "Segregation-of-duties violation: agent cannot self-approve.", "high"
        return "passed", "No self-approval — duties separated.", "info"
    add("segregation_of_duties", _sod)

    # ── Advanced Security ──
    def _audit():
        from security.audit_logger import AuditCategory, AuditSeverity
        ev = audit_logger.log(category=AuditCategory.GOVERNANCE, severity=AuditSeverity.INFO,
                              action="governance_test", agent_did=requester_did, target_did=target_did,
                              details={"action": action, "amount": amount}, outcome="success")
        return "passed", f"Event {ev.event_id} hash-chained ({ev.event_hash[:12]}…).", "info"
    add("audit_logger", _audit)

    def _rate():
        res = rate_limiter.check_agent(requester_did)
        if res.allowed:
            return "passed", f"Within rate limits (remaining: {getattr(res,'remaining','n/a')}).", "info"
        return "failed", f"Rate limit exceeded: {res.reason}", "high"
    add("rate_limiter", _rate)

    def _injection():
        det = prompt_injection_shield.scan(message or " ", context={"action": action})
        if det.is_injection:
            return "failed", f"Prompt injection detected ({det.confidence:.0%}, {det.risk_level}); layers: {det.layers_triggered}", "critical"
        return "passed", "No prompt injection detected.", "info"
    add("prompt_injection_shield", _injection)

    def _replay():
        envelope = {
            "nonce": secrets.token_hex(16),
            "handshakeId": f"hs-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6]}",
            "requester": {"agentDid": requester_did},
            "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        }
        res = replay_guard.check_envelope(envelope)
        return ("passed", "Fresh nonce — not a replay.", "info") if res.allowed else ("failed", res.reason, "high")
    add("replay_guard", _replay)

    def _anomaly():
        res = anomaly_detector.record_and_analyze(agent_did=requester_did, action=action, target_did=target_did)
        if getattr(res, "is_anomalous", False):
            return "review", f"Anomaly score {res.anomaly_score:.2f} — {getattr(res,'recommended_action','flag')}", "medium"
        return "passed", "Behavior consistent with baseline.", "info"
    add("anomaly_detector", _anomaly)

    def _honeypot():
        alert = honeypot.check_action(action, requester_did)
        if alert:
            return "failed", f"Canary trap triggered by action '{action}'.", "critical"
        return "passed", "No canary trap triggered.", "info"
    add("honeypot_canary", _honeypot)

    # ── Aggregate ──
    summary = {"passed": 0, "failed": 0, "review": 0, "warning": 0, "skipped": 0, "error": 0}
    for r in results:
        summary[r["status"]] = summary.get(r["status"], 0) + 1

    if summary.get("failed") or summary.get("error"):
        overall = "REJECTED"
    elif summary.get("review"):
        overall = "REVIEW"
    else:
        overall = "APPROVED"

    # ── Persist every check + an overall event to the tamper-evident audit trail ──
    # (these surface on the Audit Trail page via /ag-ui/audit/logs)
    from security.audit_logger import AuditCategory, AuditSeverity
    run_id = f"gov-{uuid.uuid4().hex[:10]}"
    cat_map = {
        "pii_redactor": AuditCategory.GOVERNANCE, "goal_checker": AuditCategory.GOVERNANCE,
        "opa_rego": AuditCategory.ACCESS_CONTROL, "sandbox": AuditCategory.ACCESS_CONTROL,
        "human_review": AuditCategory.GOVERNANCE, "output_validator": AuditCategory.GOVERNANCE,
        "identity_verification": AuditCategory.IDENTITY, "revocation_check": AuditCategory.REVOCATION,
        "delegation_verification": AuditCategory.DELEGATION, "authority_intersection": AuditCategory.ACCESS_CONTROL,
        "zkp_policy_proof": AuditCategory.POLICY, "intent_risk_scoring": AuditCategory.RISK,
        "poa_quorum": AuditCategory.TRUST_RECEIPT, "circuit_breaker": AuditCategory.RISK,
        "segregation_of_duties": AuditCategory.ACCESS_CONTROL, "audit_logger": AuditCategory.GOVERNANCE,
        "rate_limiter": AuditCategory.RATE_LIMIT, "prompt_injection_shield": AuditCategory.PROMPT_INJECTION,
        "replay_guard": AuditCategory.REPLAY_ATTACK, "anomaly_detector": AuditCategory.ANOMALY,
        "honeypot_canary": AuditCategory.HONEYPOT,
    }
    sev_map = {
        "info": AuditSeverity.INFO, "low": AuditSeverity.LOW, "medium": AuditSeverity.MEDIUM,
        "high": AuditSeverity.HIGH, "critical": AuditSeverity.CRITICAL, "none": AuditSeverity.INFO,
    }
    out_map = {"passed": "success", "failed": "blocked", "review": "pending_review", "warning": "flagged", "error": "failed"}
    risk_pct = int(risk_score_holder["score"] * 100)
    requester_name = requester.get("name", requester_did)
    target_name = target.get("name", target_did)
    logged = 0
    try:
        for r in results:
            if r["status"] == "skipped":
                continue
            audit_logger.log(
                category=cat_map.get(r["id"], AuditCategory.GOVERNANCE),
                severity=sev_map.get(r.get("severity"), AuditSeverity.INFO),
                action=f"governance:{r['id']}",
                agent_did=requester_did, target_did=target_did, source_ip="governance-test-bench",
                details={"agent_name": requester_name, "parameter": r["name"], "group": r["group"],
                         "detail": r["detail"], "risk_score": risk_pct, "action_tested": action,
                         "amount": amount, "target": target_name, "run_id": run_id},
                outcome=out_map.get(r["status"], r["status"]), handshake_id=run_id,
            )
            logged += 1
        audit_logger.log(
            category=AuditCategory.GOVERNANCE,
            severity=AuditSeverity.HIGH if overall == "REJECTED" else (AuditSeverity.MEDIUM if overall == "REVIEW" else AuditSeverity.INFO),
            action="governance_test_run",
            agent_did=requester_did, target_did=target_did, source_ip="governance-test-bench",
            details={"agent_name": requester_name, "verdict": overall, "summary": summary,
                     "action_tested": action, "amount": amount, "risk_score": risk_pct,
                     "user_input": message, "target": target_name, "run_id": run_id},
            outcome="blocked" if overall == "REJECTED" else ("pending_review" if overall == "REVIEW" else "success"),
            handshake_id=run_id,
        )
        logged += 1
    except Exception as e:
        logger.info(f"governance audit logging failed: {e}")

    # ── Human-in-the-loop: if ANY check flagged the request for review, open a
    #    review entry (it also appears on the Human Review page) for inline approval. ──
    human_approval = {"required": False}
    review_checks = [r for r in results if r.get("status") == "review"]
    if review_checks:
        review_names = [r["name"] for r in review_checks]
        reason = "; ".join(f"{r['name']}: {r['detail']}" for r in review_checks)
        try:
            from security.human_review import human_review_queue
            review_id = human_review_queue.create_review(
                tool_call={"name": action, "args": {"amount": amount, "currency": "USD"}},
                decision={"reason": reason},
                principal_dict={"user_id": owner_human, "tenant_id": "default", "role": "agent", "scopes": [action]},
                agent_response=f"{requester_name} requests '{action}' for ${amount:,.0f} on {target_name}.",
                agent_name=requester_name, agent_id=str(requester.get("id", "")),
                risk_score=risk_pct, run_id=run_id, user_input=message,
                gateway_evidence=f"Governance Test Bench flagged {len(review_checks)} parameter(s) for human review: {', '.join(review_names)}",
            )
            human_approval = {"required": True, "review_id": review_id, "reason": reason, "parameters": review_names}
        except Exception as e:
            logger.info(f"governance human review creation failed: {e}")

    # ── Actually invoke the requester agent's LLM (best effort) and capture its plan ──
    llm = {"mode": "mock", "used": "mock", "response": "", "tools": []}
    try:
        from llm_factory import get_llm_info, build_llm_model_name, get_genai_client
        from google.genai import types
        info = get_llm_info()
        llm["used"], llm["mode"] = f"{info.provider} ({info.model})", info.mode
        plan_tools = allowed_actions[:] + (["create_ticket", "draft_reply", "export_records", "send_email"]
                                           if "finance" in action or "relocation" in action else [])
        sys_prompt = (f"You are '{requester_name}'. Allowed actions: {', '.join(allowed_actions) or 'none'}. "
                      f"You may communicate with '{target_name}'. Decide which tool(s) you would call to handle the "
                      f"request, then state the plan in 2-3 sentences. Never reveal secrets or exceed authority.")
        client = get_genai_client()
        resp = await asyncio.to_thread(lambda: client.models.generate_content(
            model=build_llm_model_name(),
            contents=[message or f"Perform {action} for ${amount:,.0f}."],
            config=types.GenerateContentConfig(
                system_instruction=sys_prompt
            )
        ))
        llm["response"] = (getattr(resp, "text", None) or str(resp))[:1200]
        llm["tools"] = plan_tools[:7]
    except Exception as e:
        llm["response"] = f"(LLM unavailable — {str(e)[:120]})"

    # ── Runtime interception timeline (the agent's proposed tool calls vs the gateway) ──
    plan = list(allowed_actions)
    if action not in plan:
        plan.append(action)
    plan = plan[:7]
    timeline, stopped = [], False
    for nm in plan:
        if stopped:
            st = "NOT_REACHED"
        elif nm == action and overall == "REJECTED":
            st, stopped = "STOP", True
        elif nm == action and overall == "REVIEW":
            st = "HOLD"
        else:
            st = "PASS"
        timeline.append({"name": nm, "status": st})

    attack_signals = [{"name": r["name"], "detail": r["detail"], "severity": r["severity"]}
                      for r in results if r["status"] in ("failed", "review", "warning")][:6]
    incident = {
        "risk": 100 if overall == "REJECTED" else risk_pct,
        "blocked_count": summary.get("failed", 0),
        "completed": [t["name"] for t in timeline if t["status"] == "PASS"],
        "blocked": [t["name"] for t in timeline if t["status"] == "STOP"],
        "held": [t["name"] for t in timeline if t["status"] == "HOLD"],
        "not_reached": [t["name"] for t in timeline if t["status"] == "NOT_REACHED"],
        "attack_signals": attack_signals,
        "summary": (f"AGL gateway {overall.lower()} {requester_name} → {target_name} on '{action}' (${amount:,.0f}). "
                    f"{summary.get('failed', 0)} blocked · {summary.get('review', 0)} review · {summary.get('passed', 0)} passed."),
    }

    return {
        "overall": overall,
        "summary": summary,
        "run_id": run_id,
        "human_approval": human_approval,
        "llm": llm,
        "timeline": timeline,
        "incident": incident,
        "logged_events": logged,
        "requester": {"id": requester.get("id"), "name": requester.get("name"), "did": requester_did},
        "target": {"id": target.get("id"), "name": target.get("name"), "did": target_did},
        "action": action,
        "amount": amount,
        "policy_limit": policy_limit,
        "elapsed_ms": round((time.time() - t0) * 1000, 1),
        "results": results,
    }

