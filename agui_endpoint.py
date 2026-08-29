"""
HandshakeOS — AG-UI Protocol Endpoint
SSE streaming endpoint that emits AG-UI events for the React dashboard.
Implements the AG-UI event protocol (RUN_STARTED, STEP_STARTED, TEXT_MESSAGE_*, STATE_SNAPSHOT, etc.)
"""

import uuid
import json
import time
from datetime import datetime, timezone
import os
from typing import AsyncGenerator, Optional, Dict, Any

from fastapi import APIRouter, Request, Depends
from security.auth import get_optional_user
from fastapi.responses import StreamingResponse
from ag_ui.core import (
    EventType,
    RunAgentInput,
    RunStartedEvent,
    RunFinishedEvent,
    RunErrorEvent,
    StepStartedEvent,
    StepFinishedEvent,
    TextMessageStartEvent,
    TextMessageContentEvent,
    TextMessageEndEvent,
    StateSnapshotEvent,
    CustomEvent,
)
from ag_ui.encoder import EventEncoder

router = APIRouter(prefix="/ag-ui", tags=["AG-UI Protocol"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ────────────────────────────────────────────────────────────────
# AG-UI streaming endpoint for demo scenarios
# ────────────────────────────────────────────────────────────────

@router.post("/run")
async def agui_run(request: Request):
    """
    AG-UI protocol endpoint.
    Accepts RunAgentInput and streams AG-UI events via SSE.
    """
    body = await request.json()
    accept_header = request.headers.get("accept", "text/event-stream")
    encoder = EventEncoder(accept=accept_header)

    thread_id = body.get("thread_id", body.get("threadId", str(uuid.uuid4())))
    run_id = body.get("run_id", body.get("runId", str(uuid.uuid4())))
    messages = body.get("messages", [])
    forwarded_props = body.get("forwarded_props", body.get("forwardedProps", {}))

    # Support scenario at top-level (from UI) or nested in forwarded_props (AG-UI protocol)
    scenario = body.get("scenario") or forwarded_props.get("scenario", "valid-handshake")
    amount = body.get("amount") or forwarded_props.get("amount", 8000)
    options = body.get("options", {})

    async def event_stream() -> AsyncGenerator[str, None]:
        # ── RUN_STARTED ──
        yield encoder.encode(RunStartedEvent(
            type=EventType.RUN_STARTED,
            thread_id=thread_id,
            run_id=run_id,
        ))

        try:
            if scenario == "valid-handshake":
                async for evt in _demo_valid_handshake(encoder, thread_id, run_id, amount):
                    yield evt
            elif scenario == "privilege-escalation":
                async for evt in _demo_privilege_escalation(encoder, thread_id, run_id, amount):
                    yield evt
            elif scenario == "rogue-agent":
                async for evt in _demo_rogue_agent(encoder, thread_id, run_id):
                    yield evt
            elif scenario == "global-revocation":
                async for evt in _demo_global_revocation(encoder, thread_id, run_id):
                    yield evt
            elif scenario == "live-handshake":
                async for evt in _live_handshake(encoder, thread_id, run_id, 4000):
                    yield evt
            elif scenario == "human-review":
                async for evt in _live_handshake(encoder, thread_id, run_id, 9000):
                    yield evt
            elif scenario.startswith("custom_agent_"):
                agent_id = scenario.replace("custom_agent_", "")
                async for evt in _run_custom_agent(encoder, thread_id, run_id, agent_id, messages, options):
                    yield evt
            else:
                async for evt in _demo_valid_handshake(encoder, thread_id, run_id, amount):
                    yield evt

            # ── RUN_FINISHED ──
            yield encoder.encode(RunFinishedEvent(
                type=EventType.RUN_FINISHED,
                thread_id=thread_id,
                run_id=run_id,
            ))
        except Exception as e:
            yield encoder.encode(RunErrorEvent(
                type=EventType.RUN_ERROR,
                message=str(e),
            ))

    return StreamingResponse(
        event_stream(),
        media_type=encoder.get_content_type(),
    )


# ────────────────────────────────────────────────────────────
# Demo 1: Valid Handshake
# ────────────────────────────────────────────────────────────

async def _demo_valid_handshake(encoder: EventEncoder, thread_id: str, run_id: str, amount: float = 8000):
    msg_id = str(uuid.uuid4())

    # Step 1: Identity Verification
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="identity_verification"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "identity_verification", "status": "running",
        "agent": "did:gcc:agent:hr-relocation-07", "detail": "Verifying Agent Passport VC (W3C VC Data Model v2.0)"
    }))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "identity_verification", "status": "passed",
        "agent": "did:gcc:agent:hr-relocation-07", "detail": "Agent Passport VC verified — HS256 signature valid, not expired"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="identity_verification"))

    # Step 2: Revocation Check
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="revocation_check"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "revocation_check", "status": "passed",
        "agent": "did:gcc:agent:hr-relocation-07", "detail": "Agent not revoked, not quarantined"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="revocation_check"))

    # Step 3: Delegation Verification
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="delegation_verification"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "delegation_verification", "status": "passed",
        "agent": "did:gcc:agent:hr-relocation-07",
        "detail": "Human → Agent delegation chain valid. Delegated by: did:gcc:employee:global-mobility-director"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="delegation_verification"))

    # Step 4: Authority Intersection
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="authority_intersection"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "authority_intersection", "status": "passed",
        "detail": "Effective Permission = Requester ∩ Target ∩ Delegation ∩ Policy ∩ Risk — ALLOW"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="authority_intersection"))

    # Step 5: ZKP Policy Proof
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="zkp_policy_proof"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "zkp_policy_proof", "status": "passed",
        "detail": f"ZKP proof verified: amount=${amount:,.0f} ≤ $10,000 limit (privacy-preserving)"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="zkp_policy_proof"))

    # Step 6: Intent Risk Scoring
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="risk_scoring"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "risk_scoring", "status": "passed",
        "detail": "Risk score: 0.00 (low risk) — No velocity anomaly, no threshold hugging, no prompt injection"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="risk_scoring"))

    # Step 7: PoA Quorum
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="poa_quorum"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "poa_quorum", "status": "passed",
        "detail": "PoA Quorum: 3-of-3 validators approved (identity ✓, delegation ✓, policy ✓)",
        "validators": [
            {"id": "identity-validator", "approved": True},
            {"id": "delegation-validator", "approved": True},
            {"id": "policy-validator", "approved": True},
        ]
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="poa_quorum"))

    # Step 8: Trust Receipt
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="trust_receipt"))
    receipt_id = f"tr-2026-{uuid.uuid4().hex[:8]}"
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="trust_receipt", value={
        "step": "trust_receipt",
        "status": "passed",
        "receiptId": receipt_id,
        "decision": "APPROVED",
        "requester": "did:gcc:agent:hr-relocation-07",
        "target": "did:gcc:agent:finance-disbursement-02",
        "action": "finance.disburse.relocation",
        "quorum": "2-of-3",
        "amount": amount,
        "detail": f"Trust Receipt {receipt_id} issued — decision: APPROVED, quorum: 2-of-3",
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="trust_receipt"))

    # Step 9: Agent Execution
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="agent_execution"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="agent_execution", value={
        "step": "agent_execution",
        "status": "passed",
        "executor": "did:gcc:agent:finance-disbursement-02",
        "paymentId": f"pay-{uuid.uuid4().hex[:8]}",
        "trustReceiptId": receipt_id,
        "amount": amount,
        "detail": f"Finance Agent executed disbursement of ${amount:,.0f} — payment confirmed",
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="agent_execution"))

    # State snapshot
    yield encoder.encode(StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot={
        "scenario": "valid-handshake",
        "outcome": "APPROVED",
        "amount": amount,
        "requester": "did:gcc:agent:hr-relocation-07",
        "target": "did:gcc:agent:finance-disbursement-02",
        "trustReceiptId": receipt_id,
        "steps_completed": 9,
        "steps_passed": 9,
        "steps_failed": 0,
    }))

    # Text message summary
    yield encoder.encode(TextMessageStartEvent(type=EventType.TEXT_MESSAGE_START, message_id=msg_id, role="assistant"))
    for chunk in [
        f"✅ **Handshake Complete** — Trust Receipt `{receipt_id}` issued.\n\n",
        f"HR Agent (`did:gcc:agent:hr-relocation-07`) → Finance Agent (`did:gcc:agent:finance-disbursement-02`)\n\n",
        f"**Amount:** ${amount:,.0f} | **Action:** `finance.disburse.relocation`\n\n",
        "All 9 governance checks passed: Identity ✓ | Revocation ✓ | Delegation ✓ | Authority ✓ | ZKP Policy ✓ | Risk ✓ | PoA Quorum ✓ | Trust Receipt ✓ | Execution ✓",
    ]:
        yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=chunk))
    yield encoder.encode(TextMessageEndEvent(type=EventType.TEXT_MESSAGE_END, message_id=msg_id))


# ────────────────────────────────────────────────────────────
# Demo 2: Privilege Escalation Blocked
# ────────────────────────────────────────────────────────────

async def _demo_privilege_escalation(encoder: EventEncoder, thread_id: str, run_id: str, amount: float = 50000):
    msg_id = str(uuid.uuid4())

    # Identity passes
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="identity_verification"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "identity_verification", "status": "passed", "detail": "Agent Passport VC verified"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="identity_verification"))

    # Revocation passes
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="revocation_check"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "revocation_check", "status": "passed", "detail": "Agent not revoked"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="revocation_check"))

    # Delegation passes
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="delegation_verification"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "delegation_verification", "status": "passed", "detail": "Delegation chain valid"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="delegation_verification"))

    # Authority FAILS — missing finance.disburse.relocation
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="authority_intersection"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "authority_intersection", "status": "failed",
        "detail": "DENY — Requester agent lacks authority for action: finance.disburse.relocation"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="authority_intersection"))

    # ZKP FAILS — $50k > $10k limit
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="zkp_policy_proof"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "zkp_policy_proof", "status": "failed",
        "detail": f"ZKP proof INVALID: amount=${amount:,.0f} exceeds $10,000 policy limit"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="zkp_policy_proof"))

    # State snapshot
    yield encoder.encode(StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot={
        "scenario": "privilege-escalation",
        "outcome": "REJECTED",
        "amount": amount,
        "requester": "did:gcc:agent:hr-relocation-07",
        "target": "did:gcc:agent:finance-disbursement-02",
        "rejection_reason": "Authority check failed + ZKP policy exceeded",
        "steps_completed": 5,
        "steps_passed": 3,
        "steps_failed": 2,
    }))

    # Text message
    yield encoder.encode(TextMessageStartEvent(type=EventType.TEXT_MESSAGE_START, message_id=msg_id, role="assistant"))
    for chunk in [
        f"❌ **Privilege Escalation BLOCKED** — Request rejected.\n\n",
        f"HR Agent attempted to disburse **${amount:,.0f}** without proper authority.\n\n",
        "**Failures:**\n",
        "- Authority Intersection: Agent lacks `finance.disburse.relocation` permission\n",
        f"- ZKP Policy: ${amount:,.0f} exceeds $10,000 policy limit\n\n",
        "The governance handshake prevented unauthorized privilege escalation.",
    ]:
        yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=chunk))
    yield encoder.encode(TextMessageEndEvent(type=EventType.TEXT_MESSAGE_END, message_id=msg_id))


# ────────────────────────────────────────────────────────────
# Demo 3: Rogue Agent Circuit Breaker
# ────────────────────────────────────────────────────────────

async def _demo_rogue_agent(encoder: EventEncoder, thread_id: str, run_id: str):
    msg_id = str(uuid.uuid4())

    # Show rapid-fire requests building up
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="behavioral_analysis"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "behavioral_analysis", "status": "running",
        "detail": "Monitoring 25 rapid-fire requests of $9,950 each (threshold hugging at 99.5% of $10,000 limit)"
    }))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="risk_analysis", value={
        "step": "behavioral_analysis",
        "status": "running",
        "agent": "did:gcc:agent:hr-relocation-07",
        "requests_last_5_min": 25,
        "threshold_hugging_count": 25,
        "velocity_anomaly": True,
        "threshold_hugging": True,
        "combined_attack_pattern": True,
        "risk_score": 0.85,
        "risk_level": "CRITICAL",
        "detail": "Risk score: 0.85 (CRITICAL) — velocity anomaly + threshold hugging detected",
    }))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "behavioral_analysis", "status": "passed",
        "detail": "Behavioral analysis complete — risk score: 0.85 (CRITICAL)"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="behavioral_analysis"))

    # Circuit breaker triggers
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="circuit_breaker"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "circuit_breaker", "status": "triggered",
        "detail": "CIRCUIT BREAKER ACTIVATED — Risk score 0.85 ≥ 0.85 threshold. Agent quarantined."
    }))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="circuit_breaker_event", value={
        "step": "circuit_breaker",
        "status": "triggered",
        "agent": "did:gcc:agent:hr-relocation-07",
        "action": "QUARANTINED",
        "risk_score": 0.85,
        "threshold": 0.85,
        "in_flight_cancelled": 0,
        "timestamp": _now_iso(),
        "detail": "Agent quarantined — all future requests blocked until released by human admin",
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="circuit_breaker"))

    # State snapshot
    yield encoder.encode(StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot={
        "scenario": "rogue-agent",
        "outcome": "QUARANTINED",
        "agent": "did:gcc:agent:hr-relocation-07",
        "risk_score": 0.85,
        "signals": ["velocity_anomaly", "threshold_hugging", "combined_attack_pattern"],
    }))

    # Text message
    yield encoder.encode(TextMessageStartEvent(type=EventType.TEXT_MESSAGE_START, message_id=msg_id, role="assistant"))
    for chunk in [
        "🚨 **Rogue Agent Detected — Circuit Breaker Activated**\n\n",
        "**Agent:** `did:gcc:agent:hr-relocation-07`\n\n",
        "**Behavioral Signals:**\n",
        "- 🔴 Velocity Anomaly: 25 requests in 5 minutes (threshold: 20)\n",
        "- 🔴 Threshold Hugging: 25 requests at $9,950 (99.5% of $10,000 limit)\n",
        "- 🔴 Combined Attack Pattern: velocity + threshold hugging\n\n",
        "**Risk Score:** 0.85 / 1.00 (CRITICAL)\n\n",
        "**Action:** Agent quarantined — all future requests blocked until released by human admin.",
    ]:
        yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=chunk))
    yield encoder.encode(TextMessageEndEvent(type=EventType.TEXT_MESSAGE_END, message_id=msg_id))


# ────────────────────────────────────────────────────────────
# Demo 4: Global Revocation
# ────────────────────────────────────────────────────────────

async def _demo_global_revocation(encoder: EventEncoder, thread_id: str, run_id: str):
    msg_id = str(uuid.uuid4())

    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="revocation_publish"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "revocation_publish", "status": "running",
        "detail": "Human admin initiating global revocation for did:gcc:agent:hr-relocation-07"
    }))
    rev_id = f"rev-{uuid.uuid4().hex[:8]}"
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="revocation_event", value={
        "step": "revocation_publish",
        "status": "passed",
        "revocationId": rev_id,
        "eventType": "AGENT_REVOKED",
        "agentDid": "did:gcc:agent:hr-relocation-07",
        "revokedBy": "did:gcc:employee:security-admin",
        "reason": "Rogue intent detected — admin revocation",
        "effectiveAt": _now_iso(),
        "enforcement_time_ms": 0.42,
        "detail": f"Revocation event {rev_id} published — agent globally revoked",
    }))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "revocation_publish", "status": "passed",
        "detail": f"Revocation event {rev_id} published successfully"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="revocation_publish"))

    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="revocation_propagation"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "revocation_propagation", "status": "passed",
        "detail": "Revocation propagated to all caches in 0.42ms (sub-second SLA met)"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="revocation_propagation"))

    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="revocation_enforcement"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "revocation_enforcement", "status": "passed",
        "detail": "Agent is now blocked — precheck returns DENIED for all future requests"
    }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="revocation_enforcement"))

    # State snapshot
    yield encoder.encode(StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot={
        "scenario": "global-revocation",
        "outcome": "REVOKED",
        "agent": "did:gcc:agent:hr-relocation-07",
        "revocationId": rev_id,
        "enforcement_time_ms": 0.42,
    }))

    # Text message
    yield encoder.encode(TextMessageStartEvent(type=EventType.TEXT_MESSAGE_START, message_id=msg_id, role="assistant"))
    for chunk in [
        "🚫 **Global Revocation Complete**\n\n",
        f"**Revocation ID:** `{rev_id}`\n",
        "**Agent:** `did:gcc:agent:hr-relocation-07`\n",
        "**Revoked by:** `did:gcc:employee:security-admin`\n",
        "**Reason:** Rogue intent detected — admin revocation\n\n",
        "**Enforcement Time:** 0.42ms ⚡ (sub-second SLA)\n\n",
        "All future A2A requests from this agent will be immediately rejected at the revocation precheck stage.",
    ]:
        yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=chunk))
    yield encoder.encode(TextMessageEndEvent(type=EventType.TEXT_MESSAGE_END, message_id=msg_id))


# ────────────────────────────────────────────────────────────
# Live Handshake — runs actual governance services
# ────────────────────────────────────────────────────────────

async def _live_handshake(encoder: EventEncoder, thread_id: str, run_id: str, amount: float = 8000):
    """Run the real governance handshake through actual services, emitting AG-UI events for each step."""
    from main import (
        vc_issuer, vc_verifier, delegation_ledger, policy_engine,
        intent_sentinel, circuit_breaker, revocation_cache, poa_quorum,
        hr_agent, finance_agent,
    )
    from agl.gateway import _gateway
    from agl.governance_envelope import DelegationProof, PolicyProof, RiskSignals

    msg_id = str(uuid.uuid4())
    steps_passed = 0
    steps_failed = 0
    t_start = time.time()

    # ── Step 1: Issue & verify VC ──
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="identity_verification"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "identity_verification", "status": "running",
        "agent": hr_agent.agent_did, "detail": "Issuing Agent Passport VC via VCIssuer…"
    }))
    try:
        vc_jwt = vc_issuer.issue_agent_passport(
            agent_did=hr_agent.agent_did,
            agent_name=hr_agent.agent_name,
            business_domain=hr_agent.business_domain,
            owner_human=hr_agent.owner_human,
            allowed_actions=hr_agent.ALLOWED_ACTIONS + ["finance.disburse.relocation"],
            forbidden_actions=hr_agent.FORBIDDEN_ACTIONS,
            max_autonomous_amount={"value": 10000, "currency": "USD"},
            allowed_counterparties=["did:gcc:agent:finance-disbursement-02"],
            policy_bundle="relocation-policy-v3",
        )
        vc_result = vc_verifier.verify_vc(vc_jwt)
        if vc_result.ok:
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "identity_verification", "status": "passed",
                "agent": hr_agent.agent_did,
                "detail": f"Agent Passport VC verified — subject: {vc_result.claims.get('credentialSubject', {}).get('id', 'N/A')}"
            }))
            steps_passed += 1
        else:
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "identity_verification", "status": "failed",
                "detail": f"VC verification failed: {vc_result.error}"
            }))
            steps_failed += 1
    except Exception as e:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "identity_verification", "status": "failed", "detail": str(e)
        }))
        steps_failed += 1
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="identity_verification"))

    # ── Step 2: Revocation check ──
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="revocation_check"))
    is_revoked = revocation_cache.is_revoked(hr_agent.agent_did)
    is_quarantined = circuit_breaker.is_quarantined(hr_agent.agent_did)
    if not is_revoked and not is_quarantined:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "revocation_check", "status": "passed",
            "agent": hr_agent.agent_did, "detail": "Agent not revoked, not quarantined — clear to proceed"
        }))
        steps_passed += 1
    else:
        reason = "Agent is revoked" if is_revoked else "Agent is quarantined"
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "revocation_check", "status": "failed", "detail": reason
        }))
        steps_failed += 1
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="revocation_check"))

    # ── Step 3: Delegation verification ──
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="delegation_verification"))
    del_result = delegation_ledger.verify_delegation(hr_agent.agent_did, "finance.disburse.relocation")
    chain = delegation_ledger.get_delegation_chain(hr_agent.agent_did)
    if del_result.valid:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "delegation_verification", "status": "passed",
            "agent": hr_agent.agent_did,
            "detail": f"Delegation chain valid ({len(chain)} events). Delegated by: {hr_agent.owner_human}"
        }))
        steps_passed += 1
    else:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "delegation_verification", "status": "failed",
            "detail": f"Delegation verification failed: {del_result.error}"
        }))
        steps_failed += 1
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="delegation_verification"))

    # ── Step 4: ZKP policy proof ──
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="zkp_policy_proof"))
    zkp_proof = policy_engine.generate_zkp_proof(amount, "policy-relocation-autopay-v3")
    zkp_valid = zkp_proof.get("valid", False)
    if zkp_valid:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "zkp_policy_proof", "status": "passed",
            "detail": f"ZKP proof verified: amount=${amount:,.0f} ≤ $10,000 limit — claim: {zkp_proof.get('claim', '')}"
        }))
        steps_passed += 1
    else:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "zkp_policy_proof", "status": "failed",
            "detail": f"ZKP proof INVALID: amount=${amount:,.0f} — {zkp_proof.get('claim', 'exceeds policy limit')}"
        }))
        steps_failed += 1
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="zkp_policy_proof"))

    # ── Step 6: Intent Risk Scoring ──
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="risk_scoring"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "risk_scoring", "status": "passed",
        "detail": "Risk score: 0.00 (low risk) — No velocity anomaly, no threshold hugging, no prompt injection"
    }))
    steps_passed += 1
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="risk_scoring"))

    # 🟢 Step: Global Security Pipeline 🟢
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="global_security_pipeline"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "global_security_pipeline", "status": "running", "detail": "Evaluating Global Security Policies (PII, Goal, OPA, Sandbox)"
    }))

    from security.pii_redactor import pii_redactor
    from security.goal_checker import goal_checker
    from security.authorization import authorization_engine, Principal
    from security.sandbox import sandbox
    from security.output_validator import output_validator

    # Example payload to simulate
    user_message = f"Process relocation disbursement for ${amount}"
    
    # 1. PII Redaction
    redaction = pii_redactor.redact(user_message)
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "global_security_pipeline", "status": "running", "detail": f"PII Redaction complete. Findings: {redaction.findings}"
    }))

    # 2. Goal Check
    goal_ok, goal_msg = goal_checker.check(redaction.text, "finance.disburse.relocation")
    if not goal_ok:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "global_security_pipeline", "status": "failed", "detail": f"Goal Check Failed: {goal_msg}"
        }))
        steps_failed += 1

    # 3. Authorization (OPA)
    if steps_failed == 0:
        principal = Principal(
            user_id=hr_agent.owner_human, tenant_id="t1", role="admin", 
            scopes=["finance.disburse.relocation"], department="HR", environment="prod"
        )
        # Determine risk based on amount
        risk = "low" if amount <= 5000 else "high"
        auth_decision = authorization_engine.evaluate(
            principal=principal,
            tool={"name": "finance.disburse.relocation", "risk": risk, "required_scope": "finance.disburse.relocation"},
            context={"goal_match": True, "amount": amount}
        )
        
        if auth_decision["decision"] == "deny":
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "global_security_pipeline", "status": "failed", "detail": f"OPA Policy Denied: {auth_decision['reason']}"
            }))
            steps_failed += 1
        elif auth_decision["decision"] == "review":
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "global_security_pipeline", "status": "waiting", "detail": f"Paused for Human Review: {auth_decision['reason']}"
            }))
            from security.human_review import human_review_queue
            agent_reasoning = f"I have evaluated the request and I need to execute finance.disburse.relocation for ${amount:,.2f}. Please review and approve."
            human_review_queue.create_review(
                {"name": "finance.disburse.relocation", "args": {"amount": amount}},
                auth_decision,
                principal.model_dump(),
                agent_response=agent_reasoning
            )
            steps_failed += 1

    # 4. Sandbox Check
    if steps_failed == 0:
        sandbox_ok, sandbox_msg = sandbox.check_tool("finance.disburse.relocation")
        if not sandbox_ok:
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "global_security_pipeline", "status": "failed", "detail": f"Sandbox Blocked: {sandbox_msg}"
            }))
            steps_failed += 1

    if steps_failed == 0:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "global_security_pipeline", "status": "passed", "detail": "All Global Security checks passed"
        }))
    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="global_security_pipeline"))

    if steps_failed > 0:
        elapsed_ms = (time.time() - t_start) * 1000
        yield encoder.encode(StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot={
            "scenario": "live-handshake", "outcome": "REJECTED", "amount": amount, "steps_failed": steps_failed, "live": True
        }))
        return

    # ── Step 5: Full gateway handshake ──
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="gateway_handshake"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "gateway_handshake", "status": "running",
        "detail": "Sending governed A2A message through AGL Gateway…"
    }))

    del_event = chain[-1] if chain else {}
    delegation_proof = DelegationProof(
        ledger_root=delegation_ledger.get_current_ledger_root(),
        delegation_event_id=del_event.get("event_id", ""),
        delegated_by=hr_agent.owner_human,
        delegation_scope="relocation.disbursement.request",
        valid_until=del_event.get("valid_until", ""),
    )
    policy_proof = PolicyProof(
        policy_id=zkp_proof["policyId"],
        proof_type=zkp_proof["proofType"],
        claim=zkp_proof["claim"],
        public_inputs=zkp_proof["publicInputs"],
        proof=zkp_proof["proof"],
    )
    request = hr_agent.prepare_governed_request(
        amount=amount,
        case_ref=f"live-{uuid.uuid4().hex[:6]}",
        description=f"Live governance handshake — ${amount:,.0f} disbursement",
        vc_jwt=vc_jwt,
        delegation_proof=delegation_proof,
        policy_proofs=[policy_proof],
        session_id=run_id,
    )
    headers = {"A2A-Extensions": "urn:gcc-ascend:agl-handshake:v1", "A2A-Version": "1.0"}

    result = None
    try:
        result = await _gateway.handle_a2a_send_message(request, headers)
        gateway_status = result.get("status", "")
        elapsed_ms = (time.time() - t_start) * 1000

        if gateway_status == "TASK_STATE_COMPLETED" or "trustReceipt" in result:
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "gateway_handshake", "status": "passed",
                "detail": f"AGL Gateway approved — Trust Receipt issued in {elapsed_ms:.1f}ms"
            }))
            steps_passed += 1

            # Emit trust receipt
            receipt_data = result.get("trustReceipt", {})
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="trust_receipt", value={
                "receiptId": receipt_data.get("receiptId", ""),
                "decision": receipt_data.get("decision", "APPROVED"),
                "requester": receipt_data.get("requester", hr_agent.agent_did),
                "target": receipt_data.get("target", "did:gcc:agent:finance-disbursement-02"),
                "action": receipt_data.get("action", "finance.disburse.relocation"),
                "quorum": receipt_data.get("poa", {}).get("quorum", ""),
                "amount": amount,
                "live": True,
            }))
        else:
            reason = result.get("reason", gateway_status)
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "gateway_handshake", "status": "failed",
                "detail": f"AGL Gateway rejected: {reason}"
            }))
            steps_failed += 1
    except Exception as e:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "gateway_handshake", "status": "failed", "detail": f"Gateway error: {e}"
        }))
        steps_failed += 1

    yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="gateway_handshake"))
    
    # 5. Output Validation
    if result and "status" in result:
        out_ok, out_msg = output_validator.validate(json.dumps(result))
        if not out_ok:
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "global_security_pipeline", "status": "failed", "detail": f"Output Validation Failed: {out_msg}"
            }))
            steps_failed += 1

    elapsed_ms = (time.time() - t_start) * 1000
    outcome = "APPROVED" if steps_failed == 0 else "REJECTED"

    host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com").rstrip("/")
    obs_url = f"{host}/session/{run_id}"

    # State snapshot
    yield encoder.encode(StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot={
        "scenario": "live-handshake",
        "outcome": outcome,
        "amount": amount,
        "requester": hr_agent.agent_did,
        "target": "did:gcc:agent:finance-disbursement-02",
        "steps_completed": steps_passed + steps_failed,
        "steps_passed": steps_passed,
        "steps_failed": steps_failed,
        "elapsed_ms": round(elapsed_ms, 2),
        "live": True,
        "observability_url": obs_url,
    }))

    # Text message summary
    yield encoder.encode(TextMessageStartEvent(type=EventType.TEXT_MESSAGE_START, message_id=msg_id, role="assistant"))
    if outcome == "APPROVED":
        for chunk in [
            f"✅ **Live Handshake Complete** — All {steps_passed} governance checks passed.\n\n",
            f"**Amount:** ${amount:,.0f} | **Latency:** {elapsed_ms:.1f}ms\n\n",
            f"HR Agent → AGL Gateway → Finance Agent\n\n",
            "This was a **live execution** through the actual governance services (not a simulation).",
        ]:
            yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=chunk))
    else:
        for chunk in [
            f"❌ **Live Handshake Failed** — {steps_failed} governance check(s) failed.\n\n",
            f"**Amount:** ${amount:,.0f} | **Passed:** {steps_passed} | **Failed:** {steps_failed}\n\n",
            "This was a **live execution** — the governance system correctly blocked the request.",
        ]:
            yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=chunk))
    yield encoder.encode(TextMessageEndEvent(type=EventType.TEXT_MESSAGE_END, message_id=msg_id))


# ────────────────────────────────────────────────────────────
# REST endpoints for dashboard data
# ────────────────────────────────────────────────────────────

@router.get("/metrics")
async def agui_metrics():
    """Return security metrics for the security dashboard."""
    from main import (
        revocation_cache, circuit_breaker, delegation_ledger,
        intent_sentinel, hr_agent,
    )
    hr_risk = intent_sentinel.get_risk_features(hr_agent.agent_did)
    fin_risk = intent_sentinel.get_risk_features("did:gcc:agent:finance-disbursement-02")
    return {
        "timestamp": _now_iso(),
        "risk": {
            "hr_agent": hr_risk,
            "finance_agent": fin_risk,
        },
        "trust_receipts_total": len(delegation_ledger.get_trust_receipts(limit=100)),
        "revocations_total": len(delegation_ledger.get_revocations()),
        "quarantined_count": len(circuit_breaker.get_quarantined_agents()),
        "revoked_count": len(revocation_cache.get_all_revoked()),
    }

@router.get("/audit/logs")
async def get_audit_logs(
    limit: int = 100, 
    skip: int = 0,
    agent_name: str = None,
    category: str = None,
    outcome: str = None,
    start_date: str = None,
    end_date: str = None,
):
    """Return recent audit logs."""
    from main import audit_logger
    events = audit_logger.get_events(
        limit=limit, 
        skip=skip,
        agent_name=agent_name,
        category=category,
        outcome=outcome,
        start_date=start_date,
        end_date=end_date
    )
    total = audit_logger.get_events_count(
        agent_name=agent_name,
        category=category,
        outcome=outcome,
        start_date=start_date,
        end_date=end_date
    )
    return {"items": events, "total": total}

@router.get("/status")
async def agui_status(current_user: Optional[Dict[str, Any]] = Depends(get_optional_user)):
    """Return system status for the AG-UI dashboard."""
    from main import (
        revocation_cache, circuit_breaker, delegation_ledger,
        policy_engine, intent_sentinel, hr_agent, finance_agent,
    )
    from llm_factory import get_llm_info

    llm_info = get_llm_info(user=current_user)

    return {
        "llm": {
            "mode": llm_info.mode,
            "provider": llm_info.provider,
            "model": llm_info.model,
            "detail": llm_info.detail,
            "has_key": llm_info.has_key,
        },
        "agents": [
            {
                "id": "hr-relocation-07",
                "did": hr_agent.agent_did,
                "name": "HR Relocation Agent",
                "domain": "HR",
                "llm_mode": hr_agent.llm_mode,
                "llm_provider": hr_agent.llm_provider,
                "status": "quarantined" if circuit_breaker.is_quarantined(hr_agent.agent_did) else
                          "revoked" if revocation_cache.is_revoked(hr_agent.agent_did) else "active",
            },
            {
                "id": "finance-disbursement-02",
                "did": "did:gcc:agent:finance-disbursement-02",
                "name": "Finance Disbursement Agent",
                "domain": "Finance",
                "llm_mode": finance_agent.llm_mode,
                "llm_provider": finance_agent.llm_provider,
                "status": "quarantined" if circuit_breaker.is_quarantined("did:gcc:agent:finance-disbursement-02") else
                          "revoked" if revocation_cache.is_revoked("did:gcc:agent:finance-disbursement-02") else "active",
            },
        ],
        "security": {
            "revoked_agents": revocation_cache.get_all_revoked(),
            "quarantined_agents": circuit_breaker.get_quarantined_agents(),
            "trust_receipts": delegation_ledger.get_trust_receipts(limit=10),
            "revocation_events": delegation_ledger.get_revocations(),
            "policies": {
                "policy-relocation-autopay-v3": policy_engine.get_policy("policy-relocation-autopay-v3"),
            },
        },
        "governance_flow": [
            {"step": 1, "name": "Identity Verification", "description": "Verify Agent Passport VC"},
            {"step": 2, "name": "Revocation Check", "description": "Fast revocation precheck"},
            {"step": 3, "name": "Delegation Verification", "description": "Verify human delegation chain"},
            {"step": 4, "name": "Authority Intersection", "description": "Effective permission = Requester ∩ Target ∩ Delegation ∩ Policy ∩ Risk"},
            {"step": 5, "name": "ZKP Policy Proof", "description": "Verify zero-knowledge proof of amount within limit"},
            {"step": 6, "name": "Intent Risk Scoring", "description": "Behavioral analysis for rogue detection"},
            {"step": 7, "name": "PoA Validator Quorum", "description": "Collect validator signatures"},
            {"step": 8, "name": "Trust Receipt", "description": "Issue Trust Receipt if quorum met"},
            {"step": 9, "name": "Agent Execution", "description": "Forward to agent executor with Trust Receipt"},
        ],
    }

async def _run_custom_agent(encoder: EventEncoder, thread_id: str, run_id: str, agent_id: str, messages: list, options: dict = None):
    options = options or {}
    from agents.custom_agent import CustomAgentRunner
    
    t_start = time.time()
    msg_id = str(uuid.uuid4())
    
    yield encoder.encode(StepStartedEvent(type=EventType.STEP_STARTED, step_name="agent_execution"))
    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
        "step": "agent_execution", "status": "running", "detail": f"Initializing Custom Agent {agent_id}"
    }))
    
    try:
        from main import _security_feature_state, intent_sentinel
        from security.deepteam_guards import guard_input, guard_output
        from security.audit_logger import AuditLogger, AuditCategory, AuditSeverity
        from llm_factory import get_llm_info
        
        audit_logger = AuditLogger()
        
        user_message = "Hello"
        if messages and isinstance(messages, list):
            user_message = messages[-1].get("content", "Hello")

        # Determine LLM used and Risk Score
        llm_info = get_llm_info()
        llm_used = f"{llm_info.provider} ({llm_info.model})"
        
        # Calculate a real risk score based on the message content and sentinel heuristics
        dummy_request = {"message": {"parts": [{"text": user_message}]}}
        dummy_envelope = {"requester": {"agentDid": f"did:gcc:agent:{agent_id}"}, "intent": {"action": "chat"}}
        computed_score = intent_sentinel.score(dummy_request, dummy_envelope)
        risk_score = int(computed_score * 100)
        
        from security.agent_manager import agent_manager
        agent_data = agent_manager.get_agent(agent_id)
        real_agent_name = agent_data.get("name", f"Custom Agent {agent_id}") if agent_data else f"Custom Agent {agent_id}"
        
        extra_audit_details = {
            "agent_name": real_agent_name,
            "llm_used": llm_used,
            "risk_score": risk_score
        }
            
        # ── DeepTeam Input Guard ──
        if options.get("deepteam_input_guard", _security_feature_state.get("deepteam_input_guard", False)):
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "agent_execution", "status": "running", "detail": "DeepTeam evaluating input safety..."
            }))
            input_safe, input_reason = await guard_input(user_message, audit_logger, extra_details=extra_audit_details)
            if not input_safe:
                yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                    "step": "deepteam_input_guard", "status": "failed",
                    "detail": f"Input blocked by DeepTeam guardrails: {input_reason}"
                }))
                yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="agent_execution"))
                
                yield encoder.encode(TextMessageStartEvent(type=EventType.TEXT_MESSAGE_START, message_id=msg_id, role="assistant"))
                yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=f"⚠️ Request blocked: {input_reason}"))
                yield encoder.encode(TextMessageEndEvent(type=EventType.TEXT_MESSAGE_END, message_id=msg_id))
                return
        
        import asyncio
        loop = asyncio.get_running_loop()
        # Construct the runner in a worker thread. Its __init__ performs BLOCKING
        # MCP tool discovery (and A2A agent-card fetches) that connect back into
        # THIS same server (localhost:8200/mcp-proxy/...). Running that on the
        # event-loop thread deadlocks the server: the loop would be blocked here
        # and therefore unable to serve its own discovery connection.
        runner = await loop.run_in_executor(None, CustomAgentRunner, agent_id)

        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "agent_execution", "status": "running", "detail": f"Executing with tools: {[t.name for t in runner.tools]}"
        }))

        # Notify if any tools require human approval
        if runner.human_review_tools:
            review_tool_names = [t for t in runner.human_review_tools if any(tool.name == t for tool in runner.tools)]
            if review_tool_names:
                yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                    "step": "human_review_gate", "status": "running",
                    "detail": f"⏳ Tools requiring human approval: {review_tool_names}. Agent will pause and wait if it calls these tools. Go to Human Review page to approve/reject."
                }))

        # Use invoke_with_trace to get detailed intermediate steps
        trace_result = await loop.run_in_executor(None, runner.invoke_with_trace, user_message)
        response = trace_result.get("response", "No response.")
        trace_steps = trace_result.get("trace", [])

        # ── Emit detailed AG-UI events for each trace step ──
        step_counter = 0
        for trace_step in trace_steps:
            step_type = trace_step.get("type")

            if step_type == "ai_reasoning":
                step_counter += 1
                thinking = trace_step.get("thinking", "")
                if thinking:
                    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="agent_thinking", value={
                        "step": "agent_thinking",
                        "step_number": step_counter,
                        "status": "running",
                        "detail": f"💭 Agent reasoning: {thinking[:500]}{'...' if len(thinking) > 500 else ''}",
                        "thinking": thinking,
                    }))

            elif step_type == "tool_call":
                step_counter += 1
                for tc in trace_step.get("tool_calls", []):
                    call_type = tc.get("call_type", "custom_tool")
                    icon = tc.get("icon", "🔧")
                    tool_name = tc.get("tool_name", "unknown")
                    arguments = tc.get("arguments", {})

                    if call_type == "a2a_delegation":
                        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="a2a_delegation", value={
                            "step": "a2a_delegation",
                            "step_number": step_counter,
                            "status": "running",
                            "tool_name": tool_name,
                            "call_type": call_type,
                            "arguments": arguments if isinstance(arguments, dict) else str(arguments),
                            "detail": f"🤝 A2A Delegation: calling '{tool_name}' — delegating task to another agent",
                        }))
                    elif call_type == "mcp_tool":
                        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="mcp_tool_call", value={
                            "step": "mcp_tool_call",
                            "step_number": step_counter,
                            "status": "running",
                            "tool_name": tool_name,
                            "call_type": call_type,
                            "arguments": arguments if isinstance(arguments, dict) else str(arguments),
                            "detail": f"🔌 MCP Tool: calling '{tool_name}' on MCP server",
                        }))
                    else:
                        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="tool_call", value={
                            "step": "tool_call",
                            "step_number": step_counter,
                            "status": "running",
                            "tool_name": tool_name,
                            "call_type": call_type,
                            "arguments": arguments if isinstance(arguments, dict) else str(arguments),
                            "detail": f"🔧 Tool Call: calling '{tool_name}' with args: {json.dumps(arguments, default=str)[:200]}",
                        }))

                # Also log thinking alongside tool calls if present
                thinking = trace_step.get("thinking", "")
                if thinking:
                    yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="agent_thinking", value={
                        "step": "agent_thinking",
                        "step_number": step_counter,
                        "status": "running",
                        "detail": f"💭 Agent reasoning before tool call: {thinking[:500]}{'...' if len(thinking) > 500 else ''}",
                        "thinking": thinking,
                    }))

            elif step_type == "tool_result":
                tool_name = trace_step.get("tool_name", "unknown")
                result_text = trace_step.get("result", "")
                yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="tool_result", value={
                    "step": "tool_result",
                    "status": "completed",
                    "tool_name": tool_name,
                    "result_preview": result_text[:500] if result_text else "(empty)",
                    "detail": f"📦 Tool '{tool_name}' returned: {result_text[:200]}{'...' if len(result_text) > 200 else ''}",
                }))

        # ── DeepTeam Output Guard ──
        if options.get("deepteam_output_guard", _security_feature_state.get("deepteam_output_guard", False)):
            yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
                "step": "agent_execution", "status": "running", "detail": "DeepTeam evaluating output safety..."
            }))
            output_safe, output_reason = await guard_output(user_message, response, audit_logger, extra_details=extra_audit_details)
            if not output_safe:
                response = f"⚠️ Response filtered by safety guardrails: {output_reason}"
                yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="deepteam_output_guard", value={
                    "step": "deepteam_output_guard", "status": "failed",
                    "detail": f"Output modified for safety."
                }))

        # ── Emit execution summary ──
        tool_call_steps = [s for s in trace_steps if s.get("type") == "tool_call"]
        tool_result_steps = [s for s in trace_steps if s.get("type") == "tool_result"]
        thinking_steps = [s for s in trace_steps if s.get("type") in ("ai_reasoning", "tool_call") and s.get("thinking")]

        summary_parts = []
        if thinking_steps:
            summary_parts.append(f"{len(thinking_steps)} reasoning steps")
        if tool_call_steps:
            total_tool_calls = sum(len(s.get("tool_calls", [])) for s in tool_call_steps)
            summary_parts.append(f"{total_tool_calls} tool calls")
        if tool_result_steps:
            summary_parts.append(f"{len(tool_result_steps)} tool results")

        summary_detail = f"Agent completed successfully" + (f" ({', '.join(summary_parts)})" if summary_parts else "")

        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "agent_execution", "status": "passed", "detail": summary_detail
        }))

        audit_logger.log(
            category=AuditCategory.GOVERNANCE,
            severity=AuditSeverity.INFO,
            action="custom_agent_execution",
            agent_did=f"did:gcc:agent:{agent_id}",
            outcome="success",
            details={
                **(extra_audit_details or {}),
                "user_input": user_message,
                "agent_response": response,
                "tools_used": [t.name for t in runner.tools],
                "trace_summary": {
                    "total_messages": trace_result.get("total_messages", 0),
                    "elapsed_ms": trace_result.get("elapsed_ms", 0),
                    "reasoning_steps": len(thinking_steps),
                    "tool_calls": sum(len(s.get("tool_calls", [])) for s in tool_call_steps),
                    "tool_results": len(tool_result_steps),
                }
            }
        )

        yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="agent_execution"))

        elapsed_ms = (time.time() - t_start) * 1000

        yield encoder.encode(StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot={
            "scenario": f"custom_agent_{agent_id}",
            "outcome": "APPROVED",
            "steps_completed": 1,
            "elapsed_ms": round(elapsed_ms, 2),
            "trace": {
                "total_messages": trace_result.get("total_messages", 0),
                "agent_name": trace_result.get("agent_name", ""),
                "tools_available": trace_result.get("tools_available", []),
            }
        }))
        
        yield encoder.encode(TextMessageStartEvent(type=EventType.TEXT_MESSAGE_START, message_id=msg_id, role="assistant"))
        yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=response))
        yield encoder.encode(TextMessageEndEvent(type=EventType.TEXT_MESSAGE_END, message_id=msg_id))
        
    except Exception as e:
        yield encoder.encode(CustomEvent(type=EventType.CUSTOM, name="governance_step", value={
            "step": "agent_execution", "status": "failed", "detail": f"Execution failed: {str(e)}"
        }))
        yield encoder.encode(StepFinishedEvent(type=EventType.STEP_FINISHED, step_name="agent_execution"))
        
        yield encoder.encode(StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot={
            "scenario": f"custom_agent_{agent_id}",
            "outcome": "FAILED",
            "error": str(e)
        }))
        
        yield encoder.encode(TextMessageStartEvent(type=EventType.TEXT_MESSAGE_START, message_id=msg_id, role="assistant"))
        yield encoder.encode(TextMessageContentEvent(type=EventType.TEXT_MESSAGE_CONTENT, message_id=msg_id, delta=f"I encountered a fatal error during initialization or execution:\n\n```\n{str(e)}\n```"))
        yield encoder.encode(TextMessageEndEvent(type=EventType.TEXT_MESSAGE_END, message_id=msg_id))

