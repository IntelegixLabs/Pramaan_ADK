"""
HandshakeOS - HR Relocation Agent (LangChain Framework)
LangChain-based agent with governance-aware tools for creating relocation
payment requests and building AGL governance envelopes.

Uses LLM factory to auto-detect API keys and use a real LLM when available,
falling back to deterministic tool execution when no key is configured.
"""

import hashlib
import json
import logging
import uuid
from typing import Optional, Any, Iterator

from langchain_core.tools import tool
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage, BaseMessage
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.prebuilt import create_react_agent

from llm_factory import build_llm, get_llm_info, is_live
from observability.tracer import get_langfuse_handler, langfuse_context

logger = logging.getLogger(__name__)

from a2a.server.agent_execution import AgentExecutor as A2AAgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCard, AgentSkill, AgentCapabilities, AgentExtension, AgentInterface,
    Part, Message, Role, TaskState, TaskStatus,
    TaskStatusUpdateEvent, TaskArtifactUpdateEvent, Artifact,
)
from google.protobuf import struct_pb2

from agl.governance_envelope import (
    build_governance_envelope,
    build_a2a_message,
    DelegationProof,
    PolicyProof,
    RiskSignals,
)


# ────────────────────────────────────────────────────────
# LangChain Tools for HR Relocation Governance
# ────────────────────────────────────────────────────────

@tool
def create_relocation_case(employee_case_ref: str, amount: float, currency: str = "USD", description: str = "") -> str:
    """Create a new employee relocation case with the specified amount and reference."""
    case = {
        "type": "relocation-disbursement",
        "employeeCaseRef": employee_case_ref,
        "amount": amount,
        "currency": currency,
        "description": description or f"Relocation disbursement for case {employee_case_ref}",
        "status": "CREATED",
    }
    return json.dumps(case)


@tool
def validate_relocation_amount(amount: float, max_limit: float = 10000.0) -> str:
    """Validate that the relocation amount is within the allowed policy limit."""
    if amount <= 0:
        return json.dumps({"valid": False, "reason": "Amount must be positive"})
    if amount > max_limit:
        return json.dumps({"valid": False, "reason": f"Amount ${amount:,.0f} exceeds limit ${max_limit:,.0f}"})
    return json.dumps({"valid": True, "amount": amount, "limit": max_limit, "headroom": max_limit - amount})


@tool
def check_agent_authority(action: str, allowed_actions: str, forbidden_actions: str) -> str:
    """Check if the agent has authority to perform the requested action.
    allowed_actions and forbidden_actions should be comma-separated lists."""
    allowed = [a.strip() for a in allowed_actions.split(",")]
    forbidden = [a.strip() for a in forbidden_actions.split(",")]
    if action in forbidden:
        return json.dumps({"authorized": False, "reason": f"Action '{action}' is explicitly forbidden"})
    if action in allowed or any(action.startswith(a.rsplit(".", 1)[0]) for a in allowed):
        return json.dumps({"authorized": True, "action": action})
    return json.dumps({"authorized": False, "reason": f"Action '{action}' not in allowed actions"})


@tool
def prepare_governance_envelope_data(
    requester_did: str,
    target_did: str,
    action: str,
    case_ref: str,
    amount: float,
) -> str:
    """Prepare the governance envelope metadata for a governed A2A request."""
    intent_hash = hashlib.sha256(f"{action}:{case_ref}".encode()).hexdigest()
    return json.dumps({
        "requester_did": requester_did,
        "target_did": target_did,
        "action": action,
        "case_ref": case_ref,
        "amount": amount,
        "intent_hash": intent_hash,
        "skill_id": "release-relocation-payment",
        "status": "ENVELOPE_READY",
    })


# ────────────────────────────────────────────────────────
# Governance-aware LLM (auto-detected from env)
# ────────────────────────────────────────────────────────

HR_SYSTEM_PROMPT = """You are the HR Relocation Agent for GCC Ascend.
Your role is to create employee relocation payment requests and submit them
through the AGL (Agent Governance Layer) for approval.

You MUST:
1. Validate the relocation amount is within policy limits ($10,000 max)
2. Check your authority for the requested action
3. Prepare the governance envelope for the AGL handshake
4. Never approve payments yourself — only the Finance Agent can disburse

Your DID: did:gcc:agent:hr-relocation-07
Your owner: did:gcc:employee:global-mobility-director
Allowed actions: relocation.case.create, relocation.disbursement.request
Forbidden actions: finance.payment.approve, finance.payment.release
"""


# ────────────────────────────────────────────────────────
# HR Relocation Agent — LangChain + A2A SDK
# ────────────────────────────────────────────────────────

class HRRelocationAgent(A2AAgentExecutor):
    """
    LangChain-based HR Relocation Agent with A2A SDK compatibility.

    Uses LangChain tools and AgentExecutor for reasoning. When a live LLM
    is configured (via API key env vars), uses real LLM reasoning via
    create_react_agent. Otherwise falls back to deterministic tool execution.
    """

    ALLOWED_ACTIONS = [
        "relocation.case.create",
        "relocation.disbursement.request",
    ]
    FORBIDDEN_ACTIONS = [
        "finance.payment.approve",
        "finance.payment.release",
    ]

    def __init__(
        self,
        agent_did: str = "did:gcc:agent:hr-relocation-07",
        owner_human: str = "did:gcc:employee:global-mobility-director",
    ):
        self.agent_did = agent_did
        self.owner_human = owner_human
        self.agent_name = "HR Relocation Agent"
        self.business_domain = "HR"
        self.model_hash = hashlib.sha256(f"{agent_did}-model-config".encode()).hexdigest()
        self.prompt_hash = hashlib.sha256(f"{agent_did}-system-prompt".encode()).hexdigest()

        # ── LangChain Agent Setup ──
        self.tools = [
            create_relocation_case,
            validate_relocation_amount,
            check_agent_authority,
            prepare_governance_envelope_data,
        ]

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", HR_SYSTEM_PROMPT),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        # Use the LLM factory — auto-detects API keys
        self._llm = build_llm()
        self._llm_info = get_llm_info()
        logger.info(f"HR Agent LLM: {self._llm_info.mode} ({self._llm_info.provider})")

    def _run_tools_directly(self, user_input: str, session_id: str = None, user_id: str = None, tags: list = None) -> dict:
        """
        Deterministic tool execution — runs governance tools in sequence.
        This is the primary execution path: it uses LangChain tools but
        drives them deterministically (no LLM needed for tool selection).
        """
        results = []
        handler = get_langfuse_handler()

        # Parse amount from input
        amount = 8000.0
        amount_match = re.search(r'\$\s*([\d,]+(?:\.\d{2})?)', user_input)
        if amount_match:
            try:
                amount = float(amount_match.group(1).replace(',', ''))
            except ValueError:
                pass

        with langfuse_context(session_id=session_id, user_id=user_id, tags=tags):
            # Step 1: Validate amount via LangChain tool
            val_result = validate_relocation_amount.invoke({"amount": amount}, config={"callbacks": [handler]} if handler else None)
            results.append(f"validate_relocation_amount → {val_result}")

            # Step 2: Check authority via LangChain tool
            auth_result = check_agent_authority.invoke({
                "action": "relocation.disbursement.request",
                "allowed_actions": ",".join(self.ALLOWED_ACTIONS),
                "forbidden_actions": ",".join(self.FORBIDDEN_ACTIONS),
            }, config={"callbacks": [handler]} if handler else None)
            results.append(f"check_agent_authority → {auth_result}")

            # Step 3: Create case via LangChain tool
            case_result = create_relocation_case.invoke({
                "employee_case_ref": f"case-{uuid.uuid4().hex[:6]}",
                "amount": amount,
            }, config={"callbacks": [handler]} if handler else None)
            results.append(f"create_relocation_case → {case_result}")

            # Step 4: Prepare envelope via LangChain tool
            env_result = prepare_governance_envelope_data.invoke({
                "requester_did": self.agent_did,
                "target_did": "did:gcc:agent:finance-disbursement-02",
                "action": "finance.disburse.relocation",
                "case_ref": f"case-{uuid.uuid4().hex[:6]}",
                "amount": amount,
            }, config={"callbacks": [handler]} if handler else None)
            results.append(f"prepare_governance_envelope_data → {env_result}")

        return {
            "input": user_input,
            "output": (
                f"Relocation request prepared (${amount:,.0f}). "
                f"Governance envelope ready for AGL handshake. "
                f"Agent: {self.agent_did}. "
                f"LangChain tools executed: validate_relocation_amount, "
                f"check_agent_authority, create_relocation_case, "
                f"prepare_governance_envelope_data."
            ),
            "tool_results": results,
        }

    @property
    def llm_mode(self) -> str:
        """Return 'live' or 'mock'."""
        return self._llm_info.mode

    @property
    def llm_provider(self) -> str:
        """Return the LLM provider name."""
        return self._llm_info.provider

    def invoke_langchain(self, user_input: str, chat_history: list = None, session_id: str = None, user_id: str = None, tags: list = None) -> dict:
        """
        Run the LangChain agent.
        When a live LLM is available, uses real LLM reasoning via create_react_agent.
        Otherwise falls back to deterministic tool execution.
        """
        if is_live():
            return self._run_with_live_llm(user_input, session_id, user_id, tags)
        return self._run_tools_directly(user_input, session_id, user_id, tags)

    def _run_with_live_llm(self, user_input: str, session_id: str = None, user_id: str = None, tags: list = None) -> dict:
        """
        Use the real LLM with create_react_agent for intelligent tool selection.
        """
        try:
            agent = create_react_agent(self._llm, self.tools)
            handler = get_langfuse_handler()
            config = {"callbacks": [handler]} if handler else None
            
            with langfuse_context(session_id=session_id, user_id=user_id, tags=tags):
                result = agent.invoke({
                    "messages": [
                        {"role": "user", "content": f"{HR_SYSTEM_PROMPT}\n\nUser Request: {user_input}"}
                    ]
                }, config=config)
                
            messages = result.get("messages", [])
            final_msg = messages[-1].content if messages else "Relocation request processed via live LLM."

            return {
                "input": user_input,
                "output": final_msg,
                "tool_results": [str(msg.content) for msg in messages],
                "llm_mode": "live",
            }
        except Exception as e:
            logger.warning(f"Live LLM failed, falling back to deterministic: {e}")
            result = self._run_tools_directly(user_input)
            result["llm_mode"] = "mock (fallback)"
            return result

    # ── A2A SDK AgentExecutor interface ──

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """A2A SDK execute — delegates to LangChain agent internally."""
        request = context.request
        task_id = context.task_id or str(uuid.uuid4())
        context_id = context.context_id or str(uuid.uuid4())

        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=task_id,
                context_id=context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_WORKING),
                final=False,
            )
        )

        user_text = ""
        if request and request.message and request.message.parts:
            for part in request.message.parts:
                if part.text:
                    user_text = part.text
                    break

        # Run LangChain agent
        lc_result = self.invoke_langchain(
            user_text,
            session_id=context_id,
            user_id=self.owner_human,
            tags=[self.agent_name, "langchain", "hr-relocation"]
        )
        agent_output = lc_result.get("output", "Request processed")

        response_data = {
            "agent": self.agent_did,
            "agentName": self.agent_name,
            "framework": "langchain",
            "businessDomain": self.business_domain,
            "requestType": "relocation-disbursement",
            "ownerHuman": self.owner_human,
            "allowedActions": self.ALLOWED_ACTIONS,
            "langchainTools": [t.name for t in self.tools],
            "message": agent_output,
            "status": "request_prepared",
        }

        metadata_struct = struct_pb2.Struct()
        metadata_struct.update(response_data)

        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                task_id=task_id,
                context_id=context_id,
                artifact=Artifact(
                    name="hr-relocation-request",
                    parts=[
                        Part(
                            text=f"Relocation request prepared by {self.agent_name} (LangChain): {agent_output}",
                            metadata=metadata_struct,
                        )
                    ],
                ),
            )
        )

        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=task_id,
                context_id=context_id,
                status=TaskStatus(
                    state=TaskState.TASK_STATE_COMPLETED,
                    message=Message(
                        role=Role.ROLE_AGENT,
                        parts=[Part(text=agent_output)],
                    ),
                ),
                final=True,
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Cancel the agent's current operation."""
        task_id = context.task_id or ""
        context_id = context.context_id or ""
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=task_id,
                context_id=context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_CANCELED),
                final=True,
            )
        )

    # ── Agent Card ──

    @staticmethod
    def get_agent_card(host: str = "localhost", port: int = 8000) -> AgentCard:
        """Return the A2A Agent Card with AGL governance extension."""
        agl_params = struct_pb2.Struct()
        agl_params.update({
            "poaQuorum": "2-of-3",
            "revocationSlaMs": 1000,
            "zkpRequired": True,
            "framework": "langchain",
        })

        return AgentCard(
            name="HR Relocation Agent",
            description="LangChain-based agent that creates employee relocation payment requests with AGL governance",
            version="1.0.0",
            supported_interfaces=[
                AgentInterface(
                    url=f"http://{host}:{port}/a2a/hr",
                    protocol_binding="jsonrpc/http",
                ),
            ],
            capabilities=AgentCapabilities(
                streaming=True,
                extensions=[
                    AgentExtension(
                        uri="urn:gcc-ascend:agl-handshake:v1",
                        description="Mandatory Proof-of-Authority governance handshake",
                        required=True,
                        params=agl_params,
                    ),
                ],
            ),
            skills=[
                AgentSkill(
                    id="request-relocation-disbursement",
                    name="Request Relocation Disbursement",
                    description="Submits a relocation payment request to Finance Agent via AGL governance",
                    tags=["hr", "relocation", "payment-request", "langchain"],
                ),
            ],
            default_input_modes=["application/json", "text/plain"],
            default_output_modes=["application/json", "text/plain"],
        )

    # ── Governance Envelope Builder (backward-compatible) ──

    def prepare_governed_request(
        self,
        amount: float,
        case_ref: str,
        vc_jwt: str,
        delegation_proof: "DelegationProof",
        policy_proofs: list["PolicyProof"],
        description: str = "",
        session_id: str = None,
    ) -> dict:
        """Create a relocation request — runs LangChain tools for validation."""
        handler = get_langfuse_handler()
        with langfuse_context(session_id=session_id, user_id=self.owner_human, tags=[self.agent_name, "relocation-request"]):
            val_result = validate_relocation_amount.invoke({"amount": amount}, config={"callbacks": [handler]} if handler else None)
        validation = json.loads(val_result)

        return {
            "request_data": {
                "type": "relocation-disbursement",
                "employeeCaseRef": employee_case_ref,
                "amount": amount,
                "currency": currency,
                "description": description or f"Relocation disbursement for case {employee_case_ref}",
                "validation": validation,
            },
            "amount": amount,
            "case_ref": employee_case_ref,
            "description": description,
        }

    def prepare_governed_request(
        self,
        amount: float,
        case_ref: str,
        description: str,
        vc_jwt: str,
        delegation_proof: DelegationProof,
        policy_proofs: list[PolicyProof],
        risk_signals: Optional[RiskSignals] = None,
        target_did: str = "did:gcc:agent:finance-disbursement-02",
    ) -> dict:
        """Build the full A2A message WITH governance envelope in metadata."""
        if risk_signals is None:
            risk_signals = RiskSignals(
                agent_model_hash=self.model_hash,
                prompt_template_hash=self.prompt_hash,
                risk_score=0.0,
            )

        envelope = build_governance_envelope(
            requester_did=self.agent_did,
            requester_vc=vc_jwt,
            target_did=target_did,
            skill_id="release-relocation-payment",
            action="finance.disburse.relocation",
            business_case_ref=case_ref,
            originating_human=self.owner_human,
            delegation_proof=delegation_proof,
            policy_proofs=policy_proofs,
            risk_signals=risk_signals,
        )

        text = (
            f"Request relocation disbursement for case {case_ref}. "
            f"{description}" if description else
            f"Request relocation disbursement for case {case_ref}."
        )

        return build_a2a_message(text=text, envelope=envelope)


# Backward-compatible alias
HRRelocationAgentExecutor = HRRelocationAgent

