"""
HandshakeOS - Finance Disbursement Agent (LangChain Framework)
LangChain-based agent with governance-aware tools for executing payments.
Executes payments ONLY with a valid Trust Receipt from the AGL Gateway.

Uses LLM factory to auto-detect API keys and use a real LLM when available,
falling back to deterministic tool execution when no key is configured.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Iterator

from langchain_core.tools import tool
from langchain_core.messages import AIMessage, HumanMessage, BaseMessage
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

from agl.trust_receipt import TrustReceipt


# ────────────────────────────────────────────────────────
# LangChain Tools for Finance Disbursement Governance
# ────────────────────────────────────────────────────────

# Module-level receipt store so tools can access it
_executed_receipts_store: set[str] = set()


@tool
def verify_trust_receipt(receipt_json: str) -> str:
    """Verify a Trust Receipt is valid and approved for payment execution.
    Returns verification result including receipt ID and decision."""
    try:
        data = json.loads(receipt_json) if isinstance(receipt_json, str) else receipt_json
    except (json.JSONDecodeError, TypeError):
        return json.dumps({"valid": False, "reason": "Invalid Trust Receipt format"})

    receipt = TrustReceipt.from_dict(data)

    if not receipt.approved or receipt.decision != "APPROVED":
        return json.dumps({
            "valid": False,
            "reason": f"Trust Receipt decision: {receipt.decision}. Cannot execute.",
            "receipt_id": receipt.receipt_id,
        })

    if receipt.receipt_id in _executed_receipts_store:
        return json.dumps({
            "valid": False,
            "reason": "Trust Receipt already used. One-time-use constraint violated.",
            "receipt_id": receipt.receipt_id,
        })

    return json.dumps({
        "valid": True,
        "receipt_id": receipt.receipt_id,
        "handshake_id": receipt.handshake_id,
        "action": receipt.action,
        "requester": receipt.requester,
        "target": receipt.target,
        "quorum": receipt.poa_quorum,
    })


@tool
def execute_payment(receipt_id: str, handshake_id: str, action: str, requester: str) -> str:
    """Execute the payment after Trust Receipt verification.
    Marks the receipt as used (one-time-use enforcement)."""
    now = datetime.now(timezone.utc).isoformat()
    payment_id = f"pay-{uuid.uuid4().hex[:8]}"

    # Mark receipt as used
    _executed_receipts_store.add(receipt_id)

    return json.dumps({
        "paymentId": payment_id,
        "status": "EXECUTED",
        "trustReceiptId": receipt_id,
        "handshakeId": handshake_id,
        "action": action,
        "requester": requester,
        "executedAt": now,
        "executedBy": "did:gcc:agent:finance-disbursement-02",
    })


@tool
def check_duplicate_receipt(receipt_id: str) -> str:
    """Check if a Trust Receipt has already been used (replay protection)."""
    is_duplicate = receipt_id in _executed_receipts_store
    return json.dumps({
        "receipt_id": receipt_id,
        "is_duplicate": is_duplicate,
        "reason": "Receipt already used" if is_duplicate else "Receipt not yet used",
    })


# ────────────────────────────────────────────────────────
# Governance-aware LLM (auto-detected from env)
# ────────────────────────────────────────────────────────

FINANCE_SYSTEM_PROMPT = """You are the Finance Disbursement Agent for GCC Ascend.
Your role is to execute approved employee relocation payments.

You MUST:
1. Verify the Trust Receipt is valid and APPROVED
2. Check the receipt hasn't been used before (one-time-use)
3. Execute the payment only after both checks pass
4. Never execute a payment without a valid Trust Receipt

Your DID: did:gcc:agent:finance-disbursement-02
Allowed actions: finance.disburse.relocation
"""


# ────────────────────────────────────────────────────────
# Finance Disbursement Agent — LangChain + A2A SDK
# ────────────────────────────────────────────────────────

class FinanceDisbursementAgent(A2AAgentExecutor):
    """
    LangChain-based Finance Disbursement Agent with A2A SDK compatibility.

    Uses LangChain tools (verify_trust_receipt, execute_payment, check_duplicate_receipt)
    for payment governance. When a live LLM is configured (via API key env vars),
    uses real LLM reasoning via create_react_agent. Otherwise falls back to
    deterministic tool execution.
    """

    ALLOWED_ACTIONS = ["finance.disburse.relocation"]

    def __init__(self, agent_did: str = "did:gcc:agent:finance-disbursement-02"):
        self.agent_did = agent_did
        self.agent_name = "Finance Disbursement Agent"
        self._executed_receipts: set[str] = _executed_receipts_store

        # ── LangChain Agent Setup ──
        self.tools = [
            verify_trust_receipt,
            execute_payment,
            check_duplicate_receipt,
        ]

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", FINANCE_SYSTEM_PROMPT),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        # Use the LLM factory — auto-detects API keys
        self._llm = build_llm()
        self._llm_info = get_llm_info()
        logger.info(f"Finance Agent LLM: {self._llm_info.mode} ({self._llm_info.provider})")

    def _run_tools_directly(self, trust_receipt_data: dict, session_id: str = None, user_id: str = None, tags: list = None) -> dict:
        """
        Deterministic tool execution — runs governance tools in sequence.
        Uses LangChain tools directly for Trust Receipt verification and payment.
        """
        results = []
        handler = get_langfuse_handler()

        with langfuse_context(session_id=session_id, user_id=user_id, tags=tags):
            # Step 1: Verify Trust Receipt via LangChain tool
            verify_result_str = verify_trust_receipt.invoke({
            "receipt_json": json.dumps(trust_receipt_data),
        }, config={"callbacks": [handler]} if handler else None)
        results.append(f"verify_trust_receipt → {verify_result_str}")
        verify_result = json.loads(verify_result_str)

        if not verify_result.get("valid"):
            return {
                "output": f"Payment rejected: {verify_result.get('reason', 'Unknown')}",
                "status": "REJECTED",
                "reason": verify_result.get("reason", "Verification failed"),
                "tool_results": results,
            }

        # Step 2: Execute payment via LangChain tool
        payment_result_str = execute_payment.invoke({
            "receipt_id": verify_result["receipt_id"],
            "handshake_id": verify_result["handshake_id"],
            "action": verify_result["action"],
            "requester": verify_result["requester"],
        }, config={"callbacks": [handler]} if handler else None)
        results.append(f"execute_payment → {payment_result_str}")
        payment_result = json.loads(payment_result_str)

        return {
            "output": f"Payment executed. ID: {payment_result['paymentId']}. "
                      f"Trust Receipt: {verify_result['receipt_id']}. "
                      f"LangChain tools: verify_trust_receipt, execute_payment.",
            "status": "EXECUTED",
            "payment": payment_result,
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

    def invoke_langchain(self, trust_receipt_data: dict, session_id: str = None, user_id: str = None, tags: list = None) -> dict:
        """
        Run the LangChain agent for Trust Receipt verification and payment.
        When a live LLM is available, uses real LLM reasoning via create_react_agent.
        Otherwise falls back to deterministic tool execution.
        """
        if is_live():
            return self._run_with_live_llm(trust_receipt_data, session_id, user_id, tags)
        return self._run_tools_directly(trust_receipt_data, session_id, user_id, tags)

    def _run_with_live_llm(self, trust_receipt_data: dict, session_id: str = None, user_id: str = None, tags: list = None) -> dict:
        """
        Use the real LLM with create_react_agent for intelligent tool selection.
        The LLM decides which tools to call and in what order.
        """
        try:
            agent = create_react_agent(self._llm, self.tools)
            handler = get_langfuse_handler()
            config = {"callbacks": [handler]} if handler else None
            
            with langfuse_context(session_id=session_id, user_id=user_id, tags=tags):
                result = agent.invoke({
                    "messages": [
                        HumanMessage(content=(
                            f"{FINANCE_SYSTEM_PROMPT}\n\n"
                            f"Process this Trust Receipt and execute the payment if valid:\n"
                            f"{json.dumps(trust_receipt_data, indent=2)}"
                        ))
                    ]
                }, config=config)
            # Extract the final message from the agent
            messages = result.get("messages", [])
            final_msg = messages[-1].content if messages else "Payment processed via live LLM."

            # Check if payment was executed by looking at tool results
            payment_data = None
            for msg in messages:
                if hasattr(msg, 'content') and isinstance(msg.content, str):
                    try:
                        parsed = json.loads(msg.content)
                        if parsed.get("paymentId"):
                            payment_data = parsed
                        elif parsed.get("valid") is False:
                            return {
                                "output": f"Payment rejected: {parsed.get('reason', 'Unknown')}",
                                "status": "REJECTED",
                                "reason": parsed.get("reason", "Verification failed"),
                                "tool_results": [str(msg.content) for msg in messages],
                                "llm_mode": "live",
                            }
                    except (json.JSONDecodeError, TypeError):
                        continue

            if payment_data:
                return {
                    "output": f"Payment executed via live LLM. ID: {payment_data['paymentId']}. "
                              f"Trust Receipt verified and payment confirmed.",
                    "status": "EXECUTED",
                    "payment": payment_data,
                    "tool_results": [str(msg.content) for msg in messages],
                    "llm_mode": "live",
                }

            return {
                "output": final_msg,
                "status": "EXECUTED",
                "payment": {},
                "tool_results": [str(msg.content) for msg in messages],
                "llm_mode": "live",
            }

        except Exception as e:
            logger.warning(f"Live LLM failed, falling back to deterministic: {e}")
            result = self._run_tools_directly(trust_receipt_data)
            result["llm_mode"] = "mock (fallback)"
            return result

    # ── A2A SDK AgentExecutor interface ──

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """A2A SDK execute — delegates to LangChain agent internally."""
        task_id = context.task_id or str(uuid.uuid4())
        context_id = context.context_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=task_id,
                context_id=context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_WORKING),
                final=False,
            )
        )

        # Extract trust receipt from request metadata
        request = context.request
        trust_receipt_data = None
        if request and request.message and request.message.metadata:
            metadata_dict = dict(request.message.metadata)
            agl = metadata_dict.get("agl", {})
            if hasattr(agl, 'items'):
                trust_receipt_data = dict(agl).get("trustReceipt")

        if not trust_receipt_data and request and hasattr(request, '_trust_receipt'):
            trust_receipt_data = request._trust_receipt

        if not trust_receipt_data or not isinstance(trust_receipt_data, dict):
            await event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=task_id,
                    context_id=context_id,
                    status=TaskStatus(
                        state=TaskState.TASK_STATE_REJECTED,
                        message=Message(
                            role=Role.ROLE_AGENT,
                            parts=[Part(text="No Trust Receipt found. Payment requires AGL governance approval.")],
                        ),
                    ),
                    final=True,
                )
            )
            return

        # Run LangChain agent for Trust Receipt verification + payment
        lc_result = self.invoke_langchain(
            trust_receipt_data,
            session_id=context_id,
            user_id=self.agent_did,
            tags=[self.agent_name, "langchain", "payment-execution"]
        )

        if lc_result["status"] == "REJECTED":
            await event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=task_id,
                    context_id=context_id,
                    status=TaskStatus(
                        state=TaskState.TASK_STATE_REJECTED,
                        message=Message(
                            role=Role.ROLE_AGENT,
                            parts=[Part(text=lc_result["output"])],
                        ),
                    ),
                    final=True,
                )
            )
            return

        # Publish payment confirmation artifact
        payment_data = lc_result.get("payment", {})
        metadata_struct = struct_pb2.Struct()
        metadata_struct.update({**payment_data, "framework": "langchain"})

        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                task_id=task_id,
                context_id=context_id,
                artifact=Artifact(
                    name="payment-confirmation",
                    parts=[
                        Part(
                            text=lc_result["output"],
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
                        parts=[Part(text=lc_result["output"])],
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

    # ── Legacy execute for AGL gateway direct calls ──

    async def execute_direct(self, request: dict) -> dict:
        """Direct execution for the AGL gateway (non-A2A-SDK path).
        Delegates to LangChain tools internally."""
        now = datetime.now(timezone.utc).isoformat()
        task_id = f"task-{uuid.uuid4().hex[:8]}"

        metadata = request.get("message", {}).get("metadata", {})
        agl = metadata.get("agl", {})
        trust_receipt_data = agl.get("trustReceipt")

        if not trust_receipt_data:
            return {"taskId": task_id, "status": "TASK_STATE_REJECTED",
                    "reason": "No Trust Receipt found.", "timestamp": now}

        # Use LangChain agent for verification + execution
        lc_result = self.invoke_langchain(
            trust_receipt_data,
            session_id=task_id,
            user_id=self.agent_did,
            tags=[self.agent_name, "langchain", "payment-execution"]
        )

        if lc_result["status"] == "REJECTED":
            return {"taskId": task_id, "status": "TASK_STATE_REJECTED",
                    "reason": lc_result.get("reason", lc_result["output"]), "timestamp": now}

        payment = lc_result.get("payment", {})
        message_parts = request.get("message", {}).get("parts", [])
        request_text = " ".join(p.get("text", "") for p in message_parts)

        return {
            "taskId": task_id,
            "status": "TASK_STATE_COMPLETED",
            "timestamp": now,
            "framework": "langchain",
            "artifacts": [{
                "name": "payment-confirmation",
                "parts": [{"type": "application/json", "data": {
                    **payment,
                    "description": request_text,
                    "langchainTools": ["verify_trust_receipt", "execute_payment"],
                }}],
            }],
            "history": [{"role": "agent", "parts": [
                {"text": lc_result["output"]}
            ]}],
        }

    # ── Agent Card ──

    @staticmethod
    def get_agent_card(host: str = "localhost", port: int = 8000) -> AgentCard:
        """Return A2A Agent Card with AGL extension."""
        agl_params = struct_pb2.Struct()
        agl_params.update({
            "poaQuorum": "3-of-5",
            "revocationSlaMs": 1000,
            "zkpRequired": True,
            "framework": "langchain",
        })

        return AgentCard(
            name="Finance Disbursement Agent",
            description="LangChain-based agent that executes approved employee relocation payments after AGL trust validation",
            version="1.0.0",
            supported_interfaces=[
                AgentInterface(
                    url=f"http://{host}:{port}/a2a/finance",
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
                    id="release-relocation-payment",
                    name="Release Relocation Payment",
                    description="Disburses relocation support after AGL trust validation",
                    tags=["finance", "relocation", "payment", "langchain"],
                ),
            ],
            default_input_modes=["application/json"],
            default_output_modes=["application/json"],
        )


# Backward-compatible alias
FinanceDisbursementAgentExecutor = FinanceDisbursementAgent

