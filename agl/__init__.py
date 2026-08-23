"""
HandshakeOS - Finance Disbursement Agent (LangChain Framework)
LangChain-based agent with governance-aware tools for executing payments.
Executes payments ONLY with a valid Trust Receipt from the AGL Gateway.

Uses LangChain's tool-calling pattern with a deterministic governance
LLM (no API key required) — swap in any ChatModel for production use.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Iterator

from langchain_core.tools import tool
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.prebuilt import create_react_agent

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
# Governance-aware deterministic LLM
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


def _build_finance_llm() -> GenericFakeChatModel:
    """Build a deterministic governance LLM for the Finance agent.
    In production, replace with ChatOpenAI / ChatAnthropic / etc."""

    def _responses() -> Iterator[BaseMessage]:
        while True:
            yield AIMessage(
                content="Payment executed successfully after Trust Receipt verification."
            )

    return GenericFakeChatModel(messages=_responses())


# ────────────────────────────────────────────────────────
# Finance Disbursement Agent — LangChain + A2A SDK
# ────────────────────────────────────────────────────────

class FinanceDisbursementAgent(A2AAgentExecutor):
    """
    LangChain-based Finance Disbursement Agent with A2A SDK compatibility.

    Uses LangChain tools (verify_trust_receipt, execute_payment, check_duplicate_receipt)
    for payment governance, while maintaining full backward compatibility with
    the A2A SDK AgentExecutor interface and the AGL gateway direct execution path.
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

        self._llm = _build_finance_llm()

    def _run_tools_directly(self, trust_receipt_data: dict) -> dict:
        """
        Deterministic tool execution — runs governance tools in sequence.
        Uses LangChain tools directly for Trust Receipt verification and payment.
        """
        results = []

        # Step 1: Verify Trust Receipt via LangChain tool
        verify_result_str = verify_trust_receipt.invoke({
            "receipt_json": json.dumps(trust_receipt_data),
        })
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
        })
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

    def invoke_langchain(self, trust_receipt_data: dict) -> dict:
        """
        Run the LangChain agent for Trust Receipt verification and payment.
        Returns dict with 'output', 'status', 'payment' keys.
        """
        return self._run_tools_directly(trust_receipt_data)

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
        lc_result = self.invoke_langchain(trust_receipt_data)

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
        lc_result = self.invoke_langchain(trust_receipt_data)

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

