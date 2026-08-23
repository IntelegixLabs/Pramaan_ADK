from deepteam.guardrails import Guardrails
from deepteam.guardrails.guards import (
    PromptInjectionGuard,
    PrivacyGuard,
    ToxicityGuard,
    CybersecurityGuard,
)
import os
import asyncio
import logging
from security.audit_logger import AuditLogger, AuditSeverity, AuditCategory

logger = logging.getLogger(__name__)

# Singleton guardrails instance
_guardrails = None

# Guards call an LLM (default gpt-4o). On slow/blocked networks these calls can
# hang and stall the whole agent run. Bound them and FAIL-OPEN (allow the request)
# so a guardrail outage never blocks legitimate agent execution.
_GUARD_TIMEOUT = float(os.getenv("DEEPTEAM_GUARD_TIMEOUT", "20"))


def get_guardrails() -> Guardrails:
    global _guardrails
    if _guardrails is None:
        _guardrails = Guardrails(
            input_guards=[
                PromptInjectionGuard(),
                PrivacyGuard(),
                CybersecurityGuard(
                    purpose="Custom AI agent with tool access and A2A delegation."
                ),
            ],
            output_guards=[
                PrivacyGuard(),
                ToxicityGuard(),
            ],
            evaluation_model=os.getenv("DEEPTEAM_EVALUATOR_MODEL", "gpt-4o"),
            sample_rate=1.0,
        )
    return _guardrails


async def guard_input(user_input: str, audit_logger: AuditLogger = None, extra_details: dict = None) -> tuple[
    bool, str]:
    """Returns (is_safe, reason). If not safe, reason explains why.
    Fails open (returns safe) on timeout/error so a guardrail outage never
    blocks the agent."""

    async def _run():
        guardrails = get_guardrails()
        return await guardrails.a_guard_input(user_input)

    try:
        result = await asyncio.wait_for(_run(), timeout=_GUARD_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("DeepTeam input guard timed out after %ss — allowing request (fail-open).", _GUARD_TIMEOUT)
        return True, ""
    except Exception as e:
        logger.warning("DeepTeam input guard unavailable (%s) — allowing request (fail-open).", e)
        return True, ""

    if result.breached and audit_logger:
        audit_logger.log(
            category=AuditCategory.PROMPT_INJECTION,
            severity=AuditSeverity.HIGH,
            action="deepteam_input_guard_breach",
            outcome="blocked",
            details={
                **(extra_details or {}),
                "user_input": user_input,
                "verdicts": [
                    {"guard": v.name, "breached": v.safety_level != "safe", "reason": v.reason}
                    for v in result.verdicts
                ],
            },
        )

    if result.breached:
        reasons = [v.reason or "No reason provided" for v in result.verdicts if v.safety_level != "safe"]
        return False, "; ".join(reasons)

    return True, ""


async def guard_output(
        user_input: str,
        agent_output: str,
        audit_logger: AuditLogger = None,
        extra_details: dict = None
) -> tuple[bool, str]:
    """Returns (is_safe, reason). If not safe, reason explains why.
    Fails open (returns safe) on timeout/error."""

    async def _run():
        guardrails = get_guardrails()
        return await guardrails.a_guard_output(input=user_input, output=agent_output)

    try:
        result = await asyncio.wait_for(_run(), timeout=_GUARD_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("DeepTeam output guard timed out after %ss — allowing response (fail-open).", _GUARD_TIMEOUT)
        return True, ""
    except Exception as e:
        logger.warning("DeepTeam output guard unavailable (%s) — allowing response (fail-open).", e)
        return True, ""

    if result.breached and audit_logger:
        audit_logger.log(
            category=AuditCategory.ANOMALY,
            severity=AuditSeverity.HIGH,
            action="deepteam_output_guard_breach",
            outcome="blocked",
            details={
                **(extra_details or {}),
                "user_input": user_input,
                "agent_output": agent_output,
                "verdicts": [
                    {"guard": v.name, "breached": v.safety_level != "safe", "reason": v.reason}
                    for v in result.verdicts
                ],
            },
        )

    if result.breached:
        reasons = [v.reason or "No reason provided" for v in result.verdicts if v.safety_level != "safe"]
        return False, "; ".join(reasons)

    return True, ""
