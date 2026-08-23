"""
HandshakeOS - Circuit Breaker
Quarantines agents and cancels in-flight tasks when risk threshold is exceeded.
"""

from dataclasses import dataclass
from collections import defaultdict
from threading import Lock
from typing import Optional


@dataclass
class CircuitBreakerResult:
    triggered: bool
    action: str = ""
    details: str = ""


class CircuitBreaker:
    """Circuit breaker for rogue agent quarantine."""

    def __init__(self, risk_threshold: float = 0.85):
        self.risk_threshold = risk_threshold
        self._quarantined_agents: set[str] = set()
        self._inflight_tasks: dict[str, list[str]] = defaultdict(list)
        self._lock = Lock()

    def evaluate(self, agent_did: str, risk_score: float,
                 revocation_cache=None) -> CircuitBreakerResult:
        """Evaluate risk score and trigger circuit breaker if threshold exceeded."""
        with self._lock:
            if risk_score >= self.risk_threshold:
                self._quarantined_agents.add(agent_did)
                cancelled = self._inflight_tasks.pop(agent_did, [])

                if revocation_cache is not None:
                    from datetime import datetime, timezone
                    revocation_cache.revoke(agent_did, {
                        "eventType": "CIRCUIT_BREAKER_TRIGGERED",
                        "agentDid": agent_did,
                        "reason": f"Risk score {risk_score:.2f} exceeded threshold {self.risk_threshold}",
                        "effectiveAt": datetime.now(timezone.utc).isoformat(),
                    })

                return CircuitBreakerResult(
                    triggered=True,
                    action="QUARANTINED",
                    details=f"Agent {agent_did} quarantined. Risk={risk_score:.2f}. "
                            f"Cancelled {len(cancelled)} in-flight tasks.",
                )

            return CircuitBreakerResult(triggered=False, action="PASS", details="Risk within limits")

    def quarantine(self, agent_did: str):
        """Add agent to quarantine."""
        with self._lock:
            self._quarantined_agents.add(agent_did)

    def is_quarantined(self, agent_did: str) -> bool:
        with self._lock:
            return agent_did in self._quarantined_agents

    def register_inflight_task(self, agent_did: str, task_id: str):
        """Track an in-flight task for an agent."""
        with self._lock:
            self._inflight_tasks[agent_did].append(task_id)

    def cancel_inflight_tasks(self, agent_did: str) -> list[str]:
        """Cancel all in-flight tasks for a quarantined agent."""
        with self._lock:
            cancelled = self._inflight_tasks.pop(agent_did, [])
            return cancelled

    def release(self, agent_did: str):
        """Remove agent from quarantine."""
        with self._lock:
            self._quarantined_agents.discard(agent_did)

    def get_quarantined_agents(self) -> list[str]:
        with self._lock:
            return list(self._quarantined_agents)
