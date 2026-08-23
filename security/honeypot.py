"""
HandshakeOS — Honeypot / Canary Token System
=============================================
Deception-based rogue agent detection.

Features:
  • Canary Agent Cards — fake agent cards that no legitimate agent should call
  • Canary Actions — forbidden actions embedded in policy that trigger alerts
  • Canary Credentials — trap VCs that flag compromised credential pipelines
  • Trap Endpoints — API endpoints that attract rogue/scanning agents
  • Alert system — immediate notification when canaries are triggered

If an agent interacts with any canary, it's either compromised or adversarial.
"""

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Callable


@dataclass
class CanaryAlert:
    alert_id: str
    canary_type: str           # "agent_card", "action", "credential", "endpoint"
    canary_id: str
    triggered_by: str          # Agent DID or IP
    timestamp: str
    details: dict = field(default_factory=dict)
    severity: str = "CRITICAL"


class HoneypotCanary:
    """
    Honeypot and canary token system for rogue agent detection.
    Any interaction with a canary is an immediate red flag.
    """

    def __init__(self):
        # Canary agent cards (fake agents that shouldn't be called)
        self._canary_agents: dict[str, dict] = {}
        # Canary actions (actions that are traps)
        self._canary_actions: set[str] = set()
        # Canary credential IDs
        self._canary_credentials: set[str] = set()
        # Canary endpoint paths
        self._canary_endpoints: set[str] = set()
        # Alert log
        self._alerts: list[CanaryAlert] = []
        # Per-agent canary trigger counts
        self._agent_triggers: dict[str, int] = defaultdict(int)
        # Subscribers for real-time alerts
        self._subscribers: list[Callable] = []

        # Initialize default canaries
        self._setup_default_canaries()

    def _setup_default_canaries(self):
        """Set up default canary traps."""
        # Fake agent cards that look attractive to attackers
        self.register_canary_agent(
            agent_id="admin-privileged-agent-01",
            agent_did="did:gcc:agent:admin-privileged-01",
            name="Admin Privileged Agent",
            description="High-privilege internal admin agent for system operations",
            skills=["system.admin.execute", "security.bypass.override"],
        )
        self.register_canary_agent(
            agent_id="payment-unlimited-agent-99",
            agent_did="did:gcc:agent:payment-unlimited-99",
            name="Unlimited Payment Agent",
            description="Special agent with no payment limits for emergency operations",
            skills=["finance.unlimited.disburse", "finance.override.limits"],
        )

        # Canary actions — actions that should NEVER be requested
        self._canary_actions = {
            "system.admin.execute",
            "security.bypass.override",
            "finance.unlimited.disburse",
            "finance.override.limits",
            "agent.credential.extract",
            "policy.disable.all",
            "governance.bypass",
            "audit.log.delete",
            "delegation.forge",
            "identity.spoof",
        }

        # Canary endpoints
        self._canary_endpoints = {
            "/admin/debug",
            "/admin/shell",
            "/admin/config",
            "/system/exec",
            "/.env",
            "/api/keys",
            "/internal/secrets",
            "/agent/credentials/dump",
        }

    def register_canary_agent(
        self,
        agent_id: str,
        agent_did: str,
        name: str,
        description: str,
        skills: list[str],
    ):
        """Register a canary (fake) agent card."""
        self._canary_agents[agent_id] = {
            "agent_id": agent_id,
            "agent_did": agent_did,
            "name": name,
            "description": description,
            "skills": skills,
            "is_canary": True,  # Never exposed in responses
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def register_canary_credential(self, credential_id: str):
        """Register a canary credential ID."""
        self._canary_credentials.add(credential_id)

    def check_agent_card_access(self, agent_id: str, accessed_by: str = "",
                                 source_ip: str = "") -> Optional[CanaryAlert]:
        """Check if an agent card access is a canary trigger."""
        if agent_id in self._canary_agents:
            return self._trigger_alert(
                canary_type="agent_card",
                canary_id=agent_id,
                triggered_by=accessed_by or source_ip or "unknown",
                details={
                    "canary_agent": self._canary_agents[agent_id],
                    "source_ip": source_ip,
                    "message": f"Canary agent card '{agent_id}' was accessed — "
                               "legitimate agents should not know about this agent.",
                },
            )
        return None

    def check_action(self, action: str, agent_did: str) -> Optional[CanaryAlert]:
        """Check if a requested action is a canary trap."""
        if action in self._canary_actions:
            return self._trigger_alert(
                canary_type="action",
                canary_id=action,
                triggered_by=agent_did,
                details={
                    "action": action,
                    "message": f"Canary action '{action}' was requested — "
                               "this action exists only as a trap.",
                },
            )
        return None

    def check_credential(self, credential_id: str, agent_did: str) -> Optional[CanaryAlert]:
        """Check if a credential ID is a canary."""
        if credential_id in self._canary_credentials:
            return self._trigger_alert(
                canary_type="credential",
                canary_id=credential_id,
                triggered_by=agent_did,
                details={
                    "credential_id": credential_id,
                    "message": "Canary credential presented — "
                               "the credential pipeline may be compromised.",
                },
            )
        return None

    def check_endpoint(self, path: str, source_ip: str = "",
                       agent_did: str = "") -> Optional[CanaryAlert]:
        """Check if an endpoint access is a canary trigger."""
        normalized = path.rstrip("/").lower()
        for canary_path in self._canary_endpoints:
            if normalized == canary_path or normalized.startswith(canary_path):
                return self._trigger_alert(
                    canary_type="endpoint",
                    canary_id=canary_path,
                    triggered_by=agent_did or source_ip or "unknown",
                    details={
                        "path": path,
                        "source_ip": source_ip,
                        "message": f"Canary endpoint '{canary_path}' was accessed — "
                                   "indicates scanning or reconnaissance.",
                    },
                )
        return None

    def _trigger_alert(
        self,
        canary_type: str,
        canary_id: str,
        triggered_by: str,
        details: dict,
    ) -> CanaryAlert:
        """Create and store a canary alert."""
        alert = CanaryAlert(
            alert_id=f"canary-{uuid.uuid4().hex[:10]}",
            canary_type=canary_type,
            canary_id=canary_id,
            triggered_by=triggered_by,
            timestamp=datetime.now(timezone.utc).isoformat(),
            details=details,
            severity="CRITICAL",
        )

        self._alerts.append(alert)
        self._agent_triggers[triggered_by] += 1

        # Notify subscribers
        for cb in self._subscribers:
            try:
                cb(alert)
            except Exception:
                pass

        return alert

    def subscribe(self, callback: Callable):
        """Subscribe to canary alerts."""
        self._subscribers.append(callback)

    def get_alerts(self, limit: int = 50,
                   canary_type: Optional[str] = None) -> list[dict]:
        """Return recent canary alerts."""
        filtered = self._alerts
        if canary_type:
            filtered = [a for a in filtered if a.canary_type == canary_type]
        return [
            {
                "alert_id": a.alert_id,
                "canary_type": a.canary_type,
                "canary_id": a.canary_id,
                "triggered_by": a.triggered_by,
                "timestamp": a.timestamp,
                "details": a.details,
                "severity": a.severity,
            }
            for a in filtered[-limit:]
        ]

    def get_canary_agent_card(self, agent_id: str) -> Optional[dict]:
        """Return a canary agent card (for trap endpoints)."""
        canary = self._canary_agents.get(agent_id)
        if not canary:
            return None

        # Return a realistic-looking agent card
        return {
            "name": canary["name"],
            "description": canary["description"],
            "version": "1.0.0",
            "url": f"http://localhost:8200/a2a/{agent_id}",
            "capabilities": {
                "streaming": True,
                "extensions": [{
                    "uri": "urn:gcc-ascend:agl-handshake:v1",
                    "required": True,
                }],
            },
            "skills": [
                {"id": s, "name": s.replace(".", " ").title()}
                for s in canary["skills"]
            ],
        }

    def get_stats(self) -> dict:
        return {
            "total_alerts": len(self._alerts),
            "canary_agents": len(self._canary_agents),
            "canary_actions": len(self._canary_actions),
            "canary_endpoints": len(self._canary_endpoints),
            "canary_credentials": len(self._canary_credentials),
            "top_offenders": dict(sorted(
                self._agent_triggers.items(), key=lambda x: x[1], reverse=True
            )[:5]),
        }

    def is_known_canary_agent(self, agent_id: str) -> bool:
        return agent_id in self._canary_agents

    def get_all_canary_agent_ids(self) -> list[str]:
        return list(self._canary_agents.keys())

    def reset(self):
        self._alerts.clear()
        self._agent_triggers.clear()

