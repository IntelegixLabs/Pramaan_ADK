"""
HandshakeOS - Revocation Cache
Local in-memory denylist for sub-second revocation enforcement.
Implements fail-closed pattern.
"""

from dataclasses import dataclass


@dataclass
class RevocationCheckResult:
    allowed: bool
    reason: str = ""


class RevocationCache:
    """Local denylist for fast revocation checks. Fail-closed design."""

    def __init__(self):
        self._revoked_agents: dict[str, dict] = {}
        self._bus_healthy: bool = True

    def is_revoked(self, agent_did: str) -> bool:
        return agent_did in self._revoked_agents

    def revoke(self, agent_did: str, event: dict):
        """Add agent to the local denylist."""
        self._revoked_agents[agent_did] = event

    def precheck_revocation(self, agent_did: str) -> RevocationCheckResult:
        """Check revocation with fail-closed pattern."""
        if agent_did in self._revoked_agents:
            return RevocationCheckResult(
                allowed=False,
                reason="Agent right-to-act revoked",
            )

        if not self._bus_healthy:
            return RevocationCheckResult(
                allowed=False,
                reason="Fail-closed: revocation state unavailable",
            )

        return RevocationCheckResult(allowed=True)

    def set_bus_health(self, healthy: bool):
        self._bus_healthy = healthy

    def get_all_revoked(self) -> dict[str, dict]:
        return dict(self._revoked_agents)

    def clear(self, agent_did: str):
        """Remove an agent from the denylist."""
        self._revoked_agents.pop(agent_did, None)

