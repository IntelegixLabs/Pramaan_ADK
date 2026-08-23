"""
HandshakeOS - Revocation Bus
In-memory pub/sub for global agent revocation propagation.
In production, replace with Redis Pub/Sub, NATS, or Kafka.
"""

import uuid
import asyncio
from datetime import datetime, timezone
from typing import Callable, Optional


class RevocationBus:
    """In-memory pub/sub revocation bus for demo. Production: use Redis/NATS/Kafka."""

    def __init__(self):
        self._subscribers: list[Callable] = []
        self._events: list[dict] = []
        self._sequence_counter: int = 0

    async def publish(self, revocation_event: dict):
        """Publish a revocation event to all subscribers."""
        self._events.append(revocation_event)
        for callback in self._subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(revocation_event)
                else:
                    callback(revocation_event)
            except Exception as e:
                print(f"[RevocationBus] Subscriber error: {e}")

    def subscribe(self, callback: Callable):
        """Register a subscriber for revocation events."""
        self._subscribers.append(callback)

    def create_revocation_event(
        self,
        agent_did: str,
        revoked_by: str,
        reason: str,
        sequence_number: Optional[int] = None,
        signature: str = "admin-signature",
    ) -> dict:
        """Create a revocation event dict."""
        self._sequence_counter += 1
        seq = sequence_number if sequence_number is not None else self._sequence_counter

        return {
            "eventType": "AGENT_REVOKED",
            "revocationId": f"rev-{uuid.uuid4().hex[:8]}",
            "agentDid": agent_did,
            "revokedBy": revoked_by,
            "reason": reason,
            "effectiveAt": datetime.now(timezone.utc).isoformat(),
            "globalSequence": seq,
            "signature": signature,
        }

    def get_events(self) -> list[dict]:
        return list(self._events)



