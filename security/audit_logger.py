"""
HandshakeOS — Security Audit Logger
====================================
Structured, append-only security audit trail for all governance events.
Every security-relevant action is recorded with severity, category, agent context,
and tamper-evident hash chaining.

Production: ship events to SIEM (Splunk, Elastic, etc.) via structured logging.
"""

import hashlib
import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Optional, Callable

from security.audit_repository import audit_repository


class AuditSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuditCategory(str, Enum):
    IDENTITY = "IDENTITY"                       # VC issuance / verification
    DELEGATION = "DELEGATION"                   # Delegation grant / revoke
    POLICY = "POLICY"                           # Policy proof verification
    RISK = "RISK"                               # Intent sentinel / circuit breaker
    REVOCATION = "REVOCATION"                   # Agent revocation events
    ACCESS_CONTROL = "ACCESS_CONTROL"           # Authority intersection checks
    PROMPT_INJECTION = "PROMPT_INJECTION"       # Prompt injection attempts
    REPLAY_ATTACK = "REPLAY_ATTACK"             # Replay attack detection
    RATE_LIMIT = "RATE_LIMIT"                   # Rate limiting events
    ANOMALY = "ANOMALY"                         # Behavioral anomaly detection
    HONEYPOT = "HONEYPOT"                       # Honeypot / canary triggers
    GOVERNANCE = "GOVERNANCE"                   # General governance flow
    QUARANTINE = "QUARANTINE"                   # Agent quarantine events
    TRUST_RECEIPT = "TRUST_RECEIPT"             # Trust receipt issuance


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    category: str
    severity: str
    action: str
    agent_did: str = ""
    target_did: str = ""
    source_ip: str = ""
    details: dict = field(default_factory=dict)
    outcome: str = ""           # "success", "failure", "blocked", "alert"
    handshake_id: str = ""
    previous_hash: str = ""
    event_hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLogger:
    """
    Append-only, hash-chained security audit logger.
    Every event is linked to the previous one via SHA-256, creating a
    tamper-evident audit trail.
    """

    def __init__(self, max_events: int = 10000):
        self._events: list[AuditEvent] = []
        self._lock = Lock()
        self._max_events = max_events
        self._previous_hash = "genesis"
        self._chain_start_hash = "genesis"
        self._subscribers: list[Callable] = []
        # Per-agent event counters for quick stats
        self._agent_event_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # Severity counters
        self._severity_counts: dict[str, int] = defaultdict(int)

    def log(
        self,
        category: AuditCategory,
        severity: AuditSeverity,
        action: str,
        agent_did: str = "",
        target_did: str = "",
        source_ip: str = "",
        details: Optional[dict] = None,
        outcome: str = "success",
        handshake_id: str = "",
    ) -> AuditEvent:
        """Record a security audit event with hash-chain integrity."""
        with self._lock:
            event_id = f"audit-{uuid.uuid4().hex[:10]}"
            now = datetime.now(timezone.utc).isoformat()

            # Compute hash chain
            hash_input = f"{event_id}:{now}:{category.value}:{action}:{self._previous_hash}"
            event_hash = hashlib.sha256(hash_input.encode()).hexdigest()

            event = AuditEvent(
                event_id=event_id,
                timestamp=now,
                category=category.value,
                severity=severity.value,
                action=action,
                agent_did=agent_did,
                target_did=target_did,
                source_ip=source_ip,
                details=details or {},
                outcome=outcome,
                handshake_id=handshake_id,
                previous_hash=self._previous_hash,
                event_hash=event_hash,
            )

            self._events.append(event)
            self._previous_hash = event_hash
            
            # Save to database
            try:
                audit_repository.save_event(event.to_dict())
            except Exception as e:
                print(f"Failed to save audit event to db: {e}")

            # Update counters
            if agent_did:
                self._agent_event_counts[agent_did][category.value] += 1
            self._severity_counts[severity.value] += 1

            # Evict oldest if over limit
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events:]
                if self._events:
                    self._chain_start_hash = self._events[0].previous_hash

            # Copy subscriber list while under lock
            subscribers = list(self._subscribers)

        # Notify subscribers (outside lock to prevent deadlocks)
        for cb in subscribers:
            try:
                cb(event)
            except Exception:
                pass

        return event

    def subscribe(self, callback: Callable):
        """Subscribe to audit events in real-time."""
        with self._lock:
            self._subscribers.append(callback)

    def get_events(
        self,
        limit: int = 50,
        skip: int = 0,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        agent_did: Optional[str] = None,
        agent_name: Optional[str] = None,
        outcome: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        since: Optional[str] = None,
    ) -> list[dict]:
        """Query audit events with filtering."""
        # Query from database directly
        return audit_repository.get_events(
            limit=limit,
            skip=skip,
            category=category,
            severity=severity,
            agent_did=agent_did,
            agent_name=agent_name,
            outcome=outcome,
            start_date=start_date,
            end_date=end_date,
        )

    def get_events_count(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        agent_did: Optional[str] = None,
        agent_name: Optional[str] = None,
        outcome: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> int:
        return audit_repository.get_events_count(
            category=category,
            severity=severity,
            agent_did=agent_did,
            agent_name=agent_name,
            outcome=outcome,
            start_date=start_date,
            end_date=end_date,
        )

    def get_threat_summary(self) -> dict:
        """Return a high-level threat summary for the security dashboard."""
        with self._lock:
            now = time.time()
            recent_cutoff = datetime.fromtimestamp(now - 300, tz=timezone.utc).isoformat()

            recent_events = [e for e in self._events if e.timestamp >= recent_cutoff]
            recent_high = [e for e in recent_events if e.severity in ("HIGH", "CRITICAL")]
            recent_blocks = [e for e in recent_events if e.outcome == "blocked"]

            # Identify top-offending agents
            agent_threats: dict[str, int] = defaultdict(int)
            for e in recent_high:
                if e.agent_did:
                    agent_threats[e.agent_did] += 1

            return {
                "total_events": len(self._events),
                "severity_counts": dict(self._severity_counts),
                "recent_5min": {
                    "total": len(recent_events),
                    "high_critical": len(recent_high),
                    "blocked": len(recent_blocks),
                },
                "top_threat_agents": dict(sorted(
                    agent_threats.items(), key=lambda x: x[1], reverse=True
                )[:5]),
                "chain_integrity": self.verify_chain_integrity(),
            }

    def verify_chain_integrity(self) -> dict:
        """Verify the hash chain has not been tampered with."""
        if not self._events:
            return {"valid": True, "checked": 0}

        prev_hash = self._chain_start_hash
        for i, event in enumerate(self._events):
            if event.previous_hash != prev_hash:
                return {
                    "valid": False,
                    "broken_at_index": i,
                    "event_id": event.event_id,
                    "expected_previous": prev_hash,
                    "actual_previous": event.previous_hash,
                }
            prev_hash = event.event_hash

        return {"valid": True, "checked": len(self._events)}

    def get_agent_security_profile(self, agent_did: str) -> dict:
        """Return security profile for a specific agent."""
        with self._lock:
            events = [e for e in self._events if e.agent_did == agent_did]
            categories = self._agent_event_counts.get(agent_did, {})
            blocked = [e for e in events if e.outcome == "blocked"]
            high_sev = [e for e in events if e.severity in ("HIGH", "CRITICAL")]

            return {
                "agent_did": agent_did,
                "total_events": len(events),
                "blocked_count": len(blocked),
                "high_severity_count": len(high_sev),
                "category_breakdown": dict(categories),
                "last_event": events[-1].to_dict() if events else None,
                "threat_level": (
                    "CRITICAL" if len(high_sev) > 10 else
                    "HIGH" if len(high_sev) > 5 else
                    "MEDIUM" if len(blocked) > 3 else
                    "LOW"
                ),
            }

