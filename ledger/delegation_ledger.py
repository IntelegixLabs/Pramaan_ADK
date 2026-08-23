"""
HandshakeOS - Delegation Ledger
Append-only hash-chain ledger tracking human-to-agent delegation, trust receipts, and revocations.
"""

import sqlite3
import hashlib
import json
import uuid
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional
from threading import Lock


@dataclass
class DelegationResult:
    valid: bool
    event_id: str = ""
    delegated_by: str = ""
    scope: dict = field(default_factory=dict)
    error: str = ""


class DelegationLedger:
    """Permissioned hash-chain ledger for delegation events, trust receipts, and revocations."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "handshakeos.db")
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._write_lock = Lock()

    def initialize(self):
        """Create tables from schema.sql."""
        if os.environ.get("VERCEL"):
            self.db_path = "/tmp/demo.db"
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r") as f:
            self._conn.executescript(f.read())
        self._conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        return self._conn

    def _compute_event_hash(self, event_id: str, event_type: str,
                            agent_did: str, previous_hash: str) -> str:
        data = f"{event_id}:{event_type}:{agent_did}:{previous_hash}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _get_previous_event_hash(self, agent_did: str) -> str:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT event_hash FROM delegation_events WHERE agent_did = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (agent_did,)
        ).fetchone()
        return row["event_hash"] if row else "genesis"

    def grant_delegation(
        self,
        human_leader_id: str,
        agent_did: str,
        policy_id: str,
        scope: dict,
        valid_hours: int = 24,
        signed_by: str = "",
        signature: str = "",
    ) -> str:
        """Record a HUMAN_DELEGATION_GRANTED event."""
        conn = self._get_conn()
        event_id = f"del-{uuid.uuid4().hex[:8]}"
        event_type = "HUMAN_DELEGATION_GRANTED"
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(hours=valid_hours)
        previous_hash = self._get_previous_event_hash(agent_did)
        event_hash = self._compute_event_hash(event_id, event_type, agent_did, previous_hash)

        with self._write_lock:
            conn.execute(
                "INSERT INTO delegation_events "
                "(event_id, event_type, human_leader_id, agent_did, policy_id, scope_json, "
                "valid_from, valid_until, previous_event_hash, event_hash, signed_by, signature) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, event_type, human_leader_id, agent_did, policy_id,
                 json.dumps(scope), now.isoformat(), valid_until.isoformat(),
                 previous_hash, event_hash, signed_by or human_leader_id,
                 signature or f"sig-{event_id}")
            )
            conn.commit()
        return event_id

    def verify_delegation(self, agent_did: str, action: str,
                          current_time: Optional[datetime] = None) -> DelegationResult:
        """Check if there's a valid, non-expired delegation for this agent covering the action."""
        conn = self._get_conn()
        now = current_time or datetime.now(timezone.utc)
        now_str = now.isoformat()

        rows = conn.execute(
            "SELECT * FROM delegation_events WHERE agent_did = ? "
            "AND event_type = 'HUMAN_DELEGATION_GRANTED' "
            "AND valid_from <= ? AND valid_until >= ? "
            "ORDER BY created_at DESC",
            (agent_did, now_str, now_str)
        ).fetchall()

        # Check if agent has been revoked AFTER the most recent delegation
        latest_delegation_time = rows[0]["valid_from"] if rows else None
        if latest_delegation_time:
            revoked = conn.execute(
                "SELECT * FROM revocation_events WHERE agent_did = ? "
                "AND effective_at > ? "
                "ORDER BY effective_at DESC LIMIT 1",
                (agent_did, latest_delegation_time)
            ).fetchone()
            if revoked:
                return DelegationResult(valid=False, error="Agent has been revoked")
        else:
            # No valid delegations found, check for any revocation
            revoked = conn.execute(
                "SELECT * FROM revocation_events WHERE agent_did = ? LIMIT 1",
                (agent_did,)
            ).fetchone()
            if revoked:
                return DelegationResult(valid=False, error="Agent has been revoked")

        for row in rows:
            scope = json.loads(row["scope_json"])
            scope_actions = scope.get("actions", [])
            scope_pattern = scope.get("pattern", "")

            # Check if action matches scope
            if action in scope_actions:
                return DelegationResult(
                    valid=True,
                    event_id=row["event_id"],
                    delegated_by=row["human_leader_id"],
                    scope=scope,
                )
            # Wildcard/prefix match
            if scope_pattern and action.startswith(scope_pattern):
                return DelegationResult(
                    valid=True,
                    event_id=row["event_id"],
                    delegated_by=row["human_leader_id"],
                    scope=scope,
                )

        return DelegationResult(
            valid=False,
            error=f"No valid delegation found for agent {agent_did} action {action}"
        )

    def get_delegation_chain(self, agent_did: str) -> list[dict]:
        """Return all delegation events for an agent."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM delegation_events WHERE agent_did = ? ORDER BY created_at ASC",
            (agent_did,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_current_ledger_root(self) -> str:
        """Return the hash of the latest event across all agents."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT event_hash FROM delegation_events ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return row["event_hash"] if row else "genesis"

    def store_trust_receipt(
        self,
        receipt_id: str,
        handshake_id: str,
        requester_did: str,
        target_did: str,
        action: str,
        decision: str,
        quorum: str,
        validator_sigs: str,
        risk_score: float,
        ledger_root: str,
    ):
        """Store a Trust Receipt in the ledger."""
        conn = self._get_conn()
        with self._write_lock:
            conn.execute(
                "INSERT INTO trust_receipts "
                "(receipt_id, handshake_id, requester_agent_did, target_agent_did, action, "
                "decision, poa_quorum, validator_signatures, risk_score, ledger_root) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (receipt_id, handshake_id, requester_did, target_did, action,
                 decision, quorum, validator_sigs, risk_score, ledger_root)
            )
            conn.commit()

    def store_revocation(
        self,
        revocation_id: str,
        agent_did: str,
        revoked_by: str,
        reason: str,
        sequence_number: int,
        signature: str,
    ):
        """Store a revocation event."""
        conn = self._get_conn()
        with self._write_lock:
            conn.execute(
                "INSERT INTO revocation_events "
                "(revocation_id, agent_did, revoked_by, reason, effective_at, "
                "global_sequence_number, signature) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (revocation_id, agent_did, revoked_by, reason,
                 datetime.now(timezone.utc).isoformat(), sequence_number, signature)
            )
            conn.commit()

    def get_trust_receipts(self, limit: int = 50) -> list[dict]:
        """Return recent trust receipts."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM trust_receipts ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_revocations(self) -> list[dict]:
        """Return all revocation events."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM revocation_events ORDER BY effective_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

