import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional
from threading import Lock

class AuditRepository:
    """Repository for storing and retrieving security audit events."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "handshakeos.db")
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._write_lock = Lock()

    def initialize(self):
        """Create tables if not exist."""
        if os.environ.get("VERCEL"):
            self.db_path = "/tmp/demo.db"
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        
        with self._write_lock:
            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    agent_did TEXT,
                    target_did TEXT,
                    source_ip TEXT,
                    details_json TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    handshake_id TEXT,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
            ''')
            self._conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        return self._conn

    def save_event(self, event: Dict):
        conn = self._get_conn()
        with self._write_lock:
            conn.execute(
                """INSERT INTO audit_events 
                (event_id, timestamp, category, severity, action, agent_did, target_did, 
                source_ip, details_json, outcome, handshake_id, previous_hash, event_hash) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["event_id"],
                    event["timestamp"],
                    event["category"],
                    event["severity"],
                    event["action"],
                    event.get("agent_did", ""),
                    event.get("target_did", ""),
                    event.get("source_ip", ""),
                    json.dumps(event.get("details", {})),
                    event.get("outcome", ""),
                    event.get("handshake_id", ""),
                    event.get("previous_hash", ""),
                    event.get("event_hash", "")
                )
            )
            conn.commit()

    def get_events(self, limit: int = 100, skip: int = 0, category: Optional[str] = None, severity: Optional[str] = None, agent_did: Optional[str] = None, agent_name: Optional[str] = None, outcome: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict]:
        conn = self._get_conn()
        query = "SELECT * FROM audit_events WHERE 1=1"
        params = []
        
        if category:
            query += " AND category = ?"
            params.append(category)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if agent_did:
            query += " AND agent_did = ?"
            params.append(agent_did)
        if outcome:
            query += " AND outcome = ?"
            params.append(outcome)
        if agent_name:
            query += " AND (json_extract(details_json, '$.agent_name') LIKE ? OR agent_did LIKE ?)"
            params.append(f"%{agent_name}%")
            params.append(f"%{agent_name}%")
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
            
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, skip])
        
        rows = conn.execute(query, params).fetchall()
        
        results = []
        for r in rows:
            results.append({
                "event_id": r["event_id"],
                "timestamp": r["timestamp"],
                "category": r["category"],
                "severity": r["severity"],
                "action": r["action"],
                "agent_did": r["agent_did"],
                "target_did": r["target_did"],
                "source_ip": r["source_ip"],
                "details": json.loads(r["details_json"]),
                "outcome": r["outcome"],
                "handshake_id": r["handshake_id"],
                "previous_hash": r["previous_hash"],
                "event_hash": r["event_hash"]
            })
        return results

    def get_events_count(self, category: Optional[str] = None, severity: Optional[str] = None, agent_did: Optional[str] = None, agent_name: Optional[str] = None, outcome: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None) -> int:
        conn = self._get_conn()
        query = "SELECT COUNT(*) FROM audit_events WHERE 1=1"
        params = []
        
        if category:
            query += " AND category = ?"
            params.append(category)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if agent_did:
            query += " AND agent_did = ?"
            params.append(agent_did)
        if outcome:
            query += " AND outcome = ?"
            params.append(outcome)
        if agent_name:
            query += " AND (json_extract(details_json, '$.agent_name') LIKE ? OR agent_did LIKE ?)"
            params.append(f"%{agent_name}%")
            params.append(f"%{agent_name}%")
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
            
        return conn.execute(query, params).fetchone()[0]

audit_repository = AuditRepository()
