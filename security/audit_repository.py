import json
from typing import List, Dict, Optional
from security.db import db

class AuditRepository:
    """Repository for storing and retrieving security audit events."""

    def __init__(self, db_path: str = None):
        db.initialize()

    def initialize(self):
        db.initialize()

    def save_event(self, event: Dict):
        db.execute(
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

    def get_events(self, limit: int = 100, skip: int = 0, category: Optional[str] = None, severity: Optional[str] = None, agent_did: Optional[str] = None, agent_name: Optional[str] = None, outcome: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict]:
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
            query += " AND (details_json LIKE ? OR agent_did LIKE ?)"
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
        
        rows = db.fetchall(query, tuple(params))
        
        results = []
        for r in rows:
            results.append({
                "event_id": r["event_id"],
                "timestamp": r["timestamp"],
                "category": r["category"],
                "severity": r["severity"],
                "action": r["action"],
                "agent_did": r.get("agent_did", ""),
                "target_did": r.get("target_did", ""),
                "source_ip": r.get("source_ip", ""),
                "details": json.loads(r["details_json"]) if r.get("details_json") else {},
                "outcome": r.get("outcome", ""),
                "handshake_id": r.get("handshake_id", ""),
                "previous_hash": r.get("previous_hash", ""),
                "event_hash": r.get("event_hash", "")
            })
        return results

    def get_events_count(self, category: Optional[str] = None, severity: Optional[str] = None, agent_did: Optional[str] = None, agent_name: Optional[str] = None, outcome: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None) -> int:
        query = "SELECT COUNT(*) as count FROM audit_events WHERE 1=1"
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
            query += " AND (details_json LIKE ? OR agent_did LIKE ?)"
            params.append(f"%{agent_name}%")
            params.append(f"%{agent_name}%")
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
            
        row = db.fetchone(query, tuple(params))
        if row:
            return list(row.values())[0]
        return 0

audit_repository = AuditRepository()
