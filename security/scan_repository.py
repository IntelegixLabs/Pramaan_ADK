import uuid
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional
from security.db import db

class ScanRepository:
    """Repository for storing and retrieving security scan results with user data isolation."""

    def __init__(self, db_path: str = None):
        db.initialize()

    def initialize(self):
        db.initialize()

    def save_scan(self, scan_type: str, target_name: str, findings: list, risk_score: float, report: dict = None, user_id: Optional[str] = None) -> str:
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO security_scans (scan_id, scan_type, target_name, findings_json, risk_score, created_at, report_json, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, scan_type, target_name, json.dumps(findings), risk_score, now, json.dumps(report) if report else None, user_id)
        )
        return scan_id

    def get_all_scans(self, user_id: Optional[str] = None) -> List[Dict]:
        if user_id:
            rows = db.fetchall("SELECT * FROM security_scans WHERE user_id = ? OR user_id IS NULL ORDER BY created_at DESC", (user_id,))
        else:
            rows = db.fetchall("SELECT * FROM security_scans ORDER BY created_at DESC")
        
        results = []
        for r in rows:
            results.append({
                "scan_id": r["scan_id"],
                "scan_type": r["scan_type"],
                "target_name": r["target_name"],
                "findings": json.loads(r["findings_json"]) if r.get("findings_json") else [],
                "risk_score": r["risk_score"],
                "created_at": str(r["created_at"]),
                "report": json.loads(r["report_json"]) if r.get("report_json") else None,
                "user_id": r.get("user_id"),
            })
        return results

    def get_scan(self, scan_id: str, user_id: Optional[str] = None) -> Optional[Dict]:
        if user_id:
            r = db.fetchone("SELECT * FROM security_scans WHERE scan_id = ? AND (user_id = ? OR user_id IS NULL)", (scan_id, user_id))
        else:
            r = db.fetchone("SELECT * FROM security_scans WHERE scan_id = ?", (scan_id,))
            
        if r:
            return {
                "scan_id": r["scan_id"],
                "scan_type": r["scan_type"],
                "target_name": r["target_name"],
                "findings": json.loads(r["findings_json"]) if r.get("findings_json") else [],
                "risk_score": r["risk_score"],
                "created_at": str(r["created_at"]),
                "report": json.loads(r["report_json"]) if r.get("report_json") else None,
                "user_id": r.get("user_id"),
            }
        return None

    def delete_scan(self, scan_id: str, user_id: Optional[str] = None) -> bool:
        if user_id:
            db.execute("DELETE FROM security_scans WHERE scan_id = ? AND (user_id = ? OR user_id IS NULL)", (scan_id, user_id))
        else:
            db.execute("DELETE FROM security_scans WHERE scan_id = ?", (scan_id,))
        return True

scan_repository = ScanRepository()
