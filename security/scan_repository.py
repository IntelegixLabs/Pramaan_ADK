import sqlite3
import uuid
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional
from threading import Lock

class ScanRepository:
    """Repository for storing and retrieving security scan results."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "handshakeos.db")
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._write_lock = Lock()

    def initialize(self):
        """Create tables if not exist (already handled by ledger initialize but safe here)."""
        if os.environ.get("VERCEL"):
            self.db_path = "/tmp/demo.db"
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        
        # Ensure the table exists in case ledger hasn't initialized yet
        with self._write_lock:
            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS security_scans (
                    scan_id TEXT PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            try:
                self._conn.execute("ALTER TABLE security_scans ADD COLUMN report_json TEXT;")
            except sqlite3.OperationalError:
                pass
            self._conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        return self._conn

    def save_scan(self, scan_type: str, target_name: str, findings: list, risk_score: float, report: dict = None) -> str:
        conn = self._get_conn()
        scan_id = str(uuid.uuid4())
        with self._write_lock:
            conn.execute(
                "INSERT INTO security_scans (scan_id, scan_type, target_name, findings_json, risk_score, created_at, report_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, scan_type, target_name, json.dumps(findings), risk_score, datetime.now(timezone.utc).isoformat(), json.dumps(report) if report else None)
            )
            conn.commit()
        return scan_id

    def get_all_scans(self) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM security_scans ORDER BY created_at DESC").fetchall()
        
        results = []
        for r in rows:
            results.append({
                "scan_id": r["scan_id"],
                "scan_type": r["scan_type"],
                "target_name": r["target_name"],
                "findings": json.loads(r["findings_json"]),
                "risk_score": r["risk_score"],
                "created_at": r["created_at"],
                "report": json.loads(r["report_json"]) if "report_json" in r.keys() and r["report_json"] else None
            })
        return results

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        conn = self._get_conn()
        r = conn.execute("SELECT * FROM security_scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if r:
            return {
                "scan_id": r["scan_id"],
                "scan_type": r["scan_type"],
                "target_name": r["target_name"],
                "findings": json.loads(r["findings_json"]),
                "risk_score": r["risk_score"],
                "created_at": r["created_at"],
                "report": json.loads(r["report_json"]) if "report_json" in r.keys() and r["report_json"] else None
            }
        return None

    def delete_scan(self, scan_id: str) -> bool:
        conn = self._get_conn()
        with self._write_lock:
            cursor = conn.execute("DELETE FROM security_scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

scan_repository = ScanRepository()
