import uuid
import json
import sqlite3
import os
import logging
from datetime import datetime, timezone
from threading import Lock

logger = logging.getLogger(__name__)

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/handshakeos.db"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "handshakeos.db")


class HumanReviewQueue:
    def __init__(self, db_path=DB_PATH):
        self.reviews = {}  # review_id -> review_data (in-memory for polling)
        self.db_path = db_path
        self._lock = Lock()
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS human_reviews (
                    id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    tool_args TEXT,
                    agent_name TEXT,
                    agent_id TEXT,
                    risk_score INTEGER DEFAULT 0,
                    run_id TEXT,
                    user_input TEXT,
                    policy_reason TEXT,
                    principal_json TEXT,
                    agent_response TEXT,
                    gateway_evidence TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    reviewer_notes TEXT,
                    reviewed_by TEXT,
                    reviewed_at TEXT,
                    timestamp TEXT NOT NULL
                );
            ''')
            conn.commit()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def create_review(self, tool_call: dict, decision: dict, principal_dict: dict, agent_response: str = "",
                      agent_name: str = "", agent_id: str = "", risk_score: int = 0,
                      run_id: str = "", user_input: str = "", gateway_evidence: str = "") -> str:
        review_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        review_data = {
            "id": review_id,
            "tool": tool_call,
            "tool_name": tool_call.get("name", ""),
            "tool_args": json.dumps(tool_call.get("args", {})),
            "agent_name": agent_name,
            "agent_id": agent_id,
            "risk_score": risk_score,
            "run_id": run_id,
            "user_input": user_input,
            "policy_reason": decision.get("reason", ""),
            "principal": principal_dict,
            "agent_response": agent_response,
            "gateway_evidence": gateway_evidence,
            "status": "pending",
            "reviewer_notes": "",
            "reviewed_by": "",
            "reviewed_at": "",
            "timestamp": now
        }

        # Store in memory for fast polling
        with self._lock:
            self.reviews[review_id] = review_data

        # Persist to database
        try:
            conn = self._get_conn()
            conn.execute('''
                INSERT INTO human_reviews 
                (id, tool_name, tool_args, agent_name, agent_id, risk_score, run_id, user_input,
                 policy_reason, principal_json, agent_response, gateway_evidence, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                review_id, review_data["tool_name"], review_data["tool_args"],
                agent_name, agent_id, risk_score, run_id, user_input,
                review_data["policy_reason"], json.dumps(principal_dict),
                agent_response, gateway_evidence, "pending", now
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to persist review {review_id}: {e}")

        # Log to audit trail
        self._log_audit(review_id, "pending", "system", "")

        return review_id

    def get_pending_reviews(self) -> list[dict]:
        try:
            conn = self._get_conn()
            rows = conn.execute("SELECT * FROM human_reviews WHERE status='pending' ORDER BY timestamp ASC").fetchall()
            conn.close()
            return [self._row_to_dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to fetch pending reviews: {e}")
            return [r for r in self.reviews.values() if r["status"] == "pending"]

    def get_all_reviews(self) -> list[dict]:
        """Return all reviews (pending, approved, rejected) from DB."""
        try:
            conn = self._get_conn()
            rows = conn.execute('SELECT * FROM human_reviews ORDER BY timestamp DESC').fetchall()
            conn.close()
            return [self._row_to_dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to fetch all reviews: {e}")
            # Fallback to in-memory
            return list(self.reviews.values())

    def get_resolved_reviews(self) -> list[dict]:
        """Return approved and rejected reviews from DB."""
        try:
            conn = self._get_conn()
            rows = conn.execute(
                "SELECT * FROM human_reviews WHERE status IN ('approved', 'rejected') ORDER BY reviewed_at DESC"
            ).fetchall()
            conn.close()
            return [self._row_to_dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to fetch resolved reviews: {e}")
            return [r for r in self.reviews.values() if r["status"] in ("approved", "rejected")]

    def get_review_stats(self) -> dict:
        """Return counts of pending, approved, rejected reviews."""
        try:
            conn = self._get_conn()
            pending = conn.execute("SELECT COUNT(*) FROM human_reviews WHERE status='pending'").fetchone()[0]
            approved = conn.execute("SELECT COUNT(*) FROM human_reviews WHERE status='approved'").fetchone()[0]
            rejected = conn.execute("SELECT COUNT(*) FROM human_reviews WHERE status='rejected'").fetchone()[0]
            conn.close()
            return {"pending": pending, "approved": approved, "rejected": rejected}
        except Exception:
            p = sum(1 for r in self.reviews.values() if r["status"] == "pending")
            a = sum(1 for r in self.reviews.values() if r["status"] == "approved")
            d = sum(1 for r in self.reviews.values() if r["status"] == "rejected")
            return {"pending": p, "approved": a, "rejected": d}

    def approve(self, review_id: str, reviewer: str = "admin", reviewer_notes: str = "") -> bool:
        now = datetime.now(timezone.utc).isoformat()
        updated_in_db = False

        try:
            conn = self._get_conn()
            cursor = conn.execute('''
                UPDATE human_reviews SET status='approved', reviewed_by=?, reviewed_at=?, reviewer_notes=?
                WHERE id=? AND status='pending'
            ''', (reviewer, now, reviewer_notes, review_id))
            updated_in_db = cursor.rowcount > 0
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to persist approval for {review_id}: {e}")

        if not updated_in_db:
            return False

        # Update in-memory (for polling) if it exists
        with self._lock:
            if review_id in self.reviews:
                self.reviews[review_id]["status"] = "approved"
                self.reviews[review_id]["reviewed_by"] = reviewer
                self.reviews[review_id]["reviewed_at"] = now
                self.reviews[review_id]["reviewer_notes"] = reviewer_notes

        # Log to audit
        self._log_audit(review_id, "approved", reviewer, reviewer_notes)
        return True

    def reject(self, review_id: str, reviewer: str = "admin", reviewer_notes: str = "") -> bool:
        now = datetime.now(timezone.utc).isoformat()
        updated_in_db = False

        try:
            conn = self._get_conn()
            cursor = conn.execute('''
                UPDATE human_reviews SET status='rejected', reviewed_by=?, reviewed_at=?, reviewer_notes=?
                WHERE id=? AND status='pending'
            ''', (reviewer, now, reviewer_notes, review_id))
            updated_in_db = cursor.rowcount > 0
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to persist rejection for {review_id}: {e}")

        if not updated_in_db:
            return False

        with self._lock:
            if review_id in self.reviews:
                self.reviews[review_id]["status"] = "rejected"
                self.reviews[review_id]["reviewed_by"] = reviewer
                self.reviews[review_id]["reviewed_at"] = now
                self.reviews[review_id]["reviewer_notes"] = reviewer_notes

        self._log_audit(review_id, "rejected", reviewer, reviewer_notes)
        return True

    def get_status(self, review_id: str) -> str:
        with self._lock:
            if review_id in self.reviews:
                return self.reviews[review_id]["status"]
        return "not_found"

    def get_review(self, review_id: str) -> dict:
        with self._lock:
            return self.reviews.get(review_id)

    def _row_to_dict(self, row) -> dict:
        return {
            "id": row["id"],
            "tool": {"name": row["tool_name"], "args": json.loads(row["tool_args"] or "{}")},
            "tool_name": row["tool_name"],
            "agent_name": row["agent_name"] or "",
            "agent_id": row["agent_id"] or "",
            "risk_score": row["risk_score"] or 0,
            "run_id": row["run_id"] or "",
            "user_input": row["user_input"] or "",
            "policy_reason": row["policy_reason"] or "",
            "principal": json.loads(row["principal_json"] or "{}"),
            "agent_response": row["agent_response"] or "",
            "gateway_evidence": row["gateway_evidence"] or "",
            "status": row["status"],
            "reviewer_notes": row["reviewer_notes"] or "",
            "reviewed_by": row["reviewed_by"] or "",
            "reviewed_at": row["reviewed_at"] or "",
            "timestamp": row["timestamp"]
        }

    def _log_audit(self, review_id: str, action: str, reviewer: str, notes: str):
        try:
            from security.audit_logger import AuditLogger, AuditCategory, AuditSeverity
            audit_logger = AuditLogger()

            review = None
            with self._lock:
                review = self.reviews.get(review_id, {})

            audit_logger.log(
                category=AuditCategory.GOVERNANCE,
                severity=AuditSeverity.INFO if action == "pending" else (AuditSeverity.MEDIUM if action == "approved" else AuditSeverity.HIGH),
                action=f"human_review_{action}",
                agent_did=review.get("agent_id", ""),
                outcome=action,
                details={
                    "review_id": review_id,
                    "tool_name": review.get("tool_name", review.get("tool", {}).get("name", "")),
                    "agent_name": review.get("agent_name", ""),
                    "risk_score": review.get("risk_score", 0),
                    "reviewer": reviewer,
                    "reviewer_notes": notes,
                    "user_input": review.get("user_input", ""),
                }
            )
        except Exception as e:
            logger.error(f"Failed to log audit for review {review_id}: {e}")


human_review_queue = HumanReviewQueue()
