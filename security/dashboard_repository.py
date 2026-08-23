import sqlite3
import uuid
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from threading import Lock

class DashboardRepository:
    def __init__(self, db_path: str = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "handshakeos.db")
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._write_lock = Lock()

    def initialize(self):
        if os.environ.get("VERCEL"):
            self.db_path = "/tmp/demo.db"
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        
        with self._write_lock:
            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS dashboard_agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    scan_interval_minutes INTEGER NOT NULL,
                    last_scan_time TIMESTAMP,
                    next_scan_time TIMESTAMP,
                    last_score REAL,
                    agent_type TEXT DEFAULT 'a2a',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            
            try:
                self._conn.execute("ALTER TABLE dashboard_agents ADD COLUMN agent_type TEXT DEFAULT 'a2a';")
            except sqlite3.OperationalError:
                pass

            # Remove legacy demo rows that were auto-seeded before explicit tracking existed.
            self._conn.execute("DELETE FROM dashboard_agents WHERE agent_id LIKE 'default-%'")
            
            self._conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        return self._conn

    @staticmethod
    def _normalize_url(url: Optional[str]) -> str:
        if not url:
            return ""
        return url.strip().rstrip("/").lower()

    def _find_agent_id_by_url(self, url: str) -> Optional[str]:
        if not url:
            return None
        conn = self._get_conn()
        target = self._normalize_url(url)
        rows = conn.execute("SELECT agent_id, url FROM dashboard_agents").fetchall()
        for row in rows:
            if self._normalize_url(row["url"]) == target:
                return row["agent_id"]
        return None

    def add_agent(self, name: str, url: str, scan_interval_minutes: int, agent_type: str = "a2a") -> str:
        conn = self._get_conn()
        agent_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        canonical_url = url.strip().rstrip("/")
        
        # Check if already exists — update metadata so MCP re-tracks fix agent_type
        existing_id = self._find_agent_id_by_url(canonical_url)
        if existing_id:
            with self._write_lock:
                conn.execute(
                    "UPDATE dashboard_agents SET name = ?, url = ?, scan_interval_minutes = ?, agent_type = ? WHERE agent_id = ?",
                    (name, canonical_url, scan_interval_minutes, agent_type, existing_id),
                )
                conn.commit()
            self.sync_agent_from_latest_scan(existing_id)
            return existing_id

        with self._write_lock:
            conn.execute(
                "INSERT INTO dashboard_agents (agent_id, name, url, scan_interval_minutes, agent_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (agent_id, name, canonical_url, scan_interval_minutes, agent_type, now.isoformat())
            )
            conn.commit()
        self.sync_agent_from_latest_scan(agent_id)
        return agent_id

    def update_agent_interval(self, agent_id: str, scan_interval_minutes: int):
        conn = self._get_conn()
        now = datetime.now(timezone.utc)
        next_scan = now + timedelta(minutes=scan_interval_minutes) if scan_interval_minutes > 0 else None
        
        with self._write_lock:
            conn.execute(
                "UPDATE dashboard_agents SET scan_interval_minutes = ?, next_scan_time = ? WHERE agent_id = ?",
                (scan_interval_minutes, next_scan.isoformat() if next_scan else None, agent_id)
            )
            conn.commit()

    def update_agent_scan(self, agent_id: str, last_score: float, last_scan_time: Optional[str] = None):
        conn = self._get_conn()
        r = conn.execute("SELECT scan_interval_minutes FROM dashboard_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not r:
            return
            
        interval = r["scan_interval_minutes"]
        now = datetime.now(timezone.utc)
        scan_time = last_scan_time or now.isoformat()
        next_scan = now + timedelta(minutes=interval) if interval > 0 else None
        
        with self._write_lock:
            conn.execute(
                "UPDATE dashboard_agents SET last_score = ?, last_scan_time = ?, next_scan_time = ? WHERE agent_id = ?",
                (last_score, scan_time, next_scan.isoformat() if next_scan else None, agent_id)
            )
            conn.commit()

    def update_agent_scan_by_url(self, url: str, target_name: str, last_score: float):
        agent_id = self._find_agent_id_by_url(url)
        if not agent_id and target_name:
            agent_id = self._find_agent_id_by_url(target_name)
        if not agent_id and target_name:
            conn = self._get_conn()
            r = conn.execute(
                "SELECT agent_id FROM dashboard_agents WHERE name = ?",
                (target_name,),
            ).fetchone()
            if r:
                agent_id = r["agent_id"]
        if agent_id:
            self.update_agent_scan(agent_id, last_score)

    def remove_agent(self, agent_id: str):
        conn = self._get_conn()
        with self._write_lock:
            conn.execute("DELETE FROM dashboard_agents WHERE agent_id = ?", (agent_id,))
            conn.commit()

    def _scan_matches_agent(self, scan: Dict, agent: Dict) -> bool:
        expected_type = "mcp" if (agent.get("agent_type") or "").lower() == "mcp" else "agent"
        if scan.get("scan_type") != expected_type:
            return False

        agent_url = self._normalize_url(agent.get("url"))
        agent_name = (agent.get("name") or "").strip().lower()
        target_name = scan.get("target_name") or ""
        target_norm = self._normalize_url(target_name)
        target_lower = target_name.strip().lower()

        report = scan.get("report") or {}
        fetched = self._normalize_url(report.get("fetched_from"))

        return (
            target_norm == agent_url
            or target_lower == agent_name
            or target_name == agent.get("url")
            or target_name == agent.get("name")
            or (fetched and fetched == agent_url)
        )

    def _find_latest_scan_for_agent(self, agent: Dict) -> Optional[Dict]:
        try:
            from security.scan_repository import scan_repository
            scans = scan_repository.get_all_scans()
        except Exception:
            return None

        matching = [scan for scan in scans if self._scan_matches_agent(scan, agent)]
        if not matching:
            return None

        return max(matching, key=lambda scan: scan.get("created_at") or "")

    def sync_agent_from_latest_scan(self, agent_id: str) -> None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM dashboard_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not row:
            return

        agent = dict(row)
        if agent.get("last_score") is not None:
            return

        latest = self._find_latest_scan_for_agent(agent)
        if not latest or latest.get("risk_score") is None:
            return

        self.update_agent_scan(
            agent_id,
            float(latest["risk_score"]),
            latest.get("created_at"),
        )

    def _enrich_agent_with_latest_scan(self, agent: Dict) -> Dict:
        if agent.get("last_score") is not None:
            return agent

        latest = self._find_latest_scan_for_agent(agent)
        if not latest or latest.get("risk_score") is None:
            return agent

        enriched = dict(agent)
        enriched["last_score"] = latest["risk_score"]
        enriched["last_scan_time"] = latest.get("created_at")
        self.sync_agent_from_latest_scan(agent["agent_id"])
        return enriched

    def get_all_agents(self) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM dashboard_agents ORDER BY created_at DESC").fetchall()
        # Only return agents explicitly tracked via the scanner "Track on Dashboard" flow.
        agents = [
            dict(r)
            for r in rows
            if not str(r["agent_id"]).startswith("default-")
        ]
        return [self._enrich_agent_with_latest_scan(agent) for agent in agents]

    def get_agents_due_for_scan(self) -> List[Dict]:
        conn = self._get_conn()
        now_str = datetime.now(timezone.utc).isoformat()
        
        # get agents where next_scan_time is not null and <= now
        rows = conn.execute(
            "SELECT * FROM dashboard_agents WHERE next_scan_time IS NOT NULL AND next_scan_time <= ?",
            (now_str,)
        ).fetchall()
        
        # Also return agents that have NEVER been scanned but have an interval > 0
        never_scanned = conn.execute(
            "SELECT * FROM dashboard_agents WHERE last_scan_time IS NULL AND scan_interval_minutes > 0"
        ).fetchall()
        
        # return combined (ensure unique by agent_id)
        agents = {r["agent_id"]: dict(r) for r in rows}
        for r in never_scanned:
            agents[r["agent_id"]] = dict(r)
            
        return list(agents.values())

dashboard_repository = DashboardRepository()
