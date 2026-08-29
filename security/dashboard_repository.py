import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from security.db import db

class DashboardRepository:
    def __init__(self, db_path: str = None):
        db.initialize()

    def initialize(self):
        db.initialize()

    @staticmethod
    def _normalize_url(url: Optional[str]) -> str:
        if not url:
            return ""
        return url.strip().rstrip("/").lower()

    def _find_agent_id_by_url(self, url: str) -> Optional[str]:
        if not url:
            return None
        target = self._normalize_url(url)
        rows = db.fetchall("SELECT agent_id, url FROM dashboard_agents")
        for row in rows:
            if self._normalize_url(row["url"]) == target:
                return row["agent_id"]
        return None

    def add_agent(self, name: str, url: str, scan_interval_minutes: int, agent_type: str = "a2a") -> str:
        agent_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        canonical_url = url.strip().rstrip("/")
        
        # Check if already exists — update metadata
        existing_id = self._find_agent_id_by_url(canonical_url)
        if existing_id:
            db.execute(
                "UPDATE dashboard_agents SET name = ?, url = ?, scan_interval_minutes = ?, agent_type = ? WHERE agent_id = ?",
                (name, canonical_url, scan_interval_minutes, agent_type, existing_id),
            )
            self.sync_agent_from_latest_scan(existing_id)
            return existing_id

        db.execute(
            "INSERT INTO dashboard_agents (agent_id, name, url, scan_interval_minutes, agent_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, name, canonical_url, scan_interval_minutes, agent_type, now.isoformat())
        )
        self.sync_agent_from_latest_scan(agent_id)
        return agent_id

    def update_agent_interval(self, agent_id: str, scan_interval_minutes: int):
        now = datetime.now(timezone.utc)
        next_scan = now + timedelta(minutes=scan_interval_minutes) if scan_interval_minutes > 0 else None
        db.execute(
            "UPDATE dashboard_agents SET scan_interval_minutes = ?, next_scan_time = ? WHERE agent_id = ?",
            (scan_interval_minutes, next_scan.isoformat() if next_scan else None, agent_id)
        )

    def update_agent_scan(self, agent_id: str, last_score: float, last_scan_time: Optional[str] = None):
        r = db.fetchone("SELECT scan_interval_minutes FROM dashboard_agents WHERE agent_id = ?", (agent_id,))
        if not r:
            return
            
        interval = r["scan_interval_minutes"]
        now = datetime.now(timezone.utc)
        scan_time = last_scan_time or now.isoformat()
        next_scan = now + timedelta(minutes=interval) if interval > 0 else None
        
        db.execute(
            "UPDATE dashboard_agents SET last_score = ?, last_scan_time = ?, next_scan_time = ? WHERE agent_id = ?",
            (last_score, scan_time, next_scan.isoformat() if next_scan else None, agent_id)
        )

    def update_agent_scan_by_url(self, url: str, target_name: str, last_score: float):
        agent_id = self._find_agent_id_by_url(url)
        if not agent_id and target_name:
            agent_id = self._find_agent_id_by_url(target_name)
        if not agent_id and target_name:
            r = db.fetchone("SELECT agent_id FROM dashboard_agents WHERE name = ?", (target_name,))
            if r:
                agent_id = r["agent_id"]
        if agent_id:
            self.update_agent_scan(agent_id, last_score)

    def remove_agent(self, agent_id: str):
        db.execute("DELETE FROM dashboard_agents WHERE agent_id = ?", (agent_id,))

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
        row = db.fetchone("SELECT * FROM dashboard_agents WHERE agent_id = ?", (agent_id,))
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
        rows = db.fetchall("SELECT * FROM dashboard_agents ORDER BY created_at DESC")
        agents = [
            dict(r)
            for r in rows
            if not str(r.get("agent_id", "")).startswith("default-")
        ]
        return [self._enrich_agent_with_latest_scan(agent) for agent in agents]

    def get_agents_due_for_scan(self) -> List[Dict]:
        now_str = datetime.now(timezone.utc).isoformat()
        rows = db.fetchall(
            "SELECT * FROM dashboard_agents WHERE next_scan_time IS NOT NULL AND next_scan_time <= ?",
            (now_str,)
        )
        never_scanned = db.fetchall(
            "SELECT * FROM dashboard_agents WHERE last_scan_time IS NULL AND scan_interval_minutes > 0"
        )
        agents = {r["agent_id"]: dict(r) for r in rows}
        for r in never_scanned:
            agents[r["agent_id"]] = dict(r)
            
        return list(agents.values())

dashboard_repository = DashboardRepository()
