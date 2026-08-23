from fastapi import APIRouter, HTTPException
from typing import List, Dict
import httpx
from pydantic import BaseModel


class UrlValidateRequest(BaseModel):
    url: str


from security.pii_redactor import pii_redactor
from security.goal_checker import goal_checker
from security.output_validator import output_validator
from security.sandbox import sandbox
from security.authorization import authorization_engine
from security.human_review import human_review_queue
from security.agent_manager import agent_manager
from fastapi import UploadFile, File, Form
from security.document_scanner import scan_document
from security.rag_manager import rag_manager
from security.pii_redactor import pii_redactor

router = APIRouter(prefix="/admin", tags=["admin", "security"])


# --- PII Redactor ---
@router.get("/pii")
async def get_pii_rules():
    return pii_redactor.get_patterns()


@router.post("/pii")
async def set_pii_rules(patterns: dict):
    pii_redactor.set_patterns(patterns)
    return {"status": "success"}


# --- Goal Checker ---
@router.get("/goals")
async def get_goals():
    return goal_checker.get_rules()


@router.post("/goals")
async def set_goals(rules: dict):
    goal_checker.set_rules(rules)
    return {"status": "success"}


# --- Output Validator ---
@router.get("/output-validator")
async def get_output_validator():
    return {"blocklist": output_validator.get_blocklist()}


@router.post("/output-validator")
async def set_output_validator(body: dict):
    if "blocklist" in body:
        output_validator.set_blocklist(body["blocklist"])
    return {"status": "success"}


# --- Sandbox ---
@router.get("/sandbox")
async def get_sandbox():
    return sandbox.get_config()


@router.post("/sandbox")
async def set_sandbox(config: dict):
    sandbox.set_config(
        blocked=config.get("blocked_tools", sandbox.blocked_tools),
        max_calls=config.get("max_tool_calls", sandbox.max_tool_calls)
    )
    return {"status": "success"}


# --- Authorization (OPA Rego) ---
@router.get("/authorization")
async def get_rego_policy():
    return {"rego": authorization_engine.get_rego()}


@router.post("/authorization")
async def set_rego_policy(body: dict):
    if "rego" in body:
        authorization_engine.set_rego(body["rego"])
    return {"status": "success"}


# --- Human Review ---
@router.get("/reviews")
async def get_pending_reviews():
    return human_review_queue.get_pending_reviews()


@router.get("/reviews/all")
async def get_all_reviews():
    return human_review_queue.get_all_reviews()


@router.get("/reviews/resolved")
async def get_resolved_reviews():
    return human_review_queue.get_resolved_reviews()


@router.get("/reviews/stats")
async def get_review_stats():
    return human_review_queue.get_review_stats()


class ReviewActionRequest(BaseModel):
    reviewer_notes: str = ""
    reviewer: str = "admin"


@router.post("/reviews/{review_id}/approve")
async def approve_review(review_id: str, req: ReviewActionRequest = None):
    req = req or ReviewActionRequest()
    if human_review_queue.approve(review_id, reviewer=req.reviewer, reviewer_notes=req.reviewer_notes):
        return {"status": "approved"}
    raise HTTPException(status_code=404, detail="Review not found or not pending")


@router.post("/reviews/{review_id}/reject")
async def reject_review(review_id: str, req: ReviewActionRequest = None):
    req = req or ReviewActionRequest()
    if human_review_queue.reject(review_id, reviewer=req.reviewer, reviewer_notes=req.reviewer_notes):
        return {"status": "rejected"}
    raise HTTPException(status_code=404, detail="Review not found or not pending")


# --- Custom Agents ---
@router.post("/agents/validate-url")
async def validate_url(body: UrlValidateRequest):
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(body.url)
            response.raise_for_status()

            # Attempt to parse JSON to return to the frontend
            data = None
            if "application/json" in response.headers.get("content-type", ""):
                data = response.json()
            elif response.text.strip().startswith("{"):
                try:
                    data = response.json()
                except Exception:
                    pass

            return {"status": "success", "data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Connection failed: {str(e)}")


@router.get("/agents")
async def get_custom_agents():
    return agent_manager.get_all_agents()


@router.delete("/agents/{agent_id}")
async def delete_custom_agent(agent_id: str):
    if agent_manager.delete_agent(agent_id):
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Agent not found")


# --- RAG Knowledge Base ---
@router.post("/rag/upload")
async def upload_document(file: UploadFile = File(...), skip_security: bool = Form(False),
                          mask_pii: bool = Form(False)):
    content = await file.read()

    # 1. Extract text for scanning
    try:
        text_preview = rag_manager.extract_text(content, file.filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 1.5 Mask PII if enabled
    if mask_pii:
        redaction_result = pii_redactor.redact(text_preview)
        text_preview = redaction_result.text

    # 2. Agentic Security Scan
    scan_result = {"is_safe": True, "reason": "Security scan bypassed."}
    if not skip_security:
        scan_result = scan_document(file.filename, text_preview)
        if not scan_result.get("is_safe", False):
            raise HTTPException(status_code=403,
                                detail=f"Agentic Security Rejected Document: {scan_result.get('reason')}")

    # 3. Ingest into Chroma
    try:
        doc_info = rag_manager.ingest_document(file.filename, raw_text=text_preview)
        return {"status": "success", "document": doc_info, "scan": scan_result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest document: {str(e)}")


@router.get("/rag/documents")
async def get_documents():
    return rag_manager.get_documents()


@router.get("/rag/documents/{doc_id}")
async def get_document_content(doc_id: str):
    text = rag_manager.get_document_text(doc_id)
    if not text or text == "Text not found.":
        raise HTTPException(status_code=404, detail="Document text not found")
    return {"id": doc_id, "text": text}


@router.delete("/rag/documents/{doc_id}")
async def delete_document(doc_id: str):
    if rag_manager.delete_document(doc_id):
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Document not found")


@router.get("/agents/{agent_id}")
async def get_custom_agent(agent_id: str):
    agent = agent_manager.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.post("/agents")
async def create_custom_agent(agent_data: dict):
    agent = agent_manager.create_agent(agent_data)
    return agent


@router.put("/agents/{agent_id}")
async def update_custom_agent(agent_id: str, agent_data: dict):
    agent = agent_manager.update_agent(agent_id, agent_data)
    return agent


@router.delete("/agents/{agent_id}")
async def delete_custom_agent(agent_id: str):
    agent_manager.delete_agent(agent_id)
    return {"status": "success"}


# --- Security Scans ---
from security.scan_repository import scan_repository


@router.get("/scans")
async def get_security_scans():
    return {"scans": scan_repository.get_all_scans()}


@router.delete("/scans/{scan_id}")
async def delete_security_scan(scan_id: str):
    if scan_repository.delete_scan(scan_id):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Scan not found")


@router.post("/scans/compare")
async def compare_scans(body: dict):
    scan1_id = body.get("scan1_id")
    scan2_id = body.get("scan2_id")
    if not scan1_id or not scan2_id:
        raise HTTPException(status_code=400, detail="Missing scan IDs")

    scan1 = scan_repository.get_scan(scan1_id)
    scan2 = scan_repository.get_scan(scan2_id)

    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    # Generate delta: new vulnerabilities vs resolved ones
    s1_findings = {f["title"]: f for f in scan1["findings"]}
    s2_findings = {f["title"]: f for f in scan2["findings"]}

    resolved = [f for title, f in s1_findings.items() if title not in s2_findings]
    new_vulns = [f for title, f in s2_findings.items() if title not in s1_findings]
    persistent = [f for title, f in s2_findings.items() if title in s1_findings]

    return {
        "scan1": scan1,
        "scan2": scan2,
        "comparison": {
            "resolved": resolved,
            "new_vulnerabilities": new_vulns,
            "persistent": persistent,
            "score_delta": scan2["risk_score"] - scan1["risk_score"]
        }
    }


# --- Dashboard Agents (Tracking) ---
from security.dashboard_repository import dashboard_repository


@router.get("/dashboard-agents")
async def get_dashboard_agents():
    return dashboard_repository.get_all_agents()


@router.get("/dashboard-agents-enriched")
async def get_dashboard_agents_enriched():
    """Return dashboard agents enriched with real metrics from their latest scans."""
    from security.scan_repository import scan_repository
    agents = dashboard_repository.get_all_agents()
    all_scans = scan_repository.get_all_scans()

    enriched = []
    for agent in agents:
        agent_enriched = dict(agent)

        # Find the latest matching scan
        expected_type = "mcp" if (agent.get("agent_type") or "").lower() == "mcp" else "agent"
        matching_scans = [
            s for s in all_scans
            if dashboard_repository._scan_matches_agent(s, agent)
        ]
        matching_scans.sort(key=lambda s: s.get("created_at", ""), reverse=True)
        scan_count = len(matching_scans)
        latest = matching_scans[0] if matching_scans else None

        agent_enriched["total_scans"] = scan_count

        # Build score history from all matching scans (newest first, take last 10)
        score_history = []
        for s in matching_scans[:10]:
            r = s.get("report") or {}
            sc = r.get("security_score")
            if sc is None:
                sc = s.get("risk_score")
            if sc is not None:
                score_history.append({
                    "score": sc,
                    "date": s.get("created_at", ""),
                })
        score_history.reverse()  # oldest first for sparkline
        agent_enriched["score_history"] = score_history

        if latest and latest.get("report"):
            report = latest["report"]
            summary = report.get("summary", {})

            agent_enriched["summary"] = summary
            agent_enriched["grade"] = report.get("grade")
            agent_enriched["security_score"] = report.get("security_score")
            agent_enriched["findings_count"] = summary.get("total_findings", 0)

            if expected_type == "mcp":
                mcp_scores = report.get("mcp_scores", {})
                agent_enriched["dimension_scores"] = {
                    "tool_security": mcp_scores.get("tool_security", 0),
                    "prompt_security": mcp_scores.get("prompt_security", 0),
                    "authentication": mcp_scores.get("authentication", 0),
                    "resource_security": mcp_scores.get("resource_security", 0),
                    "data_leakage": mcp_scores.get("data_leakage", 0),
                }
                disc = report.get("discovery", {})
                agent_enriched["tools_count"] = disc.get("tools_count", 0)
                agent_enriched["resources_count"] = disc.get("resources_count", 0)
                agent_enriched["prompts_count"] = disc.get("prompts_count", 0)
                agent_enriched["exposed_tools"] = disc.get("exposed_tools", [])[:8]
                agent_enriched["exposed_prompts"] = disc.get("exposed_prompts", [])[:5]
                agent_enriched["description"] = report.get("agent_name") or agent.get("name", "")
                agent_enriched["fetch_time_ms"] = report.get("fetch_time_ms")
                # security capabilities
                agent_enriched["capabilities"] = {
                    "has_governance": report.get("has_governance", False),
                    "has_rate_limiting": report.get("has_rate_limiting", False),
                    "has_replay_guard": report.get("has_replay_guard", False),
                    "has_zkp": report.get("has_zkp", False),
                    "has_quorum": report.get("has_quorum", False),
                }
            else:
                agent_scores = report.get("agent_scores", {})
                agent_enriched["dimension_scores"] = {
                    "identity_auth": agent_scores.get("identity_auth", 0),
                    "governance_policy": agent_scores.get("governance_policy", 0),
                    "prompt_resilience": agent_scores.get("prompt_resilience", 0),
                    "privilege_routing": agent_scores.get("privilege_routing", 0),
                    "threat_mitigation": agent_scores.get("threat_mitigation", 0),
                }
                agent_enriched["description"] = report.get("agent_description") or report.get(
                    "agent_name") or agent.get("name", "")
                agent_enriched["agent_version"] = report.get("agent_version")
                agent_enriched["skills_count"] = report.get("skills_count", 0)
                agent_enriched["extensions_count"] = report.get("extensions_count", 0)
                agent_enriched["fetch_time_ms"] = report.get("scan_time_ms") or report.get("fetch_time_ms")
                agent_enriched["capabilities"] = {
                    "has_authentication": report.get("has_authentication", False),
                    "has_governance": report.get("has_governance", False),
                    "has_rate_limiting": report.get("has_rate_limiting", False),
                    "has_replay_guard": report.get("has_replay_guard", False),
                    "has_zkp": report.get("has_zkp", False),
                    "has_quorum": report.get("has_quorum", False),
                }
        else:
            agent_enriched["dimension_scores"] = {}
            agent_enriched["summary"] = {}
            agent_enriched["grade"] = None
            agent_enriched["security_score"] = None
            agent_enriched["description"] = None
            agent_enriched["findings_count"] = 0
            agent_enriched["capabilities"] = {}

        enriched.append(agent_enriched)

    return enriched


@router.get("/dashboard-overview")
async def get_dashboard_overview():
    """Compute real aggregate security overview from all stored scans."""
    from security.scan_repository import scan_repository
    from datetime import datetime, timezone, timedelta
    from collections import defaultdict

    agents = dashboard_repository.get_all_agents()
    all_scans = scan_repository.get_all_scans()

    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)

    # --- Aggregate findings from all scans ---
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_findings = 0
    a2a_scores = []
    mcp_scores = []
    all_scores = []
    scans_this_week = 0

    # Group scans by date for trend
    scan_trend = defaultdict(lambda: {"a2a_scan": 0, "mcp_scan": 0})

    for scan in all_scans:
        report = scan.get("report") or {}
        summary = report.get("summary", {})
        scan_type = scan.get("scan_type", "agent")
        created_at = scan.get("created_at", "")

        for sev in severity_totals:
            severity_totals[sev] += summary.get(sev, 0)
        total_findings += summary.get("total_findings", 0)

        sc = report.get("security_score")
        if sc is None:
            sc = scan.get("risk_score")
        if sc is not None:
            all_scores.append(sc)
            if scan_type == "mcp":
                mcp_scores.append(sc)
            else:
                a2a_scores.append(sc)

        # Check if scan is from this week
        try:
            scan_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            if scan_dt >= week_ago:
                scans_this_week += 1
            date_key = scan_dt.strftime("%m/%d")
            if scan_type == "mcp":
                scan_trend[date_key]["mcp_scan"] += 1
            else:
                scan_trend[date_key]["a2a_scan"] += 1
        except (ValueError, TypeError):
            pass

    # Risk Score
    avg_score = round(sum(all_scores) / len(all_scores)) if all_scores else 0
    avg_a2a = round(sum(a2a_scores) / len(a2a_scores)) if a2a_scores else 0
    avg_mcp = round(sum(mcp_scores) / len(mcp_scores)) if mcp_scores else 0

    if avg_score >= 90:
        grade = "A"
    elif avg_score >= 75:
        grade = "B"
    elif avg_score >= 60:
        grade = "C"
    elif avg_score >= 40:
        grade = "D"
    else:
        grade = "F"

    # Sparkline: take last 7 distinct score values
    recent_scores = [s for s in all_scores[-7:]] if len(all_scores) > 0 else [0]

    # Partition agents
    a2a_agents = [a for a in agents if
                  (a.get("agent_type") or "").lower() != "mcp" and not str(a.get("agent_id", "")).startswith(
                      "default-")]
    mcp_agents = [a for a in agents if
                  (a.get("agent_type") or "").lower() == "mcp" and not str(a.get("agent_id", "")).startswith(
                      "default-")]

    # Trend data: sorted by date
    trend_data = []
    for date_key in sorted(scan_trend.keys()):
        trend_data.append({
            "date": date_key,
            "a2a_scan": scan_trend[date_key]["a2a_scan"],
            "mcp_scan": scan_trend[date_key]["mcp_scan"],
        })

    # Findings breakdown per severity with cumulative counts from all scans
    total_with_findings = sum(severity_totals.values())
    triaged = severity_totals.get("info", 0)
    triaged_pct = round((triaged / total_with_findings) * 100) if total_with_findings > 0 else 0

    # Finding categories count (distinct types)
    finding_types = set()
    for scan in all_scans:
        report = scan.get("report") or {}
        for f in report.get("findings", []):
            title = f.get("title") or f.get("category", "")
            if title:
                finding_types.add(title)
        for f in report.get("red_team_findings", []):
            title = f.get("title") or f.get("category", "")
            if title:
                finding_types.add(title)

    # Alert density
    total_tracked = len(a2a_agents) + len(mcp_agents)
    alert_density = round(total_findings / total_tracked, 1) if total_tracked > 0 else 0

    return {
        "risk_score": {
            "grade": grade,
            "score": avg_score,
            "sparkline": recent_scores,
            "a2a_score": avg_a2a,
            "mcp_score": avg_mcp,
        },
        "open_findings": {
            "types": len(finding_types),
            "total": total_findings,
            "triaged_percent": triaged_pct,
            "severities": [
                {"label": "Critical", "count": severity_totals["critical"], "color": "#7f1d1d"},
                {"label": "High", "count": severity_totals["high"], "color": "#dc2626"},
                {"label": "Medium", "count": severity_totals["medium"], "color": "#f97316"},
                {"label": "Low", "count": severity_totals["low"], "color": "#eab308"},
                {"label": "Info", "count": severity_totals["info"], "color": "#38bdf8"},
            ],
        },
        "trend_data": trend_data,
        "fleet_metrics": {
            "tracked_agents": len(a2a_agents),
            "mcp_nodes": len(mcp_agents),
            "total_scans": len(all_scans),
            "scans_this_week": scans_this_week,
            "avg_score": avg_score,
            "critical_findings": severity_totals["critical"],
            "alert_density": alert_density,
        },
        "fleet_breakdown": {
            "a2a_count": len(a2a_agents),
            "mcp_count": len(mcp_agents),
        },
    }


@router.post("/dashboard-agents")
async def add_or_update_dashboard_agent(body: dict):
    agent_id = body.get("agent_id")
    name = body.get("name")
    url = body.get("url")
    interval = body.get("scan_interval_minutes", 0)
    agent_type = body.get("agent_type", "a2a")

    if agent_id:
        dashboard_repository.update_agent_interval(agent_id, interval)
        return {"status": "success", "agent_id": agent_id}
    else:
        if not name or not url:
            raise HTTPException(status_code=400, detail="Missing name or url")
        new_id = dashboard_repository.add_agent(name, url, interval, agent_type)
        return {"status": "success", "agent_id": new_id}


@router.delete("/dashboard-agents/{agent_id}")
async def delete_dashboard_agent(agent_id: str):
    dashboard_repository.remove_agent(agent_id)
    return {"status": "success"}


# --- DeepTeam Red Teaming ---
import glob
import os
import json


@router.post("/deepteam/scan/{agent_id}")
async def run_deepteam_scan(agent_id: str):
    from security.deepteam_scanner import run_redteam_scan
    from security.agent_manager import agent_manager
    from main import audit_logger

    agent = agent_manager.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    try:
        result = await run_redteam_scan(
            agent_id=agent_id,
            agent_name=agent["name"],
            audit_logger=audit_logger
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/deepteam/results")
async def get_deepteam_results():
    results = []
    for filepath in glob.glob("deepteam-results/*.json"):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                # Just return summary for listing
                results.append({
                    "id": os.path.basename(filepath),
                    "file": filepath,
                    "target_purpose": data.get("target_purpose", ""),
                    "timestamp": os.path.getmtime(filepath)
                })
        except:
            pass
    return sorted(results, key=lambda x: x["timestamp"], reverse=True)


@router.get("/scanners/a2a-urls")
async def get_a2a_urls():
    try:
        with open("configs/a2a_url.json", "r") as f:
            return json.load(f)
    except:
        return []


@router.get("/scanners/mcp-urls")
async def get_mcp_urls():
    try:
        with open("configs/mcp_url.json", "r") as f:
            return json.load(f)
    except:
        return []


# --- MCP Builder Routes ---
from security.mcp_manager import mcp_manager


@router.get("/mcps")
async def get_all_mcps():
    return mcp_manager.get_all_mcps()


@router.get("/mcps/{mcp_id}")
async def get_mcp(mcp_id: str):
    mcp = mcp_manager.get_mcp(mcp_id)
    if not mcp:
        raise HTTPException(status_code=404, detail="MCP not found")
    return mcp


@router.post("/mcps")
async def create_mcp(mcp_data: dict):
    return mcp_manager.create_mcp(mcp_data)


@router.put("/mcps/{mcp_id}")
async def update_mcp(mcp_id: str, mcp_data: dict):
    return mcp_manager.update_mcp(mcp_id, mcp_data)


@router.delete("/mcps/{mcp_id}")
async def delete_mcp(mcp_id: str):
    mcp_manager.delete_mcp(mcp_id)
    return {"status": "success"}
