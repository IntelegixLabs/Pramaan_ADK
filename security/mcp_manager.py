import json
import uuid
import os
from typing import Optional, List, Dict, Any
from security.db import db

def _get_backend_base() -> str:
    return (
        os.getenv("BACKEND_URL")
        or os.getenv("API_BASE_URL")
        or os.getenv("VITE_PROXY_URL_BASE")
        or "http://localhost:8200"
    ).rstrip("/")


DEFAULT_MCPS = [
    {
        "id": "mcp-github-1",
        "name": "GitHub Copilot MCP",
        "description": "Default configuration for GitHub Copilot MCP Server.",
        "server_url": "https://api.githubcopilot.com/mcp/",
        "proxy_url": f"{_get_backend_base()}/mcp-proxy/mcp-github-1",
        "auth_type": "Bearer",
        "auth_token": "",
        "environment": "Production",
        "status": "ACTIVE",
        "risk_tier": "MEDIUM",
        "allowed_tools": [],
        "allowed_resources": [],
        "allowed_prompts": [],
        "owner": "System",
        "is_hosted": False,
        "script_content": "",
        "hosted_tools": [],
        "hosted_resources": [],
        "hosted_prompts": [],
        "is_default": True
    }
]


class MCPManager:
    def __init__(self, db_path=None):
        db.initialize()

    def _format_mcp_record(self, r: dict) -> dict:
        mcp = dict(r)
        mcp['tools'] = json.loads(mcp['tools']) if mcp.get('tools') else []
        mcp['resources'] = json.loads(mcp['resources']) if mcp.get('resources') else []
        mcp['prompts'] = json.loads(mcp['prompts']) if mcp.get('prompts') else []
        mcp['allowed_tools'] = mcp['tools']
        mcp['allowed_resources'] = mcp['resources']
        mcp['allowed_prompts'] = mcp['prompts']
        mcp['hosted_tools'] = mcp.get('hosted_tools') or mcp['tools']
        mcp['hosted_resources'] = mcp.get('hosted_resources') or mcp['resources']
        mcp['hosted_prompts'] = mcp.get('hosted_prompts') or mcp['prompts']
        mcp['is_default'] = False
        mcp['status'] = mcp.get('status') or 'ACTIVE'
        mcp['auth_type'] = mcp.get('auth_type') or 'None'
        mcp['environment'] = mcp.get('environment') or 'Production'
        mcp['risk_tier'] = mcp.get('risk_tier') or 'LOW'
        mcp['proxy_url'] = f"{_get_backend_base()}/mcp-proxy/{mcp['id']}"
        mcp['is_hosted'] = mcp.get('transport') == 'python' or bool(mcp.get('tools') and any(isinstance(t, dict) and t.get('code') for t in mcp['tools']))
        return mcp

    def get_all_mcps(self, user_id: Optional[str] = None):
        if user_id:
            rows = db.fetchall('SELECT * FROM custom_mcps WHERE user_id = ? OR user_id IS NULL', (user_id,))
        else:
            rows = db.fetchall('SELECT * FROM custom_mcps')
            
        mcps = [self._format_mcp_record(r) for r in rows]
        return DEFAULT_MCPS + mcps

    def get_mcp(self, mcp_id: str, user_id: Optional[str] = None):
        for default_mcp in DEFAULT_MCPS:
            if default_mcp['id'] == mcp_id:
                return default_mcp

        if user_id:
            row = db.fetchone('SELECT * FROM custom_mcps WHERE id = ? AND (user_id = ? OR user_id IS NULL)', (mcp_id, user_id))
        else:
            row = db.fetchone('SELECT * FROM custom_mcps WHERE id = ?', (mcp_id,))
            
        if not row:
            return None
            
        return self._format_mcp_record(row)

    def create_mcp(self, mcp_data: dict, user_id: Optional[str] = None):
        mcp_id = str(uuid.uuid4())
        tools = mcp_data.get('tools') or mcp_data.get('allowed_tools') or []
        resources = mcp_data.get('resources') or mcp_data.get('allowed_resources') or []
        prompts = mcp_data.get('prompts') or mcp_data.get('allowed_prompts') or []

        db.execute('''
            INSERT INTO custom_mcps (
                id, name, description, server_url, transport, tools, resources, prompts, user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            mcp_id,
            mcp_data.get('name', 'Custom MCP Server'),
            mcp_data.get('description', ''),
            mcp_data.get('server_url', ''),
            mcp_data.get('transport', 'stdio'),
            json.dumps(tools),
            json.dumps(resources),
            json.dumps(prompts),
            user_id or mcp_data.get('user_id')
        ))

        return self.get_mcp(mcp_id, user_id)

    def update_mcp(self, mcp_id: str, mcp_data: dict, user_id: Optional[str] = None):
        tools = mcp_data.get('tools') or mcp_data.get('allowed_tools') or []
        resources = mcp_data.get('resources') or mcp_data.get('allowed_resources') or []
        prompts = mcp_data.get('prompts') or mcp_data.get('allowed_prompts') or []

        query = '''
            UPDATE custom_mcps 
            SET name = ?, description = ?, server_url = ?, transport = ?, tools = ?, resources = ?, prompts = ?
            WHERE id = ?
        '''
        params = [
            mcp_data.get('name'),
            mcp_data.get('description'),
            mcp_data.get('server_url'),
            mcp_data.get('transport', 'stdio'),
            json.dumps(tools),
            json.dumps(resources),
            json.dumps(prompts),
            mcp_id
        ]
        if user_id:
            query += ' AND (user_id = ? OR user_id IS NULL)'
            params.append(user_id)

        db.execute(query, tuple(params))
        return self.get_mcp(mcp_id, user_id)

    def delete_mcp(self, mcp_id: str, user_id: Optional[str] = None):
        if user_id:
            db.execute('DELETE FROM custom_mcps WHERE id = ? AND (user_id = ? OR user_id IS NULL)', (mcp_id, user_id))
        else:
            db.execute('DELETE FROM custom_mcps WHERE id = ?', (mcp_id,))
        return True


mcp_manager = MCPManager()
