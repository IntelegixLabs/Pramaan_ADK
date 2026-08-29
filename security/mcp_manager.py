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

    def _extract_capabilities(self, mcp_data: dict):
        is_hosted = mcp_data.get('is_hosted', False) or mcp_data.get('transport') == 'python'
        
        if is_hosted:
            tools = mcp_data.get('hosted_tools') if mcp_data.get('hosted_tools') is not None else (mcp_data.get('tools') or [])
            resources = mcp_data.get('hosted_resources') if mcp_data.get('hosted_resources') is not None else (mcp_data.get('resources') or [])
            prompts = mcp_data.get('hosted_prompts') if mcp_data.get('hosted_prompts') is not None else (mcp_data.get('prompts') or [])
            transport = 'python'
        else:
            tools = mcp_data.get('allowed_tools') if mcp_data.get('allowed_tools') is not None else (mcp_data.get('tools') or [])
            resources = mcp_data.get('allowed_resources') if mcp_data.get('allowed_resources') is not None else (mcp_data.get('resources') or [])
            prompts = mcp_data.get('allowed_prompts') if mcp_data.get('allowed_prompts') is not None else (mcp_data.get('prompts') or [])
            transport = mcp_data.get('transport') or 'sse'

        return transport, tools or [], resources or [], prompts or []

    def _format_mcp_record(self, r: dict) -> dict:
        mcp = dict(r)
        tools = json.loads(mcp['tools']) if mcp.get('tools') else []
        resources = json.loads(mcp['resources']) if mcp.get('resources') else []
        prompts = json.loads(mcp['prompts']) if mcp.get('prompts') else []

        is_hosted = (
            mcp.get('transport') == 'python'
            or any(isinstance(t, dict) and ('code' in t or 'name' in t) for t in tools)
            or any(isinstance(res, dict) and ('code' in res or 'name' in res) for res in resources)
            or any(isinstance(p, dict) and ('code' in p or 'name' in p) for p in prompts)
        )

        mcp['tools'] = tools
        mcp['resources'] = resources
        mcp['prompts'] = prompts

        mcp['hosted_tools'] = tools if is_hosted else []
        mcp['hosted_resources'] = resources if is_hosted else []
        mcp['hosted_prompts'] = prompts if is_hosted else []

        mcp['allowed_tools'] = [t if isinstance(t, str) else t.get('name', '') for t in tools] if not is_hosted else []
        mcp['allowed_resources'] = [res if isinstance(res, str) else res.get('name', '') for res in resources] if not is_hosted else []
        mcp['allowed_prompts'] = [p if isinstance(p, str) else p.get('name', '') for p in prompts] if not is_hosted else []

        mcp['is_hosted'] = is_hosted
        mcp['is_default'] = False
        mcp['status'] = mcp.get('status') or 'ACTIVE'
        mcp['auth_type'] = mcp.get('auth_type') or 'None'
        mcp['environment'] = mcp.get('environment') or 'Production'
        mcp['risk_tier'] = mcp.get('risk_tier') or 'LOW'
        mcp['proxy_url'] = f"{_get_backend_base()}/mcp-proxy/{mcp['id']}"
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
        transport, tools, resources, prompts = self._extract_capabilities(mcp_data)

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
            transport,
            json.dumps(tools),
            json.dumps(resources),
            json.dumps(prompts),
            user_id or mcp_data.get('user_id')
        ))

        return self.get_mcp(mcp_id, user_id)

    def update_mcp(self, mcp_id: str, mcp_data: dict, user_id: Optional[str] = None):
        transport, tools, resources, prompts = self._extract_capabilities(mcp_data)

        query = '''
            UPDATE custom_mcps 
            SET name = ?, description = ?, server_url = ?, transport = ?, tools = ?, resources = ?, prompts = ?
            WHERE id = ?
        '''
        params = [
            mcp_data.get('name'),
            mcp_data.get('description'),
            mcp_data.get('server_url'),
            transport,
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
