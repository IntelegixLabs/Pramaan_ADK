import sqlite3
import json
import uuid
import os
from typing import Optional, List, Dict, Any

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/handshakeos.db"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "handshakeos.db")

DEFAULT_MCPS = [
    {
        "id": "mcp-github-1",
        "name": "GitHub Copilot MCP",
        "description": "Default configuration for GitHub Copilot MCP Server.",
        "server_url": "https://api.githubcopilot.com/mcp/",
        "proxy_url": "http://localhost:8200/mcp-proxy/mcp-github-1",
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
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mcp_servers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    owner TEXT,
                    server_url TEXT,
                    proxy_url TEXT,
                    auth_type TEXT,
                    auth_token TEXT,
                    environment TEXT,
                    status TEXT,
                    risk_tier TEXT,
                    allowed_tools TEXT,
                    allowed_resources TEXT,
                    is_hosted BOOLEAN DEFAULT 0,
                    script_content TEXT,
                    allowed_prompts TEXT
                )
            ''')
            columns_to_add = [
                ('allowed_prompts', 'TEXT'),
                ('owner', 'TEXT'),
                ('is_hosted', 'BOOLEAN DEFAULT 0'),
                ('script_content', 'TEXT'),
                ('hosted_tools', 'TEXT'),
                ('hosted_resources', 'TEXT'),
                ('hosted_prompts', 'TEXT'),
                ('user_id', 'TEXT')
            ]
            for col_name, col_type in columns_to_add:
                try:
                    cursor.execute(f'ALTER TABLE mcp_servers ADD COLUMN {col_name} {col_type}')
                except sqlite3.OperationalError:
                    pass
            conn.commit()

    def get_all_mcps(self, user_id: Optional[str] = None):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if user_id:
                cursor.execute('SELECT * FROM mcp_servers WHERE user_id = ? OR user_id IS NULL', (user_id,))
            else:
                cursor.execute('SELECT * FROM mcp_servers')
            mcps = [dict(row) for row in cursor.fetchall()]
            for mcp in mcps:
                mcp['allowed_tools'] = json.loads(mcp['allowed_tools']) if mcp.get('allowed_tools') else []
                mcp['allowed_resources'] = json.loads(mcp['allowed_resources']) if mcp.get('allowed_resources') else []
                mcp['allowed_prompts'] = json.loads(mcp['allowed_prompts']) if mcp.get('allowed_prompts') else []
                mcp['hosted_tools'] = json.loads(mcp['hosted_tools']) if mcp.get('hosted_tools') else []
                mcp['hosted_resources'] = json.loads(mcp['hosted_resources']) if mcp.get('hosted_resources') else []
                mcp['hosted_prompts'] = json.loads(mcp['hosted_prompts']) if mcp.get('hosted_prompts') else []
                mcp['is_hosted'] = bool(mcp.get('is_hosted', False))
                mcp['is_default'] = False

            # Prepend default MCPs
            return DEFAULT_MCPS + mcps

    def get_mcp(self, mcp_id: str, user_id: Optional[str] = None):
        # Check defaults first
        for default_mcp in DEFAULT_MCPS:
            if default_mcp['id'] == mcp_id:
                return default_mcp

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if user_id:
                cursor.execute('SELECT * FROM mcp_servers WHERE id = ? AND (user_id = ? OR user_id IS NULL)', (mcp_id, user_id))
            else:
                cursor.execute('SELECT * FROM mcp_servers WHERE id = ?', (mcp_id,))
            row = cursor.fetchone()
            if not row:
                return None
            mcp = dict(row)
            if mcp:
                mcp['allowed_tools'] = json.loads(mcp['allowed_tools']) if mcp.get('allowed_tools') else []
                mcp['allowed_resources'] = json.loads(mcp['allowed_resources']) if mcp.get('allowed_resources') else []
                mcp['allowed_prompts'] = json.loads(mcp['allowed_prompts']) if mcp.get('allowed_prompts') else []
                mcp['hosted_tools'] = json.loads(mcp['hosted_tools']) if mcp.get('hosted_tools') else []
                mcp['hosted_resources'] = json.loads(mcp['hosted_resources']) if mcp.get('hosted_resources') else []
                mcp['hosted_prompts'] = json.loads(mcp['hosted_prompts']) if mcp.get('hosted_prompts') else []
                mcp['is_hosted'] = bool(mcp.get('is_hosted', False))
                mcp['is_default'] = False
                return dict(mcp)

    def _save_hosted_script(self, mcp_id: str, mcp_data: dict):
        import os
        script_path = os.path.join(os.path.dirname(__file__), '..', 'hosted_mcps', f"{mcp_id}.py")
        is_hosted = bool(mcp_data.get('is_hosted', False))

        if is_hosted:
            # Dynamically generate the FastMCP script
            script = "from mcp.server.fastmcp import FastMCP, Context\nimport asyncio\n\n"
            script += f"mcp = FastMCP(\"{mcp_data.get('name', 'HostedServer')}\")\n\n"

            for tool in mcp_data.get('hosted_tools', []):
                desc = tool.get('description', '') or ''
                script += f"@mcp.tool(description={desc!r})\n" if desc else "@mcp.tool()\n"
                script += tool.get('code', '') + "\n\n"

            for resource in mcp_data.get('hosted_resources', []):
                uri = resource.get('name', '') or ''
                desc = resource.get('description', '') or ''
                if desc:
                    script += f"@mcp.resource({uri!r}, description={desc!r})\n"
                else:
                    script += f"@mcp.resource({uri!r})\n"
                script += resource.get('code', '') + "\n\n"

            for prompt in mcp_data.get('hosted_prompts', []):
                desc = prompt.get('description', '') or ''
                script += f"@mcp.prompt(description={desc!r})\n" if desc else "@mcp.prompt()\n"
                script += prompt.get('code', '') + "\n\n"

            script += "if __name__ == \"__main__\":\n"
            script += "    mcp.run(transport=\"stdio\")\n"

            os.makedirs(os.path.dirname(script_path), exist_ok=True)
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script)

            # Save the generated script back to mcp_data so it gets saved in DB if needed
            mcp_data['script_content'] = script
        else:
            if os.path.exists(script_path):
                os.remove(script_path)

    def create_mcp(self, mcp_data: dict, user_id: Optional[str] = None):
        mcp_id = str(uuid.uuid4())
        # Generate custom proxy URL based on ID
        proxy_url = f"http://localhost:8200/mcp-proxy/{mcp_id}"

        self._save_hosted_script(mcp_id, mcp_data)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO mcp_servers (
                    id, name, description, owner, server_url, proxy_url, auth_type, auth_token, environment, status, risk_tier, allowed_tools, allowed_resources, allowed_prompts, is_hosted, script_content, hosted_tools, hosted_resources, hosted_prompts, user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                mcp_id,
                mcp_data.get('name', 'Custom MCP Server'),
                mcp_data.get('description', ''),
                mcp_data.get('owner', ''),
                mcp_data.get('server_url', ''),
                proxy_url,
                mcp_data.get('auth_type', 'None'),
                mcp_data.get('auth_token', ''),
                mcp_data.get('environment', 'Production'),
                mcp_data.get('status', 'ACTIVE'),
                mcp_data.get('risk_tier', 'LOW'),
                json.dumps(mcp_data.get('allowed_tools', [])),
                json.dumps(mcp_data.get('allowed_resources', [])),
                json.dumps(mcp_data.get('allowed_prompts', [])),
                bool(mcp_data.get('is_hosted', False)),
                mcp_data.get('script_content', ''),
                json.dumps(mcp_data.get('hosted_tools', [])),
                json.dumps(mcp_data.get('hosted_resources', [])),
                json.dumps(mcp_data.get('hosted_prompts', [])),
                user_id or mcp_data.get('user_id')
            ))
            conn.commit()

        return self.get_mcp(mcp_id, user_id)

    def update_mcp(self, mcp_id: str, mcp_data: dict, user_id: Optional[str] = None):
        self._save_hosted_script(mcp_id, mcp_data)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            query = '''
                UPDATE mcp_servers 
                SET name = ?, description = ?, owner = ?, server_url = ?, auth_type = ?, auth_token = ?, environment = ?, status = ?, risk_tier = ?, allowed_tools = ?, allowed_resources = ?, allowed_prompts = ?, is_hosted = ?, script_content = ?, hosted_tools = ?, hosted_resources = ?, hosted_prompts = ?
                WHERE id = ?
            '''
            params = [
                mcp_data.get('name'),
                mcp_data.get('description'),
                mcp_data.get('owner'),
                mcp_data.get('server_url'),
                mcp_data.get('auth_type'),
                mcp_data.get('auth_token'),
                mcp_data.get('environment'),
                mcp_data.get('status'),
                mcp_data.get('risk_tier'),
                json.dumps(mcp_data.get('allowed_tools', [])),
                json.dumps(mcp_data.get('allowed_resources', [])),
                json.dumps(mcp_data.get('allowed_prompts', [])),
                bool(mcp_data.get('is_hosted', False)),
                mcp_data.get('script_content', ''),
                json.dumps(mcp_data.get('hosted_tools', [])),
                json.dumps(mcp_data.get('hosted_resources', [])),
                json.dumps(mcp_data.get('hosted_prompts', [])),
                mcp_id
            ]
            if user_id:
                query += ' AND (user_id = ? OR user_id IS NULL)'
                params.append(user_id)

            cursor.execute(query, tuple(params))
            conn.commit()

        return self.get_mcp(mcp_id, user_id)

    def delete_mcp(self, mcp_id: str, user_id: Optional[str] = None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute('DELETE FROM mcp_servers WHERE id = ? AND (user_id = ? OR user_id IS NULL)', (mcp_id, user_id))
            else:
                cursor.execute('DELETE FROM mcp_servers WHERE id = ?', (mcp_id,))
            conn.commit()

        import os
        script_path = os.path.join(os.path.dirname(__file__), '..', 'hosted_mcps', f"{mcp_id}.py")
        if os.path.exists(script_path):
            os.remove(script_path)

        return True


mcp_manager = MCPManager()
