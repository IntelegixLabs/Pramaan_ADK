import json
import uuid
from typing import Optional, List, Dict, Any
from security.db import db

DEFAULT_AGENTS = [
    {
        "id": "default-hr",
        "name": "HR Agent",
        "description": "Manages employee relocation, salary negotiations, and contract generation.",
        "system_prompt": "You are the HR Agent. You handle employee relocations and salary negotiations. Always enforce geographic limits and salary caps.",
        "policies": {"geographic_limits": True, "salary_cap_enforcement": True},
        "max_budget": 50,
        "is_default": True,
        "tools": [
            {
                "id": "tool-hr-1",
                "name": "calculate_relocation_budget",
                "description": "Calculates the relocation budget based on distance and employee tier.",
                "code": "# Pre-configured core tool\ndef calculate_relocation_budget(tier: str, distance_km: int) -> float:\n    pass"
            }
        ]
    },
    {
        "id": "default-finance",
        "name": "Finance Agent",
        "description": "Handles corporate disbursements, wire transfers, and budget approvals.",
        "system_prompt": "You are the Finance Agent. You execute disbursements upon verifying trust receipts and PoA quorums.",
        "policies": {"require_poa_quorum": True, "verify_trust_receipts": True},
        "max_budget": 1000,
        "is_default": True,
        "tools": [
            {
                "id": "tool-fin-1",
                "name": "execute_wire_transfer",
                "description": "Executes a wire transfer to a specified account after validation.",
                "code": "# Pre-configured core tool\ndef execute_wire_transfer(amount: float, account: str) -> bool:\n    pass"
            }
        ]
    }
]

class AgentManager:
    def __init__(self, db_path=None):
        db.initialize()

    def get_all_agents(self, user_id: Optional[str] = None):
        if user_id:
            rows = db.fetchall('SELECT * FROM custom_agents WHERE user_id = ? OR user_id IS NULL', (user_id,))
        else:
            rows = db.fetchall('SELECT * FROM custom_agents')
            
        agents = []
        for r in rows:
            agent = dict(r)
            agent['policies'] = json.loads(agent['policies']) if agent.get('policies') else {}
            agent['mcp_server_urls'] = json.loads(agent['mcp_server_urls']) if agent.get('mcp_server_urls') else []
            agent['a2a_agent_urls'] = json.loads(agent['a2a_agent_urls']) if agent.get('a2a_agent_urls') else []
            agent['allowed_tools'] = json.loads(agent['allowed_tools']) if agent.get('allowed_tools') else []
            agent['denied_tools'] = json.loads(agent['denied_tools']) if agent.get('denied_tools') else []
            agent['human_review_tools'] = json.loads(agent['human_review_tools']) if agent.get('human_review_tools') else []
            agent['tools'] = json.loads(agent['tools']) if agent.get('tools') else []
            agent['is_default'] = False
            agents.append(agent)
        
        # Prepend default agents
        return DEFAULT_AGENTS + agents

    def get_agent(self, agent_id: str, user_id: Optional[str] = None):
        for default_agent in DEFAULT_AGENTS:
            if default_agent['id'] == agent_id:
                return default_agent

        if user_id:
            row = db.fetchone('SELECT * FROM custom_agents WHERE id = ? AND (user_id = ? OR user_id IS NULL)', (agent_id, user_id))
        else:
            row = db.fetchone('SELECT * FROM custom_agents WHERE id = ?', (agent_id,))
            
        if not row:
            return None
            
        agent = dict(row)
        agent['policies'] = json.loads(agent['policies']) if agent.get('policies') else {}
        agent['mcp_server_urls'] = json.loads(agent['mcp_server_urls']) if agent.get('mcp_server_urls') else []
        agent['a2a_agent_urls'] = json.loads(agent['a2a_agent_urls']) if agent.get('a2a_agent_urls') else []
        agent['allowed_tools'] = json.loads(agent['allowed_tools']) if agent.get('allowed_tools') else []
        agent['denied_tools'] = json.loads(agent['denied_tools']) if agent.get('denied_tools') else []
        agent['human_review_tools'] = json.loads(agent['human_review_tools']) if agent.get('human_review_tools') else []
        agent['tools'] = json.loads(agent['tools']) if agent.get('tools') else []
        agent['is_default'] = False
        return agent

    def create_agent(self, agent_data: dict, user_id: Optional[str] = None):
        agent_id = str(uuid.uuid4())
        tools = agent_data.get('tools', [])
        for tool in tools:
            if not tool.get('id'):
                tool['id'] = str(uuid.uuid4())

        db.execute('''
            INSERT INTO custom_agents (
                id, name, description, system_prompt, policies, max_budget, tools, mcp_server_urls, a2a_agent_urls,
                user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            agent_id,
            agent_data.get('name', 'Custom Agent'),
            agent_data.get('description', ''),
            agent_data.get('system_prompt', 'You are a helpful assistant.'),
            json.dumps(agent_data.get('policies', {})),
            agent_data.get('max_budget', 10),
            json.dumps(tools),
            json.dumps(agent_data.get('mcp_server_urls', [])),
            json.dumps(agent_data.get('a2a_agent_urls', [])),
            user_id or agent_data.get('user_id')
        ))
        return self.get_agent(agent_id, user_id)

    def update_agent(self, agent_id: str, agent_data: dict, user_id: Optional[str] = None):
        tools = agent_data.get('tools', [])
        for tool in tools:
            if not tool.get('id'):
                tool['id'] = str(uuid.uuid4())

        query = '''
            UPDATE custom_agents 
            SET name = ?, description = ?, system_prompt = ?, policies = ?, max_budget = ?, tools = ?, mcp_server_urls = ?, a2a_agent_urls = ?
            WHERE id = ?
        '''
        params = [
            agent_data.get('name'),
            agent_data.get('description'),
            agent_data.get('system_prompt'),
            json.dumps(agent_data.get('policies', {})),
            agent_data.get('max_budget', 10),
            json.dumps(tools),
            json.dumps(agent_data.get('mcp_server_urls', [])),
            json.dumps(agent_data.get('a2a_agent_urls', [])),
            agent_id
        ]
        if user_id:
            query += ' AND (user_id = ? OR user_id IS NULL)'
            params.append(user_id)

        db.execute(query, tuple(params))
        return self.get_agent(agent_id, user_id)

    def delete_agent(self, agent_id: str, user_id: Optional[str] = None):
        if user_id:
            db.execute('DELETE FROM custom_agents WHERE id = ? AND (user_id = ? OR user_id IS NULL)', (agent_id, user_id))
        else:
            db.execute('DELETE FROM custom_agents WHERE id = ?', (agent_id,))
        return True

agent_manager = AgentManager()
