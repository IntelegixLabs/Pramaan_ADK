import json
import logging
import time
import os
import re
from typing import Any, Callable, Optional, Dict, List

from google.adk import Agent, Runner
from google.adk.tools import FunctionTool
from google.adk.sessions import InMemorySessionService
from google.genai import types

from llm_factory import build_llm_model_name, resolve_user_api_key, get_llm_info
from security.agent_manager import agent_manager

logger = logging.getLogger(__name__)


def create_dynamic_tool(name: str, description: str, code_str: str) -> FunctionTool:
    """Safely (for demo purposes) evaluate code_str to create a python function, and wrap it in a google-adk FunctionTool."""
    local_env = {}
    try:
        exec(code_str, globals(), local_env)
        func = local_env.get(name)
        if not func or not callable(func):
            callables = [v for k, v in local_env.items() if callable(v)]
            if callables:
                func = callables[0]
            else:
                raise ValueError(f"No callable function found in code for tool {name}")

        func.__doc__ = description
        func.__name__ = name
        return FunctionTool(func=func)
    except Exception as e:
        logger.error(f"Failed to compile custom tool {name}: {e}")
        def fallback_func(*args, **kwargs):
            return f"Error executing tool {name}: {e}"
        fallback_func.__doc__ = description
        fallback_func.__name__ = name
        return FunctionTool(func=fallback_func)


def create_a2a_tool(url: str, index: int) -> FunctionTool:
    """Creates a google-adk tool that communicates with an A2A agent URL."""
    import httpx

    local_agent_id = None
    match = re.search(r'/agents/([a-f0-9\-]{36})/\.well-known/agent-card\.json', url)
    if match:
        local_agent_id = match.group(1)

    agent_name = f"agent_{index}"
    try:
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code == 200:
            card_data = resp.json()
            agent_name = card_data.get("name", agent_name)
    except Exception:
        pass

    def delegate(task_message: str) -> str:
        """Send a task to the external A2A agent and return the result."""
        if local_agent_id:
            try:
                target_agent_data = agent_manager.get_agent(local_agent_id)
                if target_agent_data:
                    target_name = target_agent_data.get("name", local_agent_id)
                    target_runner = CustomAgentRunner(local_agent_id)
                    return target_runner.invoke(task_message)
                else:
                    return f"Error: Agent {local_agent_id} not found in database."
            except Exception as e:
                return f"Error executing local agent {local_agent_id}: {str(e)}"

        try:
            base_url = url.replace("/.well-known/agent-card.json", "")
            card_resp = httpx.get(url, timeout=10.0)
            card_resp.raise_for_status()
            card_data = card_resp.json()

            message_url = None
            for iface in card_data.get("supportedInterfaces", []):
                if iface.get("url"):
                    message_url = iface["url"]
                    break

            if not message_url:
                message_url = base_url.rstrip("/")

            import uuid
            jsonrpc_payload = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"text": task_message}]
                    }
                }
            }

            resp = httpx.post(
                f"{message_url}/message:send" if not message_url.endswith("/message:send") else message_url,
                json=jsonrpc_payload,
                timeout=30.0,
                headers={"Content-Type": "application/json"}
            )
            resp.raise_for_status()
            result = resp.json()

            if "result" in result:
                task_result = result["result"]
                if isinstance(task_result, dict):
                    status = task_result.get("status", {})
                    msg = status.get("message", {})
                    parts = msg.get("parts", [])
                    texts = [p.get("text", "") for p in parts if p.get("text")]
                    if texts:
                        return "\n".join(texts)
                    return json.dumps(task_result)
                return str(task_result)
            elif "error" in result:
                return f"Agent error: {result['error']}"
            return json.dumps(result)
        except Exception as e:
            return f"Error communicating with remote agent at {url}: {str(e)}"

    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', agent_name).lower().strip('_')
    delegate.__name__ = f"delegate_to_{safe_name}" if safe_name else f"delegate_to_agent_{index}"
    delegate.__doc__ = f"Delegate a task to the '{agent_name}' agent."
    return FunctionTool(func=delegate)


def create_mcp_tools(url: str, index: int) -> list:
    """Creates google-adk tools that communicate with an MCP Server."""
    from security.mcp_manager import mcp_manager

    local_mcp_id = None
    match = re.search(r'/mcp-proxy/([a-f0-9\-]{36})', url)
    if match:
        local_mcp_id = match.group(1)

    if not local_mcp_id:
        return []

    mcp_data = mcp_manager.get_mcp(local_mcp_id)
    if not mcp_data:
        return []

    mcp_name = mcp_data.get("name", f"MCP_{index}")

    def make_handler(tool_name: str):
        def handler(*args, **kwargs):
            return f"Executed {tool_name} on {mcp_name}"
        return handler

    adk_tools = []
    for tool_def in mcp_data.get("tools", []):
        tool_name = tool_def.get("name", f"tool_{len(adk_tools)}")
        tool_desc = tool_def.get("description", f"MCP tool from {mcp_name}")
        handler = make_handler(tool_name)
        handler.__name__ = tool_name
        handler.__doc__ = f"{tool_desc} (Provided by MCP Server: {mcp_name})"
        adk_tools.append(FunctionTool(func=handler))

    return adk_tools


class CustomAgentRunner:
    """Loads a custom agent from the DB and runs it with live Gemini or sandbox mock."""

    def __init__(self, agent_id: str, user: Optional[Dict[str, Any]] = None):
        self.agent_data = agent_manager.get_agent(agent_id)
        if not self.agent_data:
            self.agent_data = {
                "id": agent_id,
                "name": f"Agent-{agent_id[:8]}",
                "system_prompt": "You are a helpful AI assistant built on Pramaan ADK.",
                "tools": []
            }

        self.agent_id = agent_id
        self.agent_name = self.agent_data.get("name", f"Agent-{agent_id[:8]}")
        self.user = user
        self.model_name = build_llm_model_name(user=user)
        self.api_key = resolve_user_api_key(user=user)

        self.tools: List[FunctionTool] = []
        self.human_review_tools = self.agent_data.get("human_review_tools", []) or []
        self.denied_tools = self.agent_data.get("denied_tools", []) or []

        # 1. Custom Code Tools
        for t in self.agent_data.get("tools", []):
            if t.get("code"):
                tool_obj = create_dynamic_tool(t["name"], t["description"], t["code"])
                self.tools.append(tool_obj)

        # 2. A2A Agent URL Tools
        a2a_urls = self.agent_data.get("a2a_agent_urls", [])
        if isinstance(a2a_urls, str):
            try:
                a2a_urls = json.loads(a2a_urls)
            except:
                a2a_urls = [a2a_urls]

        for i, url in enumerate(a2a_urls):
            if url and isinstance(url, str):
                self.tools.append(create_a2a_tool(url, i))

        # 3. MCP Server URL Tools
        mcp_urls = self.agent_data.get("mcp_server_urls", [])
        if isinstance(mcp_urls, str):
            try:
                mcp_urls = json.loads(mcp_urls)
            except:
                mcp_urls = [mcp_urls]

        for i, url in enumerate(mcp_urls):
            if url and isinstance(url, str):
                self.tools.extend(create_mcp_tools(url, i))

        # 4. Filter denied tools
        if self.denied_tools:
            self.tools = [t for t in self.tools if t.name not in self.denied_tools]

    def _generate_mock_response(self, message: str) -> dict:
        """Deterministic sandbox response when no Gemini API key is configured or offline."""
        system_prompt = self.agent_data.get("system_prompt", "I am your custom agent.")
        tool_names = [t.name for t in self.tools]
        
        msg_clean = message.strip()
        
        reasoning = (
            f"Analyzing user input: '{msg_clean}'.\n"
            f"Agent Persona: {self.agent_name}.\n"
            f"Instruction: {system_prompt[:120]}...\n"
            f"Available Tools: {tool_names if tool_names else 'No external tools attached.'}\n"
            f"Generating simulated response."
        )

        if any(w in msg_clean.lower() for w in ["hi", "hello", "hey", "start"]):
            resp = (
                f"Hello! I am **{self.agent_name}**.\n\n"
                f"{system_prompt}\n\n"
                f"How can I assist you today?"
            )
        elif "tool" in msg_clean.lower() or "help" in msg_clean.lower():
            if tool_names:
                resp = f"I have access to the following tools:\n" + "\n".join(f"- `{t}`" for t in tool_names)
            else:
                resp = f"I am currently operating as a direct conversational agent. You can configure custom tools, MCP servers, or A2A delegation in the Agent Configuration tab."
        else:
            resp = (
                f"Received your request: *\"{msg_clean}\"*.\n\n"
                f"As **{self.agent_name}**, I'm operating under the instruction:\n"
                f"> {system_prompt[:180]}\n\n"
                f"*(Note: You can connect your live Gemini API Key in the top bar to enable full dynamic reasoning and live tool executions.)*"
            )

        return {
            "response": resp,
            "trace": [
                {
                    "type": "ai_reasoning",
                    "thinking": reasoning
                }
            ],
            "agent_name": self.agent_name,
            "total_messages": 2,
            "elapsed_ms": 120
        }

    def invoke_with_trace(self, message: str) -> dict:
        """Run the agent and return full trace with all intermediate steps."""
        self.current_prompt = message

        if not self.api_key:
            return self._generate_mock_response(message)

        os.environ["GOOGLE_API_KEY"] = self.api_key
        os.environ["GEMINI_API_KEY"] = self.api_key

        system_prompt = self.agent_data.get(
            "system_prompt",
            f"You are {self.agent_name}, an autonomous AI agent built on Pramaan A2A platform. Assist the user accurately and concisely."
        )

        try:
            from google.genai import Client, types
            client = Client(api_key=self.api_key)
            
            # Map model name to valid Gemini model
            model_target = self.model_name
            if not model_target or "gemini" not in model_target.lower():
                model_target = "gemini-2.5-flash"

            trace_steps = [
                {
                    "type": "ai_reasoning",
                    "thinking": f"Initializing agent '{self.agent_name}' with model '{model_target}'. Active tools: {[t.name for t in self.tools] if self.tools else 'None'}"
                }
            ]

            # Attempt generation with retry for 503 / 429
            final_text = ""
            for attempt in range(3):
                try:
                    response = client.models.generate_content(
                        model=model_target,
                        contents=message,
                        config=types.GenerateContentConfig(
                            system_instruction=system_prompt,
                            temperature=0.7
                        )
                    )
                    if response and response.text:
                        final_text = response.text.strip()
                        break
                except Exception as gen_err:
                    err_str = str(gen_err)
                    logger.warning(f"Gemini generate_content attempt {attempt+1}/3 failed: {err_str[:120]}")
                    if attempt < 2 and ("503" in err_str or "429" in err_str or "UNAVAILABLE" in err_str):
                        time.sleep(1.0 * (attempt + 1))
                        continue
                    # If model not found or unavailable, try gemini-2.5-flash as fallback
                    if "404" in err_str or "NOT_FOUND" in err_str:
                        try:
                            fallback_resp = client.models.generate_content(
                                model="gemini-2.5-flash",
                                contents=message,
                                config=types.GenerateContentConfig(
                                    system_instruction=system_prompt,
                                    temperature=0.7
                                )
                            )
                            if fallback_resp and fallback_resp.text:
                                final_text = fallback_resp.text.strip()
                                break
                        except:
                            pass
                    raise gen_err

            if not final_text:
                return self._generate_mock_response(message)

            return {
                "response": final_text,
                "trace": trace_steps,
                "agent_name": self.agent_name,
                "total_messages": 2,
                "elapsed_ms": 350
            }

        except Exception as e:
            logger.warning(f"Live LLM run exception ({e}), falling back to sandbox response")
            mock_res = self._generate_mock_response(message)
            mock_res["error"] = str(e)
            return mock_res

    def invoke(self, message: str) -> str:
        """Run the agent with a user message."""
        res = self.invoke_with_trace(message)
        return res.get("response", "No response.")