import json
import logging
import time
from typing import Any, Callable

from langchain_core.tools import tool, Tool, StructuredTool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage

from llm_factory import build_llm
from security.agent_manager import agent_manager

logger = logging.getLogger(__name__)


def create_dynamic_tool(name: str, description: str, code_str: str) -> Tool:
    """Safely (for demo purposes) evaluate code_str to create a python function, and wrap it in a Langchain Tool."""
    local_env = {}
    try:
        # We expect the code_str to define a function with the same name as the tool
        exec(code_str, globals(), local_env)
        func = local_env.get(name)
        if not func or not callable(func):
            # Fallback if they didn't name it exactly right, just grab the first callable
            callables = [v for k, v in local_env.items() if callable(v)]
            if callables:
                func = callables[0]
            else:
                raise ValueError(f"No callable function found in code for tool {name}")

        # Wrap it in a Langchain Tool
        return Tool(
            name=name,
            description=description,
            func=func
        )
    except Exception as e:
        logger.error(f"Failed to compile custom tool {name}: {e}")
        return Tool(
            name=name,
            description=description,
            func=lambda *args, **kwargs: f"Error executing tool {name}: {e}"
        )


def create_a2a_tool(url: str, index: int) -> Tool:
    """Creates a LangChain tool that communicates with an A2A agent URL.

    Supports two modes:
    1. Local agents (same server): Extracts agent_id from the URL and invokes
       the agent directly via CustomAgentRunner for zero-latency communication.
    2. Remote agents: Uses httpx to fetch the agent card, then sends a JSON-RPC
       message/send request to the agent's supported interface URL.
    """
    import re
    import httpx

    # Try to extract agent_id from URL pattern: /agents/{uuid}/.well-known/agent-card.json
    local_agent_id = None
    match = re.search(r'/agents/([a-f0-9\-]{36})/\.well-known/agent-card\.json', url)
    if match:
        local_agent_id = match.group(1)

    # Fetch the agent name for a better tool description
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
        # Mode 1: Local agent — call directly via CustomAgentRunner
        if local_agent_id:
            try:
                logger.info(f"[A2A Delegation] 🤝 Delegating to local agent '{agent_name}' (id={local_agent_id})")
                logger.info(
                    f"[A2A Delegation] 📨 Message: {task_message[:200]}{'...' if len(task_message) > 200 else ''}")
                t0 = time.time()

                target_agent_data = agent_manager.get_agent(local_agent_id)
                if target_agent_data:
                    from llm_factory import build_llm
                    from langchain_core.messages import HumanMessage, SystemMessage

                    target_name = target_agent_data.get("name", local_agent_id)
                    logger.info(
                        f"[A2A Delegation] 🎯 Target agent: '{target_name}', system_prompt length={len(target_agent_data.get('system_prompt', ''))}")

                    llm = build_llm()
                    target_tools = []
                    for t in target_agent_data.get("tools", []):
                        if t.get("code"):
                            target_tools.append(create_dynamic_tool(t["name"], t["description"], t["code"]))

                    logger.info(f"[A2A Delegation] 🔧 Target agent tools: {[t.name for t in target_tools]}")

                    target_executor = create_react_agent(llm, target_tools)
                    messages = [
                        SystemMessage(content=target_agent_data.get("system_prompt", "You are a helpful assistant.")),
                        HumanMessage(content=task_message)
                    ]
                    result = target_executor.invoke({"messages": messages})
                    result_messages = result.get("messages", [])

                    elapsed_ms = (time.time() - t0) * 1000
                    logger.info(
                        f"[A2A Delegation] ✅ Agent '{target_name}' completed in {elapsed_ms:.1f}ms, {len(result_messages)} messages")

                    if result_messages:
                        response = result_messages[-1].content
                        logger.info(
                            f"[A2A Delegation] 📩 Response: {response[:200]}{'...' if len(response) > 200 else ''}")
                        return response
                    return "Agent completed but returned no response."
                else:
                    logger.warning(f"[A2A Delegation] ❌ Agent {local_agent_id} not found in database")
                    return f"Error: Agent {local_agent_id} not found in database."
            except Exception as e:
                logger.error(f"[A2A Delegation] ❌ Error executing local agent {local_agent_id}: {str(e)}")
                return f"Error executing local agent {local_agent_id}: {str(e)}"

        # Mode 2: Remote agent — use httpx to send JSON-RPC message/send
        try:
            logger.info(f"[A2A Delegation] 🌐 Delegating to remote agent at {url}")
            logger.info(f"[A2A Delegation] 📨 Message: {task_message[:200]}{'...' if len(task_message) > 200 else ''}")
            t0 = time.time()

            # Derive base URL from agent card URL
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

            elapsed_ms = (time.time() - t0) * 1000
            logger.info(f"[A2A Delegation] ✅ Remote agent responded in {elapsed_ms:.1f}ms")

            if "result" in result:
                task_result = result["result"]
                if isinstance(task_result, dict):
                    status = task_result.get("status", {})
                    msg = status.get("message", {})
                    parts = msg.get("parts", [])
                    texts = [p.get("text", "") for p in parts if p.get("text")]
                    if texts:
                        response = "\n".join(texts)
                        logger.info(
                            f"[A2A Delegation] 📩 Response: {response[:200]}{'...' if len(response) > 200 else ''}")
                        return response
                    return json.dumps(task_result)
                return str(task_result)
            elif "error" in result:
                logger.warning(f"[A2A Delegation] ❌ Agent error: {result['error']}")
                return f"Agent error: {result['error']}"
            return json.dumps(result)
        except Exception as e:
            logger.error(f"[A2A Delegation] ❌ Error communicating with remote agent at {url}: {str(e)}")
            return f"Error communicating with remote agent at {url}: {str(e)}"

    # Use a sanitized agent name for the tool
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', agent_name).lower().strip('_')

    return Tool(
        name=f"delegate_to_{safe_name}" if safe_name else f"delegate_to_agent_{index}",
        description=f"Delegate a task to the '{agent_name}' agent. Send a natural language message describing what you need this agent to do, and it will process the request and return the result.",
        func=delegate
    )


def create_mcp_tools(url: str, index: int) -> list:
    """Creates LangChain tools that communicate with an MCP Server.

    Discovers the server's REAL tools (name, description, JSON input schema) via
    the proxy and builds schema-aware StructuredTools, so the LLM emits correctly
    structured arguments (e.g. {"numbers": [1,2,3]}) that map straight onto the
    MCP tool's `arguments`. Falls back to stored DB metadata if live discovery
    fails (e.g. the MCP server is unreachable).
    """
    import re
    import asyncio
    import concurrent.futures
    from security.mcp_manager import mcp_manager

    local_mcp_id = None
    match = re.search(r'/mcp-proxy/([a-f0-9\-]{36})', url)
    if match:
        local_mcp_id = match.group(1)

    if not local_mcp_id:
        # For non-Pramaan remote MCP URLs, tool discovery would require an async SSE connection during init.
        # For now, we only support local proxy URLs which provide fast DB discovery.
        return []

    mcp_data = mcp_manager.get_mcp(local_mcp_id)
    if not mcp_data:
        logger.error(f"MCP server {local_mcp_id} not found in database.")
        return []

    mcp_name = mcp_data.get("name", f"MCP_{index}")

    def make_handler(tool_name: str):
        def handler(*args, **kwargs):
            if kwargs and list(kwargs.keys()) != ["__arg1"]:
                call_args = kwargs
            else:
                raw = kwargs.get("__arg1") if kwargs else (args[0] if args else {})
                if isinstance(raw, dict):
                    call_args = raw
                elif isinstance(raw, str):
                    try:
                        parsed = json.loads(raw)
                        call_args = parsed if isinstance(parsed, dict) else {"input": parsed}
                    except Exception:
                        call_args = {"input": raw}
                else:
                    call_args = raw if isinstance(raw, dict) else {}

            logger.info(f"[MCP Tool Call] 🔌 Calling MCP tool '{tool_name}' on server '{mcp_name}'")
            logger.info(f"[MCP Tool Call] 📋 Arguments: {json.dumps(call_args, default=str)[:300]}")
            t0 = time.time()

            async def _execute():
                from mcp.client.sse import sse_client
                from mcp.client.session import ClientSession
                try:
                    async with sse_client(url) as streams:
                        async with ClientSession(streams[0], streams[1]) as session:
                            await session.initialize()
                            result = await session.call_tool(tool_name, arguments=call_args)
                            return "\n".join(c.text for c in result.content if hasattr(c, 'text'))
                except Exception as e:
                    return f"Failed to execute MCP tool {tool_name}: {str(e)}"

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(asyncio.run, _execute()).result()

            elapsed_ms = (time.time() - t0) * 1000
            logger.info(f"[MCP Tool Call] ✅ Tool '{tool_name}' completed in {elapsed_ms:.1f}ms")
            logger.info(f"[MCP Tool Call] 📩 Result: {str(result)[:300]}{'...' if len(str(result)) > 300 else ''}")
            return result

        return handler

    # ── 1) Live discovery: fetch the real tool schemas from the MCP server ──
    def _discover():
        async def _list():
            from mcp.client.sse import sse_client
            from mcp.client.session import ClientSession
            async with sse_client(url) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    return [
                        {"name": t.name, "description": t.description or "", "schema": t.inputSchema or {}}
                        for t in listed.tools
                    ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, _list()).result()

    discovered = []
    try:
        discovered = _discover()
    except Exception as e:
        logger.warning(f"MCP live tool discovery failed for {mcp_name} ({url}): {e}")

    langchain_tools = []

    if discovered:
        for t in discovered:
            schema = t.get("schema") or {"type": "object", "properties": {}}
            langchain_tools.append(StructuredTool.from_function(
                func=make_handler(t["name"]),
                name=t["name"],
                description=f"{t.get('description') or t['name']} (Provided by MCP Server: {mcp_name})",
                args_schema=schema,
            ))
        return langchain_tools

    # ── 2) Fallback: build from stored DB metadata (no live schema available) ──
    all_tools = mcp_data.get("hosted_tools", []) + mcp_data.get("allowed_tools", [])
    for t in all_tools:
        if isinstance(t, dict):
            tool_name = t.get("name")
            tool_desc = t.get("description", f"Execute {tool_name} on {mcp_name}")
            schema = t.get("inputSchema") or t.get("schema")
        elif isinstance(t, str):
            tool_name, tool_desc, schema = t, f"Tool {t} on {mcp_name}", None
        else:
            continue
        if not tool_name:
            continue

        if schema:
            langchain_tools.append(StructuredTool.from_function(
                func=make_handler(tool_name),
                name=tool_name,
                description=f"{tool_desc} (Provided by MCP Server: {mcp_name})",
                args_schema=schema,
            ))
        else:
            langchain_tools.append(Tool(
                name=f"{tool_name}",
                description=f"{tool_desc} (Provided by MCP Server: {mcp_name})",
                func=make_handler(tool_name),
            ))

    return langchain_tools


class CustomAgentRunner:
    """Loads a custom agent from the DB and runs it."""

    def __init__(self, agent_id: str):
        self.agent_data = agent_manager.get_agent(agent_id)
        if not self.agent_data:
            raise ValueError(f"Agent {agent_id} not found")

        self.agent_id = agent_id
        self.agent_name = self.agent_data.get("name", f"Agent-{agent_id[:8]}")
        logger.info(f"[Agent Init] 🤖 Initializing agent '{self.agent_name}' (id={agent_id})")

        self.llm = build_llm()
        self.tools = []

        # Read tool execution boundaries
        self.human_review_tools = self.agent_data.get("human_review_tools", []) or []
        self.denied_tools = self.agent_data.get("denied_tools", []) or []

        # 1. Custom Code Tools
        for t in self.agent_data.get("tools", []):
            if t.get("code"):
                tool_obj = create_dynamic_tool(t["name"], t["description"], t["code"])
                self.tools.append(tool_obj)
                logger.info(f"[Agent Init] 🔧 Registered custom tool: '{t['name']}'")

        # 2. A2A Agent URL Tools
        a2a_urls = self.agent_data.get("a2a_agent_urls", [])
        if isinstance(a2a_urls, str):
            try:
                a2a_urls = json.loads(a2a_urls)
            except:
                a2a_urls = [a2a_urls]

        for i, url in enumerate(a2a_urls):
            if url and isinstance(url, str):
                a2a_tool = create_a2a_tool(url, i)
                self.tools.append(a2a_tool)
                logger.info(f"[Agent Init] 🤝 Registered A2A delegation tool: '{a2a_tool.name}' → {url}")

        # 3. MCP Server URL Tools
        mcp_urls = self.agent_data.get("mcp_server_urls", [])
        if isinstance(mcp_urls, str):
            try:
                mcp_urls = json.loads(mcp_urls)
            except:
                mcp_urls = [mcp_urls]

        for i, url in enumerate(mcp_urls):
            if url and isinstance(url, str):
                mcp_tools_list = create_mcp_tools(url, i)
                self.tools.extend(mcp_tools_list)
                logger.info(f"[Agent Init] 🔌 Registered {len(mcp_tools_list)} MCP tools from: {url}")

        # 4. Apply Tool Execution Boundaries
        if self.denied_tools:
            denied_count = len([t for t in self.tools if t.name in self.denied_tools])
            self.tools = [t for t in self.tools if t.name not in self.denied_tools]
            if denied_count:
                logger.info(f"[Agent Init] 🚫 Removed {denied_count} denied tools: {self.denied_tools}")

        if self.human_review_tools:
            self.tools = [
                self._wrap_with_human_review(t) if t.name in self.human_review_tools else t
                for t in self.tools
            ]
            logger.info(f"[Agent Init] 👤 Human review required for tools: {self.human_review_tools}")

        logger.info(
            f"[Agent Init] ✅ Agent '{self.agent_name}' ready with {len(self.tools)} tools: {[t.name for t in self.tools]}")

        self.agent_executor = create_react_agent(self.llm, self.tools)

    def _wrap_with_human_review(self, original_tool: Tool) -> Tool:
        """Wrap a tool so it pauses for human approval before executing."""
        import time
        from security.human_review import human_review_queue

        real_func = original_tool.func
        tool_name = original_tool.name
        tool_description = original_tool.description
        agent_name = self.agent_data.get("name", "Unknown Agent")
        agent_id = self.agent_data.get("id", "")

        def gated_func(*args, **kwargs):
            import uuid as _uuid
            # Build a description of the tool call for the reviewer
            tool_args = kwargs if kwargs else (args[0] if args else {})
            tool_call_info = {
                "name": tool_name,
                "description": tool_description,
                "args": tool_args
            }
            principal_info = {
                "user_id": "system",
                "tenant_id": "default",
                "role": "agent",
                "scopes": ["tool_execution"]
            }

            run_id = str(_uuid.uuid4())[:12]

            # Submit to the Human Review queue
            user_prompt = getattr(self, "current_prompt", str(tool_args))
            agent_reasoning = f"Agent wants to call tool '{tool_name}' to fulfill the user's request.\n\nPayload: {json.dumps(tool_args, indent=2)}"

            review_id = human_review_queue.create_review(
                tool_call=tool_call_info,
                decision={
                    "reason": f"Agent '{agent_name}' requires human approval to execute tool '{tool_name}'. This tool is configured under 'Approval Required' in Tool Execution Boundaries."},
                principal_dict=principal_info,
                agent_response=agent_reasoning,
                agent_name=agent_name,
                agent_id=agent_id,
                risk_score=0,
                run_id=run_id,
                user_input=user_prompt,
                gateway_evidence=f"AgentShield held this proposed tool action before execution and routed it to a human reviewer. Tool '{tool_name}' is marked as requiring human approval in the agent's Tool Execution Boundaries configuration."
            )

            logger.info(f"[HumanReview] Created review {review_id} for tool '{tool_name}' — waiting for approval...")

            # Poll for approval with a timeout
            timeout_seconds = 120
            poll_interval = 2
            elapsed = 0

            while elapsed < timeout_seconds:
                status = human_review_queue.get_status(review_id)
                if status == "approved":
                    logger.info(f"[HumanReview] Tool '{tool_name}' APPROVED (review {review_id})")
                    return real_func(*args, **kwargs)
                elif status == "rejected":
                    logger.info(f"[HumanReview] Tool '{tool_name}' REJECTED (review {review_id})")
                    return f"⛔ Tool call '{tool_name}' was rejected by a human reviewer. The action was not executed."

                time.sleep(poll_interval)
                elapsed += poll_interval

            logger.warning(f"[HumanReview] Tool '{tool_name}' TIMED OUT after {timeout_seconds}s (review {review_id})")
            return f"⏱️ Human review for tool '{tool_name}' timed out after {timeout_seconds} seconds. The tool call was not executed. Please try again after a reviewer is available."

        return Tool(
            name=original_tool.name,
            description=original_tool.description,
            func=gated_func
        )

    def invoke(self, message: str) -> str:
        """Run the agent with a user message."""
        self.current_prompt = message
        try:
            logger.info(
                f"[Agent Run] ▶️  Agent '{self.agent_name}' processing: {message[:200]}{'...' if len(message) > 200 else ''}")
            t_start = time.time()

            messages = [
                SystemMessage(content=self.agent_data.get("system_prompt", "You are a helpful assistant.")),
                HumanMessage(content=message)
            ]
            result = self.agent_executor.invoke({"messages": messages})
            all_messages = result.get("messages", [])

            elapsed_ms = (time.time() - t_start) * 1000

            # Log detailed trace of all intermediate steps
            self._log_message_trace(all_messages, elapsed_ms)

            if all_messages:
                return all_messages[-1].content
            return "No response."
        except Exception as e:
            logger.error(f"[Agent Run] ❌ Agent '{self.agent_name}' failed: {e}")
            return f"Agent execution failed: {e}"

    def invoke_with_trace(self, message: str) -> dict:
        """Run the agent and return full trace with all intermediate steps."""
        self.current_prompt = message
        trace_steps = []

        try:
            logger.info(
                f"[Agent Run] ▶️  Agent '{self.agent_name}' processing: {message[:200]}{'...' if len(message) > 200 else ''}")
            t_start = time.time()

            messages = [
                SystemMessage(content=self.agent_data.get("system_prompt", "You are a helpful assistant.")),
                HumanMessage(content=message)
            ]
            result = self.agent_executor.invoke({"messages": messages})
            all_messages = result.get("messages", [])

            elapsed_ms = (time.time() - t_start) * 1000

            # Build structured trace
            for msg in all_messages:
                if isinstance(msg, SystemMessage):
                    trace_steps.append({
                        "type": "system_prompt",
                        "content": msg.content[:100] + "..." if len(msg.content) > 100 else msg.content
                    })
                elif isinstance(msg, HumanMessage):
                    trace_steps.append({
                        "type": "user_message",
                        "content": msg.content
                    })
                elif isinstance(msg, AIMessage):
                    step = {"type": "ai_reasoning"}
                    if msg.content:
                        step["thinking"] = msg.content

                    # Extract tool calls
                    tool_calls = getattr(msg, 'tool_calls', None) or []
                    if not tool_calls:
                        tool_calls = getattr(msg, 'additional_kwargs', {}).get('tool_calls', [])

                    if tool_calls:
                        step["type"] = "tool_call"
                        step["tool_calls"] = []
                        for tc in tool_calls:
                            if isinstance(tc, dict):
                                tc_info = {
                                    "tool_name": tc.get("name", "unknown"),
                                    "arguments": tc.get("args", tc.get("arguments", {})),
                                }
                            else:
                                tc_info = {
                                    "tool_name": getattr(tc, 'name', 'unknown'),
                                    "arguments": getattr(tc, 'args', {}),
                                }

                            # Classify the tool call type
                            tool_name = tc_info["tool_name"]
                            if tool_name.startswith("delegate_to_"):
                                tc_info["call_type"] = "a2a_delegation"
                                tc_info["icon"] = "🤝"
                            elif any(t.name == tool_name and "(Provided by MCP Server:" in t.description for t in
                                     self.tools):
                                tc_info["call_type"] = "mcp_tool"
                                tc_info["icon"] = "🔌"
                            else:
                                tc_info["call_type"] = "custom_tool"
                                tc_info["icon"] = "🔧"

                            step["tool_calls"].append(tc_info)

                    trace_steps.append(step)

                elif isinstance(msg, ToolMessage):
                    trace_steps.append({
                        "type": "tool_result",
                        "tool_name": getattr(msg, 'name', 'unknown'),
                        "result": msg.content[:500] if msg.content else "",
                        "tool_call_id": getattr(msg, 'tool_call_id', ''),
                    })

            # Log the trace
            self._log_message_trace(all_messages, elapsed_ms)

            final_response = all_messages[-1].content if all_messages else "No response."

            return {
                "response": final_response,
                "trace": trace_steps,
                "elapsed_ms": round(elapsed_ms, 2),
                "agent_name": self.agent_name,
                "tools_available": [t.name for t in self.tools],
                "total_messages": len(all_messages),
            }

        except Exception as e:
            logger.error(f"[Agent Run] ❌ Agent '{self.agent_name}' failed: {e}")
            return {
                "response": f"Agent execution failed: {e}",
                "trace": trace_steps,
                "error": str(e),
                "agent_name": self.agent_name,
            }

    def _log_message_trace(self, messages: list, elapsed_ms: float):
        """Log a detailed trace of all messages in the agent's execution."""
        tool_call_count = 0
        ai_step_count = 0

        for msg in messages:
            if isinstance(msg, SystemMessage):
                continue
            elif isinstance(msg, HumanMessage):
                continue
            elif isinstance(msg, AIMessage):
                ai_step_count += 1

                # Log thinking/reasoning
                if msg.content:
                    logger.info(
                        f"[Agent Think] 💭 Step {ai_step_count} reasoning: {msg.content[:300]}{'...' if len(msg.content) > 300 else ''}")

                # Log tool calls
                tool_calls = getattr(msg, 'tool_calls', None) or []
                if not tool_calls:
                    tool_calls = getattr(msg, 'additional_kwargs', {}).get('tool_calls', [])

                for tc in tool_calls:
                    tool_call_count += 1
                    if isinstance(tc, dict):
                        name = tc.get("name", "unknown")
                        args = tc.get("args", tc.get("arguments", {}))
                    else:
                        name = getattr(tc, 'name', 'unknown')
                        args = getattr(tc, 'args', {})

                    if name.startswith("delegate_to_"):
                        logger.info(
                            f"[Agent Action] 🤝 A2A Delegation #{tool_call_count}: calling '{name}' with: {json.dumps(args, default=str)[:300]}")
                    else:
                        logger.info(
                            f"[Agent Action] 🔧 Tool Call #{tool_call_count}: calling '{name}' with: {json.dumps(args, default=str)[:300]}")

            elif isinstance(msg, ToolMessage):
                tool_name = getattr(msg, 'name', 'unknown')
                result_preview = msg.content[:300] if msg.content else "(empty)"
                logger.info(
                    f"[Agent Result] 📦 Tool '{tool_name}' returned: {result_preview}{'...' if len(msg.content or '') > 300 else ''}")

        logger.info(
            f"[Agent Run] ✅ Agent '{self.agent_name}' completed in {elapsed_ms:.1f}ms | {ai_step_count} reasoning steps | {tool_call_count} tool calls | {len(messages)} total messages")
