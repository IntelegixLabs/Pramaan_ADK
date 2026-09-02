import asyncio
import json
import os
import uuid
import subprocess
import threading
from typing import Dict, Optional
from fastapi import APIRouter, Request, HTTPException, Response
from sse_starlette.sse import EventSourceResponse, ServerSentEvent

from security.mcp_manager import mcp_manager

router = APIRouter(prefix="/mcp-proxy", tags=["MCP Proxy"])

# Store running processes and their lock/queues
class ProxySession:
    def __init__(self, mcp_id: str, process: subprocess.Popen, queue: asyncio.Queue):
        self.mcp_id = mcp_id
        self.process = process
        self.queue = queue
        self.lock = asyncio.Lock()

sessions: Dict[str, ProxySession] = {}

def reader_thread(process: subprocess.Popen, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
    """Reads stdout from the subprocess and puts it into the asyncio queue."""
    try:
        for line in iter(process.stdout.readline, b''):
            text = line.decode('utf-8').strip()
            if text:
                asyncio.run_coroutine_threadsafe(queue.put(text), loop)
    except Exception:
        pass
    finally:
        asyncio.run_coroutine_threadsafe(queue.put(None), loop)

async def start_hosted_mcp(mcp_id: str) -> Optional[ProxySession]:
    script_path = os.path.join(os.path.dirname(__file__), '..', 'hosted_mcps', f"{mcp_id}.py")
    if not os.path.exists(script_path):
        return None
        
    import sys
    process = subprocess.Popen(
        [sys.executable, script_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=os.environ.copy(),
        bufsize=0 # Unbuffered
    )
    
    queue = asyncio.Queue()
    loop = asyncio.get_running_loop()
    
    # Start thread to read stdout
    t = threading.Thread(target=reader_thread, args=(process, loop, queue), daemon=True)
    t.start()
    
    session = ProxySession(mcp_id, process, queue)
    return session

@router.get("/{mcp_id}")
async def mcp_proxy_get(mcp_id: str, request: Request):
    """
    Acts as the SSE endpoint for the MCP client, OR a simple validation endpoint.
    """
    mcp_data = mcp_manager.get_mcp(mcp_id)
    if not mcp_data:
        raise HTTPException(status_code=404, detail="MCP Server not found")
        
    # If it's a simple validation request from the AgentBuilder (not expecting SSE)
    if "text/event-stream" not in request.headers.get("accept", ""):
        # Check if the file exists for hosted
        if mcp_data.get("is_hosted"):
            script_path = os.path.join(os.path.dirname(__file__), '..', 'hosted_mcps', f"{mcp_id}.py")
            if not os.path.exists(script_path):
                raise HTTPException(status_code=500, detail="Hosted script file not found")
        
        # Build capability lists safely depending on if they are objects or strings
        def extract_names(cap_list):
            return [c.get("name") if isinstance(c, dict) else c for c in cap_list if c]

        tools = extract_names(mcp_data.get("hosted_tools", []) + mcp_data.get("allowed_tools", []))
        resources = extract_names(mcp_data.get("hosted_resources", []) + mcp_data.get("allowed_resources", []))
        prompts = extract_names(mcp_data.get("hosted_prompts", []) + mcp_data.get("allowed_prompts", []))

        return {
            "status": "ok", 
            "mcp_id": mcp_id, 
            "type": "hosted" if mcp_data.get("is_hosted") else "remote",
            "name": mcp_data.get("name"),
            "description": mcp_data.get("description"),
            "capabilities": {
                "tools": tools,
                "resources": resources,
                "prompts": prompts
            }
        }

    # --- Handle SSE Connection ---
    session_id = str(uuid.uuid4())
    
    if mcp_data.get("is_hosted"):
        session = await start_hosted_mcp(mcp_id)
        if not session:
            raise HTTPException(status_code=500, detail="Failed to start hosted MCP process")
            
        sessions[session_id] = session
        
        async def event_generator():
            try:
                # 1. Send the endpoint URL for POST messages
                base_url = str(request.base_url).rstrip('/')
                yield ServerSentEvent(
                    event="endpoint",
                    data=f"{base_url}/mcp-proxy/messages?session_id={session_id}"
                )
                
                # 2. Stream stdout from the thread queue
                while True:
                    text = await session.queue.get()
                    if text is None: # EOF marker
                        break
                    yield ServerSentEvent(event="message", data=text)
                        
            except asyncio.CancelledError:
                pass
            finally:
                # Cleanup process when client disconnects
                if session_id in sessions:
                    del sessions[session_id]
                try:
                    session.process.terminate()
                except OSError:
                    pass

        return EventSourceResponse(event_generator())
        
    else:
        server_url = mcp_data.get("server_url")
        if server_url:
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url=server_url, status_code=307)
        raise HTTPException(status_code=400, detail="MCP server has no server_url configured")

@router.post("/messages")
async def mcp_proxy_post(request: Request, session_id: str):
    """
    Receives JSON-RPC messages from the client and writes them to the subprocess stdin.
    """
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Invalid or expired session")
        
    session = sessions[session_id]
    body = await request.body()
    
    if session.process.stdin is None:
        raise HTTPException(status_code=500, detail="Process stdin not available")
        
    async with session.lock:
        session.process.stdin.write(body)
        session.process.stdin.write(b'\n')
        session.process.stdin.flush()
        
    return Response(status_code=202)
