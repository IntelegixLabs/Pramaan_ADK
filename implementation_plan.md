# Implement Hosted MCP Servers in Pramaan

Currently, the Pramaan UI acts as a governance registry to manage connections to **external** MCP servers via SSE URLs. The user wants to expand this capability to allow writing, building, and hosting Python-based MCP servers directly within the Pramaan UI.

## User Review Required

> [!WARNING]
> Hosting arbitrary Python scripts dynamically inside the Pramaan backend introduces security, stability, and resource management implications. An infinite loop in a script could hang processes, and multiple scripts will consume memory. Since this is likely for local development, we will proceed, but in a production enterprise environment, these scripts would typically be deployed to isolated containers (e.g., Docker/Kubernetes) or serverless environments (AWS Lambda).

> [!IMPORTANT]
> **Dependency Management:** If you write Python code that imports external libraries (e.g., `requests`, `pandas`), you must ensure those libraries are installed in the Python environment running the Pramaan backend, as the hosted scripts will share the same environment.

## Open Questions

1. **Execution Model:** MCP Servers usually communicate over standard input/output (stdio) or via HTTP Server-Sent Events (SSE). 
   - *Option A (Easier for User):* You write standard stdio scripts (like your example), and Pramaan launches a new Python process for every incoming agent connection, passing messages via stdin/stdout.
   - *Option B (Easier for Backend):* We require your script to run an SSE server on a specific port (e.g., `mcp.run(transport="sse", port=8001)`), and Pramaan proxies requests to that port. 
   - *Recommendation:* Option A is more standard for MCP, but Option B is much easier to implement in the short term. Which do you prefer?

2. **Code Editor:** I plan to integrate Monaco Editor (the editor that powers VS Code) into the UI so you get syntax highlighting and a great coding experience. Are you okay with adding this dependency to the frontend?

## Proposed Changes

### Frontend (`Pramaan_A2A_UI`)

- **Dependencies:** Install `@monaco-editor/react`.
- **MCPBuilderPage.tsx:**
  - Add a "Hosting Mode" toggle: **Remote Connection** vs **Hosted Code**.
  - If **Hosted Code** is selected, hide the `Upstream Server URL`, `Auth Type`, and `Auth Token` fields.
  - Display the Monaco Editor for the user to write their Python FastMCP code.
  - Add `is_hosted` and `script_content` to the form payload.

### Backend Database (`Pramaan_A2A/security/mcp_manager.py`)

- **Schema Update:** Alter `mcp_servers` table to include `is_hosted BOOLEAN DEFAULT 0` and `script_content TEXT`.
- **API Update:** Update CRUD operations to save and return these new fields.

### Backend Execution (`Pramaan_A2A`)

- **File Management:** When a hosted MCP is created or updated, save the `script_content` to a dedicated directory: `Pramaan_A2A/hosted_mcps/{mcp_id}.py`.
- **Execution Engine:** Depending on the answer to Open Question 1, build the bridge to either proxy requests to a dynamic port or spawn the script via `subprocess.Popen` and stream the stdio to the incoming SSE connection.

## Verification Plan

### Manual Verification
1. Create a new "Hosted" MCP Server in the UI.
2. Paste the provided FastMCP Python example into the code editor.
3. Save the MCP Server.
4. Verify the backend successfully writes the script to disk.
5. Use the "Test MCP" panel in the UI to send a message and verify the agent successfully interacts with the dynamically hosted tools (`calculate_sum`, etc.).
