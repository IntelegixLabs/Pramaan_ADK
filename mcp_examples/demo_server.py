import asyncio
import os
from mcp.server.fastmcp import FastMCP, Context

# Initialize the server
mcp = FastMCP("ExplainerServer")


# --- 1. Tools ---
@mcp.tool()
def calculate_sum(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b


# --- 2. Resources ---
@mcp.resource("config://app-settings")
def get_settings() -> str:
    """Provides application configuration settings to the LLM."""
    return '{"theme": "dark", "version": "1.0.0"}'


# --- 3. Prompts ---
@mcp.prompt()
def code_review(code: str) -> str:
    """Prompt template for reviewing code."""
    return f"Please act as a senior developer and review the following code for bugs and security issues:\n\n```\n{code}\n```"


# --- 4. Logging & Progress ---
@mcp.tool()
async def process_large_data(dataset_id: str, ctx: Context) -> str:
    """A long running task that reports progress and logs."""
    ctx.info(f"Starting processing for dataset {dataset_id}")
    
    total_steps = 5
    for step in range(total_steps):
        await asyncio.sleep(0.5) # Simulate work
        ctx.debug(f"Completed step {step + 1}")
        await ctx.report_progress(step + 1, total_steps)
        
    ctx.info("Processing complete")
    return "Dataset processed successfully!"


# --- 5. Securing File Access with Roots ---
@mcp.tool()
async def read_workspace_file(filename: str, ctx: Context) -> str:
    """Read a file, but only if it falls within the client-provided roots."""
    roots = await ctx.request_roots()
    
    # Simple check if file path starts with any allowed root
    is_allowed = False
    for root in roots:
        if filename.startswith(root.uri.replace("file://", "")):
            is_allowed = True
            break
            
    if not is_allowed:
        raise ValueError(f"Access to {filename} is denied. Outside of allowed roots.")
        
    try:
        with open(filename, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"

if __name__ == "__main__":
    # Runs using STDIO Transport
    mcp.run(transport="stdio")
