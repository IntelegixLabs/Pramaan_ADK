from mcp.server.fastmcp import FastMCP, Context
import asyncio

mcp = FastMCP("Calculator MCP Server")

@mcp.tool()
def my_tool(numbers: list[int]) -> str:
    return f'Sum of numbers {sum(numbers)}'

@mcp.resource("config://app-settings")
def get_settings() -> str:
    return '{"key": "value"}'

@mcp.prompt()
def code_review(code: str) -> str:
    return f'Review this:\n{code}'

if __name__ == "__main__":
    mcp.run(transport="stdio")
