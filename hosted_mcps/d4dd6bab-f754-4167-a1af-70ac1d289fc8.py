from mcp.server.fastmcp import FastMCP, Context
import asyncio

mcp = FastMCP("Calculator MCP Server")

@mcp.tool(description='Given a list of numbers return their sum')
def sum_tool(numbers: list[int]) -> str:
    return f'Sum is {sum(numbers)}'

@mcp.resource('config://app-settings', description='Configuration resource.')
def get_settings() -> str:
    return '{"key": "value"}'

@mcp.prompt(description='Prompt for code review.')
def code_review(code: str) -> str:
    return f'Review this:\n{code}'

if __name__ == "__main__":
    mcp.run(transport="stdio")
