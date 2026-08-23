class Sandbox:
    def __init__(self):
        self.blocked_tools = ["run_shell", "execute_python", "raw_sql", "generic_http_request", "unrestricted_browser", "delete_database", "change_admin_password", "write_local_file"]
        self.max_tool_calls = 5
    
    def set_config(self, blocked: list[str], max_calls: int):
        self.blocked_tools = blocked
        self.max_tool_calls = max_calls

    def get_config(self):
        return {"blocked_tools": self.blocked_tools, "max_tool_calls": self.max_tool_calls}

    def check_tool(self, tool_name: str) -> tuple[bool, str]:
        if tool_name in self.blocked_tools:
            return False, f"Tool {tool_name} is blocked by sandbox policy"
        return True, "Allowed"

    def check_budget(self, tool_calls_count: int) -> tuple[bool, str]:
        if tool_calls_count > self.max_tool_calls:
            return False, f"Autonomy budget exceeded ({tool_calls_count} > {self.max_tool_calls})"
        return True, "Allowed"

sandbox = Sandbox()
