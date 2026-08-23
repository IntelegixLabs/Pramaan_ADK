class GoalChecker:
    def __init__(self):
        self.allowed_tools = {
            "login_support": ["search_public_docs", "create_ticket", "reset_password"],
            "customer_email": ["send_customer_email", "fetch_templates", "read_inbox"],
            "record_cleanup": ["delete_record", "merge_duplicate", "archive_record"],
            "relocation": ["search_public_docs", "create_relocation_case", "validate_relocation_amount", "finance.disburse.relocation"],
            "payroll": ["view_payslip", "update_tax_info", "finance.process_payroll"],
            "general_support": ["search_public_docs", "escalate_to_human"]
        }
    
    def set_tools_for_goal(self, goal: str, tools: list[str]):
        self.allowed_tools[goal] = tools
        
    def get_rules(self):
        return self.allowed_tools

    def set_rules(self, rules: dict):
        self.allowed_tools = rules

    def classify_goal(self, message: str) -> str:
        text = message.lower()
        if "login" in text or "password" in text:
            return "login_support"
        if "email" in text or "message" in text:
            return "customer_email"
        if "delete" in text or "duplicate" in text:
            return "record_cleanup"
        if "relocate" in text or "relocation" in text or "move" in text:
            return "relocation"
        if "payroll" in text or "salary" in text or "payslip" in text:
            return "payroll"
        return "general_support"

    def check(self, message: str, tool_name: str) -> tuple[bool, str]:
        goal = self.classify_goal(message)
        allowed = self.allowed_tools.get(goal, [])
        if tool_name not in allowed:
            return False, f"Tool {tool_name} does not match classified goal {goal}"
        return True, "Tool matches user goal"

goal_checker = GoalChecker()
