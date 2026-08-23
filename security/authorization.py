import subprocess
import json
import os
import uuid
from pydantic import BaseModel


def _is_serverless() -> bool:
    return bool(os.environ.get("VERCEL"))


class Principal(BaseModel):
    user_id: str
    tenant_id: str
    role: str
    scopes: list[str]
    department: str
    environment: str

class AuthorizationEngine:
    def __init__(self):
        self._bundle_rego_file = os.path.join(os.path.dirname(__file__), "policy.rego")
        self.rego_file = self._bundle_rego_file
        self.opa_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "opa.exe")
        if not os.path.exists(self.rego_file):
            self.write_default_rego()

    def get_rego(self):
        try:
            with open(self.rego_file, "r") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def set_rego(self, content: str):
        if _is_serverless():
            self.rego_file = os.path.join("/tmp", "policy.rego")
        else:
            self.rego_file = self._bundle_rego_file
        with open(self.rego_file, "w") as f:
            f.write(content)

    def write_default_rego(self):
        rego = """package agentsecgov
import rego.v1

default decision := {
  "decision": "deny",
  "reason": "no allow rule matched"
}

has_scope(scope) if {
  input.principal.scopes[_] == scope
}

# --- HR Department Rules ---
decision := {
  "decision": "allow",
  "reason": "HR member executing HR relocation action"
} if {
  input.principal.department == "HR"
  input.tool.name == "finance.disburse.relocation"
  input.tool.risk == "low"
  has_scope("finance.disburse.relocation")
}

decision := {
  "decision": "review",
  "reason": "HR member executing high-risk relocation action requires review"
} if {
  input.principal.department == "HR"
  input.tool.name == "finance.disburse.relocation"
  input.tool.risk == "high"
  has_scope("finance.disburse.relocation")
}

# --- Finance Department Rules ---
decision := {
  "decision": "allow",
  "reason": "Finance member executing payroll action"
} if {
  input.principal.department == "Finance"
  input.tool.name == "finance.process_payroll"
  has_scope("finance.process_payroll")
}

# --- Goal Integrity Checks ---
decision := {
  "decision": "deny",
  "reason": "goal mismatch: tool execution does not align with user intent"
} if {
  input.context.goal_match == false
}

# --- General Low Risk ---
decision := {
  "decision": "allow",
  "reason": "low-risk scoped action allowed"
} if {
  input.tool.risk == "low"
  has_scope(input.tool.required_scope)
}

# --- Critical Actions ---
# Always deny critical actions unless they have breakglass scope
decision := {
  "decision": "deny",
  "reason": "critical tool without breakglass scope"
} if {
  input.tool.risk == "critical"
  not has_scope("breakglass:critical")
}
"""
        self.set_rego(rego)

    def evaluate(self, principal: Principal, tool: dict, context: dict) -> dict:
        if not os.path.exists(self.opa_path):
            # Fallback if OPA is not installed
            print(f"OPA binary not found at {self.opa_path}")
            return {"decision": "allow", "reason": "OPA not installed"}

        input_data = {
            "principal": principal.model_dump(),
            "tool": tool,
            "context": context
        }
        input_file = os.path.join(
            "/tmp" if _is_serverless() else ".",
            f"opa_input_{uuid.uuid4().hex[:8]}.json",
        )
        try:
            with open(input_file, "w") as f:
                json.dump(input_data, f)
            
            result = subprocess.run(
                [self.opa_path, "eval", "-i", input_file, "-d", self.rego_file, "data.agentsecgov.decision"],
                capture_output=True, text=True
            )
            out = json.loads(result.stdout)
            if "result" in out and len(out["result"]) > 0:
                return out["result"][0]["expressions"][0]["value"]
            return {"decision": "deny", "reason": "OPA evaluation returned empty"}
        except Exception as e:
            return {"decision": "deny", "reason": f"Error running OPA: {str(e)}"}
        finally:
            if os.path.exists(input_file):
                os.remove(input_file)

authorization_engine = AuthorizationEngine()
