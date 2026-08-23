import re
from pydantic import BaseModel

class RedactionResult(BaseModel):
    text: str
    findings: list[dict]

class PiiRedactor:
    def __init__(self):
        self.patterns = {
            "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "PHONE": r"\+?\d[\d\s().-]{7,}\d",
            "ACCOUNT_NUMBER": r"\bACCT-\d{6,}\b",
            "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "IP_ADDRESS": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "AWS_API_KEY": r"\bAKIA[0-9A-Z]{16}\b",
            "GENERIC_API_KEY": r"(?i)(?:api[_-]?key|token|secret)[\s:=]+[\"']?[A-Za-z0-9\-_]{20,}['\"]?"
        }
    
    def add_pattern(self, entity: str, pattern: str):
        self.patterns[entity] = pattern

    def remove_pattern(self, entity: str):
        if entity in self.patterns:
            del self.patterns[entity]

    def get_patterns(self):
        return self.patterns

    def set_patterns(self, new_patterns: dict):
        self.patterns = new_patterns

    def redact(self, text: str) -> RedactionResult:
        findings = []
        redacted = text
        for entity, pattern in self.patterns.items():
            matches = re.findall(pattern, redacted)
            if matches:
                # Replace each match with its entity tag
                redacted = re.sub(pattern, f"[{entity}]", redacted)
                findings.append({"entity": entity, "count": len(matches)})
        return RedactionResult(text=redacted, findings=findings)

# Singleton instance
pii_redactor = PiiRedactor()
