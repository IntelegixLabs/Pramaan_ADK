class OutputValidator:
    def __init__(self):
        self.blocklist = ["password", "secret", "private_key", "ssn", "api_key", "auth_token", "jwt", "confidential", "internal_only", "classified", "DO_NOT_SHARE"]
    
    def set_blocklist(self, words: list[str]):
        self.blocklist = words
        
    def get_blocklist(self):
        return self.blocklist

    def validate(self, output: str) -> tuple[bool, str]:
        if not output:
            return True, "Valid output"
            
        lowered = str(output).lower()
        for word in self.blocklist:
            if word.lower() in lowered:
                return False, f"Output contains blocked term: {word}"
        return True, "Valid output"

output_validator = OutputValidator()
