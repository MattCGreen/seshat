import yaml
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

# --- PII Patterns ---
PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ssn":   re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}

# --- Loader ---
def load_policy(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text())

# --- Scanner ---
def scan_for_pii(parameters: dict) -> list[dict]:
    hits = []
    for param_key, param_value in parameters.items():
        if not isinstance(param_value, str):
            continue
        for pii_type, pattern in PII_PATTERNS.items():
            if pattern.search(param_value):
                hits.append({"field": param_key, "pii_type": pii_type})
    return hits

# --- Evaluator ---
print(f"Time: {datetime.now(timezone.utc).isoformat()}")
def evaluate(tool_call: dict, policy: dict) -> None:
    rule = policy["rules"][0]  # PII-001

    if not rule["enabled"]:
        print("ALLOW  (rule disabled)")
        return

    hits = scan_for_pii(tool_call.get("parameters", {}))

    print(f"Tool:    {tool_call['tool']}")
    print(f"Agent:   {tool_call['agent']}")
    print(f"Session: {tool_call['session_id']}")
    print(f"Rule:    {rule['rule_id']} — {rule['name']}")
    print()

    if hits:
        print("DENY")
        print("Reason: PII detected in parameters without consent check")
        for hit in hits:
            print(f"  - field '{hit['field']}' contains {hit['pii_type'].upper()}")
    else:
        print("ALLOW")
        print("Reason: No PII patterns detected")


# --- Main ---
if __name__ == "__main__":
    policy_path = sys.argv[1] if len(sys.argv) > 1 else "pii_rule.yml"
    policy = load_policy(policy_path)

    mock_tool_call = {
        "tool": "query_database",
        "parameters": {
            "query": "SELECT * FROM users WHERE email = 'john@example.com'",
            "database": "production"
        },
        "agent": "hermes-data-processor",
        "session_id": "abc-123"
    }

    evaluate(mock_tool_call, policy)
