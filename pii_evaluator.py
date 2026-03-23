import json
from datetime import datetime, timezone
import yaml
import re
from pathlib import Path

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

# --- Logger ---
def log_decision(timestamp, session_id, agent, tool, parameters, rule_id, rule_name, severity, decision, reason, pii_hits):
    """Log a decision to the Seshat audit log."""
    entry = {
        "timestamp": timestamp.isoformat(),
        "session_id": session_id,
        "agent": agent,
        "tool": tool,
        "parameters": parameters,  # TODO: Redact PII in production
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "decision": decision,
        "reason": reason,
        "pii_hits": pii_hits
    }

    with open("seshat_audit.jsonl", "a") as log_file:
        # Append the JSON object to the file without pretty-printing
        json.dump(entry, log_file)
        log_file.write("\n")

# --- Evaluator ---
def evaluate(session_id, agent, tool, parameters):
    """Evaluate tool call parameters against PII detection rules."""
    policy = load_policy("pii_rule.yml")  # Load and parse policies from pii_rule.yml
    rule = policy["rules"][0]  # Assuming the first rule is the one we want to use

    if not rule["enabled"]:
        print(f"ALLOW  (rule disabled)")
        return "ALLOW"

    hits = scan_for_pii(parameters)

    print(f"Tool:    {tool}")
    print(f"Agent:   {agent}")
    print(f"Session: {session_id}")
    print(f"Rule:    {rule['rule_id']} — {rule['name']}")
    print()

    if hits:
        decision = "DENY"
        reason = "PII detected in parameters without consent check"
    else:
        decision = "ALLOW"
        reason = "No PII patterns detected"

    # Log the decision
    log_decision(
        timestamp=datetime.now(timezone.utc),
        session_id=session_id,
        agent=agent,
        tool=tool,
        parameters=parameters,
        rule_id=rule["rule_id"],
        rule_name=rule["name"],
        severity=rule.get("severity", "high"),  # Default to 'high' if not specified
        decision=decision,
        reason=reason,
        pii_hits=hits
    )

    return decision

# Example usage
if __name__ == "__main__":
    session_id = "abc-123"
    agent = "hermes-data-processor"
    tool = "query_database"
    
    # Test case 1: Query with PII
    parameters_with_pii = {
        "query": "SELECT * FROM users WHERE email = 'john@example.com'",
        "database": "production"
    }
    decision_with_pii = evaluate(session_id, agent, tool, parameters_with_pii)
    print(f"Decision with PII: {decision_with_pii}")

    # Test case 2: Query without PII
    parameters_without_pii = {
        "query": "SELECT * FROM users WHERE id = 1",
        "database": "production"
    }
    decision_without_pii = evaluate(session_id, agent, tool, parameters_without_pii)
    print(f"Decision without PII: {decision_without_pii}")
