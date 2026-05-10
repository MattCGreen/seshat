import yaml
import re
import sys
import json
from pathlib import Path
from datetime import datetime, timezone


# --- PII Patterns ---
PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\(?\b\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){15,16}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
}

# --- Loader ---
def load_policy(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text())

def load_policies(*paths: str) -> list[dict]:
    if not paths:
        paths = [f for f in Path(".").glob("*.yml")]
    
    policies = []
    for path in paths:
        policy = load_policy(str(path))
        policy["source_file"] = path
        policies.append(policy)
    
    return policies

def collect_rules(policies: list[dict]) -> list[dict]:
    rules = []
    for policy in policies:
        rules.extend({
            **rule,
            "policy": policy["policy"]["name"],
            "source_file": policy.get("source_file", "")
        } for rule in policy["policy"].get("rules", []))
    return rules

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
def evaluate_rule(tool_call: dict, rule: dict) -> tuple[str, str, list[dict]]:
    pii_hits = scan_for_pii(tool_call.get("parameters", {}))
    
    if rule["type"] == "pii_check":
        if pii_hits:
            return "DENY", "PII detected in parameters without consent check", pii_hits
        else:
            return "ALLOW", "No PII patterns detected", []
    elif rule["type"] == "disclosure_check":
        domain = tool_call["parameters"].get("domain")
        disclosure_provided = tool_call["parameters"].get(rule["required_field"], False)
        
        if domain in rule.get("consequential_domains", []):
            if not disclosure_provided:
                return "DENY", f"Consequential domain {domain} without disclosure", []
            else:
                return "ALLOW", "Disclosure provided for consequential domain", []
        else:
            return "ALLOW", "Domain not consequential or disclosure not applicable", []
    else:
        return "UNKNOWN", "Rule type not supported", []

def evaluate(tool_call: dict, rules: list[dict]) -> None:
    rule_results = []
    
    for rule in rules:
        if not rule.get("enabled", True):
            print(f"Rule {rule['rule_id']} is disabled. Skipping.")
            continue
        
        decision, reason, pii_hits = evaluate_rule(tool_call, rule)
        rule_results.append({
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "policy": rule["policy"],
            "severity": rule.get("severity", "medium"),
            "decision": decision,
            "reason": reason,
            "pii_hits": pii_hits
        })
    
    print(f"\nTool:    {tool_call['tool']}")
    print(f"Agent:   {tool_call['agent']}")
    print(f"Session: {tool_call['session_id']}")
    print(f"Time:    {datetime.now(timezone.utc).isoformat()}\n")
    
    print("Rule Results:")
    for result in rule_results:
        print(f"  Rule ID: {result['rule_id']} - {result['rule_name']} → {result['decision']}")
    
    final_decision = "ALLOW" if all(r["decision"] == "ALLOW" for r in rule_results) else "DENY"
    reasons = [f"{r['rule_id']}: {r['reason']}" for r in rule_results if r["decision"] != "ALLOW"]
    
    print(f"\nFinal Decision: {final_decision}")
    print("Reasons:")
    for reason in reasons:
        print(f"  - {reason}")
    
    log_audit_entry(tool_call, rule_results)

# --- Audit Log ---
def log_audit_entry(tool_call: dict, rule_results: list[dict]) -> None:
    final_decision = "ALLOW" if all(r["decision"] == "ALLOW" for r in rule_results) else "DENY"
    audit_log_path = "seshat_audit.jsonl"
    
    with open(audit_log_path, "a") as log_file:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": tool_call["session_id"],
            "agent": tool_call["agent"],
            "tool": tool_call["tool"],
            "parameters": tool_call.get("parameters", {}),
            # TODO: Redact PII in production
            "rule_results": rule_results,
            "final_decision": final_decision
        }
        log_file.write(json.dumps(entry) + "\n")

# --- Main ---
if __name__ == "__main__":
    policy_paths = sys.argv[1:] if len(sys.argv) > 1 else []
    policies = load_policies(*policy_paths)
    rules = collect_rules(policies)

    # Test Case 1: PII detected, no disclosure issue
    tool_call_1 = {
        "tool": "query_database",
        "parameters": {
            "query": "SELECT * FROM users WHERE email = 'john@example.com'",
            "database": "production"
        },
        "agent": "hermes-data-processor",
        "session_id": "abc-123"
    }
    print("\nTest Case 1:")
    evaluate(tool_call_1, rules)

    # Test Case 2: No PII, consequential domain without disclosure
    tool_call_2 = {
        "tool": "evaluate_application",
        "parameters": {
            "applicant_id": "12345",
            "domain": "lending",
            "disclosure_provided": False
        },
        "agent": "hermes-loan-processor",
        "session_id": "def-456"
    }
    print("\nTest Case 2:")
    evaluate(tool_call_2, rules)

    # Test Case 3: Clean call
    tool_call_3 = {
        "tool": "get_weather",
        "parameters": {
            "location": "Denver, CO"
        },
        "agent": "hermes-assistant",
        "session_id": "ghi-789"
    }
    print("\nTest Case 3:")
    evaluate(tool_call_3, rules)

    # Test Case 4: Both rules triggered
    tool_call_4 = {
        "tool": "process_application",
        "parameters": {
            "query": "Check credit for SSN 123-45-6789",
            "domain": "lending",
            "disclosure_provided": False
        },
        "agent": "hermes-loan-processor",
        "session_id": "jkl-012"
    }
    print("\nTest Case 4:")
    evaluate(tool_call_4, rules)
