import yaml
import re
import sys
import json
from pathlib import Path
from datetime import datetime, timezone


# --- Constants ---
AUDIT_LOG_PATH = "seshat_audit.jsonl"

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
    try:
        return yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as e:
        print(f"ERROR: Failed to parse {path}: {e}")
        raise

def load_policies(*paths: str) -> list[dict]:
    if not paths:
        yml_files = list(Path(".").glob("*.yml"))
        yaml_files = list(Path(".").glob("*.yaml"))
        paths = yml_files + yaml_files

    policies = []
    for path in paths:
        try:
            policy = load_policy(str(path))
            policy["source_file"] = str(path)
            policies.append(policy)
        except yaml.YAMLError as e:
            print(f"ERROR: Failed to parse {path}: {e}")
            print(f"Skipping {path} and continuing.")
        except FileNotFoundError:
            print(f"ERROR: Policy file not found: {path}")

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

# --- Redactor ---
def redact_pii(parameters: dict) -> dict:
    """
    Return a copy of parameters with PII values replaced
    by typed redaction tokens.

    Only top-level string values are redacted in v0.4.
    Nested dicts and lists pass through unchanged. This
    will be addressed in a future version.
    """
    redacted = {}
    for key, value in parameters.items():
        if not isinstance(value, str):
            redacted[key] = value
            continue

        redacted_value = value
        for pii_type, pattern in PII_PATTERNS.items():
            token = f"[REDACTED:{pii_type.upper()}]"
            redacted_value = pattern.sub(token, redacted_value)

        redacted[key] = redacted_value

    return redacted

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

def evaluate(tool_call: dict, rules: list[dict]) -> str:
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

    # Fail-closed: no rules evaluated means DENY
    if not rule_results:
        print("\nNo enabled rules to evaluate. Failing closed.")
        final_decision = "DENY"
        rule_results = [{
            "rule_id": "SYSTEM",
            "rule_name": "fail-closed-no-rules",
            "policy": "system",
            "severity": "high",
            "decision": "DENY",
            "reason": "No enabled rules available to evaluate this tool call",
            "pii_hits": []
        }]
    else:
        final_decision = "ALLOW" if all(r["decision"] == "ALLOW" for r in rule_results) else "DENY"

    redacted_params = redact_pii(tool_call.get("parameters", {}))

    print(f"\nTool:    {tool_call['tool']}")
    print(f"Agent:   {tool_call['agent']}")
    print(f"Session: {tool_call['session_id']}")
    print(f"Time:    {datetime.now(timezone.utc).isoformat()}")
    print(f"Parameters (redacted): {json.dumps(redacted_params, indent=2)}\n")

    print("Rule Results:")
    for result in rule_results:
        print(f"  Rule ID: {result['rule_id']} - {result['rule_name']} → {result['decision']}")

    reasons = [f"{r['rule_id']}: {r['reason']}" for r in rule_results if r["decision"] != "ALLOW"]

    print(f"\nFinal Decision: {final_decision}")
    print("Reasons:")
    for reason in reasons:
        print(f"  - {reason}")

    log_audit_entry(tool_call, rule_results)
    return final_decision

# --- Audit Log ---
def log_audit_entry(tool_call: dict, rule_results: list[dict]) -> None:
    final_decision = "ALLOW" if all(r["decision"] == "ALLOW" for r in rule_results) else "DENY"

    redacted_params = redact_pii(tool_call.get("parameters", {}))

    with open(AUDIT_LOG_PATH, "a") as log_file:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": tool_call["session_id"],
            "agent": tool_call["agent"],
            "tool": tool_call["tool"],
            "parameters": redacted_params,
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

    # Test Case 5: Fail-closed when no rules loaded
    print("\nTest Case 5: Empty rules list (fail-closed test)")
    empty_result = evaluate(tool_call_3, [])
    print(f"Result: {empty_result}")

    # --- Redaction Tests ---
    print("\n=== Redaction Tests ===")

    redaction_test_cases = [
        {
            "name": "Single email",
            "input": {"query": "Contact john@example.com for details"},
            "expected_contains": "[REDACTED:EMAIL]"
        },
        {
            "name": "Multiple PII types",
            "input": {"note": "Call 555-123-4567 or email jane@test.com"},
            "expected_contains_all": ["[REDACTED:PHONE]", "[REDACTED:EMAIL]"]
        },
        {
            "name": "Non-string values pass through",
            "input": {"count": 5, "active": True, "name": "test"},
            "expected_unchanged": True
        },
        {
            "name": "SSN redaction",
            "input": {"data": "SSN is 123-45-6789"},
            "expected_contains": "[REDACTED:SSN]"
        }
    ]

    for test in redaction_test_cases:
        result = redact_pii(test["input"])
        print(f"\nTest: {test['name']}")
        print(f"  Input:  {test['input']}")
        print(f"  Output: {result}")

        if "expected_contains" in test:
            found = any(test["expected_contains"] in str(v) for v in result.values())
            print(f"  Pass: {found}")
        elif "expected_contains_all" in test:
            all_found = all(
                any(token in str(v) for v in result.values())
                for token in test["expected_contains_all"]
            )
            print(f"  Pass: {all_found}")
        elif test.get("expected_unchanged"):
            print(f"  Pass: {result == test['input']}")
