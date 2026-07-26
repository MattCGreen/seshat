#!/usr/bin/env python3
"""
Seshat Evaluation Engine — Verification Script
===============================================
Run this to confirm the evaluation engine in scripts/eval.py is working
correctly. Tests: PII denial + redaction, clean allow, fail-closed,
disclosure check (deny + allow), audit log integrity.

Usage:
    python scripts/test_eval.py

Expects policy files at ~/.seshat/policies/pii_rule.yml and
~/.seshat/policies/colorado_ai_act.yml. Uses a temp audit log
(cleaned up on exit).
"""

import sys
import os
import json
import tempfile

# Ensure we can import eval.py from the same directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from eval import evaluate_tool_call

POLICIES_DIR = os.path.join(os.path.expanduser("~"), ".seshat", "policies")
POLICY_FILES = [
    os.path.join(POLICIES_DIR, "pii_rule.yml"),
    os.path.join(POLICIES_DIR, "colorado_ai_act.yml"),
]


def main():
    results = []
    audit_log = tempfile.mktemp(suffix=".jsonl")

    # TEST 1: DENY — PII in parameters
    tc1 = {
        "tool": "query_database",
        "agent": "hermes",
        "session_id": "s1",
        "parameters": {
            "query": "SELECT * FROM users WHERE email='john@example.com'",
        },
    }
    e1 = evaluate_tool_call(tc1, POLICY_FILES, audit_log)
    t1 = e1["final_decision"] == "DENY"
    t1r = "example.com" not in e1["parameters"].get("query", "")
    results.append(("DENY PII + redaction", t1 and t1r))
    print(f"TEST 1 DENY PII: {'PASS' if t1 and t1r else 'FAIL'}")
    if not t1 or not t1r:
        print(f"  decision={e1['final_decision']}, redacted={e1['parameters']}")

    # TEST 2: ALLOW — clean tool call
    tc2 = {
        "tool": "terminal",
        "agent": "hermes",
        "session_id": "s2",
        "parameters": {"command": "ls -la /tmp"},
    }
    e2 = evaluate_tool_call(tc2, POLICY_FILES, audit_log)
    t2 = e2["final_decision"] == "ALLOW"
    results.append(("ALLOW clean", t2))
    print(f"TEST 2 ALLOW clean: {'PASS' if t2 else 'FAIL'}")

    # TEST 3: FAIL-CLOSED — no policies
    tc3 = {
        "tool": "terminal",
        "agent": "hermes",
        "session_id": "s3",
        "parameters": {"command": "echo hi"},
    }
    e3 = evaluate_tool_call(tc3, [], audit_log)
    t3 = e3["final_decision"] == "DENY"
    results.append(("Fail-closed", t3))
    print(f"TEST 3 Fail-closed: {'PASS' if t3 else 'FAIL'}")

    # TEST 4: DENY — consequential domain without disclosure
    tc4 = {
        "tool": "ai_decision",
        "agent": "hermes",
        "session_id": "s4",
        "parameters": {"domain": "lending", "decision": "approve"},
    }
    e4 = evaluate_tool_call(tc4, POLICY_FILES, audit_log)
    t4 = e4["final_decision"] == "DENY"
    results.append(("DENY no disclosure", t4))
    print(f"TEST 4 DENY no disclosure: {'PASS' if t4 else 'FAIL'}")

    # TEST 5: ALLOW — consequential domain WITH disclosure
    tc5 = {
        "tool": "ai_decision",
        "agent": "hermes",
        "session_id": "s5",
        "parameters": {
            "domain": "lending",
            "decision": "approve",
            "disclosure_provided": True,
        },
    }
    e5 = evaluate_tool_call(tc5, POLICY_FILES, audit_log)
    t5 = e5["final_decision"] == "ALLOW"
    results.append(("ALLOW with disclosure", t5))
    print(f"TEST 5 ALLOW with disclosure: {'PASS' if t5 else 'FAIL'}")

    # TEST 6: Audit log JSONL integrity
    with open(audit_log, "r") as f:
        lines = f.readlines()
    all_valid = False
    try:
        all_valid = all(json.loads(l.strip()) for l in lines if l.strip())
    except (json.JSONDecodeError, TypeError):
        pass
    t6 = all_valid and len(lines) == 5
    results.append(("Audit log JSONL", t6))
    print(f"TEST 6 Audit log: {len(lines)} entries, valid: {'PASS' if t6 else 'FAIL'}")

    # Summary
    print(f"\n{'=' * 50}")
    all_pass = all(r[1] for r in results)
    for name, passed in results:
        print(f"  {name}: {'PASS' if passed else 'FAIL'}")
    print(f"\n{'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")

    # Cleanup
    if os.path.exists(audit_log):
        os.unlink(audit_log)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
