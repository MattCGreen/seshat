"""
Seshat v0.5 — Test Suite
=========================
20 tests covering the evaluation engine and plugin hook logic.

Run: python tests/test_evaluator.py
"""
import sys
import os
import json
import tempfile

# Add eval/ and plugin/ to path
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_DIR, "eval"))
sys.path.insert(0, os.path.join(REPO_DIR, "plugin"))

from evaluator import (
    evaluate_tool_call, scan_for_pii, redact_pii,
    load_policies, collect_rules, compute_audit_entry,
)


def run_tests():
    results = []
    passed = 0

    def check(name, cond):
        nonlocal passed
        results.append((name, cond))
        if cond:
            passed += 1
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")

    # --- Setup ---
    policies_dir = os.path.join(REPO_DIR, "policies")
    policy_files = [
        os.path.join(policies_dir, "pii_rule.yml"),
        os.path.join(policies_dir, "colorado_ai_act.yml"),
    ]
    audit_log = tempfile.mktemp(suffix=".jsonl")

    print("=== Evaluation Engine (12 tests) ===")

    # TEST 1: DENY PII
    tc = {"tool": "terminal", "agent": "h", "session_id": "s1",
          "parameters": {"cmd": "echo john@example.com"}}
    e = evaluate_tool_call(tc, policy_files, audit_log)
    check("DENY PII", e["final_decision"] == "DENY"
          and "example.com" not in e["parameters"]["cmd"])

    # TEST 2: ALLOW clean
    tc2 = {"tool": "terminal", "agent": "h", "session_id": "s2",
           "parameters": {"cmd": "ls -la"}}
    e2 = evaluate_tool_call(tc2, policy_files, audit_log)
    check("ALLOW clean", e2["final_decision"] == "ALLOW")

    # TEST 3: Fail-closed no policies
    tc3 = {"tool": "terminal", "agent": "h", "session_id": "s3",
           "parameters": {"cmd": "echo hi"}}
    e3 = evaluate_tool_call(tc3, [], audit_log)
    check("Fail-closed no policies", e3["final_decision"] == "DENY")

    # TEST 4: DENY consequential without disclosure
    tc4 = {"tool": "ai_decision", "agent": "h", "session_id": "s4",
           "parameters": {"domain": "lending", "decision": "approve"}}
    e4 = evaluate_tool_call(tc4, policy_files, audit_log)
    check("DENY no disclosure", e4["final_decision"] == "DENY")

    # TEST 5: ALLOW consequential WITH disclosure
    tc5 = {"tool": "ai_decision", "agent": "h", "session_id": "s5",
           "parameters": {"domain": "lending", "decision": "approve",
                          "disclosure_provided": True}}
    e5 = evaluate_tool_call(tc5, policy_files, audit_log)
    check("ALLOW with disclosure", e5["final_decision"] == "ALLOW")

    # TEST 6: Nested dict PII DENY (C2 fix)
    tc7 = {"tool": "api_call", "agent": "h", "session_id": "s7",
           "parameters": {"payload": {"email": "john@example.com"}}}
    e7 = evaluate_tool_call(tc7, policy_files, audit_log)
    check("C2 Nested dict PII DENY", e7["final_decision"] == "DENY")

    # TEST 7: Nested PII redacted in audit (C2 fix)
    check("C2 Nested PII redacted",
          "example.com" not in json.dumps(e7["parameters"]))

    # TEST 8: PII in list DENY + redacted (C2 fix)
    tc9 = {"tool": "api_call", "agent": "h", "session_id": "s9",
           "parameters": {"emails": ["a@b.com", "c@d.org"]}}
    e9 = evaluate_tool_call(tc9, policy_files, audit_log)
    check("C2 PII in list DENY+redacted",
          e9["final_decision"] == "DENY"
          and "b.com" not in json.dumps(e9["parameters"]))

    # TEST 9: Malformed YAML doesn't crash (C1 fix)
    bad_policy = tempfile.mktemp(suffix=".yml")
    with open(bad_policy, "w") as f:
        f.write("- just a list\n- not a dict\n")
    e10 = evaluate_tool_call(tc2, [bad_policy], audit_log)
    os.unlink(bad_policy)
    check("C1 Malformed YAML doesn't crash", e10["final_decision"] == "DENY")

    # TEST 10: Empty YAML doesn't crash (C1 fix)
    empty_policy = tempfile.mktemp(suffix=".yml")
    with open(empty_policy, "w") as f:
        f.write("")
    e11 = evaluate_tool_call(tc2, [empty_policy], audit_log)
    os.unlink(empty_policy)
    check("C1 Empty YAML doesn't crash", e11["final_decision"] == "DENY")

    # TEST 11: Non-serializable args don't crash (C1 fix)
    tc12 = {"tool": "terminal", "agent": "h", "session_id": "s12",
            "parameters": {"o": object()}}
    e12 = evaluate_tool_call(tc12, policy_files, audit_log)
    check("C1 Non-serializable args", e12["final_decision"] in ("ALLOW", "DENY"))

    # TEST 12: Audit log JSONL integrity
    with open(audit_log, "r") as f:
        lines = f.readlines()
    all_valid = all(json.loads(l.strip()) for l in lines if l.strip())
    check("Audit JSONL valid", all_valid)

    # --- Plugin Hook Tests ---
    print("\n=== Plugin Hooks (8 tests) ===")

    # Import plugin hooks (need parent dir for package import)
    plugin_parent = os.path.join(REPO_DIR)
    sys.path.insert(0, plugin_parent)
    for mod_name in list(sys.modules.keys()):
        if "plugin_hooks" in mod_name or "seshat_pep" in mod_name:
            del sys.modules[mod_name]

    # Import plugin as a package
    import importlib
    plugin_pkg = importlib.import_module("plugin.plugin_hooks")

    os.environ["SESHAT_AUDIT_LOG"] = tempfile.mktemp(suffix=".jsonl")

    def reset_cache():
        plugin_pkg._policy_cache = {
            "paths_mtime": {}, "context_mtime": None,
            "rules": [], "context": {}
        }

    # TEST 13: BLOCKS PII
    reset_cache()
    r = plugin_pkg.seshat_pre_tool_call(
        "terminal", {"command": "curl ?email=j@x.com"}, "t1")
    check("BLOCKS PII", r is not None and r.get("action") == "block")

    # TEST 14: ALLOWS clean
    reset_cache()
    check("ALLOWS clean",
          plugin_pkg.seshat_pre_tool_call(
              "terminal", {"command": "ls -la"}, "t2") is None)

    # TEST 15: Exempt meta-tools
    check("Exempt meta-tools",
          plugin_pkg.seshat_pre_tool_call("todo", {"todos": []}, "t3") is None)

    # TEST 16: post_tool_call logs both phases
    plugin_pkg.seshat_post_tool_call(
        "terminal", {"command": "ls"},
        json.dumps({"output": "ok", "exit_code": 0, "error": None}),
        "t2", 42)
    with open(os.environ["SESHAT_AUDIT_LOG"], "r") as f:
        hook_lines = f.readlines()
    phases = [json.loads(l.strip()).get("phase", "?")
              for l in hook_lines if l.strip()]
    check("post_tool_call audit",
          "pre_call" in phases and "post_call" in phases)

    # TEST 17: H3 — error:null not misclassified
    check("H3 error:null not misclassified",
          json.loads(hook_lines[-1].strip())["exit_code"] == 0)

    # TEST 18: Context blocklist
    reset_cache()
    r = plugin_pkg.seshat_pre_tool_call(
        "shell_exec", {"command": "rm"}, "t4")
    check("Context blocklist",
          r is not None and r.get("action") == "block")

    # TEST 19: H1 — Self-protection blocks writes to ~/.seshat/
    reset_cache()
    seshat_home = os.path.join(os.path.expanduser("~"), ".seshat")
    r = plugin_pkg.seshat_pre_tool_call(
        "write_file",
        {"path": os.path.join(seshat_home, "evil.yml"), "content": "x"},
        "t6")
    check("H1 Self-protection",
          r is not None and r.get("action") == "block"
          and "protected" in r.get("message", "").lower())

    # TEST 20: C1 — Circular reference → fail-closed block
    reset_cache()
    circular = {}
    circular["self"] = circular
    r = plugin_pkg.seshat_pre_tool_call(
        "terminal", {"command": circular}, "t7")
    check("C1 Circular ref block",
          r is not None and r.get("action") == "block")

    # --- Summary ---
    total = len(results)
    print(f"\n{'=' * 50}")
    print(f"Results: {passed}/{total} passed")
    if passed < total:
        for name, cond in results:
            if not cond:
                print(f"  FAILED: {name}")
    print(f"\n{'ALL TESTS PASSED' if passed == total else 'SOME TESTS FAILED'}")

    # Cleanup
    os.unlink(audit_log)
    os.unlink(os.environ["SESHAT_AUDIT_LOG"])

    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
