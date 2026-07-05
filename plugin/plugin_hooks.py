"""
Seshat PEP Hooks — pre_tool_call and post_tool_call
====================================================
pre_tool_call: Intercepts every tool call, evaluates against YAML policies,
               returns {"action": "block", "message": ...} to DENY.
post_tool_call: Enriches the audit log with post-execution result.
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import evaluator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — resolved from ~/.seshat/ and environment
# ---------------------------------------------------------------------------
_SESHAT_HOME = Path.home() / ".seshat"
_POLICIES_DIR = _SESHAT_HOME / "policies"
_CONTEXTS_DIR = _SESHAT_HOME / "contexts"
_AUDIT_LOG = _SESHAT_HOME / "audit" / "seshat_audit.jsonl"

# Tools that bypass Seshat (meta-tools that don't touch external resources)
_EXEMPT_TOOLS = frozenset({
    "todo",
    "memory",
    "session_search",
    "clarify",
    "skill_view",
    "skills_list",
})

# Paths the agent should not be allowed to write to (self-protection)
_SESHAT_PROTECTED_PATHS = [str(_SESHAT_HOME), str(Path(__file__).parent.parent)]

# Cache: policies loaded once, hot-reloadable on file change
_policy_cache: dict = {"paths_mtime": {}, "context_mtime": None, "rules": [], "context": {}}
_cache_lock = threading.Lock()


def _get_config() -> dict:
    """Load Seshat config from environment or defaults."""
    return {
        "enabled": os.environ.get("SESHAT_PEP_ENABLED", "true").lower() == "true",
        "context": os.environ.get("SESHAT_CONTEXT", "example_inspector"),
        "policies_dir": os.environ.get("SESHAT_POLICIES_DIR", str(_POLICIES_DIR)),
        "audit_log": os.environ.get("SESHAT_AUDIT_LOG", str(_AUDIT_LOG)),
    }


def _load_context(context_name: str) -> dict:
    """Load a governance context YAML file."""
    context_path = _CONTEXTS_DIR / f"{context_name}.yaml"
    if not context_path.exists():
        logger.warning("Seshat: Context file not found: %s", context_path)
        return {}
    try:
        with open(context_path, "r", encoding="utf-8") as f:
            ctx = yaml.safe_load(f)
            if not isinstance(ctx, dict):
                logger.warning("Seshat: Context %s root is %s, expected dict", context_path, type(ctx).__name__)
                return {}
            return ctx
    except Exception as e:
        logger.error("Seshat: Failed to load context %s: %s", context_path, e)
        return {}


def _get_policy_files(policies_dir: str) -> list[str]:
    """Find all .yml/.yaml policy files in the policies directory."""
    pdir = Path(policies_dir)
    if not pdir.exists():
        return []
    files = sorted(list(pdir.glob("*.yml")) + list(pdir.glob("*.yaml")))
    return [str(f) for f in files]


def _check_policy_cache(config: dict) -> list[dict]:
    """Load policies if not cached or if files changed. Thread-safe (M7 fix).

    Returns the list of collected rules (including context-derived rules).
    """
    with _cache_lock:
        policy_files = _get_policy_files(config["policies_dir"])
        needs_reload = False

        # Check if any policy file changed (by mtime)
        current_mtimes = {}
        for pf in policy_files:
            try:
                current_mtimes[pf] = os.path.getmtime(pf)
            except OSError:
                pass

        if current_mtimes != _policy_cache["paths_mtime"]:
            needs_reload = True

        # Check if context file changed
        context_path = _CONTEXTS_DIR / f"{config['context']}.yaml"
        context_mtime = None
        if context_path.exists():
            try:
                context_mtime = os.path.getmtime(str(context_path))
            except OSError:
                pass
        if context_mtime != _policy_cache.get("context_mtime"):
            needs_reload = True

        if not needs_reload and _policy_cache["rules"]:
            return _policy_cache["rules"]

        # Reload
        if not policy_files:
            logger.warning("Seshat: No policy files found in %s", config["policies_dir"])
            _policy_cache["rules"] = []
            _policy_cache["paths_mtime"] = current_mtimes
            _policy_cache["context_mtime"] = context_mtime
            return []

        policies = evaluator.load_policies(*policy_files)
        rules = evaluator.collect_rules(policies)

        # Add context-derived rules (tool blocklist/allowlist from delegation limits)
        context = _load_context(config["context"])
        _policy_cache["context"] = context

        blocked_tools = context.get("delegation_limits", {}).get("blocked_tools", [])
        if blocked_tools:
            rules.append({
                "rule_id": "CTX-BLOCK",
                "name": "context-tool-blocklist",
                "type": "tool_blocklist",
                "severity": "high",
                "enabled": True,
                "blocked_tools": blocked_tools,
                "policy": "governance-context",
                "source_file": "context",
            })

        # Self-protection rule: block writes to ~/.seshat/ and the plugin dir (H1 fix)
        rules.append({
            "rule_id": "SESHAT-SELF",
            "name": "seshat-self-protection",
            "type": "seshat_path_block",
            "severity": "high",
            "enabled": True,
            "protected_paths": _SESHAT_PROTECTED_PATHS,
            "policy": "system",
            "source_file": "system",
        })

        _policy_cache["rules"] = rules
        _policy_cache["paths_mtime"] = current_mtimes
        _policy_cache["context_mtime"] = context_mtime

        logger.info("Seshat: Loaded %d rules from %d policy files + context '%s'",
                    len(rules), len(policy_files), config["context"])
        return rules


# ---------------------------------------------------------------------------
# Self-protection check (H1 fix)
# ---------------------------------------------------------------------------
def _args_reference_protected_paths(args: dict) -> str | None:
    """Check if any string arg references a protected path.

    Checks raw string values in args (not JSON-serialized) so that
    Windows backslash paths match correctly.

    Returns the protected path string if found, None otherwise.
    """
    def _check_value(value):
        if isinstance(value, str):
            for protected in _SESHAT_PROTECTED_PATHS:
                norm_protected = protected.replace("\\", "/").lower()
                norm_value = value.replace("\\", "/").lower()
                if norm_protected in norm_value:
                    return protected
        elif isinstance(value, dict):
            for v in value.values():
                hit = _check_value(v)
                if hit:
                    return hit
        elif isinstance(value, list):
            for item in value:
                hit = _check_value(item)
                if hit:
                    return hit
        return None

    return _check_value(args)


# ---------------------------------------------------------------------------
# pre_tool_call — THE POLICY ENFORCEMENT POINT
# ---------------------------------------------------------------------------
def seshat_pre_tool_call(tool_name: str, args: dict, task_id: str, **kwargs):
    """Intercept every tool call before execution.

    Returns:
        None — allow the tool call to proceed
        {"action": "block", "message": str} — veto the tool call

    The entire body is wrapped in try/except (C1 fix): if anything crashes,
    we fail-CLOSED by returning a block, not fail-open by letting Hermes
    skip the hook and proceed.
    """
    try:
        config = _get_config()

        if not config["enabled"]:
            return None

        # Exempt meta-tools that don't touch external resources
        if tool_name in _EXEMPT_TOOLS:
            return None

        # Self-protection: block any write to ~/.seshat/ or plugin dir (H1)
        if tool_name in ("write_file", "patch", "terminal"):
            protected_hit = _args_reference_protected_paths(args)
            if protected_hit:
                audit_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "session_id": task_id,
                    "agent": "hermes",
                    "tool": tool_name,
                    "parameters": evaluator.redact_pii(args),
                    "rule_results": [{
                        "rule_id": "SESHAT-SELF",
                        "rule_name": "seshat-self-protection",
                        "policy": "system",
                        "severity": "high",
                        "decision": "DENY",
                        "reason": f"Tool call references protected path: {protected_hit}",
                        "pii_hits": [],
                    }],
                    "final_decision": "DENY",
                    "phase": "pre_call",
                }
                try:
                    evaluator.log_audit_entry(audit_entry, config["audit_log"])
                except Exception as log_err:
                    logger.error("Seshat: Failed to write audit log: %s", log_err)
                logger.warning("Seshat: SELF-PROTECTION — blocked %s (writes to %s)", tool_name, protected_hit)
                return {
                    "action": "block",
                    "message": (
                        f"Seshat PEP: DENY (self-protection) — Tool '{tool_name}' references "
                        f"a protected governance path ({protected_hit}). "
                        f"Policy and audit files cannot be modified by agent tool calls."
                    ),
                }

        # Load rules (cached, hot-reloadable, thread-safe)
        rules = _check_policy_cache(config)

        # Fail-closed: no rules means no evaluation possible (always on — H4 fix)
        if not rules:
            audit_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": task_id,
                "agent": "hermes",
                "tool": tool_name,
                "parameters": evaluator.redact_pii(args),
                "rule_results": [{
                    "rule_id": "SYSTEM",
                    "rule_name": "fail-closed-no-rules",
                    "policy": "system",
                    "severity": "high",
                    "decision": "DENY",
                    "reason": "No policy rules loaded — Seshat cannot evaluate this tool call",
                    "pii_hits": [],
                }],
                "final_decision": "DENY",
                "phase": "pre_call",
            }
            try:
                evaluator.log_audit_entry(audit_entry, config["audit_log"])
            except Exception as log_err:
                logger.error("Seshat: Failed to write audit log: %s", log_err)
            logger.warning("Seshat: FAIL-CLOSED — blocked %s (no rules loaded)", tool_name)
            return {
                "action": "block",
                "message": (
                    "Seshat PEP: DENY (fail-closed) — No governance policy rules are loaded. "
                    "Tool calls cannot be evaluated. Check ~/.seshat/policies/ for policy files."
                ),
            }

        # Construct tool_call dict for evaluation
        tool_call = {
            "tool": tool_name,
            "agent": "hermes",
            "session_id": task_id,
            "parameters": args,
        }

        # Evaluate
        entry = evaluator.compute_audit_entry(tool_call, rules)

        # Log the pre-call decision
        entry["phase"] = "pre_call"
        try:
            evaluator.log_audit_entry(entry, config["audit_log"])
        except Exception as log_err:
            logger.error("Seshat: Failed to write audit log: %s", log_err)

        if entry["final_decision"] == "DENY":
            # Build human-readable denial reason
            deny_reasons = [
                f"  • {r['rule_id']} ({r['rule_name']}): {r['reason']}"
                for r in entry["rule_results"]
                if r["decision"] == "DENY"
            ]
            deny_text = "\n".join(deny_reasons) if deny_reasons else "  • Unknown denial reason"

            logger.warning("Seshat: DENY — blocked %s\n%s", tool_name, deny_text)
            return {
                "action": "block",
                "message": (
                    f"Seshat PEP: DENY — Tool '{tool_name}' was blocked by governance policy.\n"
                    f"Reasons:\n{deny_text}\n"
                    f"Decision logged to audit trail: {config['audit_log']}"
                ),
            }

        # ALLOW — proceed with execution
        logger.debug("Seshat: ALLOW — %s", tool_name)
        return None

    except Exception as e:
        # C1 fix: any unhandled exception → fail-CLOSED, not fail-open.
        # Hermes skips crashing hooks, so we must never let an exception escape.
        logger.error("Seshat: PRE_TOOL_CALL CRASHED — failing closed: %s", e, exc_info=True)
        return {
            "action": "block",
            "message": (
                f"Seshat PEP: DENY (fail-closed — internal error) — "
                f"The governance evaluator encountered an unexpected error: {e}. "
                f"Tool calls are blocked until the issue is resolved. "
                f"Check Seshat logs and policy files."
            ),
        }


# ---------------------------------------------------------------------------
# post_tool_call — audit enrichment (Agent Intent → Agent Action chain)
# ---------------------------------------------------------------------------
def seshat_post_tool_call(
    tool_name: str,
    args: dict,
    result: str,
    task_id: str,
    duration_ms: int,
    **kwargs,
):
    """After execution, log the actual result alongside the pre-call decision.

    Creates the 'Agent Intent → Agent Action' audit chain.
    Wrapped in try/except (C1 fix): a logging failure must not crash the hook.
    """
    try:
        config = _get_config()

        if not config["enabled"]:
            return

        if tool_name in _EXEMPT_TOOLS:
            return

        # Build post-call audit entry
        # Parse result to extract exit code / error if possible
        result_summary = ""
        exit_code = None
        try:
            parsed = json.loads(result) if isinstance(result, str) else result
            if isinstance(parsed, dict):
                # H3 fix: check error truthiness, not key presence
                if parsed.get("error"):
                    exit_code = 1
                    result_summary = str(parsed["error"])[:200]
                elif "exit_code" in parsed:
                    exit_code = parsed["exit_code"]
                    result_summary = "ok" if exit_code == 0 else "non-zero exit"
                else:
                    result_summary = str(parsed)[:200]
            elif parsed is not None:
                # Non-dict JSON (string, number, list)
                result_summary = str(parsed)[:200]
        except (json.JSONDecodeError, TypeError):
            result_summary = str(result)[:200] if result else ""

        post_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": task_id,
            "tool": tool_name,
            "phase": "post_call",
            "parameters_redacted": evaluator.redact_pii(args),
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "result_summary": result_summary,
        }

        try:
            evaluator.log_audit_entry(post_entry, config["audit_log"])
        except Exception as log_err:
            logger.error("Seshat: Failed to write post-call audit log: %s", log_err)

        logger.debug("Seshat: post_call logged — %s (%dms, exit=%s)",
                     tool_name, duration_ms, exit_code)

    except Exception as e:
        # C1 fix: never let post_tool_call crash escape (Hermes would skip it)
        logger.error("Seshat: POST_TOOL_CALL CRASHED — %s", e, exc_info=True)
