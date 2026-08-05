"""
Seshat Evaluator — Policy evaluation engine
============================================
Adapted from Seshat v0.4 (pii_evaluator.py) for the PEP plugin.
Evaluates tool calls against YAML policies: PII detection, disclosure
checks, fail-closed decisions, and JSONL audit logging.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII Patterns — regex-based detection (LLM semantic in Phase 4)
# ---------------------------------------------------------------------------
PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\(?\b\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){15,16}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

# PII field names that, if present as URL query parameter keys, indicate
# the corresponding value should be scanned for PII content.
_PII_QUERY_KEYS = frozenset({
    "email", "e-mail", "mail",
    "phone", "tel", "telephone", "mobile",
    "ssn", "social_security",
    "name", "full_name", "firstname", "lastname", "first_name", "last_name",
    "address", "street", "city", "zip", "zipcode", "postal",
    "dob", "birthday", "birthdate",
    "account", "account_id", "acct",
    "token", "api_key", "apikey", "key",
    "password", "passwd", "pwd",
    "user", "username", "userid", "user_id",
})

# URL scheme detection — strings matching this are treated as URLs and
# routed to _scan_url instead of the free-text PII scanner.
_URL_SCHEMES = frozenset({"http", "https", "ftp", "ws", "wss"})


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------
def load_policy(path: str) -> dict:
    """Load a single YAML policy file. Raises on parse failure."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_policies(*paths: str) -> list[dict]:
    """Load multiple policy files, skipping unreadable ones.

    Validates each parsed root is a dict — non-dict YAML (empty file,
    scalar, top-level list) is skipped with a warning so it cannot
    crash the hook (C1 fix).
    """
    policies = []
    for path in paths:
        try:
            policy = load_policy(str(path))
            if not isinstance(policy, dict):
                logger.warning(
                    "Seshat: Policy %s root is %s, expected dict — skipping",
                    path, type(policy).__name__,
                )
                continue
            policy["source_file"] = str(path)
            policies.append(policy)
        except Exception as e:
            logger.warning("Seshat: Failed to load policy %s: %s", path, e)
    return policies


def collect_rules(policies: list[dict]) -> list[dict]:
    """Flatten rules from all loaded policies, enriched with source metadata."""
    rules = []
    for policy in policies:
        policy_dict = policy.get("policy", {})
        if not isinstance(policy_dict, dict):
            continue
        policy_name = policy_dict.get("name", "unknown")
        for rule in policy_dict.get("rules", []):
            rules.append({
                **rule,
                "policy": policy_name,
                "source_file": policy.get("source_file", ""),
            })
    return rules


# ---------------------------------------------------------------------------
# PII scanning and redaction (recursive — C2 fix)
# ---------------------------------------------------------------------------
def scan_for_pii(parameters: dict) -> list[dict]:
    """Scan parameter values for PII patterns. Returns list of hits.

    Recursively walks nested dicts and lists so that PII inside
    structured parameters (e.g., {"payload": {"email": "a@b.com"}})
    is detected, not just top-level strings.
    """
    hits = []
    _scan_value(parameters, "", hits)
    return hits


def _looks_like_url(value: str) -> bool:
    """Check if a string is a URL that should use structured scanning.
    Returns True for strings with a recognized scheme (http://, https://, etc.)
    or strings that start with www. and contain a dot in the domain portion.
    Bare domain names without a scheme are NOT treated as URLs -- only
    strings with an explicit scheme or a clear www. prefix, to avoid
    misclassifying ordinary text as URLs.
    """
    if not isinstance(value, str) or len(value) < 8:
        return False
    lowered = value.lower().lstrip()
    for scheme in _URL_SCHEMES:
        prefix = scheme + "://"
        if lowered.startswith(prefix):
            return True
    if lowered.startswith("www."):
        if "/" in lowered[4:]:
            return True
    return False


def _scan_url(url: str, field_path: str, hits: list):
    """Scan a URL for PII using structured parsing.

    URL path segments often contain numeric IDs (e.g., product.4201002520)
    that false-positive on the phone and IP address regexes because periods
    in the path act as digit-group separators. This function:

    1. Scans query parameter VALUES for all PII types (PII can legitimately
       appear in query strings on poorly designed endpoints).
    2. Scans the hostname for IP addresses (raw IP URLs).
    3. Does NOT scan the URL path -- path segments are server-defined routes,
       product IDs, and slugs, not user data.

    PII in query strings is detected when the parameter key is in a known
    PII field name set (_PII_QUERY_KEYS) -- this catches ?email=...&phone=...
    while allowing ?s=searchterm&product_id=12345 to pass through.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        # If URL parsing fails, fall back to full-text scan
        for pii_type, pattern in PII_PATTERNS.items():
            if pattern.search(url):
                hits.append({"field": field_path or "<root>", "pii_type": pii_type})
        return

    # 1. Check if the hostname is a raw IP address
    if parsed.hostname:
        if PII_PATTERNS["ip_address"].search(parsed.hostname):
            hits.append({
                "field": f"{field_path}.host" if field_path else "host",
                "pii_type": "ip_address",
            })

    # 2. Scan query parameter values
    if parsed.query:
        try:
            params = parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            params = {}
        for key, values in params.items():
            key_lower = key.lower()
            if key_lower in _PII_QUERY_KEYS:
                for val in values:
                    for pii_type, pattern in PII_PATTERNS.items():
                        if pattern.search(val):
                            hits.append({
                                "field": f"{field_path}.query.{key}" if field_path else f"query.{key}",
                                 "pii_type": pii_type,
                            })


def _scan_value(value, field_path: str, hits: list):
    """Recursively scan a value for PII patterns.

    URL-aware: if the string is a URL (has a scheme like http:// or https://),
    it is routed to _scan_url which parses the URL structurally and scans
    only query parameter values and the hostname, not the path. This prevents
    false positives on product IDs and URL path segments that match phone or
    IP patterns due to period delimiters.
    """
    if isinstance(value, str):
        if _looks_like_url(value):
            _scan_url(value, field_path, hits)
        else:
            for pii_type, pattern in PII_PATTERNS.items():
                if pattern.search(value):
                    hits.append({"field": field_path or "<root>", "pii_type": pii_type})
    elif isinstance(value, dict):
        for key, val in value.items():
            child_path = f"{field_path}.{key}" if field_path else key
            _scan_value(val, child_path, hits)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            child_path = f"{field_path}[{i}]" if field_path else f"[{i}]"
            _scan_value(item, child_path, hits)


def redact_pii(parameters: dict) -> dict:
    """Return a copy of parameters with PII values replaced by redaction tokens.

    Recursively walks nested dicts and lists so that PII inside
    structured parameters is redacted before reaching the audit log.
    """
    return _redact_value(parameters)


def _redact_value(value):
    """Recursively redact PII from a value (dict, list, or string)."""
    if isinstance(value, str):
        redacted = value
        for pii_type, pattern in PII_PATTERNS.items():
            token = f"[REDACTED:{pii_type.upper()}]"
            redacted = pattern.sub(token, redacted)
        return redacted
    elif isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------
def evaluate_rule(tool_call: dict, rule: dict, pii_hits: list[dict]) -> tuple[str, str]:
    """Evaluate a single rule against a tool call.

    Takes pre-computed pii_hits so scanning happens once per tool call,
    not once per rule (L3 fix).

    Returns:
        (decision, reason) where decision is "ALLOW", "DENY", or "UNKNOWN"
    """
    rule_type = rule.get("type", "")

    if rule_type == "pii_check":
        if pii_hits:
            return "DENY", "PII detected in parameters without consent check"
        return "ALLOW", "No PII patterns detected"

    elif rule_type == "disclosure_check":
        domain = tool_call.get("parameters", {}).get("domain")
        required_field = rule.get("required_field", "")
        disclosure_provided = tool_call.get("parameters", {}).get(required_field, False)
        consequential_domains = rule.get("consequential_domains", [])

        if domain in consequential_domains:
            if not disclosure_provided:
                return "DENY", f"Consequential domain '{domain}' without required disclosure '{required_field}'"
            return "ALLOW", "Disclosure provided for consequential domain"
        return "ALLOW", "Domain not consequential or disclosure not applicable"

    elif rule_type == "tool_blocklist":
        tool_name = tool_call.get("tool", "")
        blocked_tools = rule.get("blocked_tools", [])
        if tool_name in blocked_tools:
            return "DENY", f"Tool '{tool_name}' is blocked by policy"
        return "ALLOW", "Tool not in blocklist"

    elif rule_type == "tool_allowlist":
        tool_name = tool_call.get("tool", "")
        allowed_tools = rule.get("allowed_tools", [])
        if allowed_tools and tool_name not in allowed_tools:
            return "DENY", f"Tool '{tool_name}' not in allowlist"
        return "ALLOW", "Tool in allowlist"

    elif rule_type == "seshat_path_block":
        # Self-protection rule: always ALLOW here — the actual path check
        # is done in the hook before calling compute_audit_entry, and a
        # block is returned directly without reaching this code path.
        # This rule exists so the rule-type table is complete and the
        # type isn't flagged as UNKNOWN.
        return "ALLOW", "Self-protection path check (handled in hook)"

    else:
        return "UNKNOWN", f"Rule type '{rule_type}' not supported"


def compute_audit_entry(tool_call: dict, rules: list[dict]) -> dict:
    """Compute a full audit entry for a tool call against collected rules.

    Scans for PII once, then passes the results to each rule (L3 fix).
    """
    # Scan for PII once (not per-rule)
    pii_hits = scan_for_pii(tool_call.get("parameters", {}))

    rule_results = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue

        decision, reason = evaluate_rule(tool_call, rule, pii_hits)
        rule_results.append({
            "rule_id": rule.get("rule_id", "UNKNOWN"),
            "rule_name": rule.get("name", "unnamed"),
            "policy": rule.get("policy", "unknown"),
            "severity": rule.get("severity", "medium"),
            "decision": decision,
            "reason": reason,
            "pii_hits": pii_hits if decision == "DENY" else [],
        })

    # Fail-closed: no rules evaluated means DENY
    if not rule_results:
        final_decision = "DENY"
        rule_results = [{
            "rule_id": "SYSTEM",
            "rule_name": "fail-closed-no-rules",
            "policy": "system",
            "severity": "high",
            "decision": "DENY",
            "reason": "No enabled rules available to evaluate this tool call",
            "pii_hits": [],
        }]
    else:
        final_decision = "ALLOW" if all(
            r["decision"] == "ALLOW" for r in rule_results
        ) else "DENY"

    redacted_params = redact_pii(tool_call.get("parameters", {}))

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": tool_call.get("session_id", "unknown"),
        "agent": tool_call.get("agent", "unknown"),
        "tool": tool_call.get("tool", "unknown"),
        "parameters": redacted_params,
        "rule_results": rule_results,
        "final_decision": final_decision,
    }


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------
def log_audit_entry(entry: dict, audit_log_path: str) -> None:
    """Append an audit entry to the JSONL audit log.

    Uses default=str to handle non-JSON-serializable values gracefully
    (C1 fix — prevents TypeError crashes on exotic arg types).
    """
    log_path = Path(audit_log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def evaluate_tool_call(
    tool_call: dict,
    policy_paths: list[str],
    audit_log_path: str | None = None,
) -> dict:
    """Evaluate a tool call against YAML policies.

    Args:
        tool_call: Dict with keys 'tool', 'agent', 'session_id', 'parameters'.
        policy_paths: List of paths to YAML policy files.
        audit_log_path: If provided, append the audit entry to this JSONL file.

    Returns:
        Audit entry dict with 'final_decision' key ("ALLOW" or "DENY").
    """
    policies = load_policies(*policy_paths)
    rules = collect_rules(policies)
    entry = compute_audit_entry(tool_call, rules)

    if audit_log_path:
        log_audit_entry(entry, audit_log_path)

    return entry
