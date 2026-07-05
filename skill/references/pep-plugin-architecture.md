# Seshat PEP Plugin — Architecture Reference

## Overview

The Seshat PEP (Policy Enforcement Point) is a Hermes plugin that intercepts every tool call via the `pre_tool_call` hook, evaluates it against YAML governance policies, and blocks execution if any rule returns DENY. A `post_tool_call` hook enriches the audit log with post-execution results, creating an "Agent Intent → Agent Action" chain.

## Two-Layer Governance Model

| Layer | Mechanism | Enforcement | Purpose |
|-------|-----------|-------------|---------|
| **Skill** (PDP) | Agent loads `seshat-governance` skill + context | Advisory | Agent reasons about compliance proactively |
| **Plugin** (PEP) | `pre_tool_call` hook in `seshat_pep` plugin | **Mandatory** | Intercepts every tool call, blocks DENY, logs audit |

This maps to the standard PEP/PDP split used by Microsoft Agent Governance Toolkit and described in the arXiv "Runtime Governance for AI Agents" paper.

## Plugin File Structure

```
~/.hermes/plugins/seshat_pep/
├── plugin.yaml          # Manifest: declares hooks (pre_tool_call, post_tool_call)
├── __init__.py          # Registration: register(ctx) wires hooks
├── evaluator.py         # Evaluation engine (mirrors skill's scripts/eval.py)
└── plugin_hooks.py      # Hook implementations (pre/post tool call)
```

## Hermes Plugin Hook API

### pre_tool_call

```python
def seshat_pre_tool_call(tool_name: str, args: dict, task_id: str, **kwargs):
```

- Fires before every tool execution (built-in and plugin tools alike).
- Returns `None` to allow, or `{"action": "block", "message": "..."}` to veto.
- The first matching block directive wins. Other return values are ignored.
- Fires once per tool call (3 parallel calls = 3 fires).
- Use cases: logging, audit trails, tool call counters, blocking dangerous operations, rate limiting, per-user policy enforcement.

### post_tool_call

```python
def seshat_post_tool_call(tool_name: str, args: dict, result: str,
                          task_id: str, duration_ms: int, **kwargs):
```

- Fires after every tool returns.
- `result` is always a JSON string.
- `duration_ms` measured with `time.monotonic()` around `registry.dispatch()`.
- Return value is ignored (observer only).
- Does not fire if the tool raised an unhandled exception (error is caught and returned as error JSON, and post_tool_call fires with that error string as result).

### Plugin Registration

```python
def register(ctx):
    ctx.register_hook("pre_tool_call", seshat_pre_tool_call)
    ctx.register_hook("post_tool_call", seshat_post_tool_call)
```

`register(ctx)` is called once at startup. If it crashes, the plugin is disabled but Hermes continues.

### plugin.yaml Manifest

```yaml
name: seshat_pep
version: 0.5.0
description: "Seshat Policy Enforcement Point..."
provides_hooks:
  - pre_tool_call
  - post_tool_call
```

## Configuration

The plugin reads from `~/.seshat/`:

```
~/.seshat/
├── policies/           # YAML policy files (*.yml, *.yaml) — auto-loaded, hot-reloadable
│   ├── pii_rule.yml
│   └── colorado_ai_act.yml
├── contexts/           # Governance context files
│   └── example_inspector.yaml
└── audit/              # JSONL audit log (created at runtime)
    └── seshat_audit.jsonl
```

Environment variable overrides:

| Variable | Default | What it controls |
|----------|---------|------------------|
| `SESHAT_PEP_ENABLED` | `true` | Master switch |
| `SESHAT_CONTEXT` | `example_inspector` | Which context file to load |
| `SESHAT_POLICIES_DIR` | `~/.seshat/policies` | Where to find policy YAMLs |
| `SESHAT_AUDIT_LOG` | `~/.seshat/audit/seshat_audit.jsonl` | Audit log path |

Seshat is always fail-closed (no config toggle).

## Hook Implementation Details

### pre_tool_call flow

1. **try/except wrapper** (C1 fix): entire body wrapped — any exception returns a block, never escapes
2. Check if plugin is enabled (`SESHAT_PEP_ENABLED`)
3. Check if tool is exempt (meta-tools: todo, memory, session_search, clarify, skill_view, skills_list)
4. **Self-protection check** (H1 fix): if tool is write-capable (`write_file`, `patch`, `terminal`) and args reference `~/.seshat/` or plugin dir → block immediately
5. Load rules from policies (cached, hot-reloadable by mtime check, thread-safe via `threading.Lock`)
6. Load context-derived rules (tool blocklist from `delegation_limits.blocked_tools`, context mtime tracked for hot-reload)
7. If no rules loaded → block with "no rules" error (always fail-closed, no toggle — H4 fix)
8. Construct `tool_call` dict: `{"tool": tool_name, "agent": "hermes", "session_id": task_id, "parameters": args}`
9. Call `compute_audit_entry(tool_call, rules)` — PII scanned once, passed to all rules (L3 fix)
10. Log pre_call audit entry (wrapped in try/except — write failure doesn't prevent enforcement)
11. If DENY → return `{"action": "block", "message": "Seshat PEP: DENY — ..."}`
12. If ALLOW → return `None` (proceed)

### post_tool_call flow

1. **try/except wrapper** (C1 fix): entire body wrapped — any exception is logged, never escapes
2. Check if plugin is enabled
3. Check if tool is exempt
4. Parse result JSON to extract exit_code, error, or summary
   - **H3 fix**: uses `parsed.get("error")` (truthiness), NOT `"error" in parsed` (key presence)
   - Checks `exit_code` field; non-dict JSON results get a string summary (L1 fix)
5. Build post_call audit entry with: timestamp, session_id, tool, redacted params (recursive), exit_code, duration_ms, result_summary
6. Append to audit log (wrapped in try/except — write failure doesn't crash)

## Rule Types Supported

| Rule Type | What It Checks | Denies When | Extra Fields |
|-----------|---------------|-------------|--------------|
| `pii_check` | Regex PII patterns in parameters | Email, SSN, phone, credit card, or IP detected | None |
| `disclosure_check` | Required disclosure field for consequential domains | Domain is consequential AND required_field not truthy | `required_field`, `consequential_domains` |
| `tool_blocklist` | Tool name against blocked list | Tool name is in `blocked_tools` | `blocked_tools` (auto-derived from context) |
| `tool_allowlist` | Tool name against allowed list | Tool name NOT in `allowed_tools` (if non-empty) | `allowed_tools` |
| `seshat_path_block` | Self-protection: args referencing `~/.seshat/` or plugin dir | Write-capable tool references protected path | `protected_paths` (system-derived, handled in hook before evaluation) |

## Exempt Tools

Meta-tools that bypass Seshat evaluation (they don't touch external resources):
- `todo`, `memory`, `session_search`, `clarify`, `skill_view`, `skills_list`

## Audit Log Format

### pre_call entry
```json
{
  "timestamp": "2026-07-05T12:00:00.000000+00:00",
  "session_id": "task_abc",
  "agent": "hermes",
  "tool": "terminal",
  "parameters": {"command": "[REDACTED:EMAIL]"},
  "rule_results": [{"rule_id": "PII-001", "decision": "DENY", "reason": "..."}],
  "final_decision": "DENY",
  "phase": "pre_call"
}
```

### post_call entry
```json
{
  "timestamp": "2026-07-05T12:00:01.000000+00:00",
  "session_id": "task_abc",
  "tool": "terminal",
  "phase": "post_call",
  "parameters_redacted": {"command": "ls -la"},
  "exit_code": 0,
  "duration_ms": 42,
  "result_summary": "ok"
}
```

## Key Design Decisions

1. **Fail-closed by default**: If no policies load, all tool calls are DENY. If the hook crashes, it returns a block (the entire body is wrapped in try/except). Silence is not safety.
2. **Hot-reloadable policies**: The plugin checks file mtimes on each call and reloads if files changed. No restart needed for policy edits.
3. **Context-derived rules**: `delegation_limits.blocked_tools` from the governance context YAML is automatically converted into a `tool_blocklist` rule at load time.
4. **PII redaction in audit logs**: Parameters are recursively redacted before logging — the audit trail never contains raw PII (as of v0.5; recursive scan/redaction covers nested dicts and lists).
5. **Plugin uses relative imports**: `from . import evaluator` — works when loaded as a package by Hermes. For standalone testing, add the *parent* directory to `sys.path` and import as `from seshat_pep.plugin_hooks import ...`.
6. **Shared evaluation engine**: The skill's `scripts/eval.py` and the plugin's `evaluator.py` contain the same logic. When the repo is aligned (Phase 3), the plugin will import from the repo's `eval/` module to avoid duplication.

## Testing

The evaluation engine was tested during development with 6 engine tests + 5 hook integration tests (verified manually via `execute_code`). The hook integration tests are not yet shipped as files in the repo — they were run inline during the v0.5 build. Phase 3 will add a proper `tests/` directory.

**Evaluation engine tests (shipped):**
- DENY tool call with PII (email detected, redacted in audit log)
- ALLOW clean tool call
- Fail-closed when no policies loaded
- DENY consequential domain without disclosure
- ALLOW consequential domain WITH disclosure
- Audit log JSONL integrity

**Hook integration tests (verified during development):**
- pre_tool_call blocks PII-containing command
- pre_tool_call allows clean command
- pre_tool_call exempts meta-tools (todo, memory)
- post_tool_call logs both pre_call and post_call phases
- pre_tool_call blocks context-blocklisted tool
