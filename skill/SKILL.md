---
name: seshat-governance
description: "Governance advisory layer (PDP) for Seshat — load governance context, evaluate tool calls against YAML policies, and reason about compliance proactively. Works with the seshat_pep plugin (PEP) for mandatory enforcement."
category: governance
---
# Seshat Governance Skill (PDP)

## Purpose

Seshat is an AI governance engine that acts as an "Inspector General" for AI agent stacks. It enforces policy guardrails on agent tool calls using a two-layer architecture:

| Layer | Mechanism | Enforcement | What it does |
|-------|-----------|-------------|--------------|
| **This skill** (PDP) | Agent loads skill + context | Advisory | Agent reasons about compliance, evaluates tool calls proactively, self-documents governance posture |
| **seshat_pep plugin** (PEP) | `pre_tool_call` hook | **Mandatory** | Intercepts every tool call, blocks DENY, logs to JSONL audit trail (append-only by convention) |

This skill is the **Policy Decision Point** — it helps the agent understand what rules apply, evaluate actions before taking them, and maintain awareness of its governance posture. The plugin is the **Policy Enforcement Point** — it provides a hard boundary that cannot be bypassed by skipping the hook. Note: policy and audit files under `~/.seshat/` must be OS-protected against the agent's own write tools (the plugin includes a self-protection rule blocking writes to Seshat paths, but defense-in-depth is recommended).

Together they implement the standard PEP/PDP split used by Microsoft Agent Governance Toolkit and described in the arXiv "Runtime Governance for AI Agents" paper — but open-source and local-first.

## When to Use

- Starting a session where you operate under a specific governance role (e.g., "Inspector", "AI Auditor", "Compliance Engineer").
- Before running an agentic workflow that should be subject to policy checks
- When you want to proactively check whether a proposed action complies with governance policies
- When you need to understand what rules are active and what they enforce
- When switching between compliance postures within a session

## Prerequisites

1. Python 3.8+ with `pyyaml` installed (`pip install pyyaml`)
2. Governance context files as YAML under `~/.seshat/contexts/`
3. Policy files as YAML under `~/.seshat/policies/`
4. (Optional but recommended) The `seshat_pep` plugin enabled for mandatory enforcement

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Agent Loop (AIAgent)                                │
│                                                      │
│  ┌───────────────────────────────────────────────┐   │
│  │  THIS SKILL (Advisory / PDP)                   │   │
│  │  seshat-governance                              │   │
│  │  - Load governance context (role, authority)   │   │
│  │  - Reason about policy implications             │   │
│  │  - Proactively evaluate before acting           │   │
│  │  - Self-document compliance posture             │   │
│  └──────────────────────┬────────────────────────┘   │
│                         │ (agent voluntarily calls)   │
│  ┌──────────────────────▼────────────────────────┐   │
│  │  PLUGIN (Enforcement / PEP)                    │   │
│  │  seshat_pep — pre_tool_call hook               │   │
│  │  Intercepts EVERY tool call                    │   │
│  │  Evaluates against YAML policies               │   │
│  │  Returns ALLOW or blocks with DENY             │   │
│  │  Logs to JSONL audit trail                     │   │
│  └──────────────────────┬────────────────────────┘   │
│                         │                              │
│  ┌──────────────────────▼────────────────────────┐   │
│  │  TOOL REGISTRY (Execution)                     │   │
│  │  registry.dispatch() → handler executes        │   │
│  └───────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Part 1: Governance Context

### What Context Does

A governance context defines *who* the agent is operating as, *what* frameworks apply, and *how* it must behave. It is a portable YAML artifact — version-controlled, shareable, inspectable.

### Context File Location

Context files live in `~/.seshat/contexts/`. List available contexts:

```bash
ls -la ~/.seshat/contexts/
```

### Context Schema

```yaml
role: "Inspector"
authority_level: "L3"
active_frameworks:
  - eu_ai_act:
      - "Article 5: Prohibited Practices"
      - "Article 9: Risk Management System"
  - nist_ai_rmf:
      - "GOVERN: Establish context"
      - "MAP: Identify risks"
delegation_limits:
  max_agent_spawn: 2
  allowed_tools:
    - file_read
    - web_search
    - pii_scan
  blocked_tools:
    - shell_exec
    - cloud_write
    - db_write
compliance_posture:
  audit_level: detailed
  fail_closed: true
  pii_redaction: true
```

### Loading Context

When the PEP plugin is enabled, context is **auto-loaded** — the plugin reads `~/.seshat/contexts/<name>.yaml` at startup and converts `delegation_limits.blocked_tools` into a `tool_blocklist` rule. No manual steps needed.

For **advisory** use (this skill), load context into session memory so the agent reasons with it:

```
memory add memory "Governance role: Inspector"
memory add memory "Governance authority: L3"
memory add memory "Active frameworks: EU AI Act Article 5, Article 9; NIST AI RMF GOVERN, MAP"
memory add memory "Delegation limits: max_agent_spawn=2, blocked_tools=[shell_exec, cloud_write, db_write]"
memory add memory "Compliance posture: audit_level=detailed, fail_closed=true, pii_redaction=true"
```

### Using Context in Reasoning

- **Tool selection**: Only use tools listed in `allowed_tools`; avoid `blocked_tools`
- **Policy awareness**: Reference active frameworks when explaining decisions
- **Delegation**: Never spawn more than `max_agent_spawn` subagents
- **Audit**: If `audit_level` is `detailed`, ensure full parameters are available for logging
- **Fail-closed**: Trust that the PEP plugin will deny any action not explicitly allowed

## Part 2: Policy Evaluation

### What Policies Do

Policies define the *rules* that govern tool calls. Each policy file contains one or more rules that Seshat evaluates against the tool's name and parameters.

### Policy File Location

Policy files live in `~/.seshat/policies/`. The PEP plugin auto-loads all `*.yml` and `*.yaml` files from this directory (hot-reloadable on file change).

### Policy YAML Schema

**CRITICAL**: The `rules` list MUST be nested inside the `policy` key (`policy.rules`), NOT as a sibling of `policy` at the top level. If `rules` sits at the top level alongside `policy:`, `collect_rules()` finds zero rules and every tool call fails-closed to DENY. A copy-and-modify template with all rule types commented is at `templates/policy.yml`.

```yaml
policy:
  name: "PII Protection Policy"
  version: "1.0"
  description: "Prohibits processing of PII without consent"
  rules:
    - rule_id: "PII-001"
      name: "prohibit-pii-processing-without-consent"
      type: "pii_check"
      severity: "high"
      enabled: true
```

### Rule Types

| Rule Type | What It Checks | Denies When |
|-----------|---------------|-------------|
| `pii_check` | Regex PII patterns in parameters | Email, SSN, phone, credit card, or IP address detected |
| `disclosure_check` | Required disclosure field for consequential domains | Domain is consequential AND `required_field` is not truthy |
| `tool_blocklist` | Tool name against blocked list | Tool name is in `blocked_tools` (auto-derived from context) |
| `tool_allowlist` | Tool name against allowed list | Tool name is NOT in `allowed_tools` (if list is non-empty) |
| `seshat_path_block` | Self-protection: args referencing `~/.seshat/` or plugin dir | Write-capable tool references a protected path (system-derived, handled in hook) |

### How to Evaluate a Tool Call (Advisory)

The agent can proactively evaluate a proposed action using `execute_code`. The evaluation engine lives in this skill's `scripts/eval.py`. To verify the engine is working, run the test script first: `python scripts/test_eval.py` (expects policy files at `~/.seshat/policies/`).

```python
import sys, os, json

# Add the skill's scripts directory to path (adjust path for your platform)
# Windows: ~/AppData/Local/hermes/skills/governance/seshat-governance/scripts
# Linux:   ~/.hermes/skills/governance/seshat-governance/scripts
skill_scripts = os.path.join(
    os.path.expanduser("~"),
    "AppData", "Local", "hermes", "skills", "governance", "seshat-governance", "scripts"
)
sys.path.insert(0, skill_scripts)

from eval import evaluate_tool_call

tool_call = {
    "tool": "query_database",
    "agent": "hermes",
    "session_id": "abc-123",
    "parameters": {
        "query": "SELECT * FROM users WHERE email='john@example.com'",
        "database": "production"
    }
}

policies_dir = os.path.join(os.path.expanduser("~"), ".seshat", "policies")
policy_files = [
    os.path.join(policies_dir, "pii_rule.yml"),
    os.path.join(policies_dir, "colorado_ai_act.yml"),
]
audit_log = os.path.join(os.path.expanduser("~"), ".seshat", "audit", "seshat_audit.jsonl")

entry = evaluate_tool_call(tool_call, policy_files, audit_log)
print(f"Decision: {entry['final_decision']}")
print(f"Reasons: {[r['reason'] for r in entry['rule_results'] if r['decision'] != 'ALLOW']}")
```

### Evaluation Logic

1. **Load policies** — `yaml.safe_load` each file
2. **Collect rules** — flatten `policy.rules` across all files, enrich with source metadata
3. **Evaluate each rule** — dispatch by `type` (pii_check, disclosure_check, tool_blocklist, tool_allowlist)
4. **Compute final decision** — fail-closed: if ANY rule returns DENY, final is DENY; if NO rules loaded, final is DENY
5. **Redact PII** — recursively walk dicts and lists, replacing detected PII values with `[REDACTED:EMAIL]`, `[REDACTED:SSN]`, etc.
6. **Build audit entry** — timestamp (ISO-8601 UTC), session_id, agent, tool, redacted parameters, per-rule results, final_decision
7. **Optional logging** — append entry as JSON line to audit log

### Fail-Closed Behavior

Seshat fails closed. This means:
- If no policy files are found → DENY all tool calls
- If no rules are enabled → DENY all tool calls
- If a policy file can't be parsed → skip it (but other policies still load)
- If the PEP plugin hook crashes → returns a block (not a skip). The hook body is wrapped in try/except so no exception can escape and cause Hermes to skip it.
- If the audit log can't be written → the decision still returns (block or allow), but the write failure is logged. Audit writes never prevent enforcement.

**Silence is not safety.** No evaluation means no action.

## Part 3: PEP Plugin (Enforcement Layer)

The `seshat_pep` plugin provides **mandatory enforcement** via Hermes's `pre_tool_call` hook. When enabled, every tool call passes through Seshat before execution — the agent cannot bypass it.

### Plugin Location

```
~/.hermes/plugins/seshat_pep/
├── plugin.yaml          # Manifest
├── __init__.py          # Registration
├── evaluator.py         # Evaluation engine (shared with this skill)
└── plugin_hooks.py      # pre_tool_call + post_tool_call hooks
```

### Enabling the Plugin

```bash
hermes plugins enable seshat_pep
```

Then restart your session.

### Configuration

Environment variables (all optional, sensible defaults):

| Variable | Default | What it controls |
|----------|---------|------------------|
| `SESHAT_PEP_ENABLED` | `true` | Master switch |
| `SESHAT_CONTEXT` | `example_inspector` | Which context file to load |
| `SESHAT_POLICIES_DIR` | `~/.seshat/policies` | Where to find policy YAMLs |
| `SESHAT_AUDIT_LOG` | `~/.seshat/audit/seshat_audit.jsonl` | Audit log path |

Seshat is always fail-closed (no config toggle). If no rules load, all tool calls are DENY.

### Exempt Tools

These meta-tools bypass Seshat (they don't touch external resources):
- `todo`, `memory`, `session_search`, `clarify`, `skill_view`, `skills_list`

### Audit Trail Format

**pre_call entry** (before execution):
```json
{
  "timestamp": "2026-07-05T12:00:00+00:00",
  "session_id": "task_abc",
  "agent": "hermes",
  "tool": "terminal",
  "parameters": {"command": "[REDACTED:EMAIL]"},
  "rule_results": [{"rule_id": "PII-001", "decision": "DENY", "reason": "..."}],
  "final_decision": "DENY",
  "phase": "pre_call"
}
```

**post_call entry** (after execution):
```json
{
  "timestamp": "2026-07-05T12:00:01+00:00",
  "session_id": "task_abc",
  "tool": "terminal",
  "phase": "post_call",
  "parameters_redacted": {"command": "ls -la"},
  "exit_code": 0,
  "duration_ms": 42,
  "result_summary": "ok"
}
```

The pre_call + post_call pair creates the **Agent Intent → Agent Action** audit chain required for regulatory compliance.

### PEP Architecture Details

For the full plugin architecture, hook API signatures, design decisions, and key implementation notes, see `references/pep-plugin-architecture.md`. For the v0.5 code review findings (critical/high fixes and known limitations), see `references/code-review-findings.md`.

## Design Principles

1. **Fail closed** — No evaluation means no action. Silence is not safety. If the hook crashes, it returns a block (not a skip).
2. **Append-only audit (by convention)** — Decisions are appended, never overwritten. No hash chaining yet (roadmap). Use OS file permissions for tamper resistance.
3. **Policy as code** — Rules are human-readable YAML, version-controlled alongside the engine.
4. **Separation of concerns** — Loader, scanner, evaluator, and logger are distinct functions.
5. **Bootstrap governance** — Built the way it enforces: human authority over AI capability, local hardware, no black box.
6. **PEP/PDP split** — Advisory reasoning (this skill) + mandatory enforcement (plugin) = full governance coverage.
7. **Self-protection** — The plugin blocks agent writes to `~/.seshat/` and the plugin directory. Defense-in-depth (OS permissions) is recommended.

## Pitfalls

- **YAML schema**: `rules` MUST be inside `policy:` (as `policy.rules`), not as a top-level sibling. Wrong nesting = zero rules = everything fails-closed to DENY.
- **Plugin relative imports**: The plugin uses `from . import evaluator` — works when Hermes loads it as a package, but for standalone testing you must add the *parent* directory to `sys.path` and import as `from seshat_pep.plugin_hooks import ...`, not the plugin directory directly.
- **Hook crash = fail-OPEN in Hermes**: Hermes catches and SKIPS crashing hooks — the tool call proceeds unaudited. This is the most dangerous failure mode for a PEP. The Seshat hooks wrap their entire body in `try/except Exception` that returns a block on any error. Never remove this wrapper. When adding new logic to a hook, add it INSIDE the try block.
- **Self-protection path check on Windows**: The `_args_reference_protected_paths` function checks raw string values in args (NOT JSON-serialized) because `json.dumps` doubles backslashes on Windows, causing path mismatches. If you change the path-checking logic, always test with Windows backslash paths.
- **YAML root validation**: `load_policies` validates each parsed YAML root is a dict. Non-dict YAML (empty file, scalar, top-level list) is skipped — it does NOT crash the hook. If you add new YAML loading code, maintain this validation.
- **PII redaction depth**: As of v0.5 (post-review fix), PII scan and redaction are **recursive** — they walk nested dicts and lists. Earlier versions only scanned top-level strings, which was both an ALLOW bypass and a raw-PII-in-audit-log issue. If you revert or fork, do NOT remove the recursive `_scan_value` / `_redact_value` helpers.
- **Hot-reload**: The PEP plugin checks both policy file mtimes AND context file mtime on each call. No restart needed for policy edits or context changes. The cache is guarded by `threading.Lock` for concurrent tool-call safety.
- **Public-repo naming**: Anything bound for the public GitHub repo must use GENERIC names — e.g., `example_inspector.yaml` with `role: Inspector`, never TSA-specific or personally-identifying context names. Matt's real role-specific contexts stay local-only in `~/.seshat/contexts/` and are never pushed. When prepping repo artifacts, scrub role/employer references from filenames, YAML values, AND the plugin's default `SESHAT_CONTEXT` in `plugin_hooks.py` (all three must agree on the generic name).
- **Pre-push external review**: Matt wants a second-model code review (via delegate_task) before pushing to the repo. Subagents inherit the parent session's model — to review with a specific model, the user switches the session model first (via /model), then delegate. Include in the delegation context: absolute file paths, the verified Hermes hook API facts (pre_tool_call returns {"action": "block", "message": str} to veto; hook exceptions are caught and SKIPPED by Hermes — relevant to fail-closed claims), and known/accepted limitations so the reviewer doesn't re-report documented items.

## Extending

- **Add new rule types**: Add a new clause in `evaluate_rule()` in `scripts/eval.py` (and in the plugin's `evaluator.py`)
- **Change PII patterns**: Modify the `PII_PATTERNS` dict
- **Change audit log format**: Adjust the entry construction in `compute_audit_entry()`
- **Add semantic checks (Phase 4)**: Future `llm_check` rule type that uses a local LLM for semantic policy interpretation
- **Version control**: Keep `~/.seshat/` under Git for auditable policy history

## Verification

Run `scripts/test_eval.py` to confirm the evaluation engine works. It tests: PII denial + redaction, clean allow, fail-closed, disclosure check (deny + allow), and audit log JSONL integrity. Expects policy files at `~/.seshat/policies/`.

---
*This skill is the advisory layer of Seshat's two-layer governance model. It helps the agent reason about compliance proactively. The seshat_pep plugin provides the hard enforcement boundary. Together they implement bootstrap governance: human authority over AI capability, local-first, no black box.*
