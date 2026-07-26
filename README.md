# Seshat

Seshat is an AI governance engine that acts as a Policy Enforcement Point (PEP) for AI agent tool calls. Named after the Egyptian goddess of records and measurement, Seshat intercepts agent actions, evaluates them against YAML-defined policies, and logs every decision to an append-only audit trail.

> **Note:** The audit trail is append-only by convention (not cryptographically enforced). Hash chaining is on the roadmap. See [Design Principles](#design-principles) below.

## What It Does

1. An AI agent requests a tool call (e.g., query a database)
2. Seshat's PEP plugin intercepts the call via Hermes Agent's `pre_tool_call` hook
3. Parameters are scanned against policy rules (PII detection, disclosure checks, tool blocklists)
4. Returns ALLOW or DENY with reasoning
5. Logs the full decision (pre-call + post-call) to a JSONL audit trail

Every decision is logged. No exceptions. If Seshat can't evaluate, the agent doesn't act.

## Architecture: Two-Layer Governance (PEP/PDP)

| Layer | Mechanism | Enforcement | What it does |
|-------|-----------|-------------|--------------|
| **Skill** (PDP) | Agent loads `seshat-governance` skill + context | Advisory | Agent reasons about compliance proactively |
| **Plugin** (PEP) | `pre_tool_call` hook in `seshat_pep` plugin | **Mandatory** | Intercepts every tool call, blocks DENY, logs audit |

This maps to the standard PEP/PDP split used by Microsoft Agent Governance Toolkit and described in the arXiv "Runtime Governance for AI Agents" paper — but open-source and local-first.

## Current Status

**v0.6-pre — Four Framework Coverage**

- [x] YAML policy files with PII detection rules
- [x] Regex-based PII scanner (email, SSN, phone, credit card, IP) — recursive (nested dicts/lists)
- [x] Policy evaluator with ALLOW/DENY decisions
- [x] JSONL append-only audit trail (pre-call + post-call)
- [x] Multi-rule evaluation (PII, disclosure, tool blocklist, tool allowlist)
- [x] PII redaction in audit logs (recursive)
- [x] Hermes plugin (`seshat_pep`) with `pre_tool_call` / `post_tool_call` hooks
- [x] Fail-closed: hook crashes return block, not skip
- [x] Self-protection: agent cannot write to `~/.seshat/` or plugin directory
- [x] Hot-reloadable policies (mtime-based, thread-safe cache)
- [x] Context-derived tool blocklists from governance context YAML
- [x] Governance skill (`seshat-governance`) — advisory layer (PDP)
- [x] Four framework policy mappings: EU AI Act, NIST AI RMF, ISO 42001, Colorado SB 24-205
- [x] Example context with all four frameworks and real Hermes tool names
- [ ] Integration with additional agent frameworks
- [ ] Hash chaining for audit trail integrity (roadmap)
- [ ] LLM semantic checks (Phase 4 — roadmap)

## Repository Structure

```
seshat/
├── README.md               # This file
├── CHANGELOG.md            # Release history and changes
├── LICENSE                 # Apache 2.0
├── eval/                   # Core evaluation engine
│   ├── __init__.py
│   └── evaluator.py        # PII scan, rule dispatch, audit entries, fail-closed
├── policies/               # Example policy files (framework mappings)
│   ├── pii_rule.yml        # PII detection rule (EU AI Act Art 9)
│   ├── colorado_ai_act.yml # Consequential domain disclosure (CO SB 24-205)
│   ├── nist_ai_rmf.yml     # NIST AI RMF controls (GOVERN, MAP, MEASURE)
│   └── iso_42001.yml       # ISO 42001 controls (Clauses 8.2, 8.3, 8.4)
├── contexts/               # Example governance contexts
│   └── example_inspector.yaml
├── plugin/                 # Hermes PEP plugin
│   ├── plugin.yaml         # Manifest
│   ├── __init__.py         # Registration
│   ├── evaluator.py        # Evaluation engine (mirrors eval/evaluator.py)
│   └── plugin_hooks.py     # pre_tool_call + post_tool_call hooks
├── skill/                  # Hermes governance skill (PDP)
│   ├── SKILL.md            # Full skill documentation
│   ├── scripts/
│   │   ├── eval.py         # Evaluation engine (mirrors eval/evaluator.py)
│   │   └── test_eval.py    # Standalone test script (6 tests)
│   ├── templates/
│   │   └── policy.yml      # Commented policy template
│   └── references/
│       ├── pep-plugin-architecture.md
│       └── code-review-findings.md
└── tests/
    └── test_evaluator.py   # Test suite (24 tests)
```

## Quick Start

### Requirements

- Python 3.10+
- PyYAML
- [Hermes Agent](https://hermes-agent.nousresearch.com/) (for the PEP plugin)

### Install

**Option A — Using install.sh (recommended):**

```bash
bash install.sh          # install everything (plugin + skill + config)
bash install.sh plugin   # plugin only
bash install.sh skill    # skill only
bash install.sh config   # policies + contexts only
```

**Option B — Manual:**

1. Copy `plugin/` to `~/.hermes/plugins/seshat_pep/`
2. Copy `skill/` to `~/.hermes/skills/governance/seshat-governance/`
3. Copy `policies/` to `~/.seshat/policies/`
4. Copy `contexts/` to `~/.seshat/contexts/`
5. Enable: `hermes plugins enable seshat_pep`
6. Restart your Hermes session

### Run Tests

```bash
python tests/test_evaluator.py
```

## Design Principles

1. **Fail closed** — No evaluation means no action. If the hook crashes, it returns a block.
2. **Append-only audit (by convention)** — Decisions are appended, never overwritten. Hash chaining is on the roadmap.
3. **Policy as code** — Rules are human-readable YAML, version-controlled alongside the engine.
4. **Separation of concerns** — Loader, scanner, evaluator, and logger are distinct functions.
5. **Bootstrap governance** — Built the way it enforces: human authority over AI capability, local hardware, no black box.
6. **PEP/PDP split** — Advisory reasoning (skill) + mandatory enforcement (plugin) = full governance coverage.
7. **Self-protection** — The plugin blocks agent writes to `~/.seshat/` and the plugin directory.

## How This Was Built

I'm not a software engineer. I'm an AI compliance professional building tools to solve problems I see in the field.

Seshat's code was:

- **Generated** using local LLMs (Ollama) and Hermes Agent
- **Reviewed and verified** using cloud LLMs (Claude, GLM)
- **Code-reviewed** by Claude Fable 5 before each release
- **Directed, tested, and maintained** by me

I specify the requirements, review every function, verify the output matches intent, and make the design decisions. The LLMs write code. I own the architecture and the accountability.

This is how I believe AI tooling should work: human authority over AI capability. Seshat is built the same way it's designed to enforce, and be an audit asset.

## License

Apache 2.0

---

Author: Matthew Green
