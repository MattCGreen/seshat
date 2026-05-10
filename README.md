# Seshat

Seshat is an AI governance engine that helps human operators enforce policy guardrails on AI agent tool calls.

Named after the Egyptian goddess of records and measurement, Seshat intercepts agent actions, evaluates them against YAML-defined policies, and logs every decision to an append-only audit trail.

## What It Does

1. An AI agent requests a tool call (e.g., query a database)
2. Seshat scans the parameters against policy rules
3. Returns ALLOW or DENY with reasoning
4. Logs the full decision to a JSONL audit file

Every decision is logged. 
No exceptions. 
If Seshat can't evaluate, the agent doesn't act.

## Current Status

**v0.2 — Proof of Concept**

- [x] YAML policy file with PII detection rules
- [x] Regex-based PII scanner (email, SSN)
- [x] Policy evaluator with ALLOW/DENY decisions
- [x] JSONL append-only audit log
- [x] Multi-rule evaluation
- [x] Colorado AI Act disclosure rule
- [x] Configurable PII patterns
- [ ] Redaction of PII in audit logs
- [ ] Integration with agent frameworks

## Quick Start

### Requirements

- Python 3.10+
- PyYAML

```bash
pip install pyyaml
```

### Run
python pii_evaluator.py

This runs two test cases against the PII policy and writes decisions to seshat_audit.jsonl.

Example Output:

Tool:    query_database

Agent:   hermes-data-processor

Session: abc-123

Rule:    PII-001 — prohibit-pii-processing-without-consent

DENY

Reason: PII detected in parameters without consent check
  - field 'query' contains EMAIL



## Design Principles
Fail closed. No evaluation means no action.
Append-only logging. Decisions are never overwritten or deleted.
Policy as code. Rules are human-readable YAML, version controlled alongside the engine.
Separation of concerns. Loader, scanner, evaluator, and logger are distinct functions.

## How This Was Built

I'm not a software engineer. I'm an AI compliance professional building tools to solve problems I see in the field.

Seshat's code was:

- **Generated** using local LLMs (Ollama)
- **Reviewed and verified** using cloud LLMs (Claude mainly)
- **Directed, tested, and maintained** by me

I specify the requirements, review every function, verify the output matches intent, and make the design decisions.
The LLMs write code. I own the architecture and the accountability.

This is how I believe AI tooling should work: human authority over AI capability. Seshat is built the same way it's designed to enforce, and be an audit asset.

## License
Apache 2.0

Author
Matthew Green
