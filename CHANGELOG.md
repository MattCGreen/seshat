# Changelog

All notable changes to Seshat are documented in this file.

## [Unreleased]

### Added
- `skill/references/code-review-findings.md` — v0.5 code review findings and fixes
- `skill/templates/policy.yml` — commented policy template for new rule types
- `skill/scripts/test_eval.py` — standalone evaluation engine test script (6 tests)
- NIST AI RMF policy file (`policies/nist_ai_rmf.yml`)
- ISO 42001 policy file (`policies/iso_42001.yml`)
- CHANGELOG.md
- install.sh — one-way sync script (repo → live Hermes install)

### Changed
- plugin.yaml description: "immutable JSONL audit trail" → "append-only JSONL audit trail"
- README.md: added note clarifying audit trail is append-only by convention
- tests/test_evaluator.py — expanded to 24 tests (4 new NIST/ISO framework tests, TEST 5 updated for dual assessment IDs, hook tests renumbered 17–24)
- Example context: replaced placeholder tool names (`shell_exec`, `cloud_write`, `db_write`) with real Hermes tool names

## [0.5.0] — 2026-07-05

### Added
- Hermes plugin (`seshat_pep`) with `pre_tool_call` / `post_tool_call` hooks
- Two-layer governance architecture: PEP (plugin, mandatory enforcement) + PDP (skill, advisory reasoning)
- YAML policy files with PII detection rules (`pii_rule.yml`)
- Colorado AI Act disclosure rule (`colorado_ai_act.yml`)
- Regex-based PII scanner (email, SSN, phone, credit card, IP) — recursive for nested dicts/lists
- Multi-rule evaluation: PII check, disclosure check, tool blocklist, tool allowlist
- JSONL append-only audit trail (pre-call + post-call pairs)
- PII redaction in audit logs (recursive)
- Fail-closed: hook crashes return block, not skip; no rules loaded = DENY all
- Self-protection: agent cannot write to `~/.seshat/` or plugin directory
- Hot-reloadable policies (mtime-based, thread-safe cache)
- Context-derived tool blocklists from governance context YAML
- Governance skill (`seshat-governance`) — advisory layer (PDP)
- 20-test suite covering engine + plugin hooks

### Fixed (from v0.5 code review by Claude Fable 5)
- **C1**: Unhandled hook exceptions turned PEP fail-OPEN (Hermes skips crashing hooks). Fix: try/except wrapper around entire hook body, returns block on any error.
- **C2**: Nested-parameter PII undetected and unredacted. Fix: recursive `_scan_value` / `_redact_value` helpers.
- **H1**: Hot-reload was a self-weakening vector (agent could write permissive policy). Fix: self-protection rule blocking writes to `~/.seshat/` and plugin dir.
- **H2**: "Immutable audit trail" was aspirational, not enforced. Fix: corrected language to "append-only by convention"; hash chaining on roadmap.
- **H3**: `post_tool_call` misclassified successful calls with `error: null`. Fix: truthiness check instead of key presence.
- **H4**: `SESHAT_FAIL_CLOSED=false` was a no-op. Fix: removed the flag entirely. Seshat is always fail-closed.

### Known Limitations (accepted for v0.5)
- M2: Regex false positives (phone matches any 10-digit number, no Luhn check on credit cards, no undashed SSN)
- M3: Context load failure silently drops blocklist (mitigated by policy files loading independently)
- M4: Example context uses placeholder tool names that don't exist in Hermes
- M5: Hook integration tests not shipped as files (verified during development)
- M7: Policy cache mtime resolution could serve stale rules on sub-second edits

## [0.4.0] — 2026-03-22

### Added
- Policy evaluator with ALLOW/DENY decisions
- Multi-rule evaluation framework
- JSONL audit trail logging

## [0.3.0] — 2026-03-15

### Added
- PII rule reader and regex-based detection
- Example tool call mocking
- Initial policy YAML format
- First audit log entries
