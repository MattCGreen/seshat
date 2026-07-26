# Seshat v0.5 Code Review Findings

Review conducted by Claude Fable 5 via delegate_task (July 2026).
All critical and high findings were fixed before push.

## Findings Fixed (v0.5 release)

### Critical

**C1. Unhandled hook exceptions turn the PEP fail-OPEN.**
Hermes catches crashing hooks and SKIPS them — the tool call proceeds unaudited.
Crash vectors: non-dict YAML root (TypeError on `policy["source_file"] = ...`),
non-serializable args (TypeError in json.dumps), audit-log write failures (OSError).
One malformed YAML file → all governance silently disabled.
FIX: try/except wrapper around entire hook body returning block; YAML root validation
in `load_policies`; `default=str` in `json.dumps`.

**C2. Nested-parameter PII undetected (not just unredacted).**
`{"payload": {"email": "a@b.com"}}` → ALLOW bypass + raw PII in audit log.
Worse than documented: detection was also top-level-only, not just redaction.
FIX: recursive `_scan_value` / `_redact_value` helpers walking dicts and lists.

### High

**H1. Hot-reload is a self-weakening vector.**
Agent can `write_file` a permissive policy or empty the blocked_tools list,
applied on next tool call via mtime check. Same agent can edit/truncate audit log.
FIX: self-protection rule blocking writes to `~/.seshat/` and plugin dir.
Doc language softened: "cannot be bypassed by skipping the hook" (not absolute).

**H2. "Immutable audit trail" was aspirational, not enforced.**
Plain `open(path, "a")` — no fsync, no hash chaining, no file permissions.
FIX: renamed claims to "append-only by convention"; roadmap-noted hash chaining.

**H3. post_tool_call misclassified successful calls with `error: null`.**
`if "error" in parsed:` checks key presence, not truthiness. Hermes tools return
`"error": null` on success → logged as exit_code: 1.
FIX: `if parsed.get("error"):` (truthiness check).

**H4. `SESHAT_FAIL_CLOSED=false` was a no-op.**
Empty rules → `compute_audit_entry` independently returns DENY regardless of the flag.
FIX: removed the flag entirely. Seshat is always fail-closed (documented, no toggle).

## Known Limitations (accepted for v0.5, documented in release notes)

- **M2. Regex false positives**: Phone matches any 10-digit number (timestamps, IDs).
  Credit card matches 15-16 digit runs with no Luhn check. IP matches invalid octets.
  No undashed SSN detection. Documented; will improve in Phase 4 with LLM semantic checks.
- **M3. Context load failure silently drops blocklist**: Missing context → empty {} →
  no CTX-BLOCK rule → tools the context intended to block are ALLOWED. Logged as warning.
  Mitigation: policy files still load independently.
- **M4. Example context blocks tool names that don't exist in Hermes**: `shell_exec`,
  `cloud_write`, `db_write` aren't real Hermes tool names. Example labeled as placeholder.
- **M5. Hook integration tests not shipped as files**: Verified during development
  via `execute_code`, not in a `tests/` directory. Phase 3 adds proper test files.
- **M7. Policy cache concurrency unguarded** (partially fixed): Added `threading.Lock`
  around `_check_policy_cache`. Mtime resolution means two edits within the same
  timestamp could serve stale rules — consider content-hash in future.

## Review Technique Notes

- Reviewer was given absolute file paths, verified Hermes hook API facts, and
  known/accepted limitations so it didn't re-report documented items.
- Reviewer found a `templates/policy.yml` with `PIE-001` typo (nit, fixed).
- Reviewer confirmed engine copies (plugin evaluator.py vs skill eval.py) were
  logically identical at review time — drift was docstrings only.
- Total cost: ~$0.07 on OpenRouter intro pricing (18.5K input + 3K output tokens).
