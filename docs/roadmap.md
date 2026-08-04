# Seshat Roadmap

**Status:** Living document — update as decisions land
**Last updated:** 2026-08-03
**Source sessions:** 2026-07-26 (v1 checklist), 2026-08-03 (OB1 design review)

---

## Where Seshat Is (verified 2026-08-03)

| Dimension | Status |
|---|---|
| Version | v1.0.0 tagged, public on GitHub, clean working tree |
| Tests | 24/24 passing; reviewed by second model (0 critical / 0 high) |
| Install | install.sh one-way sync (repo → live Hermes) |
| Frameworks | All four: EU AI Act (Art 5, 9), NIST AI RMF, ISO 42001, CO SB 24-205 |
| PEP plugin | Actively enforcing (316+ audit entries logged) |
| PDP skill | Full SKILL.md + references + policy template + eval engine |

**Known doc drift:** README "Current Status" still says v0.6-pre while repo is tagged v1.0.0. Fix on next doc pass.

---

## v1.0.0 — Shipped (complete)

- [x] Repo created, public, Apache 2.0, TSA/employer references scrubbed
- [x] Clean layout: plugin/, skill/, policies/, contexts/, tests/
- [x] README, LICENSE, CHANGELOG, install.sh
- [x] Four framework policy files: EU AI Act, NIST AI RMF, ISO 42001, CO SB 24-205
- [x] PEP plugin with pre/post tool call hooks, fail-closed, self-protection, hot-reload
- [x] PDP governance skill (advisory layer)
- [x] JSONL append-only audit trail (pre-call + post-call pairs, PII redaction)
- [x] 24-test suite, second-model review clean

---

## Deferred from v1 (documented in CHANGELOG)

| Item | Target | Notes |
|---|---|---|
| LLM semantic checks (`llm_check` rule type) | Phase 4 | Local LLM evaluates tool call semantics, not just regex |
| PII regex improvements | Post-v1 | Luhn check for credit cards, undashed SSN, fewer phone false positives |
| CI/CD pipeline | Post-v1 | GitHub Actions running the 24-test suite on every push |
| Multi-agent delegation depth controls | Post-v1 | Context-level limits on subagent spawn depth |

---

## New Candidate Items — OB1 Design Review (2026-08-03)

Patterns reviewed from Open Brain (Nate B. Jones, FSL-1.1-MIT — ideas only, no code copied; Seshat stays Apache 2.0). See design-inputs memo for full analysis.

| Item | Source pattern | Size | Priority | Why |
|---|---|---|---|---|
| Hash chaining | Seshat original spec | ~40 lines | **Next** | Differentiator. EU AI Act Art. 12 in force Aug 2, 2026; tamper-evidence is the credibility story. No one else in this niche has it. |
| DENY reason codes | OB1 `unsafeReasons()` | Small | High | Turns "DENY" into "DENY: `pii_email` in parameter `cmd`" — machine-readable, answers "why" without forensics |
| Trust ladder | OB1 agent-memory | Medium | High | Instruction-grade policies require human confirmation; agent-drafted policies are advisory until reviewed. Makes the original spec's "Agent Intent" concrete |
| Unify eval engine | v1 checklist | Medium | **Do first** | 3 copies → 1; plugin imports from eval/. Everything after touches this file |
| Per-agent identity | OB1 per-agent-identity | Medium | Low | Single-user Hermes today; matters when sub-agents/cron get differentiated authority |

---

## Suggested Sequencing (2-5 hrs/week pace)

1. **Unify eval engine** (one copy) — every subsequent change touches that file
2. **Hash chaining** — the differentiator, small lift, spec-aligned
3. **DENY reason codes** — structured `reason:` field on every block
4. **Trust ladder** — policy YAML gains provenance_status / review state
5. **CI/CD pipeline** — GitHub Actions, 24-test suite on push
6. **PII regex improvements** — Luhn, undashed SSN, false-positive reduction
7. **Phase 4: LLM semantic checks** — llm_check rule type
8. **Multi-agent delegation depth controls** — context-level limits

Items 1-4 are achievable in a handful of sessions before March 2027 IAPP target.

---

## Open Questions (decide when reached)

- **Audit write failure:** fail-closed (block on audit failure) or fail-open (log-and-continue)? OB1 treats audit as best-effort; Seshat's fail-closed posture may warrant the opposite. Deliberate product decision, not inherited.
- **Hash chaining scope:** chain-only (each entry carries prev_hash) vs Merkle aggregation (later optimization, not v1).
- **Trust ladder enforcement:** schema-level CHECK (like OB1) vs evaluator-level guard. Seshat has no DB layer — likely evaluator-level, but decide consciously.

---

## Sources

- 2026-07-26 session: v1 checklist development ("Feeling Behind with Agentic AI")
- 2026-07-05 session: original spec and drift analysis ("Project Seshat Spec vs Implementation Review")
- 2026-08-03: OB1 schema/API review — design-inputs memo (trust ladder, thought audit, provenance chains, per-agent identity, recall traces)
