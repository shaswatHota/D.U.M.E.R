---
trigger: always_on
description: Milestone discipline and testing requirements
---
- Follow `docs/implementation.md`. One milestone per session; read its exit criteria first and satisfy all of them.
- Write failing tests first for: schema validation, policy decisions, replay/expiry, parsers, crypto, TTL/deletion.
- Security tests are first-class: unknown op, unknown fields, oversize/malformed frames, replay, altered args after approval, revoked device, path traversal/symlink, injection corpus.
- Every parser gets a fuzz target. Every new command gets the threat-model §7 checklist completed in its PR/commit message.
- Benchmarks (criterion) for the fast path; fail the task if matcher+dispatch p95 regresses past the budget.
- Update `docs/` and `docs/decisions/decisions.md` when behaviour or decisions change. End each session with: what was done, tests run, deferred risks.
