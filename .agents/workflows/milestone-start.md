---
description: Start a D.U.M.E.R milestone safely
---
1. Read `AGENTS.md`, `docs/implementation.md` (target milestone), `docs/architecture.md` sections it cites, and `docs/threat-model.md`.
2. Restate the milestone's deliverables and exit criteria; list which invariants it touches.
3. Write a short plan and the failing tests first.
4. Implement in small steps; run fmt/clippy/test/deny/audit after each.
5. Run the `/security-review` workflow.
6. Update docs/decisions; summarize done work, tests run, deferred risks.
