---
description: Security review of a change against the D.U.M.E.R threat model
---
1. List new/changed entry points, operations, capabilities, data flows, processes, dependencies.
2. Walk `docs/threat-model.md` §7 checklist for each operation.
3. Check invariants 1–14. Try to violate each with the new code (hijacked planner, compromised phone, hostile web content, same-user malware).
4. Confirm negative tests exist and fail without the fix; confirm fuzz target for any new parser.
5. Confirm no secrets/personal data in logs, prompts, fixtures, or the research path.
6. Report: findings by severity, fixes made, residual risks.
