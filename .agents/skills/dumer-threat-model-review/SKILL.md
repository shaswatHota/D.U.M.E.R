---
name: dumer-threat-model-review
description: Review a D.U.M.E.R change, design, or PR against the threat model and invariants; update docs/threat-model.md. Use for any security-sensitive design decision or before merging risky work.
---
# Threat-model review
1. Enumerate changes: entry points, data flows, processes, privileges, dependencies, new operations.
2. For each op: threat-model §7 checklist. For each flow: which zone, which taint labels, any secret/personal data, any egress.
3. Attempt each invariant violation from the viewpoint of: hijacked planner, hostile web page, malicious audio, compromised phone, compromised relay, same-user malware, stolen laptop.
4. Check "lethal trio" separation, default-deny, fail-closed behaviour, audit completeness, kill-switches still work without the model.
5. Output: findings (severity, exploit story, fix), residual risks, doc updates (threat model, ADRs).
