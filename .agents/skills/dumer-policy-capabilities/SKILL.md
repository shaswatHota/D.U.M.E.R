---
name: dumer-policy-capabilities
description: Implement or change the D.U.M.E.R policy broker, capability grants, risk tiers, autonomy levels, taint rules, and approval objects. Use for anything that decides Allow/Deny/RequireApproval.
---
# Policy broker
- Pure, deterministic function: `(principal, op, validated_args, capability, tier, session/device state, grant+expiry, approval, taint labels, autonomy level, budgets) -> Allow | Deny(reason) | RequireApproval(spec)`.
- **Inputs never include model confidence.** Engine error/panic/timeout ⇒ `Deny`.
- Capabilities are narrow (`app.launch:<id>`, `files.read:<folder>`…), expiring, revocable; no wildcard shell/filesystem/admin capability exists.
- Tier rules: 0–1 auto if allowlisted; 2 auto only at autonomy L3 with undo journal; 3 explicit confirm with biometric/Hello; 4 elevation flow, dual approval, no standing grants. Tier 3+ is never autonomous.
- Taint rule: `Web|File|Voice|Model`-tainted strings may not populate paths/URLs/recipients/commands of tier ≥1 ops without user confirming the exact value.
- Approval binding: canonical hash over op+args+target identity+requester+tier; single-use nonce; expiry judged by the laptop clock; any mutation invalidates.
- Tests required: allow, deny, expired grant, wrong device, altered args, missing/replayed approval, tainted arg, autonomy-level matrix, policy failure ⇒ deny, property test "no Allow for unregistered op".
- Keep the engine free of I/O so it is trivially testable and fuzzable.
