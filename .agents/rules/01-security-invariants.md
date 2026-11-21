---
trigger: always_on
description: Non-negotiable D.U.M.E.R security invariants
---
Never violate `AGENTS.md` invariants 1–14 (docs/architecture.md §4).
- Do not add any API that executes a string as a command, accepts an arbitrary executable path, or exposes a shell/PTY/exec/forwarding channel.
- Do not let LLM output, model confidence, web/file/voice content, or a network connection grant permission.
- Do not widen a capability, tier, or autonomy level without an explicit owner instruction and a threat-model note.
- On any ambiguity about security impact: stop, explain the risk, ask.
- Fail closed: errors in policy, parsing, crypto, or IPC deny the action.
