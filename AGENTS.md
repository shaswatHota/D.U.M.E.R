# AGENTS.md — D.U.M.E.R

You are building **D.U.M.E.R**, an offline-first, security-first personal agent (Rust core, local LLM as untrusted planner,
Android companion, private WireGuard+SSH-RPC link). Read, in order: `docs/architecture.md`, `docs/threat-model.md`, `docs/implementation.md`,
`docs/protocol/protocol.md`, `docs/decisions/decisions.md`.

## How to work
- Work on **one milestone at a time** (docs/implementation.md §3). Do not start a milestone before the previous exit criteria pass.
- **Tests first** for policy, protocol, parsing, crypto. A task is done only when tests pass and docs are updated.
- Before writing OS-acting code (launching apps, files, network, privileged ops) confirm M0 is complete (threat model + default-deny exist).
- If a requirement conflicts with an invariant, **stop and ask the owner** — never silently weaken an invariant.
- Verify current library versions and APIs yourself (crates, Android Keystore, llama.cpp bindings); do not assume. Prefer maintained, minimal-dependency crates; justify each new dependency in the PR/commit note.
- Keep it small: modular monolith, only the processes listed in architecture §2.

## Non-negotiable invariants (summary of architecture §4)
1. LLM never authorizes anything; model confidence is never a policy input.
2. Default deny. Unknown op/capability/device/destination ⇒ reject.
3. Every action (voice, text, phone, schedule, model) goes through the same policy broker.
4. **No shell escape hatches** — no `Shell(String)`, no arbitrary executable path, no raw PowerShell/cmd/bash, anywhere.
5. Approvals are bound to exact op+args+target identity+device+nonce+expiry.
6. `dumer-privd` never trusts the core; it verifies the user's signed approval itself.
7. Network reachability ≠ authorization.
8. Secrets never reach LLM context, logs, argv, or the research gateway (placeholders only).
9. Tainted data (web/file/voice/model) can't become targets/args of state-changing ops unconfirmed.
10. Never co-locate private data + untrusted content + an exfiltration path.
11. Policy/parser/timeout failure ⇒ fail closed.
12. User can stop/pause/revoke/disable-remote/unload-model/lock-vault without the model.
13. State changes are audited; audit has no secrets. 14. The agent cannot replace its own trusted binaries/policy/keys.

## Deterministic fast path
"Open Chrome"-style commands: match → validate → policy → execute → terse result. **Never load or call the LLM; never emit text before acting.**

## Conventions
- Rust: edition per `rust-toolchain.toml`; `#![forbid(unsafe_code)]` except reviewed OS/FFI crates; `clippy -D warnings`; `thiserror` for errors; `tracing` with secret-free fields; `zeroize`/`secrecy` for secrets.
- Wire format: deterministic CBOR, strict decoding, `deny_unknown_fields`, 64 KiB frame cap.
- No secrets in code, config samples, tests (use clearly fake values), logs, or commit history.
- Every new command follows `.agents/skills/dumer-add-command/SKILL.md` and the checklist in `docs/threat-model.md` §7.
- Rules live in `.agents/rules/`; skills in `.agents/skills/`; workflows in `.agents/workflows/`.
