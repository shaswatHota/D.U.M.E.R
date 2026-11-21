# D.U.M.E.R

Offline-first, security-first personal agent: deterministic instant commands, a local LLM as an *untrusted* planner,
a vault that keeps personal data away from the model, privileged actions behind signed approvals on your PC and phone,
and a private WireGuard + SSH-RPC link between your devices.

## What's in this pack
| Path | Purpose |
|---|---|
| `docs/architecture.md` | Revised architecture (v2) |
| `docs/implementation.md` | Milestones M0–M13, exit criteria, definition of done |
| `docs/threat-model.md` | Draft threat model + per-command checklist + pen-test list |
| `docs/protocol/protocol.md` | `dumer-rpc@1` wire protocol, handshake, approvals, enrollment |
| `docs/decisions/decisions.md` | ADRs (decided choices) |
| `docs/review-changes.md` | What changed from your v1 plans and why |
| `AGENTS.md` | Entry rules, read by Antigravity (and most other AI IDEs) |
| `.agents/rules`, `.agents/skills`, `.agents/workflows` | 5 rules, 13 project skills, 3 workflows in Antigravity's layout |

## Using it
1. Unzip into an empty repo folder and open it in Antigravity. `git init` and commit as-is.
2. Open Antigravity's customizations/rules panel and confirm the 5 rules and 13 `dumer-*` skills are listed. If they aren't (older versions used a singular `.agent/` folder), rename `.agents/` to `.agent/`.
3. Rule activation (always on / glob) is read from each rule's frontmatter; adjust it in the panel if needed.
4. First prompt:

> Read AGENTS.md and everything in docs/. Execute **Milestone M0** from docs/implementation.md: create the Cargo workspace skeleton, CI script, deny.toml,
> and finalize docs/threat-model.md. Write tests first, do not write any OS-acting code yet, and summarize what you did, tests run, and deferred risks.

Then M1, M2… one milestone per session.

## Notes
- The skills here are written for this project; no third-party skills were downloaded (supply-chain risk matters for this project).
- Verify crate versions, Android Keystore behaviour and model choices when each milestone starts; the docs deliberately don't pin them.
