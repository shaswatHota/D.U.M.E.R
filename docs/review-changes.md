# Review of the v1 plans — what changed and why

v1 (`architecture.md`, `implementation.md`) was a sound base: default-deny, typed command registry, LLM as untrusted planner,
policy broker, vertical-slice-first. **Kept as-is:** those foundations, risk tiers, capability model, milestone order idea, audit design,
research-gateway isolation, testing list.

## Conflicts with your stated requirements (fixed)

| # | Issue in v1 | Why it matters | Fix in v2 |
|---|---|---|---|
| 1 | Tailscale as default overlay | Its control plane is a cloud service — contradicts "fully offline/self-controlled"; also you likely sit behind CGNAT | Self-managed WireGuard hub (small relay, you control it); Headscale fallback |
| 2 | "Restricted OpenSSH" on Windows | Windows OpenSSH Server is a SYSTEM service → breaks "core is unprivileged" and widens attack surface | Embedded `russh` server, subsystem-only, inside WireGuard; host key pinned (SSH kept, as you wanted) |
| 3 | C#/.NET Windows adapter | Second runtime = more RAM, more IPC, two toolchains; you asked for memory-efficient stacks | Rust adapter using the `windows` crate behind a `Platform` trait |
| 4 | Phone approvals with no delivery path | Android push normally = Google FCM (cloud). v1 also said "avoid foreground service", but approvals must reach the phone | Connected-mode foreground service and/or self-hosted UnifiedPush; content-free wake-ups |
| 5 | Privileged helper "future, optional", no request format | Your brief requires: notify PC+phone with app, author, details, reason | Full Elevation flow (§7): trusted-code-gathered identity + signer, labelled "unverified" agent reason, signed approval, helper re-verifies, dual approval for tier 4 |
| 6 | No fast-path spec | You want zero LLM latency for "open chrome" | Act-first/report-after rule, matcher design, latency budget, grammar-constrained voice |
| 7 | Personal data protection vague ("encrypt separately") | You want "utmost safety" | SQLCipher + separate vault key, placeholder substitution so the LLM never sees secrets, canary tokens |
| 8 | Prompt-injection defense = "treat as data" | Necessary but weak | Dual-model pattern, taint tracking into policy, hygiene filters, budgets, eval corpus |
| 9 | Web cache/TTL only a table row | You asked for static-vs-dynamic TTL | Freshness classes, deterministic classifier, pinning, stale-while-revalidate |
| 10 | Research could use signed-in browser/AI sites | Conflicts with "blocked from personal data" | Clean anonymous profile, outbound query firewall (identifier denylist, canaries), SSRF/private-range blocking, chat-AI plugin off by default |
| 11 | Timestamp-based freshness | Phone clock drift breaks or weakens replay protection | Server-issued challenge nonce + monotonic counters; laptop clock only for approval expiry |
| 12 | Only Windows + Android | "All my devices" | `Platform` trait, Linux impl and satellite nodes (M12) |
| 13 | No VRAM planning | RTX 4050 laptop = ~6 GB VRAM | Model-size guidance, CPU for STT/TTS/embeddings, game/battery/thermal-aware unload |
| 14 | Loopback LLM server implied | Any local process can hit localhost | `dumer-infer` worker over pipes, no listener, sandboxed, no network |
| 15 | "Revisit" list too long | Open decisions stall AI-IDE agents | SQLCipher, CBOR, SSH-subsystem, Rust adapters decided; short evidence-based open list remains |

## New threats added to the model
Lethal-trio co-location, SSRF/DNS-rebinding via research, named-pipe squatting, TOCTOU on app signature, GGUF/model supply chain,
audio-injected voice commands, markdown/image exfiltration, relay compromise, lost phone, approval fatigue, helper-trusts-core confusion.

## Honest limits
- Nothing here makes the system "unhackable"; same-user malware with an unlocked vault is still a serious threat. The design limits blast radius and makes abuse noisy.
- "Kernel space" is interpreted as *elevated privilege*. A kernel driver is out of scope and would be a large new attack surface.
- Library/model versions and Android Keystore capabilities must be re-verified when each milestone starts; this plan doesn't pin them.
- Browser-automating third-party chat AIs may violate their terms and is brittle; it is an optional, off-by-default plugin.
