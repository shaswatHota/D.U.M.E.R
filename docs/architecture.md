# D.U.M.E.R — Architecture (v2)

**Status:** Baseline design, revised from the v1 "Local-First Personal Agent" plan.
**What D.U.M.E.R is:** An offline-first, security-first personal agent. A trusted deterministic core executes
known commands instantly. A local LLM is an *untrusted planner* used only when the deterministic path cannot
handle a request. It runs on the owner's laptop and is reachable from the owner's other devices over a private,
end-to-end-authenticated channel.

Read `docs/review-changes.md` for what changed from v1 and why.

---

## 1. Goals and non-goals

### Goals
1. **Offline-first / local-first.** Personal data, memory, inference and command execution stay on the owner's devices.
   The only internet-facing paths are (a) the device-to-device link and (b) the isolated Research Gateway.
2. **Instant deterministic actions.** "Open Chrome" never touches the LLM and never waits on text generation.
   *Act first, then report tersely.* See §6.
3. **Reasoning when needed.** The local model resolves ambiguous/multi-step requests, may trigger research, and proposes plans.
   It has **no authority**.
4. **Autonomous in user space, gated for privilege.** Low-risk work runs autonomously under policy. Elevated (admin/root)
   operations need explicit, action-bound approval with full provenance of the requesting program. See §7.
5. **Secure multi-device.** The laptop is the "brain". Phone and other devices are authenticated clients/satellites.
6. **Personal data in a vault.** The model never sees raw secrets. See §8.
7. **Auditable, stoppable.** Every state change is logged; the user can stop everything without asking the model.
8. **Memory/CPU frugal.** Low idle cost; yields to games and heavy foreground work. Measured, not assumed.

### Non-goals (v1)
- A kernel driver or any kernel-mode code. ("Kernel space" in the product brief means *elevated/admin/root privilege*;
  D.U.M.E.R never loads code into the kernel.)
- A general autonomous administrator; arbitrary shell access (local, model, or remote).
- Cloud memory, cloud inference, or any required cloud dependency.
- Logging into the owner's personal accounts on the owner's behalf.
- Bypassing OS prompts (UAC/polkit) or clicking through security dialogs.
- Kubernetes, Kafka, Redis, service meshes.
- Claiming to be "unhackable". The goal is small blast radius, hard-to-abuse dangerous actions, and observable failures.

### What "fully offline" means here
Inference, memory, planning, voice and command execution need no internet. Two features inherently use a network:
remote access from the phone (needs *some* path across the internet) and web research (needs the web). Both are
opt-in, isolated, and off-switchable. With them disabled, D.U.M.E.R is fully functional on the laptop.

---

## 2. System overview

```text
                 INTERNET / UNTRUSTED CONTENT
                              |
                  +-----------v-----------+      no personal data, no vault,
                  |  dumer-research       |      own OS account / sandbox,
                  |  (Research Gateway)   |      egress allowlist, SSRF-blocked
                  +-----------+-----------+
                              | text + provenance only (tainted)
=========================== LAPTOP (the "brain") ==========================
                              |
  +-----------+  IPC   +------v-----------------------------------------+
  | dumer-ui  |<------>|  dumerd  (Rust core, unprivileged, user acct)   |
  | tray/CLI/ |        |  matcher | command registry | policy broker     |
  | PTT voice |        |  task scheduler | vault client | audit writer   |
  +-----------+        |  device/session mgr | SSH-RPC server            |
                       +--+--------+----------+-----------+--------------+
                          |        |          |           |
                 pipe IPC |        | pipe IPC | pipe IPC  | ACL'd pipe
              +-----------v-+  +---v------+ +-v--------+ +v----------------------+
              | dumer-      |  | dumer-   | | dumer-   | | dumer-privd           |
              | platform    |  | infer    | | voice    | | (OPTIONAL privileged  |
              | (user-space |  | llama.cpp| | STT/TTS  | |  helper, fixed ops,   |
              | OS adapter) |  | sandboxed| | sandboxed| |  re-verifies user     |
              +-------------+  | no net   | +----------+ |  approval itself)     |
                               +----------+              +-----------------------+
                       SQLCipher DB + vault (keys in OS keystore / TPM)

   dumerd binds SSH-RPC only on the private overlay interface (never 0.0.0.0, never public).
            |
   [ WireGuard overlay ]  -- laptop & phone dial OUT to a tiny relay/hub: works behind CGNAT --
            |
=========================== PHONE / OTHER DEVICES =========================
  Android: Kotlin UI + shared Rust crates (UniFFI): proto, matcher, crypto.
  Keystore-backed approval key (biometric-gated). Local offline command subset.
  Satellite nodes (second PC, Linux box): same dumer-platform trait, enrolled like the phone.
```

Start with a handful of processes. Boundaries exist where they buy real isolation:
`dumerd`, `dumer-infer`, `dumer-research`, `dumer-voice`, optional `dumer-privd`. Everything else is a crate inside `dumerd`.

### Process/privilege summary

| Process | Runs as | Network | Sees vault? | Trust |
|---|---|---|---|---|
| dumerd | owner (unprivileged) | listens on overlay only; no general egress | via vault client, policy-gated | trusted coordinator |
| dumer-platform | owner | none | no | narrow adapter |
| dumer-infer | restricted token / sandbox | **none** | **no** (placeholders only) | untrusted planner |
| dumer-voice | restricted token / sandbox | none | no | untrusted input producer |
| dumer-research | separate OS account or AppContainer | egress allowlist via proxy | **never** | hostile-content zone |
| dumer-privd | service, minimum privileges | none | no | tiny, independently audited |
| Android app | app sandbox | overlay only | own local state | authenticated client |

---

## 3. Technology decisions

(Each is recorded in `docs/decisions/decisions.md`. Revisit only with evidence.)

| Area | Choice | Why |
|---|---|---|
| Core, matcher, policy, vault, audit | **Rust** (Tokio, serde, tracing, thiserror, zeroize, secrecy) | memory safety, low idle RAM, one language across components |
| OS adapters | **Rust** with the `windows` crate (Windows) and native/`zbus` (Linux) behind one `Platform` trait | **Changed from v1 (C#/.NET):** no second runtime, lower RAM, one toolchain, fewer IPC hops |
| Desktop UI | **Tauri** tray app; CLI first | far lighter than Electron; UI is a late milestone |
| Android | **Kotlin** UI only; shared **Rust** crates via **UniFFI** (protocol, matcher, crypto) | one implementation of parsing/crypto/matching |
| Local inference | `llama.cpp` through our own thin **`dumer-infer`** worker, talking over anonymous/ACL'd pipes | **No listening socket at all** — a localhost HTTP server is reachable by any local process |
| Output constraint | llama.cpp **GBNF / JSON-schema constrained decoding** | plans can only be valid schema instances |
| Database | **SQLite via SQLCipher** (`rusqlite` with bundled SQLCipher), WAL | decided now, not "revisit later" |
| Vector search | `sqlite-vec` (or equivalent) + small CPU embedding model | everything in one encrypted file |
| Wire format | **Deterministic CBOR** (RFC 8949 §4.2), length-prefixed, 64 KiB max frame | signable canonical bytes; compact; strict decoding |
| Transport | **SSH subsystem `dumer-rpc@1` served by an embedded Rust SSH server (`russh`)**, inside **WireGuard** | **Changed from v1:** the Windows OpenSSH Server runs as a SYSTEM service, which would break "core is unprivileged". An embedded server has no shell/PTY/forwarding *by construction* |
| Overlay | **Self-managed WireGuard, hub-and-spoke via a small relay** (laptop and phone dial out). Fallback: Headscale. Tailscale only as a convenience fallback | **Changed from v1:** Tailscale's control plane is a cloud service, and many home ISPs use CGNAT so inbound port-forwarding is unreliable |
| STT | **Vosk with a restricted grammar** for commands; **whisper.cpp (CPU)** for free dictation | grammar-constrained STT matches the deterministic command set |
| TTS | Piper (CPU) | offline, light |
| Wake word | none by default; push-to-talk. openWakeWord optional | fewer always-on mic risks |

### Hardware budget (RTX 4050 laptop GPU ≈ 6 GB VRAM, 16 GB RAM)
- Plan for a **3B–8B-class model at ~Q4 quantization**. An 8B at Q4 plus KV cache barely fits 6 GB; benchmark, don't assume.
  Candidate families (verify what is current when M10 starts): Qwen, Llama, Gemma, Phi. Pick by *structured-output reliability on D.U.M.E.R's own eval set*.
- **STT/TTS/embeddings run on CPU** so they never fight the LLM for VRAM.
- Lazy-load the model; unload after an idle timeout; **auto-unload and pause background work when a fullscreen game or
  heavy GPU app is detected**, on battery, or when thermally throttled.
- Idle target (measured and enforced in benchmarks): `dumerd` resident well under 100 MB with the model unloaded.

---

## 4. Trust zones and invariants

Zones: (1) user + approval UI, (2) policy broker, (3) unprivileged core, (4) LLM worker — *untrusted*, (5) platform adapters,
(6) privileged helper (optional), (7) research gateway — *hostile*, (8) remote devices — authenticated but still per-operation
authorized, (9) all external content (web, files, OCR, transcripts, audio, model output) — *data, never instructions*.

### Security invariants (never violate; tests must encode them)
1. **The LLM never authorizes anything.** Model confidence is not a policy input.
2. **Default deny** for unknown operations, capabilities, destinations, devices.
3. **Every action — voice, text, phone, schedule, model — passes the same policy broker.**
4. **No shell escape hatch.** No `Shell(String)`, no arbitrary exe path, no raw PowerShell/cmd/bash from any caller.
5. **Approval is bound** to the exact operation, arguments, target identity (path + signer + hash), requesting device, nonce and expiry. Any change invalidates it.
6. **The privileged helper does not trust the core.** It independently verifies the user's signed approval.
7. **Network reachability ≠ authorization.** WireGuard/SSH success only identifies a device; each request is still authorized.
8. **Secrets never enter the LLM context, logs, command lines, or the research gateway.** The model sees placeholders.
9. **Tainted data (web/file/model/voice-derived) cannot silently become the target or arguments of a state-changing action.**
10. **The "lethal trio" is never co-located:** private data + untrusted content + an exfiltration path must never be reachable from the same process/context.
11. **Policy engine failure = deny.** Parser failure = reject. Timeout = fail closed.
12. **The user can stop tasks, pause automation, disable remote, revoke devices, and unload the model without involving the model.**
13. **State-changing actions emit audit events; audit never contains secrets.**
14. **The agent cannot replace its own trusted binaries, policy, or keys.**

---

## 5. Capability, risk and autonomy model

### Capabilities (narrow, expiring, revocable)
`app.launch:<app_id>`, `system.read:basic_status`, `files.read:<approved_folder>`, `files.write:<approved_folder>`,
`files.index:<approved_folder>`, `network.research:public_web`, `device.notify`, `settings.change:<specific>`,
`priv.<fixed_op>:<target>` (see §7). Never: `shell.execute:*`, `filesystem.read:*`, persistent admin.
A grant records: subject, operation + resource, argument constraints, risk tier, source/approval ref, issued/expiry, revoked.

### Risk tiers

| Tier | Example | Default |
|---|---|---|
| 0 read-only local | time, status, list apps | auto |
| 1 reversible local | open app, create draft note | auto if allowlisted |
| 2 meaningful change | move/rename files in an approved folder | auto only with an **undo journal**, else preview/confirm |
| 3 sensitive | send message, upload, change a security setting, use a vault item | explicit confirmation with exact details (+ biometric on phone / Windows Hello on PC) |
| 4 privileged/destructive | service control, package install, firewall, mass delete | elevation flow (§7); never standing; many ops disallowed initially |

### Autonomy levels (user-selectable per task type, with kill switch)
- **L0 Observe** (answers only) · **L1 Suggest** (proposes, user triggers)
- **L2 Act-low** (executes tier 0–1 autonomously) · **L3 Act-journaled** (tier 2 in approved folders with undo journal)
- **Tier 3+ is never autonomous at any level.**
- Autonomous/scheduled work runs as **playbooks**: declarative task templates the owner approved, with step, time and network budgets,
  loop detection, and a global "pause all automation" switch.

---

## 6. Fast path vs. slow path

```text
input (text | PTT voice | phone) -> normalize
   -> FAST PATH: deterministic matcher
        exact alias table (HashMap) -> multi-pattern (aho-corasick) -> bounded fuzzy match
        typed slot extraction (app ids, numbers, durations) from registries
        -> confident + unique?  YES -> schema validate -> policy -> platform adapter -> done -> terse result
                                NO  -> short non-LLM clarification OR escalate
   -> SLOW PATH: planner (LLM) with constrained output -> every proposed step re-enters policy
```

Rules:
- **Act first, report after.** For a matched deterministic command: execute, then emit a minimal result (a tick/earcon, or ≤ 1 short line).
  No generated "Sure! I'll open Chrome…" text. The LLM is not loaded, not called, not awaited.
- **Latency budget (targets to measure, not promises):** matcher + validation + policy dispatch p95 **< 20 ms**; the OS launch itself is the dominant cost.
  Record p50/p95/p99 in benchmarks; regressions block review.
- **Voice fast path:** Vosk with a grammar generated from the live command/app registry. Act on partial hypotheses only for
  tier-0/1 commands with a unique high-confidence match; never for tier ≥ 2.
- **Slow path UX:** immediate task id + "working" state, streamed progress, result delivered later (notification if the user moved on). Cancellable.
- **Model residency:** loaded on first slow-path use, unloaded after idle timeout, never loaded just for fast commands.
- **Ambiguity margin:** if the top two matches are within a configured margin → ask or escalate; never guess on state-changing ops.

---

## 7. Privileged operations ("kernel-space" requests) — the Elevation flow

Principle: D.U.M.E.R never asks the OS for admin by itself and never ships a kernel component. Elevated work is done by an
**optional, tiny, separately installed helper (`dumer-privd`)** exposing a **fixed catalog** of narrow operations
(e.g. `priv.service.restart:<allowlisted_service>`, `priv.package.install:<signed_package>`, `priv.firewall.rule_add:<template>`).
There is no "run as admin" operation. The helper is installed once through the normal OS admin prompt.

### Flow
1. A plan/task needs privileged op *P*. The core builds an **ElevationRequest**. All descriptive fields are gathered by
   *trusted code*, not by the model:
   - operation id + exact arguments + canonical request hash
   - **subject identity** (the service/app/package affected or requesting): display name, version, file path, SHA-256,
     **code-signing publisher/author** (subject, issuer, thumbprint, validity, countersignature time), signature status, install source,
     whether currently running, parent process/task
   - requester: which device / voice / schedule / model plan, task id
   - **why** — the agent's stated reason, rendered in a clearly labelled box: *"Agent's stated reason (unverified)"*
   - effects: files/registry/services/network destinations touched, reversibility/rollback, privileges requested
   - flags: unsigned, new/rare binary, signer changed since last seen, path in a user-writable directory
   - expiry (default ≤ 5 minutes), nonce, immutable request id
2. **Presented in two places** (both render from the validated request, never from model text): the PC desktop prompt and the phone notification
   (the notification payload is content-free; details are fetched over the secure channel after wake — see §9).
3. **Approval is a signature, not a click.** Phone = non-exportable Keystore P-256 key requiring biometric per use.
   PC = Windows Hello / OS user-verification. **Tier 4 requires approval on the PC *and* the phone** (neither alone).
4. The signature covers canonical request hash + nonce + expiry. The core forwards request + signature to `dumer-privd` over an ACL'd pipe.
5. **`dumer-privd` verifies independently:** pinned approver public keys, signature, nonce uniqueness, expiry, op in catalog,
   arguments within constraints, subject identity re-checked (hash/signer) at execution time (TOCTOU guard).
6. Execute, return a typed result, write an audit event (mirrored to the phone). The OS's own UAC/polkit still applies; D.U.M.E.R doesn't bypass it.
7. **No standing tier-4 grants.** A narrow, time-boxed grant for *low-risk* privileged ops (e.g. "restart service X, 24 h") may be offered after an explicit choice, to limit approval fatigue.

Start without `dumer-privd`. Build it at M9 with exactly one trivial op, and treat adding each new op as a security review.

---

## 8. Data protection: vault, memory, secrets

### Memory classes

| Class | Examples | Retention | Notes |
|---|---|---|---|
| Config | app aliases, preferences | until changed | |
| Profile (convenience) | name, public handles, stable preferences | user-controlled | encrypted; the model gets only the *fields it needs* |
| Vault (sensitive) | secrets, IDs, private notes | opt-in | separate key, unlock required (Hello/passphrase); model **never** sees raw values |
| Task context | current multi-step task | short-lived | purged at task end |
| Index metadata | path, hash, mtime | rebuildable | explicitly selected folders only |
| External cache | web snippets | **TTL by freshness class** (§10) | tainted; never mixed with profile/vault |
| Audit | events | rolling | hash-chained; checkpoints sent to phone |

Every record: source, timestamp, confidence, sensitivity, retention, provenance, taint. Deletion propagates to embeddings and derived caches.

### Cryptography
- Whole DB: **SQLCipher**. A random 256-bit DEK is wrapped by an OS-protected key (DPAPI/TPM-backed CNG on Windows; Secret Service/TPM on Linux).
  Optional passphrase KEK via **Argon2id**.
- Vault items: additionally AEAD-encrypted (XChaCha20-Poly1305) under a **separate vault key** released only after user verification, with short auto-lock.
- `zeroize`/`secrecy` for key and secret material; no secrets in argv, env, logs, or crash dumps; disable core dumps for sensitive processes.
- Honest limit: encryption at rest does not protect against malware running as the same user while the vault is unlocked.
  Hence short unlock windows, the placeholder pattern, and the broker mediating every use.

### Placeholder pattern (how the model "uses" personal data safely)
The planner sees `{{PROFILE.email_primary}}`, never the value. When an *approved* step executes, the broker substitutes the value
deterministically, **only** into destinations allowlisted for that field. Using a vault item is a tier-3 action with explicit confirmation.

### Canary tokens
Plant fake secrets in the vault/profile/files. Any appearance in the egress filter, research gateway, model output, or logs
raises an alert and trips the kill switch for the affected pipeline.

---

## 9. Connectivity, enrollment and notifications

### Reachability
- Laptop and phone each dial **out** to a small self-run relay (WireGuard hub). Works behind CGNAT. The relay forwards ciphertext only,
  and its firewall lets peers reach *only* the agent's single port on the laptop's overlay IP.
- **Defense in depth:** the SSH layer inside WireGuard pins the laptop's host key, so a compromised relay cannot read or forge requests.
- Never expose SSH or the agent API on a public interface. Remote access is opt-in, visibly indicated, and one command/button from off.

### Protocol (details in `docs/protocol/protocol.md`)
SSH subsystem `dumer-rpc@1` only: no shell, no exec, no PTY, no agent/X11/port forwarding, password auth disabled, one key per device.
Application layer: server-issued session **challenge nonce**, per-session monotonic counters and unique request ids (no dependence on the
phone's clock), per-device capabilities, rate limits, 64 KiB frame cap, strict CBOR decoding (`deny_unknown_fields`).

### Two keys per phone (honest about Keystore limits)
1. **Transport key** (SSH/WireGuard): stored in app-private storage wrapped by a Keystore key.
2. **Approval/identity key:** non-exportable, hardware-backed where available, **ECDSA P-256**, user authentication required (biometric per use).
   Signs approvals and tier-3+ requests at the application layer.

### Enrollment
Physical presence required: a QR on the laptop carries host-key fingerprint + one-time token (≥ 128 bit, ≤ 2 min TTL).
The phone generates keys and returns public keys + proof; both screens show a short authentication string to compare.
Revocation from the laptop is immediate, and also possible by CLI without the model.

### Notifications without a cloud
Standard Android push (FCM) routes through Google. Options, in order of preference:
1. **Connected mode:** opt-in foreground service holding a low-power keepalive over the overlay; approvals arrive instantly.
2. **UnifiedPush/ntfy self-hosted on the relay** as a *content-free wake-up* ("approval pending"); the app then fetches details over the secure channel.
Notification text never contains request details.

### Other devices
`Platform` trait: Windows first, then Linux. A second PC or Linux box enrolls as a **satellite** and exposes only its own local capabilities
(e.g. `app.launch` for its registered apps) to the brain. The inference brain stays on the laptop.

---

## 10. Research gateway and knowledge cache

### Isolation
Separate OS account/AppContainer; clean browser profile (no cookies, passwords, extensions, sign-ins); no access to home, clipboard, SSH keys, app DBs;
downloads to quarantine; egress via an allowlisting proxy that **also blocks private/link-local/loopback ranges and cloud-metadata addresses (SSRF)**,
re-resolves DNS at connect time (DNS-rebinding guard), caps redirects, size and content types. Read-only research first: no forms, purchases, messages, uploads.

### Outbound query firewall (deterministic, not LLM)
Every outbound query/prompt passes: length limit → denylist of the owner's identifiers (names, handles, emails, phone, registration/ID numbers — stored as hashes/Bloom filter, not plaintext)
→ PII patterns → canary check → entropy check for key-like strings → log (hash only). A hit **blocks** and tells the user why.
Personal context is never added "to improve the answer".

### Asking third-party chat AIs through a browser
Supported only for **sanitized, generic questions** in an anonymous/clean session. Enforce: no personal accounts; assume the provider logs prompts;
site automation is brittle and may violate a site's terms, so keep it a replaceable plugin, off by default, and prefer a self-hosted metasearch (e.g. SearXNG) + page extraction first.
Responses return as tainted text.

### Freshness classes and TTL (the "cache if important" logic)

| Class | Examples | TTL | Behavior |
|---|---|---|---|
| static | definitions, math, history, protocol specs | long (months) / none, occasional revalidation | cache when used ≥ N times or user pins |
| slow | library docs, API refs, how-tos | days–weeks | stale-while-revalidate |
| fast | prices, weather, news, availability | minutes–hours | cache briefly; show age; usually don't persist |
| volatile | live scores, "right now" | none | never persist |

A small deterministic classifier (keywords + `Cache-Control`/`Last-Modified` headers + user pin) assigns the class; the LLM may *suggest* a class but cannot extend TTL beyond the class maximum.
"Important" = user-pinned, retrieved repeatedly, or explicitly asked to remember. Each entry stores source URL, fetched-at, class, TTL, content hash, taint=Web.

---

## 11. LLM and prompt-attack defenses

1. **Untrusted planner.** Structured output only (GBNF/JSON-schema). Plan = ordered `{op ∈ registry, args}`; unknown ops cannot be expressed.
2. **Dual-model pattern.** A *privileged planner* sees only user-authored/trusted text and placeholders. A *quarantined reader* processes web/file/OCR/voice-derived text and may
   return only tightly constrained data (enums, bounded numbers, short validated strings). Control flow never comes from the quarantined side.
3. **Taint tracking.** Every value carries provenance (User, Device, Web, File, Voice, Model) + sensitivity. Tainted strings can't become paths/URLs/commands/recipients of tier ≥ 1 ops without the user confirming the exact value.
4. **Input hygiene.** Strip/flag zero-width and Unicode tag characters, bidi controls, homoglyph tricks, hidden HTML/CSS text, PDF/OCR oddities; enforce size limits;
   never auto-render remote images/links in UIs (markdown-image exfiltration).
5. **Budgets.** Max steps, tokens, wall time, tool calls and network calls per task; loop/duplicate-step detection; deterministic cancel.
6. **Prompt hygiene.** System prompt lives in versioned code, never concatenated with external text; external content is wrapped in explicit data blocks with provenance.
   This is a *weak* defense; the strong ones are 1–3 and the policy broker.
7. **Model supply chain.** Pin model files by SHA-256 from a verified source; only the inference worker parses GGUF; run it sandboxed with no network and no file access beyond the model path.
8. **Voice attacks.** Audio from videos/other devices can speak commands. Tier ≥ 2 never acts on voice alone (on-screen confirm); optional speaker verification; visible mic state; PTT by default.
9. **Eval harness.** An offline corpus of injection/jailbreak/exfiltration cases runs on every planner/prompt change; zero policy bypasses is a release gate.

---

## 12. Scheduling, resources, observability, recovery

- **I/O:** Tokio. **CPU-heavy:** bounded worker pool. **GPU:** only `dumer-infer`, with explicit VRAM/concurrency caps. **OS calls:** adapters with timeouts and narrow schemas.
- Bounded queues + backpressure; interactive > indexing; cancellation tokens and deadlines; "pause background work"; event-driven file watching.
- **Audit events:** request authenticated, intent selected, policy decision + capability, approval requested/granted/denied/expired, adapter start/finish, timeout/failure, enrollment/rotation/revocation.
  Log identifiers, hashes, op names, safe summaries; never secrets, full documents, raw audio, or sensitive queries. Hash-chain records; send signed checkpoints to the phone.
- **Controls that work without the model:** stop task, pause automation, disable remote, revoke device, unload model, lock vault, export/delete memory, restore known-good config, global-hotkey panic button.
- **Recovery:** install/uninstall/disable must not depend on D.U.M.E.R running. Keep a known-good config snapshot and a rollback path.

---

## 13. Deployment and supply chain
- Start `dumerd` at login, **not** as an elevated service. OS-protected keys. Restrictive IPC ACLs (named pipes with `FILE_FLAG_FIRST_PIPE_INSTANCE`; verify peer SID/PID).
- The app registry stores **path + publisher signature** (not just a hash, since browsers auto-update); verify at launch time; launch with `CreateProcess` and allowlisted argument templates, never via a shell.
- `#![forbid(unsafe_code)]` in all crates except explicitly reviewed FFI/OS crates. `cargo-deny`, `cargo-audit`, pinned lockfile, reviewed critical deps, SBOM.
- Fuzz every parser (`cargo-fuzz`). Sign release artifacts; no silent self-update of trusted binaries; permission-changing updates need approval.

## 14. Open items to decide with evidence
Relay choice (small VPS WireGuard hub vs Headscale), exact base model, UnifiedPush vs foreground-service battery cost,
WebView2 dependency for Tauri vs a minimal native UI, which privileged ops (if any) ever ship, SQLCipher unlock UX, whether a phone-local model is worth the battery.
