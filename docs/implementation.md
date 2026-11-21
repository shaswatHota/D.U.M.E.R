# D.U.M.E.R — Implementation Plan (v2)

**Approach:** Build a narrow, secure vertical slice first. Add autonomy, inference and privilege only after the deterministic execution
and permission boundaries are reliable and tested. Architecture lives in `docs/architecture.md`; section references (§n) point there.

## 1. Development principles
1. Security boundary before powerful tools. No OS-acting code before the threat model and default-deny policy exist (M0 gate).
2. Deterministic first: never ask an LLM to do what the command registry can do.
3. Core stays unprivileged. Model output and external content are untrusted.
4. Every capability is explicit, narrow, revocable, auditable.
5. Small releases, thoroughly tested. Modular monolith; split processes only for isolation (§2).
6. **Measure** CPU, RAM, VRAM, latency, battery on the real devices (laptop: 16 GB RAM / RTX 4050 ≈ 6 GB VRAM).
7. Every milestone ends with its exit criteria green, docs updated, and a security review against `docs/threat-model.md`.

## 2. Repository layout

```text
dumer/
├── AGENTS.md  README.md
├── .agents/{rules,skills,workflows}/
├── docs/{architecture,implementation,threat-model,review-changes}.md
│   ├── decisions/decisions.md
│   └── protocol/protocol.md
├── Cargo.toml                       (workspace)
├── crates/
│   ├── dumer-proto/      wire types, CBOR codec, schemas, versioning        (shared with Android via UniFFI)
│   ├── dumer-match/      normalizer + deterministic matcher                 (shared with Android)
│   ├── dumer-crypto/     keys, signatures, AEAD, KDF, canonical hashing     (shared with Android)
│   ├── dumer-policy/     capabilities, risk tiers, taint, approvals, decisions
│   ├── dumer-audit/      append-only hash-chained audit
│   ├── dumer-vault/      SQLCipher access, vault, placeholders, TTL cache, export/delete
│   ├── dumer-platform/   `Platform` trait + windows/ + linux/ impls
│   ├── dumer-net/        embedded SSH-RPC server, sessions, enrollment, revocation
│   ├── dumer-planner/    LLM client, prompt/grammar builders, dual-model orchestration
│   ├── dumerd/           the core daemon (binary)
│   ├── dumer-infer/      inference worker (binary, llama.cpp)
│   ├── dumer-voice/      STT/TTS worker (binary)
│   ├── dumer-research/   research gateway (binary) + query firewall
│   ├── dumer-privd/      optional privileged helper (binary)    [M9]
│   ├── dumer-cli/        control CLI (stop, revoke, pause, export…)
│   └── dumer-ffi/        UniFFI bindings for Android
├── android/              Kotlin UI (thin)
├── ui/                   Tauri tray app                                       [late]
├── tests/{protocol,policy,security,injection,perf}/
├── fuzz/                 cargo-fuzz targets
├── eval/                 offline planner eval + injection corpus
└── scripts/              build, sign, dev-relay, bench
```

## 3. Milestones

Each milestone: **Deliverables → Security work → Tests → Exit criteria**. Do not start a milestone until the previous exit criteria pass.

### M0 — Repository, threat model, invariants, CI  *(gate for everything)*
- Workspace skeleton, `rust-toolchain.toml`, `deny.toml`, `.github`-style CI script (fmt, clippy `-D warnings`, test, `cargo-deny`, `cargo-audit`).
- Finalize `docs/threat-model.md` (draft provided): assets, zones, attackers, entry points, forbidden-in-v1 actions, per-command review checklist.
- Commit `docs/decisions/decisions.md`. `#![forbid(unsafe_code)]` lint config.
- **Exit:** trust boundaries and default-deny written; CI green on an empty workspace.

### M1 — Core skeleton + protocol types + audit
- `dumerd` with `--version`, `--check-config`, `--self-test`; config validation; graceful shutdown; health record.
- `dumer-proto`: request/response/approval types, deterministic CBOR, size limits, `deny_unknown_fields`.
- `dumer-audit`: append-only table, hash chaining, redaction helpers.
- **Tests:** codec round-trip + canonical-encoding property tests; fuzz target for the frame decoder.
- **Exit:** starts unprivileged, writes health record, shuts down cleanly, no shell-execution code exists anywhere.

### M2 — Command registry + deterministic matcher + fast path
- Typed `Operation` enum and `CommandDefinition {id, risk, capabilities, schema_version}`. **No `Shell(String)`.**
- `dumer-match`: normalizer, alias table, aho-corasick, bounded fuzzy match, typed slots, ambiguity margin → `Match | Ambiguous | NoMatch`.
- First commands: `system.status.read`, `application.list_registered`, `application.open`, `task.status.read`, `task.cancel`.
- Act-first/report-after result rendering (tick / one short line).
- **Tests:** unknown op fails closed; matcher golden tests; criterion benchmarks (matcher p50/p95/p99).
- **Exit:** "open chrome" style commands work with no LLM; p95 matcher+dispatch < 20 ms on the laptop; all operations audited.

### M3 — Policy broker
- Decisions: `Allow | Deny | RequireApproval`. Inputs: principal, validated op+args, capability, tier, session state, grant+expiry, approval token, **taint labels**.
- Autonomy levels, budgets, global pause. Approval objects (canonical hash, nonce, expiry) defined but not yet delivered anywhere.
- **Tests:** allow, deny, expired grant, wrong device, altered args, missing approval, replayed approval, tainted arg into tier ≥1, policy-engine failure ⇒ deny, property tests that no path yields `Allow` for an unregistered op.
- **Exit:** policy is deterministic, pure, and fully covered; model confidence is not an input.

### M4 — Platform adapter (Windows first, Rust)
- `Platform` trait: `launch_registered_app`, `basic_status`, `notify`, `lock_state`. `windows` crate implementation as a user-context process.
- App registry: app id → path + **publisher signature** (+ optional hash); verify signature at launch; launch via `CreateProcess` + allowlisted arg templates.
- Local IPC: named pipe, restrictive ACL, `FILE_FLAG_FIRST_PIPE_INSTANCE`, peer verification, versioned messages, timeouts.
- **Tests:** invalid id, unregistered exe, swapped/unsigned exe, missing exe, duplicate requests, adapter crash/restart, locked session, pipe squatting attempt.
- **Exit:** registered app launch works; adapter cannot be used as a general shell.
- Linux implementation of the trait comes in M12 (keep the trait OS-neutral now).

### M5 — Storage, vault, memory
- SQLCipher DB + migrations; DEK wrapped by OS key (DPAPI/TPM); optional Argon2id passphrase.
- Tables: devices, tasks, memory_records (with source, sensitivity, taint, retention, provenance), audit_events, grants, approvals, cache_entries.
- Vault: separate key, user-verification unlock, auto-lock; placeholder resolver with per-field destination allowlists; canary records.
- TTL engine + freshness classes (§10), export, deletion that cascades to embeddings/caches.
- **Tests:** restart survival, migration up/down, expired records excluded, deletion cascade, export, key-rotation, wrong-key failure, no secrets in logs (log-scan test).
- **Exit:** state survives restart; export/delete verified; vault unreadable without unlock.

### M6 — Local interfaces: CLI/tray + push-to-talk voice commands
- `dumer-cli` control verbs: stop, pause-automation, disable-remote, revoke-device, lock-vault, export, panic.
- `dumer-voice`: Vosk grammar-constrained command recognition generated from the registry; PTT; visible mic state; no raw audio retention; voice → same matcher → same policy.
- **Tests:** voice transcripts treated as `Voice`-tainted; tier ≥2 never executes on voice alone; grammar regeneration on registry change.
- **Exit:** spoken "open chrome" works fast and offline; panic/stop work with the model absent.

### M7 — Private remote link  *(vertical slice part 1)*
- Dev relay script (WireGuard hub) + docs; laptop and phone dial out.
- `dumer-net`: embedded `russh` server on the overlay interface only, subsystem `dumer-rpc@1`, no shell/exec/pty/forwarding, key-only auth, host-key pinning.
- Session challenge nonce, monotonic counters, per-device capabilities, rate/size limits, enrollment (QR + SAS), revocation.
- **Tests:** unknown device, replay, malformed/oversized frames, unauthorized op, revoked device, attempts to open shell/exec/forward channels (must all fail), listener not bound to public interfaces.
- **Exit:** a CLI test client can issue `application.open` over the overlay; every negative test rejected.

### M8 — Android companion  *(vertical slice part 2)*
- Kotlin UI + `dumer-ffi` (proto, matcher, crypto). Enrollment, Keystore P-256 approval key (biometric per use), connect/disconnect, command UI, task status/cancel, approval screen, local offline command subset.
- Notifications: connected-mode foreground service (opt-in) and/or self-hosted UnifiedPush/ntfy content-free wake-up. Idempotent requests, safe reconnect.
- Approval screen renders **only** from the broker-validated request; labels the agent's reason "unverified".
- **Exit (the vertical slice):** phone enrolls, issues `application.open`, receives status, approves/denies a test request, and is revoked from the laptop, after which requests fail. Arbitrary shell, unknown apps, and revoked devices are rejected in tests.

### M9 — Elevation flow + `dumer-privd`  *(optional but specified)*
- ElevationRequest builder (subject identity, Authenticode signer, hash, flags, effects); dual-device approval for tier 4; PC approval via Windows Hello.
- `dumer-privd`: fixed op catalog starting with **one** trivial op; independent verification (pinned approver keys, signature, nonce, expiry, args, TOCTOU re-check); minimum service privileges.
- **Tests:** forged approval, replayed approval, altered args, signer changed between request and execute, core-compromise simulation (core lies about fields) ⇒ helper rejects.
- **Exit:** a privileged op runs only with a valid, bound, dual approval; every new op requires a documented review.

### M10 — Local inference + planner + injection defenses
- `dumer-infer` (llama.cpp, GPU offload, pipes only, sandboxed, no network); model pinned by SHA-256; lazy load/unload; game/battery/thermal-aware.
- `dumer-planner`: GBNF/JSON-schema constrained plans; dual-model (planner vs quarantined reader); taint propagation; budgets; loop detection; placeholder substitution.
- `eval/`: planner accuracy set + injection/exfiltration corpus.
- Benchmark: cold/warm latency, VRAM/RAM peaks, CPU while on GPU, battery behaviour, thermals.
- **Exit:** ambiguous requests yield valid structured plans; **zero** policy bypasses in the injection corpus; model process can be killed/restarted without harming the core.

### M11 — Research gateway + knowledge cache
- `dumer-research`: separate account/sandbox, clean profile, egress proxy with SSRF/private-range blocking and DNS re-resolution, quarantine downloads, size/type limits; read-only first.
- Outbound query firewall (identifier denylist hashes, PII patterns, canaries, entropy); freshness classifier and TTL cache (§10); self-hosted metasearch backend first; browser-chat-AI plugin last and off by default.
- **Tests:** blocked destinations (RFC1918, loopback, link-local, metadata IPs, DNS rebinding), redirect abuse, oversized/typed content, personal identifier in query ⇒ blocked, canary in egress ⇒ alert + kill, hostile page injection ⇒ no policy effect.
- **Exit:** research works while the gateway process provably cannot read personal files, vault, or credentials.

### M12 — Full voice, playbooks, more devices
- whisper.cpp (CPU) dictation, Piper TTS, optional wake word; optional speaker verification.
- Playbooks (signed declarative autonomous tasks) with budgets; undo journal for tier-2 file ops.
- Linux `Platform` implementation; enroll a satellite device; satellites expose only their own local capabilities.
- **Exit:** a scheduled playbook runs autonomously within budget and journal; satellite enrolls/revokes like the phone.

### M13 — Hardening and release
- Fuzz all parsers (frame, CBOR, matcher input, GGUF path handling), dependency audit, SBOM, signed releases, reproducible-build attempt, rollback path, recovery docs.
- Self-pen-test checklist (see `docs/threat-model.md` §8), tabletop of lost-phone and stolen-laptop scenarios.
- **Exit:** Definition of Done (§6) complete.

## 4. Performance and resource policy
- Interactive > background. Bounded queues, deadlines, cancellation everywhere. Pause-background control. File watching, not scanning.
- Idle: `dumerd` well under 100 MB RSS with model unloaded; no busy loops; measured per release.
- VRAM plan: LLM only on GPU; STT/TTS/embeddings on CPU. Model unloads when fullscreen game/GPU-heavy app, battery, or throttling is detected.
- Benchmarks are tests: record idle CPU/RAM, matcher latency, app-launch latency, remote round-trip, model cold/warm latency, indexing throughput, Android battery, thermal behaviour.

## 5. Testing strategy
- **Unit:** schema validation, capability matching, tiering, expiry/revocation, nonces, task state machine, TTL/deletion, canonical encoding.
- **Integration:** core↔platform, core↔SQLCipher, core↔infer, phone↔relay↔core, enrollment/revocation, adapter crash/restart.
- **Security (must exist before release):** unknown op; extra/unknown fields; oversized/malformed frames; replayed request/approval; expired approval; arg mutation after approval;
  revoked device; shell/exec/PTY/forwarding channel attempts; path traversal/symlink/junction edge cases; malicious filenames/archives; prompt injection in files/web/OCR/voice;
  zero-width/bidi/homoglyph input; SSRF and DNS rebinding; canary exfiltration; named-pipe squatting; TOCTOU on app/signature; log-scan for secrets; privileged-helper distrust of core.
- **Property + fuzz:** policy never allows unregistered ops; codec never panics; matcher never matches outside registry.
- **LLM eval:** planner accuracy and injection corpus run on every prompt/grammar/model change.

## 6. Definition of done for v1
- [ ] Core runs without Administrator/root; no arbitrary shell execution exists anywhere.
- [ ] All commands have schemas, capabilities, risk tiers, tests; unknown commands fail closed.
- [ ] Fast path meets the measured latency budget and never loads the LLM.
- [ ] Remote device identity is cryptographically authenticated; replay protection works; devices revocable; SSH offers no shell/exec/forwarding.
- [ ] Sensitive operations require action-bound approval signed on a verified device; tier-4 requires dual approval.
- [ ] Approval UIs render only from broker-validated data.
- [ ] Vault encrypted; model never sees raw secrets; canaries active; logs verified secret-free.
- [ ] Model output cannot bypass the policy broker (injection corpus: zero bypasses). Tainted data can't reach privileged args unconfirmed.
- [ ] Research gateway cannot reach personal data or private network ranges; outbound query firewall active.
- [ ] Background work is resource-limited, cancellable, and game/battery aware.
- [ ] User can stop all tasks, pause automation, disable remote access, lock the vault, and revoke devices without the model.
- [ ] Install, update, recovery, and uninstall do not depend on the agent running; signed releases.

## 7. First tasks for the AI IDE
1. Read `AGENTS.md`, `docs/architecture.md`, `docs/threat-model.md`, this file.
2. Execute M0, then M1, then M2 — one milestone per session, tests first, ask before changing an invariant.
3. After each milestone: update docs, record decisions, list deferred risks.
