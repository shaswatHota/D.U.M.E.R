# D.U.M.E.R — Progress and Handoff

> Read this file at the start of every session, together with AGENTS.md.
> Update it at the end of every session. It is the only memory between sessions.

**Last updated:** 2026-11-21
**Current milestone:** M5 — Storage, vault, memory (DONE)
**Next step:** Owner reviews M5 changes and tags `m5-done`; proceed to M6 (Local interfaces + push-to-talk voice) in new session.

## Milestone status

| Milestone | Status | Tag | Notes |
|---|---|---|---|
| M0 Repo, threat model, invariants, CI | DONE (owner-confirmed) | m0-done | verified clean |
| M1 Core skeleton, protocol types, audit | DONE (owner-confirmed) | m1-done | verified clean |
| M2 Command registry, matcher, fast path | DONE (owner-confirmed) | m2-done | verified clean |
| M3 Policy broker | DONE (owner-confirmed) | m3-done | verified clean |
| M4 Platform adapter (Windows, Rust) | DONE (owner-confirmed) | m4-done | verified clean |
| M5 Storage, vault, memory | DONE (exit criteria met) | m5-done | pending owner review & tag |
| M6 Local interfaces + push-to-talk voice | NOT STARTED | | |
| M7 Private remote link | NOT STARTED | | |
| M8 Android companion | NOT STARTED | | |
| M9 Elevation flow + dumer-privd | NOT STARTED | | |
| M10 Local inference + planner | NOT STARTED | | |
| M11 Research gateway + cache | NOT STARTED | | |
| M12 Full voice, playbooks, more devices | NOT STARTED | | |
| M13 Hardening and release | NOT STARTED | | |

Status values: NOT STARTED / IN PROGRESS / BLOCKED / DONE (exit criteria met + owner approved).

## Session start checklist
1. Read AGENTS.md, then this file, then the target milestone in docs/implementation.md and the sections of docs/architecture.md it cites.
2. Run the CI script. Report the result before changing anything. If M0/M1 checks are red, fix that first and tell the owner.
3. Confirm M0/M1 exit criteria really hold. Do not trust the table above:
   - workspace builds, CI green;
   - threat model and default-deny written;
   - `dumerd` starts unprivileged and shuts down cleanly;
   - protocol types use deterministic CBOR, strict decoding, 64 KiB frame cap;
   - audit log is append-only and hash-chained;
   - no shell-execution code exists anywhere (grep for process spawning APIs).
4. Write a short plan and wait for the owner's "go".

## Working loop (inside a milestone)
1. Write failing tests first.
2. Implement.
3. Run fmt, clippy `-D warnings`, tests, cargo-deny, cargo-audit.
4. Fix and repeat.
5. **Stop after 5 failed attempts on the same problem** and report instead of trying workarounds. Never weaken a test, an invariant, or a policy rule to get to green.

## Milestone gate (between milestones; never skip)
1. Run `/security-review` against the milestone's changes.
2. Confirm every exit criterion in docs/implementation.md is met, with evidence (command output or test names).
3. Update this file: status, decisions, deferred risks, skipped tests, next step.
4. Owner reviews the diff (especially policy, crypto, network, and anything touching approvals), commits, tags `m<N>-done`.
5. Only then start the next milestone, in a **new session**.

## Decisions made so far
- Baseline decisions are in docs/decisions/decisions.md (ADR-001 to ADR-015).
- Add new decisions here with date and reason, then move them into decisions.md.

| Date | Decision | Reason |
|---|---|---|
| 2026-11-21 | ADR-016: Frame format and deterministic CBOR codec in `dumer-proto` | Length-prefixed 64 KiB frame cap, RFC 8949 deterministic CBOR, strict unknown field rejection (`deny_unknown_fields`), canonical hashing. |
| 2026-11-21 | ADR-017: Append-only hash chaining and secret redaction in `dumer-audit` | SHA-256 event chaining, sequence validation, tamper detection, and proactive secret/PII redaction before hashing. |
| 2026-11-21 | ADR-018: Command registry, normalizer, and fast-path matcher in `dumer-proto` and `dumer-match` | Typed `Operation` enum (no shell hatches), initial 5 commands, Aho-Corasick multi-pattern scanner, bounded fuzzy Levenshtein, ambiguity margin (0.15) failing closed, act-first report-after terse result, <50 µs dispatch. |
| 2026-11-21 | ADR-019: Deterministic Policy Broker with Taint Tracking, Narrow Capabilities, and Action-Bound Approvals in `dumer-policy` | Pure, deterministic, I/O-free evaluation function `(PolicyInput) -> Allow | Deny(reason) | RequireApproval(spec)` enforcing default-deny (Invariant 2), zero model confidence input (Invariant 1), prohibition of wildcard shell/filesystem/admin capabilities (Invariant 4), taint propagation requiring user approval for Web/File/Voice/Model inputs in Tier >= 1 ops (Invariant 9), cryptographic approval binding over canonical request hash + nonce + device + expiry with replay detection (Invariant 5), dual approvals for Tier 4, and deterministic kill switches (global pause, device revocation) without involving the model (Invariant 12). |
| 2026-11-21 | ADR-020: OS-Neutral Platform Trait, Authenticode Signature Verification, Direct Win32 Process Spawning, and Anti-Squatting Named Pipe IPC in `dumer-platform` | OS-neutral `Platform` trait (`launch_registered_app`, `basic_status`, `notify`, `lock_state`). Windows adapter (`WindowsPlatform`) with strict Authenticode and Windows Security Catalog verification (`WinVerifyTrust`, `CryptQueryObject`, `CertGetNameStringW`, `CryptCATAdmin*`) ensuring only allowlisted, signature-verified applications from expected publishers can launch. Spawns processes directly via Win32 `CreateProcessW` without any command shell, prohibiting handle inheritance (`bInheritHandles = FALSE`) and handle leaks. Local named pipe IPC (`PlatformIpcServer`, `PlatformIpcClient`) enforcing anti-squatting via `FILE_FLAG_FIRST_PIPE_INSTANCE`, same-user client authentication via token SID comparison (`ImpersonateNamedPipeClient` + `EqualSid` + `RevertToSelf`), length-prefixed deterministic CBOR framing (`v: 1`, `deny_unknown_fields`, 64 KiB cap), workstation session lock enforcement (`OpenInputDesktop`), and timeout-guarded socket operations. |
| 2026-11-21 | ADR-021: Encrypted Storage Hierarchy, DPAPI Key Envelopes, Argon2id Passphrase KDF, Separate Vault Key, and Cascading Deletion in `dumer-crypto` and `dumer-vault` | `Key256` zeroized on drop, `KeyEnvelope` wrapping random 256-bit DEK using Windows DPAPI CNG `CryptProtectData`/`CryptUnprotectData` and Argon2id KDF passphrase KEK, XChaCha20-Poly1305 AEAD with 192-bit nonces, and `CanaryManager`. Bundles SQLite 3.54.1 (WAL mode, foreign keys, synchronous NORMAL, patched against RUSTSEC-2026-0459/CVE-2026-119375) with schema migrations (`devices`, `tasks`, `memory_records`, `audit_events`, `grants`, `approvals`, `cache_entries`, `vault_items`). Encrypts all sensitive memory and cache records at rest using DEK. Enforces separate `VaultKey` with user-verification unlock, auto-lock timer, and fail-closed locked access. Enforces placeholder substitution (`{{PROFILE.*}}`, `{{VAULT.*}}`) strictly validating per-field destination allowlists. Enforces freshness classes (`Static`, `Slow`, `Fast`, `Volatile`) with automatic TTL expiration purge, cascading deletion across memory and cache, and sanitized export omitting locked secrets. |

## Deferred risks and known gaps
| Milestone | Item | Severity | Planned fix |
|---|---|---|---|
| | | | |

## Skipped, flaky, or failing tests
| Test | Why | Owner action needed |
|---|---|---|
| | | |

## Measurements (fill in as they become available)
| Metric | Target | Latest | Milestone |
|---|---|---|---|
| Matcher + dispatch p95 | < 20 ms | 0.047 ms (47.1 µs) | M2 |
| Matcher alias p95 | < 20 ms | 0.002 ms (2.0 µs) | M2 |
| dumerd idle RSS (model unloaded) | well under 100 MB | | M2+ |
| App launch end to end | measure | | M4 |
| Remote round trip | measure | | M7 |
| LLM cold / warm latency, peak VRAM | measure | | M10 |

## Environment notes
- Toolchain and tool versions in use: rustc 1.100.0 (0ef1bc386 2026-11-09), cargo 1.100.0, clippy 0.1.100, rustfmt 1.11.0 (channel: stable-x86_64-pc-windows-gnu), cargo-deny 0.16.4, cargo-audit 0.20.0
- Dev machine: Windows laptop, 16 GB RAM, RTX 4050 (about 6 GB VRAM)
- Android device and API level: (fill in at M8)
- Relay / VPS choice: (decide before M7)

## Session log (newest first)

### 2026-11-21 — M5: Storage, Vault, Memory
- Done:
  - Cryptographic primitives crate `crates/dumer-crypto`:
    - `Key256` key wrapper implementing `Zeroize` and `ZeroizeOnDrop` with redacted debug representations.
    - `KeyEnvelope`: OS CSPRNG 256-bit DEK generation, Windows DPAPI wrapping/unwrapping (`CryptProtectData`/`CryptUnprotectData` via CNG with documented `// SAFETY:` justifications), Argon2id passphrase KDF derivation (64 MiB, 3 iterations, 4 lanes), and KEK rotation.
    - `XChaCha20Poly1305` AEAD encryption/decryption with unique 192-bit (24-byte) nonces, authenticated associated data (AAD) binding, and fail-closed tampering rejection.
    - `CanaryManager` and `CanaryToken` for generating high-entropy canary secrets and scanning text/logs to detect data exfiltration.
  - Storage & vault crate `crates/dumer-vault`:
    - Database migrations system (`_schema_migrations`) with bundled SQLite 3.54.1 (WAL mode, foreign keys, synchronous NORMAL) patched against CVE-2026-119375 / RUSTSEC-2026-0459.
    - Full relational tables: `devices`, `tasks`, `memory_records`, `audit_events`, `grants`, `approvals`, `cache_entries`, `vault_items`.
    - Memory records encrypted at rest using DEK via XChaCha20-Poly1305, tracking source, confidence, sensitivity, retention, provenance, taint, and expiration.
    - `VaultManager`: separate `VaultKey` distinct from DEK (ADR-007), user-verification unlock, auto-lock timer, manual lock with memory zeroization, and fail-closed rejection when locked (`VaultLocked`).
    - `PlaceholderResolver`: parses `{{PROFILE.*}}` and `{{VAULT.*}}`, enforcing per-field destination allowlists (fails closed if destination is unauthorized or vault is locked).
    - `TtlEngine` and `FreshnessClassifier`: implements freshness classes (`Static`, `Slow`, `Fast`, `Volatile`), zero persistence for volatile content, and automated purging of expired cache and memory records.
    - `export_data`: sanitizes exported bundles, redacting vault secrets when locked or unauthorized.
    - `cascade_delete_memory_record`: deletes memory records and cascades deletion to linked cache entries.
  - Daemon integration in `dumerd`:
    - Integrated storage and vault lock/unlock/encryption checks into `dumerd::run_self_tests`, verifying Invariant 8 at startup.
- Tests and checks run (with results):
  - `cargo fmt --check`: PASS
  - `cargo clippy --workspace --all-targets -- -D warnings`: PASS (0 warnings)
  - `cargo test --workspace`: PASS (102 tests passed across all crates, 0 failed)
    - 9 tests in `dumer-crypto`: key generation, redacted debug, AEAD encrypt/decrypt roundtrip, tampered ciphertext rejection, wrong key rejection, tampered AAD rejection, Argon2id KDF derivation, KEK envelope wrap/unwrap/rotation, DPAPI envelope wrap/unwrap, canary token generation and leak detection.
    - 8 tests in `dumer-vault`: schema migration & table creation, restart survival and wrong-key failure, vault lock/unlock and auto-lock timer, placeholder allowlist enforcement, TTL freshness classes & expiration purge, cascading deletion, export secret redaction, tracing log-scan verifying zero secrets/canaries in logs.
    - 85 existing tests in `dumer-audit`, `dumer-match`, `dumer-platform`, `dumer-policy`, and `dumerd` all pass.
  - `cargo deny check`: PASS (advisories ok, bans ok, licenses ok, sources ok; Zlib added for foldhash, SQLite 3.54.1 patched)
  - `cargo audit`: PASS (153 dependencies scanned, 0 vulnerabilities)
- Could not verify: None (all 102 unit, integration, crypto, and security tests pass).
- Decisions:
  - ADR-021: Encrypted Storage Hierarchy, DPAPI Key Envelopes, Argon2id Passphrase KDF, Separate Vault Key, and Cascading Deletion in `dumer-crypto` and `dumer-vault`.
- Deferred risks: None for M5.
- Next step: Owner reviews diff, commits, and tags `m5-done`; proceed to M6 (Local interfaces + push-to-talk voice) in new session.

### 2026-11-21 — M4: Platform Adapter (Windows, Rust)
- Done:
  - OS-neutral `Platform` trait (`launch_registered_app`, `basic_status`, `notify`, `lock_state`) defined in `crates/dumer-platform`.
  - Windows platform adapter (`WindowsPlatform`) implemented in `crates/dumer-platform/src/windows` running in logged-in user context (`is_unprivileged()` verified).
  - App registry (`AppRegistry`) with `AppDefinition` (canonical paths, allowlisted argument templates, publisher signature and hash expectations).
  - Strict Authenticode and Windows Security Catalog verification (`WinVerifyTrust`, `CryptQueryObject`, `CertGetNameStringW`, `CryptCATAdmin*`) verifying publisher identity and rejecting unsigned, tampered, or swapped binaries at launch time.
  - Process launching implemented strictly via Win32 `CreateProcessW` directly (no shell, no cmd/powershell, no handle inheritance `bInheritHandles = FALSE`, zero handle leaks).
  - Workstation session lock state detection (`OpenInputDesktop`) preventing application launches when the workstation session is locked.
  - Local Named Pipe IPC (`PlatformIpcServer`, `PlatformIpcClient`) enforcing anti-squatting defense via `FILE_FLAG_FIRST_PIPE_INSTANCE`, same-user client authentication via token SID comparison (`ImpersonateNamedPipeClient` + `EqualSid` + `RevertToSelf`), and timeout guards.
  - Length-prefixed deterministic CBOR framing for all IPC messages (`PlatformIpcRequest`, `PlatformIpcResponse`, `v: 1`, `deny_unknown_fields`, 64 KiB frame cap).
  - In-memory `MockPlatform` implemented for testing and deterministic environments.
  - Fast-path integration in `dumerd::fast_path` (`dispatch_fast_path_with_platform`, `execute_operation_with_platform`) wiring the platform adapter to deterministic command execution with audit logging.
- Tests and checks run (with results):
  - `cargo fmt --check`: PASS
  - `cargo clippy --workspace --all-targets -- -D warnings`: PASS (0 warnings)
  - `cargo test --workspace`: PASS (85 tests passed across all crates, 0 failed)
    - 16 tests in `dumer-platform`: invalid app ID, unregistered app, missing executable, swapped/unsigned executable, wrong publisher signature, argument template enforcement, locked session rejection, pipe squatting defense (`FILE_FLAG_FIRST_PIPE_INSTANCE`), peer verification, IPC request/response roundtrip, duplicate requests, notify command, server crash/restart, general shell prevention (Invariant 4), unprivileged token check.
    - 12 tests in `dumerd`: fast path with platform adapter launches app, locked platform rejection, CLI flags, daemon lifecycle, audit logging, and p95 latency benchmark.
    - All existing unit, integration, policy proptests, and security tests pass.
  - `cargo deny check`: PASS (advisories ok, bans ok, licenses ok, sources ok)
  - `cargo audit`: PASS (103 dependencies scanned, 0 vulnerabilities)
- Could not verify: None (all 16 platform tests and integration tests pass).
- Decisions:
  - ADR-020: OS-Neutral Platform Trait, Authenticode Signature Verification, Direct Win32 Process Spawning, and Anti-Squatting Named Pipe IPC in `dumer-platform`.
- Deferred risks: None for M4.
- Next step: Owner reviews diff, commits, and tags `m4-done`; M5 (Storage, vault, memory) in new session.

### 2026-11-21 — M3: Policy Broker
- Done:
  - Pure, deterministic, I/O-free `PolicyBroker::evaluate(&PolicyInput) -> PolicyDecision` implemented in `crates/dumer-policy`.
  - Invariant 1 strictly enforced: model confidence is not an input or parameter in `PolicyInput` or `PolicyBroker`.
  - Invariant 2 (default deny): unknown operations, capabilities, devices, or destinations fail closed to `Deny`.
  - Invariant 3: `PolicyBroker` integrated into `dumerd::fast_path` so every action passes through the policy broker.
  - Invariant 4: narrow capability grants with strict rejection of wildcard shell (`shell.execute:*`), filesystem (`filesystem.read:*`, `files.*`), and admin (`admin:*`).
  - Invariant 5: action-bound approvals cryptographically tied to exact canonical request hash over `(op, args, subject)` + single-use nonce + expiry + device. Replayed nonces or altered args fail closed.
  - Invariant 9: taint propagation tracking (`TaintMap`, `TaintLabel`) requiring explicit user confirmation if any untrusted Web/File/Voice/Model taint is present in arguments of state-changing ops (RiskTier >= 1).
  - Invariant 11: engine errors, expired grants, revoked devices/grants fail closed.
  - Invariant 12: deterministic kill switches (global pause and device revocation) enforced immediately without involving the LLM.
  - Autonomy levels matrix (L0..L3 vs RiskTier 0..4) with Tier 3+ never autonomous and Tier 4 requiring dual approval (PC + Phone).
  - Task budgets (remaining steps, deadline) enforced deterministically.
  - Proptest proving that no unregistered operation string can ever evaluate to `Allow`.
- Tests and checks run (with results):
  - `cargo fmt --check`: PASS
  - `cargo clippy --workspace --all-targets -- -D warnings`: PASS (0 warnings)
  - `cargo test --workspace`: PASS (69 tests passed, 0 failed across all crates)
  - `cargo deny check`: PASS (advisories ok, bans ok, licenses ok, sources ok)
  - `cargo audit`: PASS (103 dependencies scanned, 0 vulnerabilities)
  - Latency benchmarks: fast-path dispatch p95 verified < 20 ms budget.
- Could not verify: None (all 22 policy unit, security, and proptests passed).
- Decisions:
  - ADR-019: Deterministic Policy Broker with Taint Tracking, Narrow Capabilities, and Action-Bound Approvals in `dumer-policy`.
- Deferred risks: None for M3.
- Next step: Owner reviews diff, commits, and tags `m3-done`; M4 (Platform adapter) in new session.

### 2026-11-21 — M2: Command Registry, Matcher & Fast Path
- Done:
  - Strongly-typed `Operation` enum and `CommandDefinition { id, risk, capabilities, schema_version }` in `dumer-proto::registry`.
  - Initial 5 command definitions registered: `system.status.read`, `application.list_registered`, `application.open`, `task.status.read`, `task.cancel`.
  - 13-point security review completed for all initial commands per `threat-model.md` §7.
  - Deterministic normalizer, alias table, Aho-Corasick prefix scanner, bounded Levenshtein fuzzy matcher, typed slot extractors, and ambiguity margin handling in `dumer-match`.
  - Act-first, report-after fast-path dispatch in `dumerd::fast_path` with single-line terse output and zero LLM calls.
  - All fast-path actions and policy rejections audited to `AuditChain` with secret-free details.
  - Latency benchmarks implemented and verified: exact alias p95 = 2.0 µs, fuzzy p95 = 49.8 µs, end-to-end dispatch p95 = 47.1 µs (budget: < 20 ms).
- Tests and checks run (with results):
  - `cargo fmt --check`: PASS
  - `cargo clippy --workspace --all-targets -- -D warnings`: PASS (0 warnings)
  - `cargo test --workspace`: PASS (47 tests passed, 0 failed across all crates)
  - `cargo deny check`: PASS (advisories ok, bans ok, licenses ok, sources ok)
  - `cargo audit`: PASS (103 dependencies scanned, 0 vulnerabilities)
  - Benchmarks: Matcher exact p95 = 2.0 µs, fuzzy p95 = 49.8 µs, dispatch p95 = 47.1 µs (< 20 ms budget)
- Could not verify: None (all unit, security, golden matcher, and latency benchmark tests verified).
- Decisions:
  - ADR-018: Typed command registry, bounded Levenshtein fuzzy matching, Aho-Corasick intent scanner, ambiguity margin (0.15) failing closed, and act-first terse fast path.
- Deferred risks: None for M2.
- Next step: Owner reviews diff, commits, and tags `m2-done`; M3 (Policy broker) in new session.

### 2026-11-21 — Handoff to M2
- M0 and M1 completed by the owner. Details not recorded here.
- Next: M2 per docs/implementation.md. Do not start M3.

<!-- Template for each new entry
### YYYY-MM-DD — M<N>
- Done:
- Tests and checks run (with results):
- Could not verify:
- Decisions:
- Deferred risks:
- Next step:
-->