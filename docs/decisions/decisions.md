# Architecture Decision Records (compact)

Format: **ID — Decision** · Status · Why · Revisit when

- **ADR-001 — Rust for core, policy, vault, matcher, adapters.** Accepted. Memory safety, low RAM, one toolchain. Revisit: never for the core; adapters only if a Windows API is impractical in Rust.
- **ADR-002 — Deterministic fast path; LLM only as fallback planner.** Accepted. Latency + safety. Revisit: no.
- **ADR-003 — LLM is an untrusted planner with constrained decoding.** Accepted. Revisit: no.
- **ADR-004 — Embedded `russh` SSH-RPC subsystem inside WireGuard; no OpenSSH Server.** Accepted. Keeps core unprivileged; no shell by construction. Revisit: if russh proves unmaintained/insecure → mTLS over QUIC/HTTP2 with the same app-layer protocol.
- **ADR-005 — Self-managed WireGuard hub-and-spoke relay (dial-out).** Accepted. Works behind CGNAT, no cloud control plane. Revisit: Headscale if multi-device mesh grows.
- **ADR-006 — Deterministic CBOR wire format, 64 KiB frames.** Accepted. Canonical signing. Revisit: if cross-language canonicalization bugs appear → JCS JSON.
- **ADR-007 — SQLCipher + separate vault key; placeholder substitution.** Accepted.
- **ADR-008 — Two phone keys: transport key (wrapped) + non-exportable P-256 approval key (biometric per use).** Accepted. Revisit: verify StrongBox/Keystore behaviour on the actual phone.
- **ADR-009 — Rust OS adapters behind a `Platform` trait (replaces C#).** Accepted.
- **ADR-010 — `dumer-infer` worker over pipes; no listening socket; sandboxed, no network.** Accepted.
- **ADR-011 — Elevation via optional `dumer-privd` with fixed op catalog; helper re-verifies user signature; dual approval for tier 4.** Accepted. No kernel code.
- **ADR-012 — Dual-model planner/reader + taint tracking.** Accepted.
- **ADR-013 — Notifications: connected-mode service and/or self-hosted UnifiedPush; never FCM payloads with details.** Accepted. Revisit: battery measurements.
- **ADR-014 — STT: Vosk grammar for commands, whisper.cpp CPU for dictation.** Accepted. Revisit: if accuracy poor.
- **ADR-015 — Research chat-AI browsing is an optional off-by-default plugin; self-hosted metasearch first.** Accepted.
- **ADR-016 — Frame format and deterministic CBOR codec in `dumer-proto`.** Accepted. `u32` big-endian length prefix with strict 64 KiB frame cap, `ciborium` for deterministic RFC 8949 CBOR, strict unknown field rejection (`deny_unknown_fields`), canonical request hashing.
- **ADR-017 — Append-only hash chaining and proactive secret redaction in `dumer-audit`.** Accepted. Deterministic SHA-256 event chaining with monotonic sequence tracking, tamper-detection verification, and proactive scrubbing of bearer tokens, API keys, email PII, and canary tokens before hashing.
- **ADR-018 — Command Registry, Normalizer, and Fast-Path Matcher in `dumer-proto` and `dumer-match`.** Accepted. Strongly-typed `Operation` enum with zero shell hatches, `CommandDefinition` catalog with risk tiers (0 to 4), input normalization, Aho-Corasick multi-pattern scanning, bounded Levenshtein fuzzy matching (distance <= 2), ambiguity margin check (0.15) to fail closed on ambiguous commands, act-first report-after terse result rendering, and end-to-end fast-path dispatch audited in < 50 µs (budget: < 20 ms).
- **ADR-019 — Deterministic Policy Broker with Taint Tracking, Narrow Capabilities, and Action-Bound Approvals in `dumer-policy`.** Accepted. Pure, deterministic, I/O-free evaluation function `(PolicyInput) -> Allow | Deny(reason) | RequireApproval(spec)` enforcing default-deny (Invariant 2), zero model confidence input (Invariant 1), prohibition of wildcard shell/filesystem/admin capabilities (Invariant 4), taint propagation requiring user approval for Web/File/Voice/Model inputs in Tier >= 1 ops (Invariant 9), cryptographic approval binding over canonical request hash + nonce + device + expiry with replay detection (Invariant 5), dual approvals for Tier 4, and deterministic kill switches (global pause, device revocation) without involving the model (Invariant 12).
