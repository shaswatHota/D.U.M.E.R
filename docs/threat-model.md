# D.U.M.E.R — Threat Model & Security Specification (v2)

**Status:** Finalized for Milestone M0. Normative security baseline for all development.  
**Audience:** Core maintainers, security reviewers, and subagent contributors.  
**Companion Documents:** `docs/architecture.md`, `docs/protocol/protocol.md`, `docs/decisions/decisions.md`, `docs/CONTRIBUTING-SECURITY.md`.

---

## 1. System Mission & Security Posture

D.U.M.E.R is an offline-first, security-first personal AI agent. Its security architecture assumes:
1. **The LLM is an untrusted, prompt-injectable component.** It has zero authority and cannot make security decisions.
2. **All external content is hostile.** Documents, websites, audio, transcripts, and model completions are tainted data, never executable instructions.
3. **Defense-in-depth across isolated process boundaries.** High-risk modules (inference, research, voice, privileged helper) are segregated into dedicated processes with minimal privileges.
4. **Fail closed by design.** Any parser error, schema mismatch, cryptographic validation failure, timeout, or policy ambiguity results in immediate denial.

---

## 2. Assets & Sensitivity Classification

| Asset | Sensitivity | Integrity Impact | Confidentiality Impact | Storage / Location |
|---|---|---|---|---|
| **Vault Secrets & Private Notes** | High | High (unauthorized mutation) | Critical (exfiltration) | SQLCipher DB + separate XChaCha20-Poly1305 vault key; memory protected via `secrecy`/`zeroize` |
| **Profile Data (PII, Identifiers)** | Medium-High | High (identity spoofing) | High (privacy violation) | SQLCipher DB (fields masked with placeholders before LLM exposure) |
| **Master Cryptographic Keys** | Critical | Critical (total system compromise) | Critical (impersonation, decryption) | OS Keystore (Windows DPAPI/TPM-backed CNG; Linux Secret Service); Android Hardware Keystore |
| **Device Approval & Transport Keys** | Critical | Critical (forged approvals) | Critical (MITM / eavesdropping) | Android Keystore (P-256, biometric required per use); pinned laptop host keys |
| **User Files in Approved Folders** | Medium-High | High (data loss/corruption) | Medium-High (data leakage) | Local filesystem in user-allowlisted directories only |
| **Audit Log Chain** | High | Critical (erasure of evidence) | Low-Medium (audit records contain zero secrets) | Append-only, SHA-256 hash-chained local SQLite table; signed checkpoints synced to phone |
| **Policy & Command Registry** | Critical | Critical (unauthorized capability escalation) | Low | Signed/immutable application binaries and configuration |
| **Model Weights (GGUF)** | Medium | High (backdoor/trojan insertion) | Low (open weights) | Local filesystem, pinned by SHA-256 |
| **Owner's External Accounts & Browser State** | Critical | Critical (account takeover) | Critical (session hijacking) | **Strictly out of bounds:** no access to browser profiles, password managers, or credential stores |

---

## 3. Trust Zones & Process Privilege Boundaries

```text
+---------------------------------------------------------------------------------------+
| ZONE 1: USER & APPROVAL UI (Highest Trust)                                            |
| - Physical owner interaction (Desktop UI / Android Companion)                         |
| - Approval screens render exclusively from broker-validated data; reasons labelled    |
+---------------------------------------------------------------------------------------+
        | User actions & Biometric signatures
        v
+---------------------------------------------------------------------------------------+
| ZONE 2: POLICY BROKER (Trusted Decision Core)                                         |
| - Pure deterministic logic; decides Allow | Deny | RequireApproval                    |
| - Enforces default-deny, capability scopes, risk tiers, and taint flow rules          |
+---------------------------------------------------------------------------------------+
        | Enforced policy decisions
        v
+---------------------------------------------------------------------------------------+
| ZONE 3: UNPRIVILEGED COORDINATOR CORE (dumerd)                                        |
| - Runs as standard unprivileged user; no elevated privileges                          |
| - Binds SSH-RPC exclusively to private WireGuard overlay; rejects all public listeners |
| - Mediates access to SQLCipher database and coordinates isolated workers              |
+----+----------------------+-----------------------+-----------------------------------+
     | IPC (Pipe)           | IPC (Pipe)            | IPC (Pipe)                        | ACL'd Pipe
     v                      v                       v                                   v
+----------------+  +-------------------+   +--------------------+              +-------------------+
| ZONE 5:        |  | ZONE 4:           |   | ZONE 9:            |              | ZONE 6:           |
| PLATFORM       |  | LLM WORKER        |   | VOICE WORKER       |              | PRIVILEGED HELPER |
| ADAPTER        |  | (dumer-infer)     |   | (dumer-voice)      |              | (dumer-privd)     |
| (dumer-        |  | - Sandboxed,      |   | - Vosk (grammar)   |              | - Minimal service |
|  platform)     |  |   no network      |   | - whisper.cpp      |              |   privileges      |
| - Authenticode |  | - Anonymous pipes |   | - Piper TTS        |              | - Independently   |
|   verification |  | - GBNF schema     |   | - Emits Voice-     |              |   verifies user   |
| - No shell     |  |   constrained     |   |   tainted inputs   |              |   signatures      |
+----------------+  +-------------------+   +--------------------+              +-------------------+
                            ^
                            | Tainted text only (No personal data / no vault)
+---------------------------------------------------------------------------------------+
| ZONE 7: RESEARCH GATEWAY (dumer-research) [Hostile Content Zone]                     |
| - Isolated OS account / AppContainer sandbox; clean ephemeral browser profile         |
| - Outbound Query Firewall: denylist hash check, PII filter, canary trap, entropy check|
| - Egress proxy: SSRF filter (blocks RFC 1918, link-local, loopback, cloud metadata)   |
+---------------------------------------------------------------------------------------+
        ^
        | Authenticated WireGuard + SSH-RPC (No shell / no forwarding)
+---------------------------------------------------------------------------------------+
| ZONE 8: REMOTE SATELLITES & CLIENTS (Android Companion / Satellite Nodes)             |
| - Hardware Keystore P-256 identity/approval keys; nonces + monotonic counters        |
| - Network reachability != authorization; per-operation policy evaluation              |
+---------------------------------------------------------------------------------------+
```

### Process Isolation Matrix

| Process | OS Privilege Level | Network Capability | Vault Access | Trust Level | Failure Impact |
|---|---|---|---|---|---|
| `dumerd` | Standard user account | Inbound on WireGuard overlay IP only | Gated via vault client | Trusted Coordinator | Coordinator crash; safe fail-closed |
| `dumer-platform` | Standard user account | None | None | Narrow OS Adapter | Cannot launch apps; no shell escalation |
| `dumer-infer` | Restricted token / AppContainer | **None (sandboxed)** | **None (placeholders only)** | Untrusted Planner | Plan generation stops; core unaffected |
| `dumer-voice` | Restricted token | None | None | Untrusted Producer | Voice disabled; no credential leakage |
| `dumer-research` | Dedicated OS account / AppContainer | Egress proxy allowlist only | **Never (zero personal data)** | Hostile Zone | Compromise contained in isolated account |
| `dumer-privd` | Minimal Windows Service | None | None | High (Audit & Verify) | Service fails; elevated ops refused |
| Android Companion | Android sandbox | Outbound to WireGuard hub | Local state only | Authenticated Client | Compromised device revoked at core |

---

## 4. Threat Actors & Threat Scenarios

| Threat Actor | Capabilities & Vectors | Primary Target | Mitigations & Architectural Defenses |
|---|---|---|---|
| **Hostile Web Content & Malicious Documents** | Injects adversarial text, indirect prompt injections, hidden HTML/CSS, bidi/homoglyphs, exploit payloads via web research or indexed files. | Planner hijack, unauthorized command execution, data exfiltration. | Dual-model architecture: quarantined reader consumes external content; privileged planner only receives structured enums; strict taint tracking; egress query firewall; SSRF proxy. |
| **Malicious Ambient Audio** | Emits voice commands via nearby speakers, videos, or unauthorized bystanders. | Accidental command execution. | Push-to-talk by default; Vosk grammar constraint; all voice input carries `Voice` taint; Tier ≥ 2 operations strictly forbid voice-only execution and require interactive on-screen confirmation. |
| **Compromised Android Phone** | Attacker has physical possession or malware on the enrolled mobile device. | Forged command submission, unauthorized approvals. | Biometric authentication required per signature via non-exportable hardware Keystore P-256 key; per-operation authorization; instant one-command device revocation from laptop CLI without the model; Tier 4 requires dual PC + phone approval. |
| **Compromised Relay / Network Man-in-the-Middle** | Hostile operator controls the WireGuard relay VPS; monitors or manipulates network traffic. | Eavesdropping, message forgery, replay attacks. | End-to-end encryption via russh inside WireGuard; pinned laptop host key; challenge nonces + monotonic per-session counters; replay detection; relay sees only encrypted ciphertext. |
| **Local Unprivileged Malware (Same User Context)** | Malicious process running under the same OS user account on the laptop. | Pipe squatting, memory scraping, keystroke logging, DB theft. | Restrictive named pipe ACLs with `FILE_FLAG_FIRST_PIPE_INSTANCE`; peer PID/SID verification; SQLCipher encrypted DB; separate AEAD vault key with short unlock timeouts; canary tokens; audit logging. |
| **Stolen / Lost Laptop** | Physical access to powered-off or locked laptop. | Extraction of secrets, private notes, history. | Full DB encrypted with SQLCipher (OS-protected DEK); vault additionally encrypted with user passphrase/Argon2id; non-exportable keys; panic button; DB unreadable without authentication. |
| **Malicious Model Weights / Supply Chain** | Compromised GGUF model binary, malicious upstream crate, or poisoned toolchain dependency. | Remote code execution during inference or build time. | Pinned model hashes (SHA-256); `dumer-infer` runs in a network-isolated sandbox with no filesystem access beyond the weights; `deny.toml` bans suspicious crates and enforces permissive licenses; `cargo-audit` in CI; `#![forbid(unsafe_code)]`. |
| **The Model Itself (Jailbroken / Misaligned)** | Generates deceptive plans, attempts parameter tampering, hallucinates authorization. | Policy bypass, unintended destructive state changes. | Invariant 1: Model confidence is never a policy input; GBNF grammar-constrained decoding (unknown ops are unrepresentable); every plan step is re-validated by the deterministic policy broker. |

---

## 5. Security Invariants (Normative & Absolute)

The following 14 invariants (defined in `docs/architecture.md` §4) are non-negotiable. Every pull request, design change, and test suite must enforce them:

1. **LLM Never Authorizes:** The model proposes plans; it never authorizes actions. Model confidence is never an input to policy decisions.
2. **Default Deny:** Any unknown operation, capability, destination, device, or parameter is rejected immediately.
3. **Unified Policy Broker:** Every action—regardless of origin (voice, text, remote RPC, schedule, or model)—passes through the exact same policy broker.
4. **No Shell Escape Hatches:** There is no `Shell(String)` capability, no execution of raw PowerShell/cmd/bash, and no invocation of arbitrary executable paths anywhere in the system.
5. **Cryptographically Bound Approvals:** Approvals are cryptographically bound to the canonical tuple `(op, args_hash, target_identity, device_id, nonce, expires_at)`. Any parameter variation invalidates the approval.
6. **Privileged Helper Distrusts Core:** `dumer-privd` does not trust `dumerd`. It independently verifies the user's cryptographic signature, checks nonces, validates expiry, and re-checks target binary Authenticode signatures at execution time (TOCTOU guard).
7. **Network Reachability != Authorization:** Successful WireGuard and SSH connection authenticates device identity only; each request is individually authorized under capability policies.
8. **Secrets Never Enter Model Context:** Raw vault secrets and credentials never enter the LLM context, logs, command-line arguments, or the research gateway. Placeholders (`{{VAULT.item}}`) are resolved deterministically by trusted broker code at execution time.
9. **Tainted Data Cannot Silently Actuate:** Data originating from untrusted sources (web, files, voice, model) cannot become the target or argument of a state-changing operation (Tier ≥ 1) without explicit user confirmation.
10. **Lethal Trio Separation:** Private data, untrusted external content, and an exfiltration network path must never be co-located within the same process or execution context.
11. **Fail Closed:** Any failure in policy evaluation, frame decoding, schema validation, cryptographic verification, or IPC communication results in immediate denial.
12. **Out-of-Band User Control:** The user can stop running tasks, pause automation, disable remote links, lock the vault, and revoke devices directly via CLI or hotkey without model involvement.
13. **Audited State Changes Without Secrets:** Every state-changing operation generates a cryptographically hash-chained audit event; audit payloads are strictly redacted of secrets and personal credentials.
14. **Self-Modification Prohibited:** The agent cannot alter its own trusted binaries, security policy rules, cryptographic keys, or audit logs.

---

## 6. Prohibited Capabilities & Anti-Patterns (v1 Scope)

The following capabilities and behaviors are strictly forbidden in D.U.M.E.R v1:
- Arbitrary shell or process execution (`cmd.exe`, `powershell.exe`, `/bin/sh`, arbitrary binary paths).
- Remote interactive shell, PTY allocation, or TCP/port forwarding over SSH.
- Reading or indexing files outside explicitly user-allowlisted directories.
- Indexing or accessing browser profiles, password manager databases, SSH key directories, or OS credential vaults.
- Form submission, credential entry, e-commerce purchases, messaging, or file uploads from the research gateway.
- Standing or permanent Administrator / root privileges.
- Auto-approval of Tier 3 (sensitive) or Tier 4 (privileged) operations.
- Model-initiated modifications to security policy, configurations, or cryptographic keys.
- Direct outbound network requests originating from the LLM or coordinator outside the allowlisted overlay/research proxy.
- Silent auto-updates of executable binaries without explicit user confirmation.

---

## 7. Per-Command Security Review Checklist

Every new command registered in D.U.M.E.R must complete and document this 13-point review:

1. **Capability Scope:** What exact capability is required? Is it scoped to the minimum necessary resource (e.g. `app.launch:<id>` vs `app.launch:*`)?
2. **Data Read:** What local or remote data does this command read? Are personal or sensitive records touched?
3. **State Mutation:** What state changes on the system (filesystem, registry, processes, network)?
4. **Network Access:** Does this command initiate network traffic? If yes, to what specific endpoint and over which interface?
5. **Reversibility & Undo:** Is the action reversible? If Tier 2, is an undo journal entry created before execution?
6. **Risk Tier:** What is the assigned risk tier (Tier 0: read-only, Tier 1: reversible local, Tier 2: meaningful change, Tier 3: sensitive, Tier 4: privileged)?
7. **Approval Requirements:** Is interactive approval required? Which devices must sign (PC, phone, or dual PC+phone for Tier 4)?
8. **Argument Validation & Bounds:** Are arguments strictly bounded by schema (max length, allowed charset, path canonicalization, symlink/junction rejection)?
9. **Taint Tracking:** Which taint labels (`User`, `Device`, `Web`, `File`, `Voice`, `Model`) are permitted for each parameter? Are tainted values blocked from actuation without confirmation?
10. **Failure Modes & Timeouts:** How does the command behave under timeout, partial execution, or OS error? Does it fail closed cleanly?
11. **Audit Logging:** What specific fields are logged to the hash-chained audit trail? Have all secrets, tokens, and raw credentials been excluded?
12. **Adversarial Abuse Case:** What is the worst possible outcome if a hijacked planner or compromised phone invokes this operation with adversarial inputs?
13. **Verification Test Suite:** Are there unit tests, negative/boundary tests, fuzz targets, and property tests covering this command?

---

## 8. Pre-Release Security Penetration Test Checklist

Before any production release, the following tests must be executed and pass:

- [ ] **SSH Subsystem Hardening:** Attempt to open shell, PTY, exec, or port-forwarding channels via `russh`; verify immediate channel rejection.
- [ ] **Replay Protection:** Capture legitimate RPC requests and signed approvals; replay them; verify rejection via nonces and counters.
- [ ] **Argument Tampering:** Modify parameters of an approved request by 1 bit; verify signature mismatch and policy denial.
- [ ] **Mid-Session Revocation:** Revoke an enrolled device while an active session is in flight; verify immediate teardown and subsequent refusal.
- [ ] **Public Binding Guard:** Verify `dumerd` startup fails immediately if configured to bind to `0.0.0.0` or any non-overlay network interface.
- [ ] **Port Scan Audit:** Run `nmap` against all local network interfaces; verify no unexpected listening sockets exist.
- [ ] **Hostile Content Injection:** Ingest malicious documents and web pages containing prompt injections and homoglyphs; verify zero policy bypasses in the quarantined reader.
- [ ] **Canary Exfiltration:** Inject canary secrets into profile and vault; attempt exfiltration via research queries, logs, and model output; verify alert trigger and kill switch.
- [ ] **Binary Swapping Guard:** Swap a registered application executable with an unsigned or differently-signed binary; verify launch is refused.
- [ ] **Pipe Squatting Defense:** Attempt to pre-create named pipes before `dumerd` starts; verify `FILE_FLAG_FIRST_PIPE_INSTANCE` prevents hijacking.
- [ ] **Privileged Helper Distrust:** Send forged or altered elevation requests from a mock compromised `dumerd` to `dumer-privd`; verify helper denies execution.
- [ ] **Secret Leakage Scan:** Perform memory dumps and log inspection on running processes; verify absence of plaintext keys, passwords, and tokens.
- [ ] **Lost Phone Simulation:** Revoke phone from PC CLI; verify old transport and approval keys cannot establish sessions or approve tasks.
- [ ] **Stolen Laptop Simulation:** Confirm SQLCipher database and vault cannot be mounted or decrypted without credentials.

---

## 9. Residual Risks & Accepted Constraints

1. **Same-User Local Malware:** If malware runs under the same user account while the vault is unlocked, it can access process memory.  
   *Mitigations:* Short auto-lock windows, placeholder substitution, separate vault key, Canary tokens.
2. **Compromised Operating System:** A compromised OS kernel or hypervisor can bypass all user-space security controls.  
   *Mitigations:* Accepted limitation; D.U.M.E.R does not attempt to defend against a compromised host kernel.
3. **Hardware & Side-Channel Attacks:** Physical extraction attacks against device RAM or CPU side channels.  
   *Mitigations:* Non-exportable hardware Keystore keys on Android; TPM-backed key protection on PC.
4. **Mobile Malware with Biometric Hooking:** Advanced malware hooking the mobile app's authentication loop.  
   *Mitigations:* Per-use biometric prompts backed by Android StrongBox / Keystore; dual approval (PC + Phone) mandatory for all Tier 4 operations.
5. **Model Hallucinations on Benign Requests:** The planner may generate suboptimal or incorrect plans for ambiguous requests.  
   *Mitigations:* Autonomous execution is restricted to low-risk Tiers 0–1; all state-changing actions are audited and reversible with undo journals.

---

## 10. Threat Model Changelog & Review Notes (Milestone M0)

The following revisions and enhancements were made from the initial M0 draft:

1. **Explicit Alignment with Architecture §4:** Expanded section 5 to explicitly document all 14 non-negotiable invariants directly in this specification.
2. **Trust Zone Formalization:** Replaced brief summary with an exhaustive specification of all 9 Trust Zones, process privilege boundaries, network capabilities, and vault access permissions.
3. **Process Isolation Matrix:** Added the process isolation table from `architecture.md` §2 defining the OS privilege level, network capability, and failure impact for every component.
4. **V2 Threat Mitigations:** Explicitly incorporated threat analyses and mitigations for lethal-trio co-location, SSRF/DNS-rebinding via research gateway, named-pipe squatting, Authenticode TOCTOU attacks, GGUF supply-chain risks, and audio injection.
5. **Asset Sensitivity Hierarchy:** Replaced single-line asset list with a comprehensive classification table assessing Confidentiality, Integrity, and storage security.
6. **Fail-Closed and Default-Deny Formalization:** Detailed exact failure semantics ensuring that parser errors, timeouts, or policy ambiguities fail closed without side effects.
