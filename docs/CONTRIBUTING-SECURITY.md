# Contributing to D.U.M.E.R — Security Guidelines

Welcome to D.U.M.E.R. This project is built under a **security-first, offline-first** paradigm. Because this personal agent interacts with local OS capabilities and stores sensitive user data, security is an active design requirement, not an afterthought.

Before submitting any code, architecture change, or pull request, you must read, understand, and comply with these guidelines.

---

## 1. The 14 Non-Negotiable Invariants

Every change is evaluated against the 14 core invariants from `docs/architecture.md` §4 and `docs/threat-model.md` §5. Here is what they mean in practice for contributors:

1. **LLMs Propose, Never Authorize:** Never allow model output or confidence scores to approve an action or bypass checks. The LLM is an untrusted planner; the deterministic policy broker makes all decisions.
2. **Default Deny Everywhere:** If an op, capability, parameter, target, or device is not explicitly allowlisted and validated, reject it immediately.
3. **One Chokepoint for All Actions:** All requests—whether initiated by voice, local CLI, remote phone RPC, a scheduled playbook, or the model—must route through the same central policy broker.
4. **Zero Shell Escape Hatches:** Never implement functions that execute shell strings (`cmd`, `powershell`, `sh`, `bash`). Never invoke arbitrary executable paths. Application launches must use registered application IDs with Authenticode-verified binary paths.
5. **Exact Parameter Binding for Approvals:** Approval signatures cover the canonical hash of the exact operation and arguments, requester identity, nonce, and timestamp. If arguments change by even a single byte, the previous approval is void.
6. **Privileged Helpers Must Distrust the Core:** The privileged daemon (`dumer-privd`) must never take the core coordinator's word for user intent. It independently validates the user's cryptographic signature and re-checks the target binary at execution time.
7. **Connection != Permission:** Establishing a WireGuard tunnel or authenticating via SSH only establishes device identity. Every individual operation must still be authorized under the device's capability grant.
8. **Secrets Never Reach Untrusted Contexts:** Vault items and raw credentials must never appear in LLM prompts, CLI arguments, logs, crash dumps, or outbound web queries. Use opaque placeholders (`{{VAULT.item}}`) that the trusted broker substitutes only during authorized execution.
9. **Tainted Inputs Cannot Silently Trigger State Changes:** Data originating from the web, user files, voice transcripts, or LLM output is marked as tainted. Tainted data cannot be passed into state-altering operations (Tier ≥ 1) without explicit, interactive user confirmation.
10. **Break the Lethal Trio:** Never place private user data, untrusted external content, and an exfiltration path (network egress) in the same process or memory context.
11. **Fail Closed:** If a parser encounters invalid data, a signature check fails, a timeout expires, or the policy engine throws an error, the operation must immediately fail closed without side effects.
12. **Model-Independent Out-of-Band Controls:** The user must always be able to stop active jobs, pause automation, disable remote access, lock the vault, and revoke devices using local hotkeys or CLI tools without requiring LLM cooperation.
13. **Cryptographically Audited Without Secrets:** Every state-changing action must write a tamper-evident, SHA-256 hash-chained audit record. Audit events must never log credentials, raw tokens, or sensitive queries.
14. **Immutable Core & Keys:** The agent cannot alter its own binaries, modify security policies, or rotate root cryptographic keys. Updates require explicit external intervention.

---

## 2. Adding or Modifying Commands: The 13-Point Checklist

Any pull request introducing or modifying an executable command must include completed answers to the following checklist in the PR description (see `.agents/skills/dumer-add-command/SKILL.md`):

1. **Capability Scope:** What specific capability does this command require (e.g. `app.launch:<id>`)? Is the capability narrowly scoped?
2. **Data Read:** What information does this command read from the disk or system? Does it touch personal records?
3. **State Mutation:** What persistent state does this change (files, registry, process state)?
4. **Network Footprint:** Does this initiate network communication? To where, and why?
5. **Reversibility:** Can this operation be undone? If Tier 2, does it write an undo journal entry prior to actuation?
6. **Risk Tier:** Which risk tier is assigned (Tier 0: read-only, Tier 1: reversible local, Tier 2: meaningful change, Tier 3: sensitive, Tier 4: privileged)?
7. **Approval Flow:** Does this require user confirmation? From which devices (desktop, phone, or dual PC+phone)?
8. **Argument Schema & Bounds:** Are arguments strictly validated? Are path lengths capped, characters allowlisted, and directory traversals (`..`, symlinks, junctions) rejected?
9. **Permitted Taint Labels:** Which taint labels are acceptable for each argument? Are untrusted inputs prevented from silent actuation?
10. **Failure Behavior:** How does the command handle timeouts, network drops, or OS errors? Does it leave partial state?
11. **Audit Schema:** What fields are logged? Are all secrets, tokens, and personal identifiers excluded?
12. **Adversarial Abuse Analysis:** What is the worst-case blast radius if a compromised client or adversarial planner invokes this command?
13. **Automated Test Coverage:** Does the PR include unit tests, negative/boundary tests, malformed-input tests, and property/fuzz tests?

---

## 3. Prohibited Patterns (Instant PR Rejection)

- **`std::process::Command::new("powershell")` or `"cmd"` or `"sh"`:** Automatic rejection.
- **`#[allow(unsafe_code)]` in non-FFI crates:** All crates except reviewed OS/FFI stubs must maintain `#![forbid(unsafe_code)]`.
- **`unwrap()` or `expect()` on untrusted input:** All untrusted input must be parsed into typed results with graceful, typed error handling.
- **Logging secrets or credentials:** Never use `println!` or `tracing::info!` on variables containing keys, passwords, or personal profile data. Use `secrecy::SecretBox` and `zeroize`.
- **Bypassing the policy broker:** Never execute OS actions directly from UI or RPC handlers. All requests must route through `dumer-policy`.
- **Standing Tier 4 privileges:** Tier 4 operations cannot have permanent or standing authorization grants; each invocation requires fresh, bound dual approval.

---

## 4. Testing & Verification Requirements

Every security-relevant change must follow a **test-first** approach:
- **Negative tests first:** Verify that unknown operations, malformed frames, mutated signatures, expired nonces, and unapproved devices are rejected.
- **Fuzzing:** Every new wire type or input parser must include a `cargo-fuzz` target.
- **CI clean gate:** Before asking for review, run `powershell -ExecutionPolicy Bypass -File scripts/ci.ps1` (or `scripts/ci.sh`) and verify all formatting, linter warnings, unit tests, cargo-deny checks, and cargo-audit pass.
