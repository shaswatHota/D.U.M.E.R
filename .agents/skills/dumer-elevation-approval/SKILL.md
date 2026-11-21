---
name: dumer-elevation-approval
description: Implement the privileged-operation flow — ElevationRequest, signer/author provenance, PC+phone approval, signed approvals, and the minimal dumer-privd helper. Use for any operation needing admin/root.
---
# Elevation
- There is no "run as admin" op. `dumer-privd` exposes a **fixed catalog**; start with one trivial op; every new op needs a documented security review (threat-model §7).
- ElevationRequest fields are built by trusted code: op+args+hash, subject identity (name, version, path, SHA-256, code-signing publisher subject/issuer/thumbprint/validity/countersign time, signature status, install source, running?), requester, effects, rollback, flags (unsigned, rare, signer changed, user-writable path), expiry ≤5 min, nonce. The agent's reason is shown labelled "Agent's stated reason (unverified)".
- Approval = signature: phone Keystore P-256 key with biometric per use; PC via Windows Hello/OS user verification. **Tier 4 needs both.** Notification payload is content-free; fetch details after wake.
- Helper verifies independently: pinned approver public keys, signature over canonical hash+nonce+expiry, nonce single-use, expiry, op ∈ catalog, args within constraints, subject identity re-checked at execution (TOCTOU). It never trusts fields from the core.
- OS prompts (UAC/polkit) still apply; never automate or bypass them. Minimal service privileges; ACL'd pipe; no network.
- Tests: forged/replayed/expired approval, altered args, signer swap between request and execute, lying core, missing second signer, helper restart.
