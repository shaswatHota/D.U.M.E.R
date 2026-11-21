---
name: dumer-platform-adapters
description: Implement the Rust Platform trait and Windows (windows crate) / Linux adapters — registered app launch with signature verification, notifications, status, secure local IPC (named pipes/UDS). Use for OS-facing code.
---
# Platform adapters
- `Platform` trait is OS-neutral: `launch_registered_app(AppId)`, `basic_status()`, `notify(...)`, `lock_state()`. Typed in/out only; no generic exec.
- App registry: id → path + publisher signature (+ optional hash). Verify the signature at launch time (browsers auto-update, so don't rely on hash alone). Launch with `CreateProcess` + allowlisted arg templates, no shell, no inherited handles.
- Windows IPC: named pipe with restrictive ACL, `FILE_FLAG_FIRST_PIPE_INSTANCE` (anti-squatting), verify peer SID/PID, versioned messages, timeouts. Linux: Unix domain socket with 0600 perms and `SO_PEERCRED` checks.
- Run in the logged-in user context; never request elevation. Respect locked/logged-out sessions.
- Unsafe code only in a small reviewed module with `// SAFETY:` notes.
- Tests: invalid id, unregistered/swapped/unsigned exe, missing exe, duplicate request, crash/restart, locked session, pipe squatting, path canonicalization.
