---
name: dumer-android-companion
description: Build the Kotlin Android companion — UniFFI-bound Rust crates, Keystore keys, enrollment, SSH-RPC client, approval screens, notifications/connected mode, offline command subset. Use for any Android work.
---
# Android companion
- Kotlin stays thin: UI, lifecycle, notifications, Keystore plumbing. Protocol, crypto, matcher come from shared Rust via UniFFI (`dumer-ffi`).
- Keys: (1) transport key wrapped by a Keystore key; (2) non-exportable P-256 approval key with user authentication required per use (BiometricPrompt + CryptoObject). Verify StrongBox/hardware-backed availability on the device; fall back with a visible warning.
- Approval screen renders only broker-validated fields; labels agent reason "unverified"; shows operation, exact args, subject identity/signer, effects, privileges, expiry; approve = biometric-gated signature over the canonical request hash.
- Notifications: opt-in connected-mode foreground service (low-power keepalive over overlay) and/or self-hosted UnifiedPush; payload content-free (`approval_pending`), fetch details over the session. Never FCM with details.
- Android may kill background work: reconnect safely; requests idempotent; clear connect/disconnect state.
- Local offline command subset only; no shell; no model on phone until measured.
- Secure defaults: FLAG_SECURE on approval screens, no backups of key material, no logging of request contents.
