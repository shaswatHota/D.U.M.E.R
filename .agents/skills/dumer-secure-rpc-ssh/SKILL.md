---
name: dumer-secure-rpc-ssh
description: Build or modify the D.U.M.E.R remote link — embedded russh SSH subsystem, WireGuard overlay binding, CBOR framing, handshake nonces, enrollment (QR+SAS), revocation, rate limits. Use for any network-facing server/client code.
---
# Secure RPC
- Follow `docs/protocol/protocol.md` exactly. Verify current `russh` APIs before coding.
- Server: key-only auth; accept only subsystem `dumer-rpc@1`; explicitly reject shell/exec/pty/env/agent/X11/direct-tcpip/forwarded-tcpip/streamlocal/SFTP. Add a test per rejected channel type.
- Bind only to the overlay interface address; startup self-check refuses 0.0.0.0/public bindings; a test port-scans all interfaces.
- Framing: `u32 BE len || deterministic CBOR`, max 64 KiB, check length before allocating, strict decode, reject unknown keys and indefinite lengths.
- Freshness: server nonce + client nonce signed with device identity key; strictly monotonic counters; unique request ids; no client-clock dependence.
- Authorization on every request (device capability + policy) — a valid session is not a permission.
- Enrollment needs physical presence at the laptop: QR (host-key fingerprint + ≥128-bit one-time token ≤120 s) + short authentication string confirmation. Pin the host key in the client.
- Revocation tears down sessions immediately; persisted; works from CLI without the model.
- Rate limits, max outstanding requests, idle/max session age; log events without payload contents.
- Tests/fuzz: malformed frames, oversize, replay, wrong signature, revoked device, token reuse/expiry, channel-type abuse.
