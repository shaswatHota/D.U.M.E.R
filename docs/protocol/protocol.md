# D.U.M.E.R RPC Protocol v1 (`dumer-rpc@1`)

## Transport
- WireGuard overlay (reachability) → SSH (russh server in `dumerd`) → **subsystem `dumer-rpc@1` only**.
- Server rejects: shell, exec, pty-req, env, agent/X11/TCP/stream-local forwarding, SFTP, any other subsystem. Password auth off. One public key per device.
- Listener bound to the overlay interface address only. Startup self-check fails if it would bind 0.0.0.0/public.

## Framing
`u32 big-endian length || CBOR bytes`. Max frame 65,536 bytes. Reject length 0 or > max before allocating. Deterministic CBOR (RFC 8949 §4.2); strict decode; unknown map keys rejected; indefinite-length items rejected.

## Session handshake (application layer, after SSH auth)
1. Server → `Hello{ protocol_version, server_nonce(32 random bytes), server_caps }`
2. Client → `Auth{ device_id, client_nonce, signature_over(server_nonce||client_nonce||device_id) }` using the device's P-256 identity key.
3. Server verifies device status (not revoked), signature, version → `Session{ session_id, counter_start }`.
Freshness comes from the nonces and per-session monotonic `counter`; **no reliance on client wall-clock**.

## Request
```text
Request { v:1, session_id, counter:u64 (strictly increasing), request_id:bytes16 (unique),
          op:text (registry id), args:map (op-specific schema), approval:opt<ApprovalRef> }
```
Validation order: frame → decode → version → session → counter/request_id uniqueness → op exists → args schema → device capability →
policy decision → (approval) → execute. Any failure → typed error, audit event, no side effects.

## Response
`Response { v:1, request_id, status: completed|denied|needs_approval|failed|cancelled, result:opt<map>, error:opt<{code, safe_message}> }`

## Approval
```text
ApprovalRequest { approval_id, request_hash:bytes32 (SHA-256 of canonical op+args+target identity),
                  op, args_summary, subject_identity{…}, requester, agent_reason(unverified), effects, tier,
                  nonce:bytes16, expires_at (laptop clock), required_signers:[pc|phone] }
ApprovalSignature { approval_id, request_hash, nonce, expires_at, device_id, sig (P-256 over canonical bytes) }
```
Approver UIs render from `ApprovalRequest` fields produced by trusted code. Any argument change ⇒ new `request_hash` ⇒ old approval invalid. Nonces are single-use. Tier 4 requires signatures from both `pc` and `phone`.

## Notifications
Wake-up payload carries no request detail: `{ "type":"approval_pending" }`. App then fetches `ApprovalRequest` over the session.

## Limits and rate control
Per-device rate limits, max concurrent requests, max outstanding approvals, max session age, idle timeout. Exceeding limits ⇒ throttle, audit, and optionally auto-suspend the device.

## Enrollment
Laptop (physically present) shows QR: `{ host_key_fingerprint, one_time_token(≥128b, TTL≤120s), overlay_endpoint }`.
Phone generates transport + approval keys, sends public keys + token proof; both screens display a short authentication string; owner confirms on the laptop. Revocation: `dumer-cli revoke <device>` or UI; immediate session teardown.
