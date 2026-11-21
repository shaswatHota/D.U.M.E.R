---
trigger: glob
globs: "**/*.rs,Cargo.toml"
description: Rust code standards for D.U.M.E.R
---
- `#![forbid(unsafe_code)]` by default; `unsafe` only in reviewed OS/FFI crates with a `// SAFETY:` justification and a test.
- No `unwrap()/expect()` outside tests and startup invariants; no panics on untrusted input.
- Validate untrusted input at the boundary with strict types (`deny_unknown_fields`), explicit size/length limits, and canonical path handling.
- Async (Tokio) for I/O only; CPU-heavy work in bounded pools; never block the runtime; all queues bounded; all awaits on external parties have timeouts and cancellation.
- Secrets: `secrecy::SecretBox`/`zeroize`; never `Debug`-print them; never in argv/env/logs.
- Use `thiserror` typed errors; error messages shown to users/remote peers must be safe summaries.
- Run `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`, `cargo deny check`, `cargo audit` before declaring done.
- Add a justification line for every new dependency; prefer std/small crates; check maintenance, licence, and unsafe usage.
