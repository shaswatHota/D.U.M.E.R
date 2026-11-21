---
name: dumer-security-testing
description: Create security, fuzz, property and injection tests for D.U.M.E.R and run the pre-release pen-test checklist. Use when writing tests for protocol, policy, parsers, crypto, planner, or research gateway, or before a release.
---
# Security testing
- Fuzz targets (`cargo-fuzz`): frame decoder, CBOR decode, matcher input, path canonicalizer, grammar generator, enrollment token parser.
- Property tests (`proptest`): codec round-trip/canonical form; policy never Allows unregistered ops; matcher never returns ops outside the registry; approval hash changes with any arg change.
- Negative suites: unknown op, unknown fields, oversize/malformed frames, replay, expired/altered/replayed approval, revoked device, shell/exec/PTY/forwarding attempts, traversal/symlink/junction, hostile filenames/archives, SSRF/rebinding, canary exfil, pipe squatting, binary swap, lying-core vs `dumer-privd`.
- Injection corpus in `eval/`: hidden text, zero-width/bidi, markdown image exfil, "ignore previous instructions", tool-call spoofing, multi-turn poisoning. Gate: zero policy bypasses.
- CI: fmt, clippy `-D warnings`, tests, `cargo-deny`, `cargo-audit`, secret-scan, log-scan for secrets.
- Run `docs/threat-model.md` §8 before release; record results.
