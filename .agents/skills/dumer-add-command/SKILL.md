---
name: dumer-add-command
description: Add or modify a deterministic D.U.M.E.R command (registry entry, schema, capability, risk tier, matcher aliases, handler, tests). Use whenever a new operation, voice/text phrase, or app/launch capability is introduced.
---
# Add a command
1. **Review first** — answer the 13-point checklist in `docs/threat-model.md` §7 (capability, data read, state changed, network, reversibility, tier, approval, arg bounds, taint flow, failure, audit, worst-case abuse, tests). If tier ≥3 or it touches privilege, stop and ask the owner.
2. Define the typed variant in `Operation` (no strings-as-commands) and a `CommandDefinition { id, risk, required_capabilities, input_schema_version }` in `dumer-proto`/registry.
3. Argument schema: strict types, length/charset limits, canonical paths (reject traversal, symlinks/junctions outside approved folders), `deny_unknown_fields`.
4. Handler calls only `Platform` trait methods with typed arguments; never spawn a shell; never accept paths/URLs from tainted sources without confirmation.
5. Matcher: add aliases/patterns/slot types in `dumer-match`; add golden tests including ambiguous phrases and near-misses that must NOT match. Voice grammar regenerates from the registry.
6. Policy: declare capability + tier; tier 2 needs an undo journal entry; emit audit event (op id, decision, result code, safe metadata).
7. Tests: positive; unknown/extra fields; oversize; wrong device; revoked device; missing approval (if required); tainted arg; timeout/partial failure; property test that nothing outside the registry is reachable.
8. Benchmark the fast path if the command is tier 0–1; ensure no LLM call occurs.
9. Run `/security-review`; update docs.
