---
trigger: glob
globs: "crates/dumer-planner/**,crates/dumer-infer/**,crates/dumer-research/**,crates/dumer-vault/**,eval/**"
description: LLM, privacy and research-gateway rules
---
- Planner output must be grammar/schema constrained; unknown ops are unrepresentable. Re-validate every step via registry + policy.
- Planner prompts contain only user-authored/trusted text and placeholders like `{{PROFILE.field}}`; never raw secrets or personal records.
- Web/file/OCR/voice text goes only to the quarantined reader, whose output is constrained, tainted data.
- Taint labels (User, Device, Web, File, Voice, Model) travel with values; policy consumes them.
- Research gateway: no personal data, no vault, no sign-ins; all egress through the allowlisting proxy that blocks private/loopback/link-local/metadata ranges; outbound queries pass the query firewall.
- Cache entries carry freshness class + TTL + source + taint; the LLM may suggest a class but never extends TTL.
- Never log prompts, completions, queries, transcripts, or audio content; log hashes and safe summaries.
- Any change to prompts/grammars/models must re-run `eval/` including the injection corpus.
