---
name: dumer-llm-planner-safety
description: Build the local LLM planner and its defenses — constrained decoding (GBNF/JSON schema), dual-model planner/reader, taint propagation, placeholders, budgets, injection eval corpus, dumer-infer worker. Use for anything touching prompts, grammars, models, or model output handling.
---
# LLM planner safety
- `dumer-infer` is a separate sandboxed process, pipes only, **no network, no listening socket**, no file access except the pinned model. Verify model SHA-256 before load; only this process parses GGUF.
- Plans are generated under a grammar built from the live registry; output = `[{op, args}]`. Re-validate each step through registry schema + policy anyway.
- Privileged planner sees user text + placeholders only. Quarantined reader sees external text and returns constrained values (enums/bounded/validated), tainted. Never merge the two contexts.
- Sanitize inputs: zero-width/tag chars, bidi controls, homoglyphs, hidden HTML/CSS, PDF/OCR artefacts; size caps; no auto-rendering of remote images/links.
- Budgets: steps, tokens, time, tool/network calls; detect loops/duplicates; cancellation always works.
- Lifecycle: lazy-load, idle unload, unload on fullscreen game/battery/thermal throttle. Target 3B–8B ~Q4 for ~6 GB VRAM; STT/TTS/embeddings on CPU. Benchmark cold/warm latency, VRAM/RAM peaks.
- `eval/`: planner accuracy set + injection/exfiltration corpus; gate: zero policy bypasses. Never log prompts/completions.
