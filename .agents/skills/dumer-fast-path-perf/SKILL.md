---
name: dumer-fast-path-perf
description: Implement and benchmark the deterministic matcher and fast path (act-first, report-after) and resource policy. Use when touching dumer-match, command dispatch latency, idle memory, or model residency.
---
# Fast path & performance
- Pipeline: normalize → alias HashMap → aho-corasick → bounded fuzzy match → typed slots → unique-and-confident check → schema → policy → platform → terse result. No allocations/IO beyond need on the hot path; no LLM.
- Ambiguity margin ⇒ clarify (non-LLM) or escalate; never guess for state-changing ops.
- Act first, report after: no generated preface text. Result = tick/earcon or ≤1 short line.
- Budget: matcher+validation+policy dispatch p95 < 20 ms (measure with criterion; record p50/p95/p99 in CI artefacts). Idle `dumerd` RSS well under 100 MB, model unloaded.
- Slow path: immediate task id, streamed progress, cancel; model loaded lazily, unloaded after idle, and on game/battery/thermal signals.
- Measure before optimizing; keep benchmarks in `tests/perf` and treat regressions as failures.
