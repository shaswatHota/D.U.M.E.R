//! Performance benchmark tests for D.U.M.E.R deterministic matcher and fast path dispatch.
//!
//! Enforces architecture §6 and M2 latency budget:
//! - Matcher + dispatch p95 must be < 20 ms.
//! - Measures p50, p95, and p99 over 10,000 iterations.
#![forbid(unsafe_code)]

use dumer_match::CommandMatcher;
use std::time::Instant;

#[test]
fn test_matcher_latency_budget_p95_under_20ms() {
    let matcher = CommandMatcher::new();

    let iterations = 10_000;
    let mut latencies_nanos: Vec<u64> = Vec::with_capacity(iterations);

    // Warm-up
    for _ in 0..100 {
        let _ = matcher.match_phrase("open chrome");
    }

    // Benchmark loop: "open chrome"
    for _ in 0..iterations {
        let start = Instant::now();
        let res = matcher.match_phrase("open chrome");
        let elapsed = start.elapsed().as_nanos() as u64;
        latencies_nanos.push(elapsed);
        assert!(matches!(res, dumer_match::MatchResult::Match(_)));
    }

    latencies_nanos.sort_unstable();

    let p50_nanos = latencies_nanos[iterations * 50 / 100];
    let p95_nanos = latencies_nanos[iterations * 95 / 100];
    let p99_nanos = latencies_nanos[iterations * 99 / 100];

    let p50_us = p50_nanos as f64 / 1_000.0;
    let p95_us = p95_nanos as f64 / 1_000.0;
    let p99_us = p99_nanos as f64 / 1_000.0;

    println!("\n=======================================================");
    println!("   D.U.M.E.R M2 Matcher Latency Benchmark (10,000 runs)");
    println!("=======================================================");
    println!("  p50: {:.2} µs ({:.4} ms)", p50_us, p50_us / 1000.0);
    println!("  p95: {:.2} µs ({:.4} ms)", p95_us, p95_us / 1000.0);
    println!("  p99: {:.2} µs ({:.4} ms)", p99_us, p99_us / 1000.0);
    println!("  Target budget: p95 < 20.00 ms (20,000 µs)");
    println!("=======================================================\n");

    // Strict assertion: p95 < 20 ms (20,000 µs)
    assert!(
        p95_us < 20_000.0,
        "Matcher p95 latency regression: {:.2} µs exceeds 20 ms budget",
        p95_us
    );
}

#[test]
fn test_fuzzy_matcher_latency_budget_under_20ms() {
    let matcher = CommandMatcher::new();

    let iterations = 5_000;
    let mut latencies_nanos: Vec<u64> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        let res = matcher.match_phrase("opn chrome");
        let elapsed = start.elapsed().as_nanos() as u64;
        latencies_nanos.push(elapsed);
        assert!(matches!(res, dumer_match::MatchResult::Match(_)));
    }

    latencies_nanos.sort_unstable();

    let p50_us = latencies_nanos[iterations * 50 / 100] as f64 / 1_000.0;
    let p95_us = latencies_nanos[iterations * 95 / 100] as f64 / 1_000.0;
    let p99_us = latencies_nanos[iterations * 99 / 100] as f64 / 1_000.0;

    println!(
        "Fuzzy match (opn chrome) -> p50: {:.2} µs, p95: {:.2} µs, p99: {:.2} µs",
        p50_us, p95_us, p99_us
    );

    assert!(p95_us < 20_000.0);
}
