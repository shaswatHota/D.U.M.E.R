//! End-to-end latency benchmark test for D.U.M.E.R fast-path execution.
//!
//! Measures full pipeline: phrase -> normalize -> matcher -> validate -> execute -> hash-chain audit log -> terse result.
//! Enforces architecture §6 budget: p95 < 20 ms.
#![forbid(unsafe_code)]

use dumer_audit::AuditChain;
use dumer_match::CommandMatcher;
use dumerd::fast_path::dispatch_fast_path;
use std::time::Instant;

#[test]
fn test_end_to_end_fast_path_dispatch_latency_p95_under_20ms() {
    let matcher = CommandMatcher::new();
    let mut audit_chain = AuditChain::new(None).expect("in-memory audit chain");

    let iterations = 2_000;
    let mut latencies_nanos: Vec<u64> = Vec::with_capacity(iterations);

    // Warm-up
    for i in 0..50 {
        let _ = dispatch_fast_path(&matcher, &mut audit_chain, "open chrome", 1000 + i);
    }

    // Benchmark loop: full pipeline
    for i in 0..iterations {
        let start = Instant::now();
        let res = dispatch_fast_path(&matcher, &mut audit_chain, "open chrome", 2000 + i as u64);
        let elapsed = start.elapsed().as_nanos() as u64;
        latencies_nanos.push(elapsed);
        assert!(matches!(
            res,
            Ok(dumerd::FastPathExecution::Completed { .. })
        ));
    }

    latencies_nanos.sort_unstable();

    let p50_us = latencies_nanos[iterations * 50 / 100] as f64 / 1_000.0;
    let p95_us = latencies_nanos[iterations * 95 / 100] as f64 / 1_000.0;
    let p99_us = latencies_nanos[iterations * 99 / 100] as f64 / 1_000.0;

    println!("\n=======================================================");
    println!("   D.U.M.E.R End-to-End Fast Path Dispatch Benchmark");
    println!("=======================================================");
    println!("  p50: {:.2} µs ({:.4} ms)", p50_us, p50_us / 1000.0);
    println!("  p95: {:.2} µs ({:.4} ms)", p95_us, p95_us / 1000.0);
    println!("  p99: {:.2} µs ({:.4} ms)", p99_us, p99_us / 1000.0);
    println!("  Target budget: p95 < 20.00 ms (20,000 µs)");
    println!("=======================================================\n");

    assert!(
        p95_us < 20_000.0,
        "End-to-end fast path p95 latency: {:.2} µs exceeds 20 ms budget",
        p95_us
    );
}
