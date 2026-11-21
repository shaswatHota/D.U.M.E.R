//! Integration tests for Milestone M2 fast-path execution, terse result rendering, and audit logging.
#![forbid(unsafe_code)]

use dumer_audit::{AuditChain, AuditEventType};
use dumer_match::CommandMatcher;
use dumer_proto::types::ResponseStatus;
use dumerd::fast_path::{dispatch_fast_path, FastPathExecution};

#[test]
fn test_fast_path_open_chrome_acts_first_reports_tersely_and_audits() {
    let mut audit_chain = AuditChain::new(None).expect("in-memory audit chain");
    let matcher = CommandMatcher::new();

    let initial_audit_len = audit_chain.len();

    let result = dispatch_fast_path(&matcher, &mut audit_chain, "open chrome", 1000)
        .expect("dispatch fast path");

    match result {
        FastPathExecution::Completed {
            response,
            terse_output,
        } => {
            assert_eq!(response.status, ResponseStatus::Completed);

            // Invariant & architecture §6: Terse output <= 1 short line, act-first report-after
            assert!(
                terse_output.starts_with("✓") || terse_output.starts_with("[ok]"),
                "Terse output should start with tick or [ok]: '{}'",
                terse_output
            );
            assert!(
                !terse_output.contains('\n'),
                "Terse output must be single line: '{}'",
                terse_output
            );
            assert!(
                terse_output.len() <= 60,
                "Terse output must be short: '{}'",
                terse_output
            );

            // Audit event must be appended
            assert_eq!(audit_chain.len(), initial_audit_len + 1);
            let last_event = audit_chain.events().last().expect("audit event");
            assert_eq!(last_event.event_type, AuditEventType::ActionExecuted);
            assert_eq!(last_event.op, Some("application.open".to_string()));
            assert_eq!(
                last_event.details.get("app_id"),
                Some(&"chrome".to_string())
            );
        }
        other => panic!("Expected FastPathExecution::Completed, got {:?}", other),
    }
}

#[test]
fn test_fast_path_system_status_read() {
    let mut audit_chain = AuditChain::new(None).expect("in-memory audit chain");
    let matcher = CommandMatcher::new();

    let result = dispatch_fast_path(&matcher, &mut audit_chain, "system status", 1001)
        .expect("dispatch fast path");

    match result {
        FastPathExecution::Completed {
            response,
            terse_output,
        } => {
            assert_eq!(response.status, ResponseStatus::Completed);
            assert!(
                terse_output.contains("System status: ok")
                    || terse_output.contains("System operational")
                    || terse_output.starts_with("✓"),
                "Unexpected terse output: '{}'",
                terse_output
            );
            assert_eq!(
                audit_chain.events().last().unwrap().op,
                Some("system.status.read".to_string())
            );
        }
        other => panic!("Expected FastPathExecution::Completed, got {:?}", other),
    }
}

#[test]
fn test_fast_path_negative_phrase_returns_not_handled() {
    let mut audit_chain = AuditChain::new(None).expect("in-memory audit chain");
    let matcher = CommandMatcher::new();
    let initial_audit_len = audit_chain.len();

    let result = dispatch_fast_path(
        &matcher,
        &mut audit_chain,
        "write a story about space",
        1002,
    );

    match result {
        Ok(FastPathExecution::NotHandled) => {
            // Must not execute anything, model will handle in M10 slow path
            assert_eq!(audit_chain.len(), initial_audit_len);
        }
        other => panic!("Expected FastPathExecution::NotHandled, got {:?}", other),
    }
}

#[test]
fn test_fast_path_unknown_op_fails_closed_and_audited() {
    let mut audit_chain = AuditChain::new(None).expect("in-memory audit chain");
    let initial_audit_len = audit_chain.len();

    let result = dumerd::fast_path::execute_operation_direct(
        &mut audit_chain,
        "unknown.malicious.op",
        &std::collections::BTreeMap::new(),
        [99u8; 16],
        1003,
    );

    match result {
        Ok(FastPathExecution::Denied { reason, response }) => {
            assert_eq!(response.status, ResponseStatus::Denied);
            assert!(reason.contains("Unknown operation"));
            assert_eq!(audit_chain.len(), initial_audit_len + 1);
            let event = audit_chain.events().last().unwrap();
            assert_eq!(event.event_type, AuditEventType::PolicyDecision);
            assert_eq!(event.details.get("decision"), Some(&"denied".to_string()));
        }
        other => panic!("Expected FastPathExecution::Denied, got {:?}", other),
    }
}
