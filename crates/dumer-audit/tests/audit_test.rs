//! Tests for audit logging, hash chaining, integrity verification, and secret redaction.
#![forbid(unsafe_code)]

use dumer_audit::*;
use std::collections::BTreeMap;
use tempfile::NamedTempFile;

#[test]
fn test_audit_chain_monotonic_and_verifiable() {
    let mut chain = AuditChain::new(None).expect("create in-memory chain");
    assert!(chain.is_empty());
    assert_eq!(chain.head_hash(), [0u8; 32]);

    let mut details1 = BTreeMap::new();
    details1.insert("version".to_string(), "0.1.0".to_string());
    let ev1 = chain
        .append(
            AuditEventType::DaemonStarted,
            "system".to_string(),
            None,
            details1,
            1000,
        )
        .expect("append 1");

    assert_eq!(ev1.sequence_number, 1);
    assert_eq!(ev1.prev_hash, [0u8; 32]);
    assert_eq!(chain.head_hash(), ev1.hash);

    let mut details2 = BTreeMap::new();
    details2.insert("op".to_string(), "app.launch".to_string());
    let ev2 = chain
        .append(
            AuditEventType::ActionExecuted,
            "local_user".to_string(),
            Some("application.open".to_string()),
            details2,
            1005,
        )
        .expect("append 2");

    assert_eq!(ev2.sequence_number, 2);
    assert_eq!(ev2.prev_hash, ev1.hash);
    assert_eq!(chain.head_hash(), ev2.hash);

    // Verify valid chain
    assert!(chain.verify().is_ok());
}

#[test]
fn test_audit_tamper_detection_in_event() {
    let mut chain = AuditChain::new(None).expect("create chain");

    for i in 1..=5 {
        let mut details = BTreeMap::new();
        details.insert("step".to_string(), i.to_string());
        chain
            .append(
                AuditEventType::ActionExecuted,
                "actor".to_string(),
                None,
                details,
                1000 + i,
            )
            .expect("append");
    }

    assert!(chain.verify().is_ok());

    // Create a modified copy of events with tampered details in record 3
    let mut tampered_events = chain.events().to_vec();
    tampered_events[2]
        .details
        .insert("tampered".to_string(), "malicious".to_string());

    // Create broken chain
    let broken_chain = unsafe_test_chain(tampered_events);
    let err = broken_chain.verify().unwrap_err();
    match err {
        AuditError::ChainTampered { seq, .. } => assert_eq!(seq, 3),
        other => panic!("Expected ChainTampered, got: {:?}", other),
    }
}

#[test]
fn test_audit_tamper_detection_sequence_break() {
    let mut chain = AuditChain::new(None).expect("create chain");
    for i in 1..=3 {
        chain
            .append(
                AuditEventType::PolicyDecision,
                "broker".to_string(),
                None,
                BTreeMap::new(),
                1000 + i,
            )
            .expect("append");
    }

    // Remove event 2 (sequence jump 1 -> 3)
    let mut tampered_events = chain.events().to_vec();
    tampered_events.remove(1);

    let broken_chain = unsafe_test_chain(tampered_events);
    let err = broken_chain.verify().unwrap_err();
    match err {
        AuditError::ChainTampered { seq, .. } => assert_eq!(seq, 3),
        other => panic!("Expected ChainTampered, got: {:?}", other),
    }
}

#[test]
fn test_audit_persistence_and_recovery() {
    let temp_file = NamedTempFile::new().expect("temp file");
    let path = temp_file.path().to_path_buf();

    {
        let mut chain = AuditChain::new(Some(path.clone())).expect("create persistent chain");
        let mut details = BTreeMap::new();
        details.insert("mode".to_string(), "autonomous".to_string());
        chain
            .append(
                AuditEventType::DaemonStarted,
                "init".to_string(),
                None,
                details,
                12345,
            )
            .expect("append");
        chain
            .append(
                AuditEventType::SelfTestRun,
                "test".to_string(),
                None,
                BTreeMap::new(),
                12346,
            )
            .expect("append");
    }

    // Recover from file
    let recovered_chain = AuditChain::load_from_file(&path).expect("recover from file");
    assert_eq!(recovered_chain.len(), 2);
    assert!(recovered_chain.verify().is_ok());
}

#[test]
fn test_redaction_removes_secrets_and_canaries() {
    let mut raw_details = BTreeMap::new();
    raw_details.insert(
        "api_token".to_string(),
        "sk-live-1234567890abcdef".to_string(),
    );
    raw_details.insert(
        "user_password".to_string(),
        "SuperSecretPassword123".to_string(),
    );
    raw_details.insert(
        "authorization".to_string(),
        "Bearer eyJhbGciOi...".to_string(),
    );
    raw_details.insert(
        "message".to_string(),
        "Contact user at admin@example.com with token sk-99999".to_string(),
    );
    raw_details.insert(
        "alert".to_string(),
        "Found canary token CANARY_TRAP_SECRET_01".to_string(),
    );

    let sanitized = Redactor::sanitize_details(&raw_details);

    // Sensitive keys replaced completely
    assert_eq!(sanitized.get("api_token").unwrap(), "[REDACTED]");
    assert_eq!(sanitized.get("user_password").unwrap(), "[REDACTED]");
    assert_eq!(sanitized.get("authorization").unwrap(), "[REDACTED]");

    // Sensitive values in non-sensitive keys scrubbed
    let msg = sanitized.get("message").unwrap();
    assert!(!msg.contains("admin@example.com"));
    assert!(!msg.contains("sk-99999"));
    assert!(msg.contains("[REDACTED_EMAIL]"));
    assert!(msg.contains("[REDACTED_KEY]"));

    // Canary alert replacement
    assert_eq!(sanitized.get("alert").unwrap(), "[CANARY_ALERT_REDACTED]");
}

// Helper to construct chain with arbitrary events for test verification
fn unsafe_test_chain(events: Vec<AuditEvent>) -> AuditChain {
    AuditChain::from_events_unverified(events)
}
