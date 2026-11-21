//! Integration and CLI tests for `dumerd`.
#![forbid(unsafe_code)]

use dumerd::{read_health_record, run_with_args, DaemonConfig, DaemonStatus};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_cli_version_flag() {
    let args = vec!["dumerd", "--version"];
    let code = run_with_args(args);
    assert_eq!(code, 0);
}

#[test]
fn test_cli_check_config_valid() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");

    let config = DaemonConfig {
        overlay_bind_ip: "10.100.0.1".to_string(),
        overlay_port: 8443,
        data_dir: dir.path().to_path_buf(),
        log_level: "debug".to_string(),
        max_sessions: 25,
        max_frame_size: 65536,
        idle_timeout_secs: 600,
    };

    let json = serde_json::to_string(&config).unwrap();
    fs::write(&config_path, json).unwrap();

    let args = vec![
        "dumerd".to_string(),
        "--check-config".to_string(),
        "--config".to_string(),
        config_path.to_string_lossy().to_string(),
    ];
    let code = run_with_args(args);
    assert_eq!(code, 0);
}

#[test]
fn test_cli_check_config_rejects_wildcard_0000() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("invalid_config.json");

    // Invariant 7: Never bind to 0.0.0.0
    let config = DaemonConfig {
        overlay_bind_ip: "0.0.0.0".to_string(),
        overlay_port: 2222,
        data_dir: dir.path().to_path_buf(),
        log_level: "info".to_string(),
        max_sessions: 10,
        max_frame_size: 65536,
        idle_timeout_secs: 300,
    };

    let json = serde_json::to_string(&config).unwrap();
    fs::write(&config_path, json).unwrap();

    let args = vec![
        "dumerd".to_string(),
        "--check-config".to_string(),
        "--config".to_string(),
        config_path.to_string_lossy().to_string(),
    ];
    let code = run_with_args(args);
    assert_ne!(code, 0, "0.0.0.0 must be rejected by check-config");
}

#[test]
fn test_cli_check_config_rejects_public_ip() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("public_config.json");

    // Invariant 7: Never bind to public WAN address (e.g. 8.8.8.8)
    let config = DaemonConfig {
        overlay_bind_ip: "8.8.8.8".to_string(),
        overlay_port: 2222,
        data_dir: dir.path().to_path_buf(),
        log_level: "info".to_string(),
        max_sessions: 10,
        max_frame_size: 65536,
        idle_timeout_secs: 300,
    };

    let json = serde_json::to_string(&config).unwrap();
    fs::write(&config_path, json).unwrap();

    let args = vec![
        "dumerd".to_string(),
        "--check-config".to_string(),
        "--config".to_string(),
        config_path.to_string_lossy().to_string(),
    ];
    let code = run_with_args(args);
    assert_ne!(code, 0, "Public IP must be rejected by check-config");
}

#[test]
fn test_cli_self_test_runs_and_writes_health() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");

    let config = DaemonConfig {
        overlay_bind_ip: "127.0.0.1".to_string(),
        overlay_port: 2222,
        data_dir: dir.path().to_path_buf(),
        log_level: "info".to_string(),
        max_sessions: 10,
        max_frame_size: 65536,
        idle_timeout_secs: 300,
    };

    let json = serde_json::to_string(&config).unwrap();
    fs::write(&config_path, json).unwrap();

    let args = vec![
        "dumerd".to_string(),
        "--self-test".to_string(),
        "--config".to_string(),
        config_path.to_string_lossy().to_string(),
    ];
    let code = run_with_args(args);
    assert_eq!(code, 0);

    let health_path = dir.path().join("health.json");
    assert!(health_path.exists());
    let health = read_health_record(&health_path).expect("read health");
    assert!(health.last_self_test_passed);
    assert!(health.is_unprivileged);
}

#[test]
fn test_daemon_lifecycle_health_and_audit() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");

    let config = DaemonConfig {
        overlay_bind_ip: "10.0.0.1".to_string(),
        overlay_port: 2222,
        data_dir: dir.path().to_path_buf(),
        log_level: "info".to_string(),
        max_sessions: 5,
        max_frame_size: 65536,
        idle_timeout_secs: 60,
    };

    let json = serde_json::to_string(&config).unwrap();
    fs::write(&config_path, json).unwrap();

    // Run daemon
    let args = vec![
        "dumerd".to_string(),
        "--config".to_string(),
        config_path.to_string_lossy().to_string(),
    ];
    let code = run_with_args(args);
    assert_eq!(code, 0);

    // Verify health record exists and is in Stopped state after graceful shutdown
    let health_path = dir.path().join("health.json");
    assert!(health_path.exists());
    let health = read_health_record(&health_path).expect("read health");
    assert_eq!(health.status, DaemonStatus::Stopped);
    assert!(health.is_unprivileged);
    assert_eq!(health.audit_events_count, 2); // DaemonStarted + DaemonStopped

    // Verify audit log exists, has 2 records, and passes hash chain verification
    let audit_path = dir.path().join("audit.jsonl");
    assert!(audit_path.exists());
    let chain = dumer_audit::AuditChain::load_from_file(&audit_path).expect("load audit log");
    assert_eq!(chain.len(), 2);
    assert!(chain.verify().is_ok());

    let events = chain.events();
    assert_eq!(
        events[0].event_type,
        dumer_audit::AuditEventType::DaemonStarted
    );
    assert_eq!(
        events[1].event_type,
        dumer_audit::AuditEventType::DaemonStopped
    );
    assert_eq!(events[1].prev_hash, events[0].hash);
}
