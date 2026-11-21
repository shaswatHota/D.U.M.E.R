//! Automated internal self-test suite for `dumerd` startup validation.
#![forbid(unsafe_code)]

use dumer_audit::{AuditChain, AuditEventType};
use dumer_platform::is_unprivileged;
use dumer_proto::{canonical_cbor, decode_frame, encode_frame, Hello, ProtoError};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::config::DaemonConfig;

/// Errors detected during daemon self-test.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SelfTestError {
    #[error("Coordinator process is running with elevated privileges (MUST run unprivileged)")]
    PrivilegeCheckFailed,

    #[error("Config validation failure: {0}")]
    ConfigValidationFailed(String),

    #[error("Protocol frame codec check failed: {0}")]
    ProtoCodecFailed(String),

    #[error("Audit hash chain verification failed: {0}")]
    AuditIntegrityFailed(String),
}

/// Results summary of self-test execution.
#[derive(Debug, Clone)]
pub struct SelfTestReport {
    pub unprivileged_verified: bool,
    pub config_verified: bool,
    pub proto_codec_verified: bool,
    pub audit_chain_verified: bool,
}

/// Executes all mandatory startup self-tests.
///
/// Verifies:
/// 1. Unprivileged user space execution (Invariant 4 / Architecture §2).
/// 2. Overlay bind address security (Invariant 7).
/// 3. Framing codec round-trip and canonical encoding.
/// 4. Audit logging, hash chaining, and tamper verification.
pub fn run_self_tests(config: &DaemonConfig) -> Result<SelfTestReport, SelfTestError> {
    // 1. Verify unprivileged process state
    if !is_unprivileged() {
        return Err(SelfTestError::PrivilegeCheckFailed);
    }

    // 2. Validate configuration constraints
    config
        .validate()
        .map_err(|e| SelfTestError::ConfigValidationFailed(e.to_string()))?;

    // 3. Test protocol framing and deterministic CBOR codec
    let test_hello = Hello {
        protocol_version: 1,
        server_nonce: [0x5au8; 32],
        server_caps: vec!["system.status".to_string()],
    };
    let framed = encode_frame(&test_hello)
        .map_err(|e| SelfTestError::ProtoCodecFailed(format!("encode: {}", e)))?;
    let decoded: Hello = decode_frame(&framed)
        .map_err(|e| SelfTestError::ProtoCodecFailed(format!("decode: {}", e)))?;
    if test_hello != decoded {
        return Err(SelfTestError::ProtoCodecFailed(
            "Round-trip decoded message does not match original".to_string(),
        ));
    }

    // Verify canonical determinism
    let bytes1 =
        canonical_cbor(&test_hello).map_err(|e| SelfTestError::ProtoCodecFailed(e.to_string()))?;
    let bytes2 =
        canonical_cbor(&test_hello).map_err(|e| SelfTestError::ProtoCodecFailed(e.to_string()))?;
    if bytes1 != bytes2 {
        return Err(SelfTestError::ProtoCodecFailed(
            "Canonical CBOR output is non-deterministic".to_string(),
        ));
    }

    // Verify empty frame rejected
    let empty_res = decode_frame::<Hello>(&[0, 0, 0, 0]);
    if empty_res != Err(ProtoError::EmptyFrame) {
        return Err(SelfTestError::ProtoCodecFailed(
            "Empty frame was not rejected with EmptyFrame error".to_string(),
        ));
    }

    // 4. Test audit log hash-chaining and verification
    let mut audit_chain =
        AuditChain::new(None).map_err(|e| SelfTestError::AuditIntegrityFailed(e.to_string()))?;
    let mut details = BTreeMap::new();
    details.insert("test_key".to_string(), "self_test_run".to_string());
    audit_chain
        .append(
            AuditEventType::SelfTestRun,
            "dumerd_selftest".to_string(),
            None,
            details,
            1,
        )
        .map_err(|e| SelfTestError::AuditIntegrityFailed(e.to_string()))?;

    audit_chain
        .verify()
        .map_err(|e| SelfTestError::AuditIntegrityFailed(e.to_string()))?;

    Ok(SelfTestReport {
        unprivileged_verified: true,
        config_verified: true,
        proto_codec_verified: true,
        audit_chain_verified: true,
    })
}
