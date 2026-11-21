//! Comprehensive unit and property tests for protocol framing and codec round-trip.
#![forbid(unsafe_code)]

use ciborium::value::Value;
use dumer_proto::*;
use proptest::prelude::*;
use std::collections::BTreeMap;

#[test]
fn test_hello_roundtrip() {
    let hello = Hello {
        protocol_version: 1,
        server_nonce: [42u8; 32],
        server_caps: vec!["app.launch".to_string(), "system.read".to_string()],
    };
    let framed = encode_frame(&hello).expect("encode hello");
    let decoded: Hello = decode_frame(&framed).expect("decode hello");
    assert_eq!(hello, decoded);
}

#[test]
fn test_request_response_roundtrip() {
    let mut args = BTreeMap::new();
    args.insert("app_id".to_string(), Value::Text("chrome".to_string()));
    args.insert("wait_ms".to_string(), Value::Integer(5000.into()));

    let request = Request {
        v: 1,
        session_id: [1u8; 16],
        counter: 101,
        request_id: [7u8; 16],
        op: "application.open".to_string(),
        args,
        approval: None,
    };
    let framed = encode_frame(&request).expect("encode request");
    let decoded: Request = decode_frame(&framed).expect("decode request");
    assert_eq!(request, decoded);

    let mut result_map = BTreeMap::new();
    result_map.insert("pid".to_string(), Value::Integer(1234.into()));

    let response = Response {
        v: 1,
        request_id: [7u8; 16],
        status: ResponseStatus::Completed,
        result: Some(result_map),
        error: None,
    };
    let framed_resp = encode_frame(&response).expect("encode response");
    let decoded_resp: Response = decode_frame(&framed_resp).expect("decode response");
    assert_eq!(response, decoded_resp);
}

#[test]
fn test_approval_roundtrip() {
    let approval = ApprovalRequest {
        approval_id: [9u8; 16],
        request_hash: [33u8; 32],
        op: "priv.service.restart".to_string(),
        args_summary: "Restart dumer-service".to_string(),
        subject_identity: SubjectIdentity {
            display_name: "dumer-service".to_string(),
            binary_path: "C:\\Program Files\\Dumer\\service.exe".to_string(),
            sha256_hash: [55u8; 32],
            publisher_signer: Some("D.U.M.E.R Team".to_string()),
        },
        requester: RequesterInfo {
            device_id: "phone-123".to_string(),
            channel: "phone".to_string(),
            task_id: Some([11u8; 16]),
        },
        agent_reason: "Service unresponsive".to_string(),
        effects: vec!["Service restart".to_string()],
        tier: 4,
        nonce: [12u8; 16],
        expires_at: 1700000000,
        required_signers: vec![SignerRole::Pc, SignerRole::Phone],
    };

    let framed = encode_frame(&approval).expect("encode approval");
    let decoded: ApprovalRequest = decode_frame(&framed).expect("decode approval");
    assert_eq!(approval, decoded);
}

#[test]
fn test_empty_frame_rejected() {
    let zero_len_frame = [0u8, 0, 0, 0];
    let err = decode_frame::<Hello>(&zero_len_frame).unwrap_err();
    assert_eq!(err, ProtoError::EmptyFrame);
}

#[test]
fn test_frame_too_large_rejected() {
    // 65537 bytes declared (> 65536)
    let len_prefix = 65537u32.to_be_bytes();
    let mut large_frame = vec![0u8; 65537 + 4];
    large_frame[0..4].copy_from_slice(&len_prefix);

    let err = decode_frame::<Hello>(&large_frame).unwrap_err();
    assert_eq!(
        err,
        ProtoError::FrameTooLarge {
            size: 65537,
            max: MAX_FRAME_SIZE,
        }
    );
}

#[test]
fn test_truncated_frame_rejected() {
    // Declares 20 bytes payload, but only provides 10
    let mut buf = vec![0u8; 14];
    buf[0..4].copy_from_slice(&20u32.to_be_bytes());
    let err = decode_frame::<Hello>(&buf).unwrap_err();
    assert_eq!(
        err,
        ProtoError::TruncatedFrame {
            expected: 24,
            actual: 14,
        }
    );
}

#[test]
fn test_trailing_bytes_rejected() {
    let hello = Hello {
        protocol_version: 1,
        server_nonce: [1u8; 32],
        server_caps: vec![],
    };
    let mut framed = encode_frame(&hello).expect("encode");
    framed.push(0xFF); // Inject trailing byte

    let err = decode_frame::<Hello>(&framed).unwrap_err();
    match err {
        ProtoError::TrailingBytes { .. } => {}
        other => panic!("Expected TrailingBytes, got: {:?}", other),
    }
}

#[test]
fn test_unknown_fields_rejected() {
    // Craft CBOR map with extra unexpected field
    let mut map = BTreeMap::new();
    map.insert("protocol_version", Value::Integer(1.into()));
    map.insert("server_nonce", Value::Bytes(vec![0u8; 32]));
    map.insert("server_caps", Value::Array(vec![]));
    map.insert("malicious_extra_field", Value::Text("injected".to_string()));

    let framed = encode_frame(&map).expect("encode map");
    let res: Result<Hello, _> = decode_frame(&framed);
    assert!(res.is_err(), "Expected failure due to deny_unknown_fields");
}

#[test]
fn test_compute_request_hash_determinism_and_tamper() {
    let mut args = BTreeMap::new();
    args.insert("action".to_string(), Value::Text("install".to_string()));

    let subject = SubjectIdentity {
        display_name: "tool".to_string(),
        binary_path: "C:\\bin\\tool.exe".to_string(),
        sha256_hash: [8u8; 32],
        publisher_signer: None,
    };

    let hash1 = compute_request_hash("tool.install", &args, Some(&subject)).unwrap();
    let hash2 = compute_request_hash("tool.install", &args, Some(&subject)).unwrap();
    assert_eq!(hash1, hash2, "Canonical request hash must be deterministic");

    // Any arg mutation produces a completely different hash (Invariant 5)
    let mut tampered_args = args.clone();
    tampered_args.insert("action".to_string(), Value::Text("uninstall".to_string()));
    let tampered_hash =
        compute_request_hash("tool.install", &tampered_args, Some(&subject)).unwrap();
    assert_ne!(hash1, tampered_hash);
}

// Proptest property-based testing
proptest! {
    #[test]
    fn prop_roundtrip_request(
        v in 1u32..10,
        counter in 0u64..1_000_000,
        op in "[a-z]{3,10}\\.[a-z]{3,10}",
    ) {
        let req = Request {
            v,
            session_id: [5u8; 16],
            counter,
            request_id: [9u8; 16],
            op,
            args: BTreeMap::new(),
            approval: None,
        };
        let framed = encode_frame(&req).unwrap();
        let decoded: Request = decode_frame(&framed).unwrap();
        prop_assert_eq!(req, decoded);
    }

    #[test]
    fn prop_canonical_determinism(
        counter in 0u64..1000,
        payload in "[a-zA-Z0-9]{1,50}",
    ) {
        let mut args = BTreeMap::new();
        args.insert("key".to_string(), Value::Text(payload));

        let req = Request {
            v: 1,
            session_id: [2u8; 16],
            counter,
            request_id: [3u8; 16],
            op: "test.op".to_string(),
            args,
            approval: None,
        };

        let encoded1 = canonical_cbor(&req).unwrap();
        let encoded2 = canonical_cbor(&req).unwrap();
        prop_assert_eq!(encoded1, encoded2);
    }
}
