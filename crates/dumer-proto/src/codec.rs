//! Frame encoding, decoding, and canonical hashing routines for D.U.M.E.R RPC.
#![forbid(unsafe_code)]

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

use crate::error::ProtoError;
use crate::types::{SubjectIdentity, MAX_FRAME_SIZE};

/// Encodes a value into deterministic CBOR bytes.
pub fn canonical_cbor<T: Serialize>(val: &T) -> Result<Vec<u8>, ProtoError> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).map_err(|e| ProtoError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Encodes a serializable message into a length-prefixed protocol frame:
/// `u32 (big-endian length) || deterministic CBOR bytes`.
///
/// Ensures the encoded payload is strictly within `1..=MAX_FRAME_SIZE`.
pub fn encode_frame<T: Serialize>(val: &T) -> Result<Vec<u8>, ProtoError> {
    let cbor_bytes = canonical_cbor(val)?;
    let len = cbor_bytes.len();

    if len == 0 {
        return Err(ProtoError::EmptyFrame);
    }
    if len > MAX_FRAME_SIZE {
        return Err(ProtoError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        });
    }

    let len_prefix = (len as u32).to_be_bytes();
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&len_prefix);
    frame.extend_from_slice(&cbor_bytes);
    Ok(frame)
}

/// Decodes a length-prefixed protocol frame from an in-memory byte slice.
///
/// Strict rules:
/// 1. Must contain at least 4 bytes for length prefix.
/// 2. Declared length must be > 0 and <= MAX_FRAME_SIZE.
/// 3. Frame buffer length must exactly equal 4 + length (no truncated or trailing bytes).
/// 4. Decodes CBOR with strict unknown field rejection (`deny_unknown_fields`).
pub fn decode_frame<T: serde::de::DeserializeOwned>(frame_bytes: &[u8]) -> Result<T, ProtoError> {
    if frame_bytes.len() < 4 {
        return Err(ProtoError::TruncatedFrame {
            expected: 4,
            actual: frame_bytes.len(),
        });
    }

    let declared_len = u32::from_be_bytes([
        frame_bytes[0],
        frame_bytes[1],
        frame_bytes[2],
        frame_bytes[3],
    ]) as usize;

    if declared_len == 0 {
        return Err(ProtoError::EmptyFrame);
    }
    if declared_len > MAX_FRAME_SIZE {
        return Err(ProtoError::FrameTooLarge {
            size: declared_len,
            max: MAX_FRAME_SIZE,
        });
    }

    let total_expected = 4 + declared_len;
    if frame_bytes.len() < total_expected {
        return Err(ProtoError::TruncatedFrame {
            expected: total_expected,
            actual: frame_bytes.len(),
        });
    }
    if frame_bytes.len() > total_expected {
        return Err(ProtoError::TrailingBytes {
            expected: total_expected,
            actual: frame_bytes.len(),
        });
    }

    let payload = &frame_bytes[4..total_expected];
    ciborium::from_reader(payload).map_err(|e| ProtoError::CborDecode(e.to_string()))
}

/// Reads and decodes a length-prefixed protocol frame from a stream reader.
///
/// Strictly validates declared length before allocating memory for the frame payload.
pub fn decode_frame_from_reader<R: Read, T: for<'de> Deserialize<'de>>(
    mut reader: R,
) -> Result<T, ProtoError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;

    let declared_len = u32::from_be_bytes(len_buf) as usize;
    if declared_len == 0 {
        return Err(ProtoError::EmptyFrame);
    }
    if declared_len > MAX_FRAME_SIZE {
        return Err(ProtoError::FrameTooLarge {
            size: declared_len,
            max: MAX_FRAME_SIZE,
        });
    }

    // Allocation is strictly bounded by MAX_FRAME_SIZE (64 KiB)
    let mut payload = vec![0u8; declared_len];
    reader.read_exact(&mut payload)?;

    ciborium::from_reader(&payload[..]).map_err(|e| ProtoError::CborDecode(e.to_string()))
}

/// Canonical target structure for binding requests to approvals.
#[derive(Serialize)]
struct CanonicalRequestTarget<'a> {
    op: &'a str,
    args: &'a BTreeMap<String, Value>,
    subject: Option<&'a SubjectIdentity>,
}

/// Computes SHA-256 over the canonical CBOR encoding of:
/// `(op, args, subject_identity)`.
///
/// Enforces Invariant 5: Approvals are cryptographically bound to exact op + args + target identity.
pub fn compute_request_hash(
    op: &str,
    args: &BTreeMap<String, Value>,
    subject: Option<&SubjectIdentity>,
) -> Result<[u8; 32], ProtoError> {
    let target = CanonicalRequestTarget { op, args, subject };
    let canonical_bytes = canonical_cbor(&target)?;

    let mut hasher = Sha256::new();
    hasher.update(&canonical_bytes);
    Ok(hasher.finalize().into())
}
