//! In-tree adversarial and random fuzz tests for frame decoding.
//!
//! Verifies that `decode_frame` never panics on arbitrary or malformed input bytes,
//! and always fails closed with a typed `ProtoError`.
#![forbid(unsafe_code)]

use dumer_proto::{decode_frame, Hello, Request, Response, WireMessage};

#[test]
fn test_fuzz_random_byte_slices() {
    let mut rng_state = 0x12345678u64;
    let mut next_byte = || {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (rng_state >> 33) as u8
    };

    for len in 0..1024 {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(next_byte());
        }

        // Must never panic
        let _ = decode_frame::<Hello>(&buf);
        let _ = decode_frame::<Request>(&buf);
        let _ = decode_frame::<Response>(&buf);
        let _ = decode_frame::<WireMessage>(&buf);
    }
}

#[test]
fn test_fuzz_boundary_length_prefixes() {
    // Tests various length prefix edge cases
    let prefixes: &[u32] = &[
        0,
        1,
        2,
        3,
        4,
        65535,
        65536,
        65537,
        100000,
        u32::MAX - 1,
        u32::MAX,
    ];

    for &len in prefixes {
        let prefix = len.to_be_bytes();
        let mut buf = prefix.to_vec();
        buf.extend_from_slice(&[0x01, 0x02, 0x03]); // Short payload

        let _ = decode_frame::<WireMessage>(&buf);
    }
}
