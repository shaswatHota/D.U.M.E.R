//! Fuzz target for protocol framing and CBOR decoding.
#![no_main]

use dumer_proto::{decode_frame, Hello, Request, Response, WireMessage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The frame decoder must strictly validate length, boundaries,
    // and schemas, and must never panic on arbitrary input bytes.
    let _ = decode_frame::<Hello>(data);
    let _ = decode_frame::<Request>(data);
    let _ = decode_frame::<Response>(data);
    let _ = decode_frame::<WireMessage>(data);
});
