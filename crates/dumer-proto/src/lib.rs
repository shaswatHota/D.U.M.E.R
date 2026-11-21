//! Protocol wire types, CBOR codec definitions, and schema specifications.
#![forbid(unsafe_code)]

pub mod codec;
pub mod error;
pub mod registry;
pub mod types;

pub use codec::{
    canonical_cbor, compute_request_hash, decode_frame, decode_frame_from_reader, encode_frame,
};
pub use error::ProtoError;
pub use registry::*;
pub use types::*;
