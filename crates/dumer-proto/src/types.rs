//! Wire types for the D.U.M.E.R RPC protocol (`dumer-rpc@1`).
#![forbid(unsafe_code)]

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Protocol version 1 constant.
pub const DUMER_PROTOCOL_VERSION: u32 = 1;

/// Maximum frame size: 64 KiB (65,536 bytes).
pub const MAX_FRAME_SIZE: usize = 65_536;

/// Handshake message 1 (Server -> Client).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol_version: u32,
    pub server_nonce: [u8; 32],
    pub server_caps: Vec<String>,
}

/// Handshake message 2 (Client -> Server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub device_id: String,
    pub client_nonce: [u8; 32],
    pub signature: Vec<u8>,
}

/// Handshake message 3 (Server -> Client).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub session_id: [u8; 16],
    pub counter_start: u64,
}

/// RPC Request message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u32,
    pub session_id: [u8; 16],
    pub counter: u64,
    pub request_id: [u8; 16],
    pub op: String,
    pub args: BTreeMap<String, Value>,
    pub approval: Option<ApprovalRef>,
}

/// Response status variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Completed,
    Denied,
    NeedsApproval,
    Failed,
    Cancelled,
}

/// Error details in RPC Response.
/// Only safe, non-sensitive summary messages are permitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorInfo {
    pub code: String,
    pub safe_message: String,
}

/// RPC Response message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub v: u32,
    pub request_id: [u8; 16],
    pub status: ResponseStatus,
    pub result: Option<BTreeMap<String, Value>>,
    pub error: Option<ErrorInfo>,
}

/// Subject target identity for approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectIdentity {
    pub display_name: String,
    pub binary_path: String,
    pub sha256_hash: [u8; 32],
    pub publisher_signer: Option<String>,
}

/// Requester metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterInfo {
    pub device_id: String,
    pub channel: String,
    pub task_id: Option<[u8; 16]>,
}

/// Required signer roles for approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    Pc,
    Phone,
}

/// Action-bound Approval Request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub approval_id: [u8; 16],
    pub request_hash: [u8; 32],
    pub op: String,
    pub args_summary: String,
    pub subject_identity: SubjectIdentity,
    pub requester: RequesterInfo,
    pub agent_reason: String,
    pub effects: Vec<String>,
    pub tier: u8,
    pub nonce: [u8; 16],
    pub expires_at: u64,
    pub required_signers: Vec<SignerRole>,
}

/// Signed approval payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSignature {
    pub approval_id: [u8; 16],
    pub request_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at: u64,
    pub device_id: String,
    pub sig: Vec<u8>,
}

/// Reference to a signed approval submitted with a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRef {
    pub approval_id: [u8; 16],
    pub signature: ApprovalSignature,
}

/// Content-free notification payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Notification {
    ApprovalPending,
}

/// Top-level wire message enum.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "msg_type", content = "payload", rename_all = "snake_case")]
pub enum WireMessage {
    Hello(Hello),
    Auth(Auth),
    Session(Session),
    Request(Request),
    Response(Response),
    ApprovalRequest(ApprovalRequest),
    ApprovalSignature(ApprovalSignature),
    Notification(Notification),
}
