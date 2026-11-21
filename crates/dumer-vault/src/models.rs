use serde::{Deserialize, Serialize};

/// Memory classification per architecture specification §8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryClass {
    Config,
    Profile,
    Vault,
    TaskContext,
    IndexMetadata,
    ExternalCache,
    Audit,
}

impl MemoryClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Profile => "profile",
            Self::Vault => "vault",
            Self::TaskContext => "task_context",
            Self::IndexMetadata => "index_metadata",
            Self::ExternalCache => "external_cache",
            Self::Audit => "audit",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "config" => Some(Self::Config),
            "profile" => Some(Self::Profile),
            "vault" => Some(Self::Vault),
            "task_context" => Some(Self::TaskContext),
            "index_metadata" => Some(Self::IndexMetadata),
            "external_cache" => Some(Self::ExternalCache),
            "audit" => Some(Self::Audit),
            _ => None,
        }
    }
}

/// Knowledge cache freshness classes per architecture specification §10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessClass {
    Static,
    Slow,
    Fast,
    Volatile,
}

impl FreshnessClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Slow => "slow",
            Self::Fast => "fast",
            Self::Volatile => "volatile",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "static" => Some(Self::Static),
            "slow" => Some(Self::Slow),
            "fast" => Some(Self::Fast),
            "volatile" => Some(Self::Volatile),
            _ => None,
        }
    }
}

/// A registered device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRecord {
    pub device_id: String,
    pub display_name: String,
    pub public_key: Vec<u8>,
    pub enrolled_at: u64,
    pub last_seen_at: u64,
    pub is_revoked: bool,
    pub capabilities: Vec<String>,
}

/// A tracked autonomous or manual task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskRecord {
    pub task_id: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub status: String,
    pub intent: String,
    pub risk_tier: u8,
    pub budget_json: String,
    pub result_summary: Option<String>,
}

/// A stored memory item with complete metadata, sensitivity, provenance, and taint tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryRecord {
    pub record_id: String,
    pub memory_class: MemoryClass,
    pub source: String,
    pub confidence: f64,
    pub sensitivity: String,
    pub retention: String,
    pub provenance: String,
    pub taint: String,
    pub key: String,
    pub value: Vec<u8>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

/// An immutable hash-chained audit event record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEventRecord {
    pub seq: u64,
    pub event_id: String,
    pub timestamp: u64,
    pub event_type: String,
    pub prev_hash: String,
    pub event_hash: String,
    pub payload_cbor: Vec<u8>,
}

/// An active or revoked capability grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRecord {
    pub grant_id: String,
    pub subject: String,
    pub operation: String,
    pub resource: String,
    pub argument_constraints: String,
    pub risk_tier: u8,
    pub approval_ref: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

/// A validated action-bound approval token record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub request_hash: String,
    pub nonce: Vec<u8>,
    pub device_id: String,
    pub risk_tier: u8,
    pub approver_identity: String,
    pub signature: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub used: bool,
}

/// An external cache entry with freshness tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub cache_key: String,
    pub url: String,
    pub fetched_at: u64,
    pub freshness_class: FreshnessClass,
    pub ttl_seconds: u64,
    pub expires_at: u64,
    pub content_hash: String,
    pub taint: String,
    pub content: Vec<u8>,
    pub user_pinned: bool,
}

/// An encrypted item in the vault, unreadable without the separate VaultKey.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultItem {
    pub item_id: String,
    pub label: String,
    pub destination_allowlist: Vec<String>,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub created_at: u64,
    pub updated_at: u64,
    pub is_canary: bool,
}
